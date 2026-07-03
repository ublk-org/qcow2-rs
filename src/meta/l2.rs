use super::table::{
    impl_entry_display_trait, impl_table_gen_funcs, impl_table_gen_setter, impl_table_traits,
    Table, TableEntry,
};
use super::SplitGuestOffset;
use crate::dev::Qcow2Info;
use crate::error::Qcow2Result;
use crate::helpers::Qcow2IoBuf;

impl_entry_display_trait!(L2Entry);

// L2 table entry:
//
// Bit  0 -  61:    Cluster descriptor
//
//      62:         0 for standard clusters
//                  1 for compressed clusters
//
//      63:         0 for clusters that are unused, compressed or require COW.
//                  1 for standard clusters whose refcount is exactly one.
//                  This information is only accurate in L2 tables
//                  that are reachable from the active L1 table.
//
//                  With external data files, all guest clusters have an
//                  implicit refcount of 1 (because of the fixed host = guest
//                  mapping for guest cluster offsets), so this bit should be 1
//                  for all allocated clusters.
//
// Standard Cluster Descriptor:
//
//     Bit       0:    If set to 1, the cluster reads as all zeros. The host
//                     cluster offset can be used to describe a preallocation,
//                     but it won't be used for reading data from this cluster,
//                     nor is data read from the backing file if the cluster is
//                     unallocated.
//
//                     With version 2 or with extended L2 entries (see the next
//                     section), this is always 0.
//
//          1 -  8:    Reserved (set to 0)
//
//          9 - 55:    Bits 9-55 of host cluster offset. Must be aligned to a
//                     cluster boundary. If the offset is 0 and bit 63 is clear,
//                     the cluster is unallocated. The offset may only be 0 with
//                     bit 63 set (indicating a host cluster offset of 0) when an
//                     external data file is used.
//
//         56 - 61:    Reserved (set to 0)
#[derive(Copy, Clone, Default, Debug)]
pub struct L2Entry(pub(crate) u64);

/// Mapping represents the mapping of a cluster to a source of data
/// Mapping and L2Entry can be converted to each other.
#[derive(Debug, Clone)]
pub struct Mapping {
    /// Where/how to get the mapped data from
    pub source: MappingSource,
    /// Offset in `source` from which to read the whole cluster data; for compressed clusters, this
    /// is generally not aligned to a cluster boundary
    pub cluster_offset: Option<u64>,
    /// For compressed data: Upper limit on the number of bytes that comprise the compressed data
    pub compressed_length: Option<usize>,
    /// If this is true, `cluster_offset` may be written to, and doing so will only change this
    /// cluster's data (note that for zero clusters, writing to a COPIED cluster will not change
    /// the visible data: first, the mapping must be changed to be a data cluster)
    pub copied: bool,
}

impl std::fmt::Display for Mapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Source: {:?} offset 0x{:<x} compressed_len {} copied {}",
            self.source,
            self.cluster_offset.unwrap_or(u64::MAX),
            self.compressed_length.unwrap_or(0),
            self.copied,
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MappingSource {
    /// Read the mapped data from the data file
    DataFile,
    /// Read the mapped data from the backing file
    Backing,
    /// This is zero data; use memset(0) instead of reading it
    Zero,
    /// Read compressed data from the data file
    Compressed,
    /// Unallocated
    Unallocated,
}

impl L2Entry {
    #[inline(always)]
    pub fn cluster_offset(&self) -> u64 {
        self.0 & 0x00ff_ffff_ffff_fe00u64
    }

    #[inline(always)]
    pub fn is_compressed(&self) -> bool {
        self.0 & (1u64 << 62) != 0
    }

    #[inline(always)]
    pub fn is_copied(&self) -> bool {
        self.0 & (1u64 << 63) != 0
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.0 & (1u64 << 0) != 0
    }

    #[inline(always)]
    pub fn reserved_bits(&self) -> u64 {
        if self.is_compressed() {
            self.0 & 0x8000_0000_0000_0000u64
        } else {
            self.0 & 0x3f00_0000_0000_01feu64
        }
    }

    #[inline(always)]
    pub fn compressed_descriptor(&self) -> u64 {
        self.0 & 0x3fff_ffff_ffff_ffffu64
    }

    /// If this entry is compressed, return the start host offset and upper
    /// limit on the compressed number of bytes
    #[inline(always)]
    pub fn compressed_range(&self, cluster_bits: u32) -> Option<(u64, usize)> {
        if self.is_compressed() {
            let desc = self.compressed_descriptor();
            let compressed_offset_bits = 62 - (cluster_bits - 8);
            let offset = desc & ((1 << compressed_offset_bits) - 1) & 0x00ff_ffff_ffff_ffffu64;
            let sectors = (desc >> compressed_offset_bits) as usize;
            // The first sector is not considered in `sectors`, so we add it and subtract the
            // number of bytes there that do not belong to this compressed cluster
            let length = (sectors + 1) * 512 - (offset & 511) as usize;

            Some((offset, length))
        } else {
            None
        }
    }

    /// If this entry is allocated, return the host cluster offset and the number of clusters it
    /// references; otherwise return None.
    #[inline(always)]
    pub fn allocation(&self, cluster_bits: u32) -> Option<(u64, usize)> {
        if let Some((offset, length)) = self.compressed_range(cluster_bits) {
            // Compressed clusters can cross host cluster boundaries, and thus occupy two clusters
            let cluster_size = 1u64 << cluster_bits;
            let cluster_base = offset & !(cluster_size - 1);
            let clusters =
                ((offset + length as u64 + cluster_size - 1) - cluster_base) >> cluster_bits;
            Some((cluster_base, clusters as usize))
        } else {
            match self.cluster_offset() {
                0 => None,
                ofs => Some((ofs, 1)),
            }
        }
    }

    /// Convert to mapping
    ///
    /// `guest_addr` is only used for backing offset
    #[inline]
    pub fn into_mapping(self, info: &Qcow2Info, guest_addr: &SplitGuestOffset) -> Mapping {
        //println!("into_mapping guest {:x} l2_entry {}", guest_addr.0, self);
        let cluster_bits: u32 = info.cluster_bits() as u32;
        if let Some((offset, length)) = self.compressed_range(cluster_bits) {
            Mapping {
                source: MappingSource::Compressed,
                cluster_offset: Some(offset),
                compressed_length: Some(length),
                copied: false,
            }
        } else if self.is_zero() {
            let offset = match self.cluster_offset() {
                0 => None,
                ofs => Some(ofs),
            };

            Mapping {
                source: MappingSource::Zero,
                cluster_offset: offset,
                compressed_length: None,
                copied: offset.is_some() && self.is_copied(),
            }
        } else {
            match self.cluster_offset() {
                0 => {
                    // in case of backing file, return backing mapping
                    if self.is_copied() || info.has_back_file() {
                        Mapping {
                            source: MappingSource::Backing,
                            cluster_offset: Some(guest_addr.cluster_offset(info)),
                            compressed_length: None,
                            copied: false,
                        }
                    } else {
                        Mapping {
                            source: MappingSource::Unallocated,
                            cluster_offset: Some(0),
                            compressed_length: None,
                            copied: false,
                        }
                    }
                }
                ofs => Mapping {
                    source: MappingSource::DataFile,
                    cluster_offset: Some(ofs),
                    compressed_length: None,
                    copied: self.is_copied(),
                },
            }
        }
    }

    // Convert mapping into L2Entry
    #[inline]
    pub fn from_mapping(value: Mapping, cluster_bits: u32) -> Self {
        debug_assert!(value.cluster_offset.unwrap_or(0) <= 0x00ff_ffff_ffff_ffffu64);

        let num_val: u64 = match value.source {
            MappingSource::DataFile => {
                debug_assert!(value.compressed_length.is_none());
                if value.copied {
                    (1 << 63) | value.cluster_offset.unwrap()
                } else {
                    value.cluster_offset.unwrap()
                }
            }

            MappingSource::Backing => {
                debug_assert!(value.compressed_length.is_none() && !value.copied);
                0
            }

            MappingSource::Zero => {
                debug_assert!(value.compressed_length.is_none());
                if value.copied {
                    (1 << 63) | value.cluster_offset.unwrap() | 0x1
                } else {
                    value.cluster_offset.unwrap_or(0) | 0x1
                }
            }

            MappingSource::Compressed => {
                debug_assert!(!value.copied);
                let compressed_offset_bits = 62 - (cluster_bits - 8);
                let offset = value.cluster_offset.unwrap();
                let length = value.compressed_length.unwrap();
                assert!(length < 1 << cluster_bits);

                // The first sector is not considered, so we subtract the number of bytes in it
                // that belong to this compressed cluster from `length`:
                // ceil((length - (512 - (offset & 511))) / 512)
                // = (length + 511 - 512 + (offset & 511)) / 512
                let sectors = (length - 1 + (offset & 511) as usize) / 512;

                (1 << 62) | ((sectors as u64) << compressed_offset_bits) | offset
            }
            MappingSource::Unallocated => 0,
        };

        let entry = L2Entry(num_val);
        debug_assert!(entry.reserved_bits() == 0);
        entry
    }
}

impl Mapping {
    #[inline]
    pub fn plain_offset(&self, in_cluster_offset: usize) -> Option<u64> {
        (self.source == MappingSource::DataFile && self.copied)
            .then(|| self.cluster_offset.unwrap() + in_cluster_offset as u64)
    }

    #[inline]
    pub fn allocated(&self) -> bool {
        self.source != MappingSource::Unallocated
    }
}

impl TableEntry for L2Entry {
    fn try_from_plain(value: u64, qcow2_info: &Qcow2Info) -> Qcow2Result<Self> {
        let entry = L2Entry(value);

        if entry.reserved_bits() != 0 {
            return Err(format!(
                "Invalid L2 entry 0x{:x}, reserved bits set (0x{:x})",
                value,
                entry.reserved_bits()
            )
            .into());
        }

        if !entry.is_compressed() && qcow2_info.in_cluster_offset(entry.cluster_offset()) != 0 {
            return Err(format!(
                "Invalid L2 entry 0x{:x}, offset (0x{:x}) is not aligned to cluster size (0x{:x})",
                value,
                entry.cluster_offset(),
                qcow2_info.cluster_size()
            )
            .into());
        }

        Ok(entry)
    }

    fn into_plain(self) -> u64 {
        self.0
    }
}

// Given an offset into the virtual disk, the offset into the image file can be
// obtained as follows:
//
// l2_entries = (cluster_size / sizeof(uint64_t))        [*]
//
// l2_index = (offset / cluster_size) % l2_entries
// l1_index = (offset / cluster_size) / l2_entries
//
// l2_table = load_cluster(l1_table[l1_index]);
// cluster_offset = l2_table[l2_index];
//
// return cluster_offset + (offset % cluster_size)
//
// [*] this changes if Extended L2 Entries are enabled, see next section
#[derive(Debug)]
pub struct L2Table {
    offset: Option<u64>,
    cluster_bits: u32,
    data: Qcow2IoBuf<L2Entry>,
}

impl L2Table {
    #[inline]
    pub fn get_entry(&self, info: &Qcow2Info, lookup_addr: &SplitGuestOffset) -> L2Entry {
        let l2_slice_index = lookup_addr.l2_slice_index(info);
        self.get(l2_slice_index)
    }

    #[inline]
    pub fn get_mapping(&self, info: &Qcow2Info, lookup_addr: &SplitGuestOffset) -> Mapping {
        let l2_slice_index = lookup_addr.l2_slice_index(info);
        let entry = self.get(l2_slice_index);

        entry.into_mapping(info, lookup_addr)
    }

    /// If the previous entry pointed to an allocated cluster, return
    /// the old allocation so its refcount can be decreased (offset of
    /// the first cluster and number of clusters -- compressed clusters
    /// can span across host cluster boundaries).
    ///
    /// If the allocation is reused, `None` is returned, so this function
    /// only returns `Some(_)` if some cluster is indeed leaked.
    #[must_use]
    pub fn map_cluster(&mut self, index: usize, host_cluster: u64) -> Option<(u64, usize)> {
        let allocation = self.data[index].allocation(self.cluster_bits);

        self.set(
            index,
            L2Entry::from_mapping(
                Mapping {
                    source: MappingSource::DataFile,
                    cluster_offset: Some(host_cluster),
                    compressed_length: None,
                    copied: true,
                },
                self.cluster_bits,
            ),
        );

        if let Some((a_offset, a_count)) = allocation {
            if a_offset == host_cluster && a_count == 1 {
                None
            } else {
                allocation
            }
        } else {
            None
        }
    }

    /// Following L2Table creating, and we are supporting
    /// l2 table slice
    pub fn set_cluster_bits(&mut self, cluster_bits: usize) {
        self.cluster_bits = cluster_bits as u32;
    }

    pub fn new(offset: Option<u64>, size: usize, cluster_bits: usize) -> L2Table {
        let mut t = L2Table::new_empty(offset, size);

        t.set_cluster_bits(cluster_bits);

        t
    }
}

impl From<Qcow2IoBuf<L2Entry>> for L2Table {
    fn from(data: Qcow2IoBuf<L2Entry>) -> Self {
        Self {
            offset: None,
            cluster_bits: 0,
            data,
        }
    }
}

impl_table_traits!(L2Table, L2Entry, data);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l2_table() {
        let cluster_bits = 16;
        let cluster_size = 1 << cluster_bits;
        let size = 4096;

        let l2 = L2Table::new(Some(cluster_size * 4), size, cluster_bits);
        assert!(l2.cluster_bits == cluster_bits as u32);
    }
}
