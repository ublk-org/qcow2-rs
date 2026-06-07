// borrowed from rsd project

#![allow(dead_code)]

use crate::dev::Qcow2Info;
use crate::error::Qcow2Result;
use crate::helpers::Qcow2IoBuf;
use std::cell::RefCell;
use std::collections::VecDeque;

mod addr;
mod header;
mod l1;
mod table;
pub use self::addr::SplitGuestOffset;
pub use self::header::*;
pub use self::l1::{L1Entry, L1Table};
use self::table::{
    impl_entry_display_trait, impl_table_gen_funcs, impl_table_gen_setter, impl_table_traits,
    impl_top_table_gen_funcs, impl_top_table_traits,
};
pub use self::table::{Table, TableEntry};

impl_entry_display_trait!(L2Entry);
impl_entry_display_trait!(RefTableEntry);
impl_entry_display_trait!(RefBlockEntry);

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
            match self.cluster_offset {
                None => u64::MAX,
                Some(o) => o,
            },
            match self.compressed_length {
                None => usize::MIN,
                Some(o) => o,
            },
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

#[derive(Copy, Clone, Default, Debug)]
pub struct RefTableEntry(pub u64);

impl RefTableEntry {
    const DIRTY: u64 = 0x1;
    const NEW: u64 = 0x2;
    pub fn refblock_offset(&self) -> u64 {
        self.0 & 0xffff_ffff_ffff_fe00u64
    }

    pub fn is_zero(&self) -> bool {
        self.refblock_offset() == 0
    }

    pub fn reserved_bits(&self) -> u64 {
        self.0 & 0x0000_0000_0000_01ffu64
    }
}

impl TableEntry for RefTableEntry {
    fn try_from_plain(value: u64, qcow2_info: &Qcow2Info) -> Qcow2Result<Self> {
        let entry = RefTableEntry(value);

        if entry.reserved_bits() != 0 {
            return Err(format!(
                "Invalid reftable entry 0x{:x}, reserved bits set (0x{:x})",
                value,
                entry.reserved_bits()
            )
            .into());
        }

        if qcow2_info.in_cluster_offset(entry.refblock_offset()) != 0 {
            return Err(format!(
                "Invalid reftable entry 0x{:x}, offset (0x{:x}) is not aligned to cluster size (0x{:x})",
                value,
                entry.refblock_offset(),
                qcow2_info.cluster_size()
            )
            .into());
        }

        Ok(entry)
    }

    #[inline(always)]
    fn into_plain(self) -> u64 {
        self.0
    }

    #[inline(always)]
    fn get_value(&self) -> u64 {
        self.refblock_offset()
    }
}

#[derive(Debug)]
pub struct RefTable {
    dirty_blocks: RefCell<VecDeque<u32>>,
    bs_bits: u8,
    offset: Option<u64>,
    data: Qcow2IoBuf<RefTableEntry>,
}

impl RefTable {
    pub fn new(offset: Option<u64>, size: usize, bs_bits: u8) -> Self {
        let mut rt = RefTable::new_empty(offset, size);

        rt.dirty_blocks = RefCell::new(VecDeque::new());
        rt.bs_bits = bs_bits;
        rt
    }

    /// Create a clone that covers at least `at_least_index`
    pub fn clone_and_grow(&self, clusters: usize, cluster_size: usize, bs: usize) -> Self {
        let entry_size = core::mem::size_of::<RefTableEntry>();
        let ram_size = self.data.len() * entry_size;

        //table in ram may not reach end of reftable in disk
        let (new_size, new_off) = if ram_size + entry_size < clusters * cluster_size {
            (ram_size + entry_size, self.offset)
        } else {
            (clusters * cluster_size + bs, None)
        };

        let mut new_data = Qcow2IoBuf::<RefTableEntry>::new(new_size);
        new_data.zero_buf();
        new_data[..self.data.len()].copy_from_slice(&self.data);

        Self {
            offset: new_off,
            data: new_data,
            dirty_blocks: RefCell::new(self.dirty_blocks.borrow().clone()),
            bs_bits: self.bs_bits,
        }
    }

    pub fn in_bounds(&self, index: usize) -> bool {
        index < self.data.len()
    }

    pub fn set_refblock_offset(&mut self, index: usize, rb_offset: u64) {
        let rt_entry = RefTableEntry(rb_offset);
        debug_assert!(rt_entry.reserved_bits() == 0);

        self.set(index, rt_entry);
        self.set_dirty(index);
    }
}

impl From<Qcow2IoBuf<RefTableEntry>> for RefTable {
    fn from(data: Qcow2IoBuf<RefTableEntry>) -> Self {
        Self {
            data,
            dirty_blocks: RefCell::new(VecDeque::new()),
            bs_bits: 0,
            offset: None,
        }
    }
}

impl_top_table_traits!(RefTable, RefTableEntry, data);

#[derive(Copy, Clone, Default, Debug)]
pub struct RefBlockEntry(u64);

impl RefBlockEntry {
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}
impl TableEntry for RefBlockEntry {
    #[inline(always)]
    fn try_from_plain(value: u64, _qcow2_info: &Qcow2Info) -> Qcow2Result<Self> {
        Ok(RefBlockEntry(value))
    }

    #[inline(always)]
    fn into_plain(self) -> u64 {
        self.0
    }
}

#[derive(Debug)]
pub struct RefBlock {
    offset: Option<u64>,
    raw_data: Qcow2IoBuf<RefBlockEntry>,
    refcount_order: u8,
}

impl RefBlock {
    pub fn new(refcount_order: u8, size: usize, offset: Option<u64>) -> Self {
        let mut rb = RefBlock::new_empty(offset, size);

        rb.set_refcount_order(refcount_order);
        rb
    }

    pub fn set_refcount_order(&mut self, refcount_order: u8) {
        self.refcount_order = refcount_order;
    }

    #[inline(always)]
    fn __get(&self, index: usize) -> u64 {
        let raw_data = &self.raw_data.as_u8_slice();
        match self.refcount_order {
            // refcount_bits == 1
            0 => ((raw_data[index / 8] >> (index % 8)) & 0b0000_0001) as u64,

            // refcount_bits == 2
            1 => ((raw_data[index / 4] >> (index % 4)) & 0b0000_0011) as u64,

            // refcount_bits == 4
            2 => ((raw_data[index / 2] >> (index % 2)) & 0b0000_1111) as u64,

            // refcount_bits == 8
            3 => raw_data[index] as u64,

            // refcount_bits == 16
            4 => u16::from_be_bytes(raw_data[index * 2..index * 2 + 2].try_into().unwrap()) as u64,

            // refcount_bits == 32
            5 => u32::from_be_bytes(raw_data[index * 4..index * 4 + 4].try_into().unwrap()) as u64,

            // refcount_bits == 64
            6 => u64::from_be_bytes(raw_data[index * 8..index * 8 + 8].try_into().unwrap()),

            _ => unreachable!(),
        }
    }

    fn __set(&mut self, index: usize, value: u64) -> Qcow2Result<()> {
        let raw_data = &mut self.raw_data.as_u8_slice_mut();
        match self.refcount_order {
            // refcount_bits == 1
            0 => {
                if value > 0b0000_0001 {
                    return Err(format!(
                        "Cannot increase refcount beyond {} with refcount_bits=1",
                        0b0000_0001
                    )
                    .into());
                }
                raw_data[index / 8] = (raw_data[index / 8] & !(0b0000_0001 << (index % 8)))
                    | ((value as u8) << (index % 8));
            }

            // refcount_bits == 2
            1 => {
                if value > 0b0000_0011 {
                    return Err(format!(
                        "Cannot increase refcount beyond {} with refcount_bits=2",
                        0b0000_0011
                    )
                    .into());
                }
                raw_data[index / 4] = (raw_data[index / 4] & !(0b0000_0011 << (index % 4)))
                    | ((value as u8) << (index % 4));
            }

            // refcount_bits == 4
            2 => {
                if value > 0b0000_1111 {
                    return Err(format!(
                        "Cannot increase refcount beyond {} with refcount_bits=4",
                        0b0000_1111
                    )
                    .into());
                }
                raw_data[index / 2] = (raw_data[index / 2] & !(0b0000_1111 << (index % 2)))
                    | ((value as u8) << (index % 2));
            }

            // refcount_bits == 8
            3 => {
                if value > u8::MAX as u64 {
                    return Err(format!(
                        "Cannot increase refcount beyond {} with refcount_bits=8",
                        u8::MAX
                    )
                    .into());
                }
                raw_data[index] = value as u8;
            }

            // refcount_bits == 16
            4 => {
                if value > u16::MAX as u64 {
                    return Err(format!(
                        "Cannot increase refcount beyond {} with refcount_bits=16",
                        u16::MAX
                    )
                    .into());
                }
                raw_data[index * 2] = (value >> 8) as u8;
                raw_data[index * 2 + 1] = value as u8;
            }

            // refcount_bits == 32
            5 => {
                if value > u32::MAX as u64 {
                    return Err(format!(
                        "Cannot increase refcount beyond {} with refcount_bits=32",
                        u32::MAX
                    )
                    .into());
                }
                raw_data[index * 4] = (value >> 24) as u8;
                raw_data[index * 4 + 1] = (value >> 16) as u8;
                raw_data[index * 4 + 2] = (value >> 8) as u8;
                raw_data[index * 4 + 3] = value as u8;
            }

            // refcount_bits == 64
            6 => {
                let array: &mut [u8; 8] = (&mut raw_data[index * 8..index * 8 + 8])
                    .try_into()
                    .unwrap();
                *array = value.to_be_bytes();
            }

            _ => unreachable!(),
        }

        Ok(())
    }

    pub fn increment(&mut self, index: usize) -> Qcow2Result<()> {
        let val = self
            .get(index)
            .into_plain()
            .checked_add(1)
            .ok_or_else(|| format!("Cannot increase refcount beyond {}", u64::MAX))?;
        self.__set(index, val)
    }

    pub fn decrement(&mut self, index: usize) -> Qcow2Result<()> {
        let val = self
            .get(index)
            .into_plain()
            .checked_sub(1)
            .ok_or("Cannot decrease refcount below 0")?;
        self.__set(index, val)
    }

    fn byte_indices(&self, index: usize) -> std::ops::RangeInclusive<usize> {
        match self.refcount_order {
            0 => index / 8..=index / 8,
            1 => index / 4..=index / 4,
            2 => index / 2..=index / 2,
            3 => index..=index,
            4 => index * 2..=index * 2 + 1,
            5 => index * 4..=index * 4 + 3,
            6 => index * 8..=index * 8 + 7,
            _ => unreachable!(),
        }
    }

    fn check_if_free(&self, r: std::ops::Range<usize>) -> bool {
        for i in r {
            if !self.get(i).is_zero() {
                return false;
            }
        }
        true
    }

    pub fn get_free_range(&self, start: usize, count: usize) -> Option<std::ops::Range<usize>> {
        assert!(start + count <= self.entries());
        let max_start = self.entries() - count;

        for i in start..=max_start {
            if self.check_if_free(i..i + count) {
                return Some(i..i + count);
            }
        }

        None
    }

    pub fn get_tail_free_range(&self) -> Option<std::ops::Range<usize>> {
        let r = 0..self.entries();

        for i in r.rev() {
            if !self.get(i).is_zero() {
                if i == self.entries() - 1 {
                    break;
                }
                return Some(i + 1..self.entries());
            }
        }
        None
    }

    pub fn alloc_range(&mut self, s: usize, e: usize) -> Qcow2Result<()> {
        for i in s..e {
            self.increment(i)?;
        }
        Ok(())
    }
}

impl Table for RefBlock {
    type Entry = RefBlockEntry;

    impl_table_gen_funcs!(raw_data);

    fn entries(&self) -> usize {
        self.byte_size() * 8 / (1 << self.refcount_order)
    }

    fn get(&self, index: usize) -> Self::Entry {
        RefBlockEntry(self.__get(index))
    }

    fn set(&mut self, index: usize, value: Self::Entry) {
        self.__set(index, value.into_plain()).unwrap();
    }

    fn set_with_return(&mut self, index: usize, value: Self::Entry) -> Qcow2Result<()> {
        self.__set(index, value.into_plain())
    }

    /// RefBlock is special, since RefBlockEntry is defined as u64
    fn byte_size(&self) -> usize {
        self.raw_data.len() * 8
    }
}

impl From<Qcow2IoBuf<RefBlockEntry>> for RefBlock {
    fn from(data: Qcow2IoBuf<RefBlockEntry>) -> Self {
        Self {
            offset: None,
            refcount_order: 0,
            raw_data: data,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::dev::*;
    use crate::meta::*;

    #[test]
    fn test_refcount_table() {
        let cluster_size = 1 << 16;
        let size = 4096;

        let mut rc = RefTable::new_empty(Some(cluster_size), 4096);
        assert!(rc.entries() == (size / core::mem::size_of::<u64>()));
        assert!(rc.as_ptr() != std::ptr::null());

        let entry = rc.get(0);
        assert!(entry.is_zero() == true);

        let rcb_offset = cluster_size * 3;
        rc.set(0, RefTableEntry(rcb_offset));
        let entry = rc.get(0);
        assert!(entry.refblock_offset() == rcb_offset);

        let raw_addr = rc.as_ptr() as *const u64;
        unsafe {
            assert!(u64::from_be(*raw_addr) == rcb_offset);
        };
    }

    #[test]
    fn test_refcount_block() {
        let cluster_size = 1 << 16;
        let size = 4096;
        let refcount_order = 4;
        let entries = size * 8 / (1 << refcount_order);

        let mut rc_b = RefBlock::new(refcount_order, size, Some(2 * cluster_size));
        assert!(rc_b.entries() == entries);
        assert!(rc_b.as_ptr() != std::ptr::null());

        for i in 0..entries {
            let entry = rc_b.get(i).into_plain();
            assert!(entry == 0);
            rc_b.increment(i).unwrap();
            let entry = rc_b.get(i).into_plain();
            assert!(entry == 1);
        }
    }

    #[test]
    fn test_l2_table() {
        let cluster_bits = 16;
        let cluster_size = 1 << cluster_bits;
        let size = 4096;

        let l2 = L2Table::new(Some(cluster_size * 4), size, cluster_bits);
        assert!(l2.cluster_bits == cluster_bits as u32);
    }

    /// more detailed unit test generated by AI with small fixes
    #[test]
    fn test_refcount_block2() {
        let mut refblock = RefBlock::new(3, 4096, Some(0));
        assert_eq!(refblock.entries(), 4096);
        assert_eq!(refblock.byte_size(), 4096);
        assert_eq!(refblock.get_offset(), Some(0));

        assert!(refblock.get(0).is_zero());

        assert!(refblock.increment(0).is_ok());
        assert_eq!(refblock.get(0).into_plain(), 1);

        assert!(refblock.decrement(0).is_ok());
        assert_eq!(refblock.get(0).into_plain(), 0);

        assert!(refblock.set_with_return(0, RefBlockEntry(255)).is_ok());
        assert!(refblock.set_with_return(0, RefBlockEntry(1)).is_ok());
        assert_eq!(refblock.get(0).into_plain(), 1);

        assert!(refblock.set_with_return(0, RefBlockEntry(256)).is_err());
        assert!(refblock.set_with_return(0, RefBlockEntry(255)).is_ok());
        assert_eq!(refblock.get(0).into_plain(), 255);

        assert!(refblock
            .set_with_return(0, RefBlockEntry(u16::MAX as u64 + 1))
            .is_err());
        assert!(refblock
            .set_with_return(0, RefBlockEntry(u16::MAX as u64))
            .is_err());

        assert!(refblock
            .set_with_return(0, RefBlockEntry(u32::MAX as u64 + 1))
            .is_err());
        assert!(refblock
            .set_with_return(0, RefBlockEntry(u32::MAX as u64))
            .is_err());

        assert!(refblock
            .set_with_return(0, RefBlockEntry(u64::MAX))
            .is_err());
    }

    #[test]
    fn test_format() {
        fn __test_format(cluster_bits: usize, refcount_order: u8, size: u64) {
            let p = crate::qcow2_default_params!(true, true);
            let bs = 1 << p.get_bs_bits();
            let (rc_t, rc_b, _) =
                Qcow2Header::calculate_meta_params(size, cluster_bits, refcount_order, bs);
            let clusters = 1 + rc_t.1 + rc_b.1;
            let img_size = ((clusters as usize) << cluster_bits) + 512;
            let mut buf = vec![0u8; img_size];

            Qcow2Header::format_qcow2(&mut buf, size, cluster_bits, refcount_order, bs).unwrap();

            let header = Qcow2Header::from_buf(&buf).unwrap();
            let info = Qcow2Info::new(&header, &p).unwrap();

            assert!(info.cluster_bits() == cluster_bits);
            assert!(info.virtual_size() == size);
            assert!(info.refcount_order() == refcount_order);
        }

        let sizes = [64 << 20, 64 << 30, 2 << 40];

        for c in 13..21 {
            for r in 1..7 {
                for s in sizes {
                    __test_format(c, r, s);
                }
            }
        }
    }
}
