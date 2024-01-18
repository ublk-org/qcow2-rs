// borrowed from rsd project

#![allow(dead_code)]

use crate::dev::Qcow2Info;
use crate::error::Qcow2Result;
use crate::helpers::IntAlignment;
use crate::helpers::Qcow2IoBuf;
use crate::numerical_enum;
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::mem::size_of;

macro_rules! impl_table_gen_funcs {
    ($field:ident) => {
        #[inline(always)]
        fn as_ptr(&self) -> *const u8 {
            self.$field.as_ptr() as *const u8
        }

        #[inline(always)]
        fn as_mut_ptr(&mut self) -> *mut u8 {
            self.$field.as_mut_ptr() as *mut u8
        }

        #[inline(always)]
        fn get_offset(&self) -> Option<u64> {
            self.offset
        }

        #[inline(always)]
        fn set_offset(&mut self, offset: Option<u64>) {
            self.offset = offset;
        }
    };
}

macro_rules! impl_table_gen_setter {
    ($entry:ident, $field:ident) => {
        #[inline(always)]
        fn entries(&self) -> usize {
            self.$field.len()
        }

        #[inline(always)]
        fn get(&self, index: usize) -> $entry {
            match self.$field.get(index) {
                Some(entry) => $entry(u64::from_be(entry.0)),
                None => $entry(0),
            }
        }

        #[inline(always)]
        fn set(&mut self, index: usize, entry: $entry) {
            self.$field[index] = $entry(entry.0.to_be());
        }
    };
}

macro_rules! impl_top_table_gen_funcs {
    () => {
        #[inline(always)]
        fn set_dirty(&self, idx: usize) {
            let bs_idx = ((idx as u32) << 3) >> self.bs_bits;
            let mut blkq = self.dirty_blocks.borrow_mut();

            if !blkq.contains(&bs_idx) {
                blkq.push_back(bs_idx);
            }
        }

        /// Remove specified data iff val isn't None
        #[inline(always)]
        fn pop_dirty_blk_idx(&self, val: Option<u32>) -> Option<u32> {
            let mut blkq = self.dirty_blocks.borrow_mut();

            match val {
                Some(data) => match blkq.iter().position(|x| *x == data) {
                    Some(pos) => {
                        blkq.remove(pos);
                        Some(data)
                    }
                    None => None,
                },
                None => blkq.pop_front(),
            }
        }
    };
}

macro_rules! impl_table_traits {
    ($table:ident, $entry:ident, $field:ident) => {
        impl Table for $table {
            type Entry = $entry;

            impl_table_gen_funcs!($field);
            impl_table_gen_setter!($entry, $field);
        }
    };
}

macro_rules! impl_top_table_traits {
    ($table:ident, $entry:ident, $field:ident) => {
        impl Table for $table {
            type Entry = $entry;

            impl_table_gen_funcs!($field);
            impl_table_gen_setter!($entry, $field);
            impl_top_table_gen_funcs!();
        }
    };
}

macro_rules! impl_entry_display_trait {
    ($entry:ident) => {
        impl std::fmt::Display for $entry {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:<16x}", self.into_plain())
            }
        }
    };
}

impl_entry_display_trait!(L1Entry);
impl_entry_display_trait!(L2Entry);
impl_entry_display_trait!(RefTableEntry);
impl_entry_display_trait!(RefBlockEntry);

#[derive(Debug, Default, Deserialize, Serialize)]
#[repr(packed)]
pub(crate) struct Qcow2RawHeader {
    /// QCOW magic string ("QFI\xfb")
    magic: u32,

    /// Version number (valid values are 2 and 3)
    version: u32,

    /// Offset into the image file at which the backing file name
    /// is stored (NB: The string is not null terminated). 0 if the
    /// image doesn't have a backing file.
    ///
    /// Note: backing files are incompatible with raw external data
    /// files (auto-clear feature bit 1).
    backing_file_offset: u64,

    /// Length of the backing file name in bytes. Must not be
    /// longer than 1023 bytes. Undefined if the image doesn't have
    /// a backing file.
    backing_file_size: u32,

    /// Number of bits that are used for addressing an offset
    /// within a cluster (1 << cluster_bits is the cluster size).
    /// Must not be less than 9 (i.e. 512 byte clusters).
    ///
    /// Note: qemu as of today has an implementation limit of 2 MB
    /// as the maximum cluster size and won't be able to open images
    /// with larger cluster sizes.
    ///
    /// Note: if the image has Extended L2 Entries then cluster_bits
    /// must be at least 14 (i.e. 16384 byte clusters).
    cluster_bits: u32,

    /// Virtual disk size in bytes.
    ///
    /// Note: qemu has an implementation limit of 32 MB as
    /// the maximum L1 table size.  With a 2 MB cluster
    /// size, it is unable to populate a virtual cluster
    /// beyond 2 EB (61 bits); with a 512 byte cluster
    /// size, it is unable to populate a virtual size
    /// larger than 128 GB (37 bits).  Meanwhile, L1/L2
    /// table layouts limit an image to no more than 64 PB
    /// (56 bits) of populated clusters, and an image may
    /// hit other limits first (such as a file system's
    /// maximum size).
    size: u64,

    /// 0 for no encryption
    /// 1 for AES encryption
    /// 2 for LUKS encryption
    crypt_method: u32,

    /// Number of entries in the active L1 table
    l1_size: u32,

    /// Offset into the image file at which the active L1 table
    /// starts. Must be aligned to a cluster boundary.
    l1_table_offset: u64,

    /// Offset into the image file at which the refcount table
    /// starts. Must be aligned to a cluster boundary.
    refcount_table_offset: u64,

    /// Number of clusters that the refcount table occupies
    refcount_table_clusters: u32,

    /// Number of snapshots contained in the image
    nb_snapshots: u32,

    /// Offset into the image file at which the snapshot table
    /// starts. Must be aligned to a cluster boundary.
    snapshots_offset: u64,

    // The following fields are only valid for version >= 3
    /// Bitmask of incompatible features. An implementation must
    /// fail to open an image if an unknown bit is set.
    ///
    /// Bit 0:      Dirty bit.  If this bit is set then refcounts
    /// may be inconsistent, make sure to scan L1/L2
    /// tables to repair refcounts before accessing the
    /// image.
    ///
    /// Bit 1:      Corrupt bit.  If this bit is set then any data
    /// structure may be corrupt and the image must not
    /// be written to (unless for regaining
    /// consistency).
    ///
    /// Bit 2:      External data file bit.  If this bit is set, an
    /// external data file is used. Guest clusters are
    /// then stored in the external data file. For such
    /// images, clusters in the external data file are
    /// not refcounted. The offset field in the
    /// Standard Cluster Descriptor must match the
    /// guest offset and neither compressed clusters
    /// nor internal snapshots are supported.
    ///
    /// An External Data File Name header extension may
    /// be present if this bit is set.
    ///
    /// Bit 3:      Compression type bit.  If this bit is set,
    /// a non-default compression is used for compressed
    /// clusters. The compression_type field must be
    /// present and not zero.
    ///
    /// Bit 4:      Extended L2 Entries.  If this bit is set then
    /// L2 table entries use an extended format that
    /// allows subcluster-based allocation. See the
    /// Extended L2 Entries section for more details.
    ///
    /// Bits 5-63:  Reserved (set to 0)
    incompatible_features: u64,

    /// Bitmask of compatible features. An implementation can
    /// safely ignore any unknown bits that are set.
    ///
    /// Bit 0:      Lazy refcounts bit.  If this bit is set then
    /// lazy refcount updates can be used.  This means
    /// marking the image file dirty and postponing
    /// refcount metadata updates.
    ///
    /// Bits 1-63:  Reserved (set to 0)
    compatible_features: u64,

    /// Bitmask of auto-clear features. An implementation may only
    /// write to an image with unknown auto-clear features if it
    /// clears the respective bits from this field first.
    ///
    /// Bit 0:      Bitmaps extension bit
    /// This bit indicates consistency for the bitmaps
    /// extension data.
    ///
    /// It is an error if this bit is set without the
    /// bitmaps extension present.
    ///
    /// If the bitmaps extension is present but this
    /// bit is unset, the bitmaps extension data must be
    /// considered inconsistent.
    ///
    /// Bit 1:      Raw external data bit
    /// If this bit is set, the external data file can
    /// be read as a consistent standalone raw image
    /// without looking at the qcow2 metadata.
    ///
    /// Setting this bit has a performance impact for
    /// some operations on the image (e.g. writing
    /// zeros requires writing to the data file instead
    /// of only setting the zero flag in the L2 table
    /// entry) and conflicts with backing files.
    ///
    /// This bit may only be set if the External Data
    /// File bit (incompatible feature bit 1) is also
    /// set.
    ///
    /// Bits 2-63:  Reserved (set to 0)
    autoclear_features: u64,

    /// Describes the width of a reference count block entry (width
    /// in bits: refcount_bits = 1 << refcount_order). For version 2
    /// images, the order is always assumed to be 4
    /// (i.e. refcount_bits = 16).
    /// This value may not exceed 6 (i.e. refcount_bits = 64).
    refcount_order: u32,

    /// Length of the header structure in bytes. For version 2
    /// images, the length is always assumed to be 72 bytes.
    /// For version 3 it's at least 104 bytes and must be a multiple
    /// of 8.
    header_length: u32,

    /// Additional fields
    compression_type: u8,
}

numerical_enum! {
    pub enum Qcow2HeaderExtensionType as u32 {
        End = 0,
        BackingFileFormat = 0xe2792aca,
        FeatureNameTable = 0x6803f857,
    }
}

impl Qcow2RawHeader {
    pub fn serialize_vec(&mut self) -> Qcow2Result<Vec<u8>> {
        self.header_length = size_of::<Self>().align_up(8usize).unwrap().try_into()?;

        let bincode = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian();

        let mut header_buf = bincode.serialize(self)?;
        header_buf.resize(header_buf.len().align_up(8usize).unwrap(), 0);

        assert!(header_buf.len() == self.header_length as usize);

        Ok(header_buf)
    }
}

#[derive(Default, Deserialize, Serialize)]
#[repr(packed)]
struct Qcow2HeaderExtensionHeader {
    /// Type code of the header extension
    extension_type: u32,

    /// Data length
    length: u32,
}

numerical_enum! {
    #[derive(Hash)]
    pub enum Qcow2FeatureType as u8 {
        Incompatible = 0,
        Compatible = 1,
        Autoclear = 2,
    }
}

#[derive(Debug, Clone)]
pub enum Qcow2HeaderExtension {
    BackingFileFormat(String),
    FeatureNameTable(HashMap<(Qcow2FeatureType, u8), String>),
    Unknown { extension_type: u32, data: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct SplitGuestOffset(pub u64);

impl SplitGuestOffset {
    #[inline(always)]
    pub fn guest_addr(&self) -> u64 {
        self.0
    }

    #[inline(always)]
    pub fn cluster_offset(&self, info: &Qcow2Info) -> u64 {
        let cluster_bits = info.cluster_bits();
        (((self.l1_index(info) as u64) << (cluster_bits - 3)) + self.l2_index(info) as u64)
            << cluster_bits
    }

    #[inline(always)]
    pub fn l1_index(&self, info: &Qcow2Info) -> usize {
        let guest_offset = self.0 >> (info.cluster_shift + info.l2_index_shift);
        guest_offset.try_into().unwrap()
    }

    #[inline(always)]
    pub fn l2_index(&self, info: &Qcow2Info) -> usize {
        let guest_offset = self.0 >> info.cluster_bits();
        guest_offset as usize & info.l2_index_mask
    }

    #[inline(always)]
    pub fn l2_slice_index(&self, info: &Qcow2Info) -> usize {
        let guest_offset = self.0 >> info.cluster_bits();
        guest_offset as usize & (info.l2_slice_entries as usize - 1)
    }

    #[inline(always)]
    pub fn l2_slice_key(&self, info: &Qcow2Info) -> usize {
        (self.0 >> (info.cluster_shift + info.l2_slice_index_shift)) as usize
    }

    #[inline(always)]
    pub fn l2_slice_off_in_table(&self, info: &Qcow2Info) -> usize {
        let l2_idx = self.l2_index(info);

        //todo: support extended l2 descriptor
        (l2_idx >> info.l2_slice_index_shift) << info.l2_slice_bits
    }

    #[inline(always)]
    pub fn in_cluster_offset(&self, info: &Qcow2Info) -> usize {
        self.0 as usize & info.in_cluster_offset_mask
    }
}

#[derive(Debug)]
pub struct Qcow2Header {
    raw: Qcow2RawHeader,
    backing_filename: Option<String>,
    extensions: Vec<Qcow2HeaderExtension>,
}

impl Qcow2Header {
    pub const QCOW2_MAGIC: u32 = 0x51_46_49_fb;
    pub const MAX_CLUSTER_SIZE: u32 = 2_u32 << 20;
    pub const MAX_L1_SIZE: u32 = 32_u32 << 20;
    pub const MAX_REFCOUNT_TABLE_SIZE: u32 = 8_u32 << 20;

    pub fn from_buf(header_buf: &[u8]) -> Qcow2Result<Self> {
        let bincode = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian();

        let mut header: Qcow2RawHeader =
            bincode.deserialize(&header_buf[0..size_of::<Qcow2RawHeader>()])?;
        if header.magic != Self::QCOW2_MAGIC {
            return Err("Not a qcow2 file".into());
        }

        if header.version < 2 {
            let v = header.version;
            return Err(format!("qcow2 v{} is not supported", v).into());
        }

        // refcount_order is always 4 for version 2
        if header.version == 2 {
            header.refcount_order = 4;
        }

        let cluster_size = 1u64 << header.cluster_bits;
        if cluster_size > Self::MAX_CLUSTER_SIZE as u64 {
            return Err(format!("qcow2 cluster size {} is too big", cluster_size).into());
        }

        let backing_filename = if header.backing_file_offset != 0 {
            let (offset, length) = (header.backing_file_offset, header.backing_file_size);
            if length > 1023 {
                return Err(format!(
                    "Backing file name is too long ({}, must not exceed 1023)",
                    length
                )
                .into());
            }

            let end = offset
                .checked_add(length as u64)
                .ok_or("Backing file name offset is invalid (too high)")?;
            if end >= cluster_size {
                return Err("Backing file name offset is invalid (too high)".into());
            }

            if end > header_buf.len() as u64 {
                return Err("header buffer is too small".into());
            }

            let backing_buf = header_buf[(end - (length as u64)) as usize..(end as usize)].to_vec();
            Some(
                String::from_utf8(backing_buf)
                    .map_err(|err| format!("Backing file name is invalid: {}", err))?,
            )
        } else {
            None
        };

        let mut ext_offset: u64 = header.header_length as u64;
        let mut extensions = Vec::<Qcow2HeaderExtension>::new();
        loop {
            let max_len = ext_offset + size_of::<Qcow2HeaderExtensionHeader>() as u64;
            if max_len > cluster_size || max_len > header_buf.len() as u64 {
                return Err(
                    "Header extensions exceed the first cluster or header buffer is too small"
                        .into(),
                );
            }

            let ext_hdr_buf = &header_buf[ext_offset as usize
                ..ext_offset as usize + size_of::<Qcow2HeaderExtensionHeader>()];

            ext_offset += size_of::<Qcow2HeaderExtensionHeader>() as u64;

            let ext_hdr: Qcow2HeaderExtensionHeader = bincode.deserialize(ext_hdr_buf)?;
            let max_len = ext_offset + ext_hdr.length as u64;
            if max_len > cluster_size || max_len > header_buf.len() as u64 {
                return Err("Header extensions exceed the first cluster or buffer length".into());
            }

            let ext_data = header_buf
                [ext_offset as usize..ext_offset as usize + ext_hdr.length as usize]
                .to_vec();
            ext_offset += (ext_hdr.length as u64).align_up(8u64).unwrap();

            let extension = match Qcow2HeaderExtension::from(ext_hdr.extension_type, ext_data)? {
                Some(ext) => ext,
                None => break,
            };

            extensions.push(extension);
        }

        let header = Qcow2Header {
            raw: header,
            backing_filename,
            extensions,
        };

        // No need to clear autoclear features for read-only images, and it is caller's
        // responsibility to clear the feature bit
        /*
        if header.raw.autoclear_features != 0 && !read_only {
            header.raw.autoclear_features = 0;
            header.write(queue).await?;
        }*/

        if header.raw.incompatible_features != 0 {
            let feats = (0..64)
                .filter(|bit| header.raw.incompatible_features & (1u64 << bit) != 0)
                .map(|bit| {
                    if let Some(name) = header.feature_name(Qcow2FeatureType::Incompatible, bit) {
                        format!("{} ({})", bit, name)
                    } else {
                        format!("{}", bit)
                    }
                })
                .collect::<Vec<String>>();

            return Err(
                format!("Unrecognized incompatible feature(s) {}", feats.join(", ")).into(),
            );
        }

        Ok(header)
    }

    pub fn calculate_meta_params(
        size: u64,
        cluster_bits: usize,
        refcount_order: u8,
        block_size: usize,
    ) -> ((u64, u32), (u64, u32), (u64, u32)) {
        let cluster_size = 1usize << cluster_bits;

        // cluster 0 is for header, refcount_table starts from 1st cluster
        let rc_table_offset = cluster_size as u64;
        let rc_table_size =
            Qcow2Info::__max_refcount_table_size(size, cluster_size, refcount_order, block_size);
        let rc_table_clusters = (rc_table_size + cluster_size - 1) / cluster_size;

        let rc_block_offset = rc_table_offset + ((rc_table_clusters as u64) << cluster_bits);
        let rc_block_clusters = 1;

        let l1_table_offset = rc_block_offset + cluster_size as u64;
        let l1_table_entries = Qcow2Info::get_max_l1_entries(size, cluster_bits);
        let l1_table_size = Qcow2Info::__max_l1_size(l1_table_entries, block_size);
        let l1_table_clusters = (l1_table_size + cluster_size - 1) / cluster_size;

        let rc_table = (rc_table_offset, rc_table_clusters as u32);
        let rc_block = (rc_block_offset, rc_block_clusters);
        let l1_table = (l1_table_offset, l1_table_clusters as u32);

        (rc_table, rc_block, l1_table)
    }
    /// Format in-ram qcow2 image, for test purpose
    pub fn format_qcow2(
        buf: &mut [u8],
        size: u64,
        cluster_bits: usize,
        refcount_order: u8,
        block_size: usize,
    ) -> Qcow2Result<()> {
        let cluster_size = 1usize << cluster_bits;

        if buf.len() & (block_size - 1) != 0 {
            return Err("buffer isn't cluster aligned".into());
        }

        let (rc_table, rc_blk, l1_table) =
            Self::calculate_meta_params(size, cluster_bits, refcount_order, block_size);

        // don't take l1 table into account
        let clusters = 1 + rc_table.1 + rc_blk.1;
        if (buf.len() / cluster_size) < clusters as usize {
            return Err("buffer is too small".into());
        }

        let start = rc_table.0 as usize;
        let end = start + ((rc_table.1 as usize) << cluster_bits);
        let mut rc_t = RefTable::new_empty(Some(rc_table.0), end - start);

        let start = rc_blk.0 as usize;
        let end = start + ((rc_blk.1 as usize) << cluster_bits);
        let mut ref_b = RefBlock::new(refcount_order, end - start, Some(rc_blk.0));

        //header
        ref_b.increment(0)?;
        assert!(ref_b.get(0).into_plain() == 1);

        //refcount table
        let start = rc_table.0;
        let end = start + ((rc_table.1 as u64) << cluster_bits);
        for i in (start..end).step_by(cluster_size) {
            ref_b.increment((i >> cluster_bits) as usize)?;
        }

        //me
        ref_b.increment((rc_table.1 as usize) + 1)?;

        //l1 table
        let start = l1_table.0;
        let end = start + ((l1_table.1 as u64) << cluster_bits);
        for i in (start..end).step_by(cluster_size) {
            ref_b.increment((i >> cluster_bits) as usize)?;
        }

        rc_t.set(0, RefTableEntry(rc_blk.0));

        // commit meta into external buffer
        let buf_start = buf.as_mut_ptr() as u64;
        unsafe {
            libc::memcpy(
                (buf_start + rc_table.0) as *mut libc::c_void,
                rc_t.as_ptr() as *const libc::c_void,
                (rc_table.1 as usize) << cluster_bits,
            );
        }
        unsafe {
            libc::memcpy(
                (buf_start + rc_blk.0) as *mut libc::c_void,
                ref_b.as_ptr() as *const libc::c_void,
                (rc_blk.1 as usize) << cluster_bits,
            );
        }

        // We are empty image, so nothing is in l1 table, just zero the
        // 1st sector
        unsafe {
            libc::memset((buf_start + l1_table.0) as *mut libc::c_void, 0, block_size);
        }

        let mut h = Qcow2RawHeader {
            magic: Self::QCOW2_MAGIC,
            version: 3,
            cluster_bits: cluster_bits as u32,
            size,
            refcount_order: refcount_order as u32,
            header_length: 112,
            l1_table_offset: l1_table.0,
            l1_size: 2,
            refcount_table_offset: rc_table.0,
            refcount_table_clusters: rc_table.1,
            ..Default::default()
        };

        let vec = h.serialize_vec()?;
        buf[..vec.len()].copy_from_slice(vec.as_slice());

        Ok(())
    }

    pub fn serialize_to_buf(&mut self) -> Qcow2Result<Vec<u8>> {
        let header_len = size_of::<Qcow2RawHeader>().align_up(8usize).unwrap();
        let mut header_exts = self.serialize_extensions()?;

        if let Some(backing) = self.backing_filename.as_ref() {
            self.raw.backing_file_offset = (header_len + header_exts.len()).try_into()?;
            self.raw.backing_file_size = backing.as_bytes().len().try_into()?;
        } else {
            self.raw.backing_file_offset = 0;
            self.raw.backing_file_size = 0;
        }

        let mut full_buf = self.raw.serialize_vec()?;
        full_buf.append(&mut header_exts);
        if let Some(backing) = self.backing_filename.as_ref() {
            full_buf.extend_from_slice(backing.as_bytes());
        }

        if full_buf.len() > 1 << self.raw.cluster_bits {
            return Err(format!(
                "Header is too big to write ({}, larger than a cluster ({}))",
                full_buf.len(),
                1 << self.raw.cluster_bits
            )
            .into());
        }

        Ok(full_buf)
    }

    pub fn version(&self) -> u32 {
        self.raw.version
    }

    pub fn crypt_method(&self) -> u32 {
        self.raw.crypt_method
    }

    pub fn compression_type(&self) -> u8 {
        self.raw.compression_type
    }

    pub fn header_length(&self) -> u32 {
        self.raw.header_length
    }

    pub fn size(&self) -> u64 {
        self.raw.size
    }

    pub fn cluster_bits(&self) -> u32 {
        self.raw.cluster_bits
    }

    pub fn refcount_order(&self) -> u32 {
        self.raw.refcount_order
    }

    pub fn l1_table_offset(&self) -> u64 {
        self.raw.l1_table_offset
    }

    pub fn l1_table_entries(&self) -> usize {
        self.raw.l1_size as usize
    }

    pub fn set_l1_table(&mut self, offset: u64, entries: usize) -> Qcow2Result<()> {
        self.raw.l1_size = entries.try_into()?;
        self.raw.l1_table_offset = offset;
        Ok(())
    }

    pub fn nb_snapshots(&self) -> u32 {
        self.raw.nb_snapshots
    }

    pub fn snapshots_offset(&self) -> u64 {
        self.raw.snapshots_offset
    }

    pub fn reftable_offset(&self) -> u64 {
        self.raw.refcount_table_offset
    }

    pub fn reftable_clusters(&self) -> usize {
        self.raw.refcount_table_clusters as usize
    }

    pub fn set_reftable(&mut self, offset: u64, clusters: usize) -> Qcow2Result<()> {
        self.raw.refcount_table_clusters = clusters.try_into()?;
        self.raw.refcount_table_offset = offset;
        Ok(())
    }

    pub fn backing_filename(&self) -> Option<&String> {
        self.backing_filename.as_ref()
    }

    pub fn backing_format(&self) -> Option<&String> {
        for e in &self.extensions {
            if let Qcow2HeaderExtension::BackingFileFormat(fmt) = e {
                return Some(fmt);
            }
        }

        None
    }

    pub fn feature_name(&self, feat_type: Qcow2FeatureType, bit: u32) -> Option<&String> {
        for e in &self.extensions {
            if let Qcow2HeaderExtension::FeatureNameTable(names) = e {
                if let Some(name) = names.get(&(feat_type, bit as u8)) {
                    return Some(name);
                }
            }
        }

        None
    }

    fn serialize_extensions(&self) -> Qcow2Result<Vec<u8>> {
        let bincode = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian();

        let mut result = Vec::new();
        for e in &self.extensions {
            let mut data = e.serialize_data()?;
            let ext_hdr = Qcow2HeaderExtensionHeader {
                extension_type: e.extension_type(),
                length: data.len().try_into()?,
            };
            result.append(&mut bincode.serialize(&ext_hdr)?);
            result.append(&mut data);
            result.resize(result.len().align_up(8usize).unwrap(), 0);
        }

        let end_ext = Qcow2HeaderExtensionHeader {
            extension_type: Qcow2HeaderExtensionType::End as u32,
            length: 0,
        };
        result.append(&mut bincode.serialize(&end_ext)?);
        result.resize(result.len().align_up(8usize).unwrap(), 0);

        Ok(result)
    }
}

impl Qcow2HeaderExtension {
    /// Parse an extension from its type and data.  Unrecognized types are stored as `Unknown`
    /// extensions, encountering the end of extensions returns `Ok(None)`.
    fn from(ext_type: u32, data: Vec<u8>) -> Qcow2Result<Option<Self>> {
        let ext = if let Ok(ext_type) = Qcow2HeaderExtensionType::try_from(ext_type) {
            match ext_type {
                Qcow2HeaderExtensionType::End => return Ok(None),
                Qcow2HeaderExtensionType::BackingFileFormat => {
                    let fmt = String::from_utf8(data)
                        .map_err(|err| format!("Invalid backing file format: {}", err))?;
                    Qcow2HeaderExtension::BackingFileFormat(fmt)
                }
                Qcow2HeaderExtensionType::FeatureNameTable => {
                    let mut feats = HashMap::new();
                    for feat in data.chunks(48) {
                        let feat_type: Qcow2FeatureType = match feat[0].try_into() {
                            Ok(ft) => ft,
                            Err(_) => continue, // skip unrecognized entries
                        };
                        let feat_name = String::from(
                            String::from_utf8_lossy(&feat[2..]).trim_end_matches('\0'),
                        );

                        feats.insert((feat_type, feat[1]), feat_name);
                    }
                    Qcow2HeaderExtension::FeatureNameTable(feats)
                }
            }
        } else {
            Qcow2HeaderExtension::Unknown {
                extension_type: ext_type,
                data,
            }
        };

        Ok(Some(ext))
    }

    fn extension_type(&self) -> u32 {
        match self {
            Qcow2HeaderExtension::BackingFileFormat(_) => {
                Qcow2HeaderExtensionType::BackingFileFormat as u32
            }
            Qcow2HeaderExtension::FeatureNameTable(_) => {
                Qcow2HeaderExtensionType::FeatureNameTable as u32
            }
            Qcow2HeaderExtension::Unknown {
                extension_type,
                data: _,
            } => *extension_type,
        }
    }

    fn serialize_data(&self) -> Qcow2Result<Vec<u8>> {
        match self {
            Qcow2HeaderExtension::BackingFileFormat(fmt) => Ok(fmt.as_bytes().into()),
            Qcow2HeaderExtension::FeatureNameTable(map) => {
                let mut result = Vec::new();
                for (bit, name) in map {
                    result.push(bit.0 as u8);
                    result.push(bit.1);

                    let mut padded_name = vec![0; 46];
                    let name_bytes = name.as_bytes();
                    // Might truncate in the middle of a multibyte character, but getting that
                    // right is complicated and probably not worth it
                    let truncated_len = std::cmp::min(name_bytes.len(), 46);
                    padded_name[..truncated_len].copy_from_slice(&name_bytes[..truncated_len]);
                    result.extend_from_slice(&padded_name);
                }
                Ok(result)
            }
            Qcow2HeaderExtension::Unknown {
                extension_type: _,
                data,
            } => Ok(data.clone()),
        }
    }
}

// L1 table entry:
//
// Bit  0 -  8:     Reserved (set to 0)
//
//      9 - 55:     Bits 9-55 of the offset into the image file at which the L2
//                  table starts. Must be aligned to a cluster boundary. If the
//                  offset is 0, the L2 table and all clusters described by this
//                  L2 table are unallocated.
//
//      56 - 62:    Reserved (set to 0)
//
//      63:         0 for an L2 table that is unused or requires COW, 1 if its
//                  refcount is exactly one. This information is only accurate
//                  in the active L1 table.
#[derive(Copy, Clone, Default, Debug)]
pub struct L1Entry(u64);

impl L1Entry {
    const DIRTY: u64 = 0x1;
    const NEW: u64 = 0x2;

    pub fn l2_offset(&self) -> u64 {
        self.0 & 0x00ff_ffff_ffff_fe00u64
    }

    pub fn is_copied(&self) -> bool {
        self.0 & (1u64 << 63) != 0
    }

    pub fn is_zero(&self) -> bool {
        self.l2_offset() == 0
    }

    pub fn reserved_bits(&self) -> u64 {
        self.0 & 0x7f00_0000_0000_01feu64
    }
}

impl TableEntry for L1Entry {
    fn try_from_plain(value: u64, qcow2_info: &Qcow2Info) -> Qcow2Result<Self> {
        let entry = L1Entry(value);

        if entry.reserved_bits() != 0 {
            return Err(format!(
                "Invalid L1 entry 0x{:x}, reserved bits set (0x{:x})",
                value,
                entry.reserved_bits()
            )
            .into());
        }

        if qcow2_info.in_cluster_offset(entry.l2_offset()) != 0 {
            return Err(format!(
                "Invalid L1 entry 0x{:x}, offset (0x{:x}) is not aligned to cluster size (0x{:x})",
                value,
                entry.l2_offset(),
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
        self.l2_offset()
    }
}

#[derive(Debug)]
pub struct L1Table {
    header_entries: u32,
    dirty_blocks: RefCell<VecDeque<u32>>,
    bs_bits: u8,
    offset: Option<u64>,
    data: Qcow2IoBuf<L1Entry>,
}

impl L1Table {
    pub fn new(offset: Option<u64>, data_size: usize, header_entries: u32, bs_bits: u8) -> Self {
        let mut l1 = L1Table::new_empty(offset, data_size);
        l1.header_entries = header_entries;
        l1.dirty_blocks = RefCell::new(VecDeque::new());
        l1.bs_bits = bs_bits;
        l1
    }

    pub fn update_header_entries(&mut self, entries: u32) {
        assert!((entries as usize) <= self.data.len());
        self.header_entries = entries;
    }

    /// Create a clone that covers at least `at_least_index`
    pub fn clone_and_grow(&self, at_least_index: usize, cluster_size: usize) -> Self {
        let new_size = std::cmp::max(at_least_index + 1, self.data.len());
        let new_size = new_size.align_up(cluster_size).unwrap();
        let mut new_data = Qcow2IoBuf::<L1Entry>::new(new_size);
        new_data[..self.data.len()].copy_from_slice(&self.data);

        Self {
            offset: None,
            data: new_data,
            bs_bits: self.bs_bits,
            header_entries: self.data.len() as u32,
            dirty_blocks: RefCell::new(self.dirty_blocks.borrow().clone()),
        }
    }

    pub fn in_bounds(&self, index: usize) -> bool {
        index < self.header_entries as usize
    }

    pub fn map_l2_offset(&mut self, index: usize, l2_offset: u64) {
        let l1entry = L1Entry((1 << 63) | l2_offset);
        debug_assert!(l1entry.reserved_bits() == 0);
        self.set(index, l1entry);
        self.set_dirty(index);
    }
}

impl_top_table_traits!(L1Table, L1Entry, data);

impl From<Qcow2IoBuf<L1Entry>> for L1Table {
    fn from(data: Qcow2IoBuf<L1Entry>) -> Self {
        Self {
            bs_bits: 0,
            header_entries: 0,
            offset: None,
            data,
            dirty_blocks: RefCell::new(VecDeque::new()),
        }
    }
}

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

pub trait TableEntry
where
    Self: Copy + Sized + std::fmt::Debug,
{
    fn try_from_plain(value: u64, qcow2_info: &Qcow2Info) -> Qcow2Result<Self>;
    fn into_plain(self) -> u64;

    /// Only for top table to return offset stored
    #[inline(always)]
    fn get_value(&self) -> u64 {
        panic!();
    }
}

pub trait Table: From<Qcow2IoBuf<Self::Entry>> {
    type Entry: TableEntry;

    fn entries(&self) -> usize;
    fn get(&self, index: usize) -> Self::Entry;
    fn set(&mut self, index: usize, value: Self::Entry);
    fn get_offset(&self) -> Option<u64>;
    fn set_offset(&mut self, offset: Option<u64>);

    fn as_ptr(&self) -> *const u8;
    fn as_mut_ptr(&mut self) -> *mut u8;

    fn set_with_return(&mut self, index: usize, value: Self::Entry) -> Qcow2Result<()> {
        self.set(index, value);
        Ok(())
    }

    fn byte_size(&self) -> usize {
        self.entries() * size_of::<u64>()
    }

    fn cluster_count(&self, qcow2_info: &Qcow2Info) -> usize {
        (self.byte_size() + qcow2_info.cluster_size() - 1) / qcow2_info.cluster_size()
    }

    fn is_update(&self) -> bool {
        self.get_offset().is_some()
    }

    fn new_empty(offset: Option<u64>, size: usize) -> Self {
        let table = Qcow2IoBuf::<Self::Entry>::new(size);
        unsafe {
            std::ptr::write_bytes(table.as_mut_ptr(), 0, table.len());
        }
        let mut table: Self = table.into();
        table.set_offset(offset);

        table
    }

    #[inline(always)]
    fn set_dirty(&self, _idx: usize) {}

    #[inline(always)]
    fn pop_dirty_blk_idx(&self, _val: Option<u32>) -> Option<u32> {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::dev::*;
    use crate::meta::*;

    #[test]
    fn test_l1_table() {
        let cluster_size = 1 << 16;
        let size = 4096;

        let mut l1 = L1Table::new_empty(Some(cluster_size), 4096);
        assert!(l1.entries() == (size / core::mem::size_of::<u64>()));
        assert!(l1.as_ptr() != std::ptr::null());

        let entry = l1.get(0);
        assert!(entry.is_zero() == true);

        let l2_offset = cluster_size * 3;
        l1.set(0, L1Entry(l2_offset));
        let entry = l1.get(0);
        assert!(entry.l2_offset() == l2_offset);

        let raw_addr = l1.as_ptr() as *const u64;
        unsafe {
            assert!(u64::from_be(*raw_addr) == l2_offset);
        };
    }

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
