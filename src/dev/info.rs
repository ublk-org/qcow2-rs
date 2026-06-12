use crate::error::Qcow2Result;
use crate::helpers::IntAlignment;
use crate::meta::Qcow2Header;

/// all readable Qcow2 info, make it into single cache line
#[derive(Debug)]
pub struct Qcow2Info {
    // min block size for writing out data to image, it is usually
    // logical block size of the disk for storing this image, so
    // all meta data has to be aligned with this block size
    pub(crate) block_size_shift: u8,
    pub(crate) cluster_shift: u8,
    pub(crate) l2_index_shift: u8,
    pub(crate) l2_slice_index_shift: u8,
    pub(crate) l2_slice_bits: u8,
    pub(crate) refcount_order: u8,
    pub(crate) rb_slice_bits: u8,
    pub(crate) rb_index_shift: u8,
    pub(crate) rb_slice_index_shift: u8,

    pub(crate) flags: u16,
    pub(crate) l2_slice_entries: u32,
    pub(crate) in_cluster_offset_mask: usize,
    pub(crate) l2_index_mask: usize,
    pub(crate) rb_index_mask: usize,

    pub(crate) l2_cache_cnt: u32,
    pub(crate) rb_cache_cnt: u32,
    pub(crate) virtual_size: u64,
}

impl Qcow2Info {
    const READ_ONLY: u16 = 1 << 0;
    const HAS_BACK_FILE: u16 = 1 << 1; // we have underlying backing image
    const BACK_FILE: u16 = 1 << 2; // this is one backing image, read only
    pub fn new(h: &Qcow2Header, p: &Qcow2DevParams) -> Qcow2Result<Qcow2Info> {
        let block_size_shift = p.get_bs_bits();

        let ro = p.is_read_only();

        if p.is_backing_dev() {
            assert!(ro);
        }

        let cluster_shift: u8 = h.cluster_bits().try_into().unwrap();
        let cluster_size: usize = 1usize
            .checked_shl(cluster_shift.into())
            .ok_or_else(|| format!("cluster_bits={cluster_shift} is too large"))?;
        let refcount_order: u8 = h.refcount_order().try_into().unwrap();

        //at least two l2 caches
        let (l2_slice_bits, l2_cache_cnt) = match p.l2_cache {
            Some((b, s)) => {
                debug_assert!(b >= block_size_shift && u32::from(b) <= cluster_shift as u32);
                assert!((s >> b) >= 2);
                (b, s >> b)
            }
            None => {
                let mapping_bytes = std::cmp::min(h.size() >> (cluster_shift - 3), 32 << 20);
                let bits = 12_u8;
                let cnt = std::cmp::max((mapping_bytes as usize) >> bits, 2);

                (bits, cnt)
            }
        };

        //at least two rb caches
        let (rb_slice_bits, rb_cache_cnt) = match p.rb_cache {
            Some((b, s)) => {
                debug_assert!(b >= block_size_shift && u32::from(b) <= cluster_shift as u32);
                assert!((s >> b) >= 2);
                (b, s >> b)
            }
            None => {
                let mapping_bytes = 256 << 10;
                let bits = 12_u8;
                let cnt = std::cmp::max((mapping_bytes as usize) >> bits, 2);

                (bits, cnt)
            }
        };

        //todo: support extended l2
        let l2_entries = cluster_size / std::mem::size_of::<u64>();
        let l2_slice_entries: u32 = (l2_entries as u32) >> (cluster_shift - l2_slice_bits);
        let rb_entries = cluster_size * 8 / (1 << refcount_order);
        let rb_slice_entries: u32 = (1 << (rb_slice_bits + 3)) >> refcount_order;

        Ok(Qcow2Info {
            virtual_size: h.size(),
            refcount_order,
            cluster_shift,
            l2_slice_entries,
            in_cluster_offset_mask: cluster_size - 1,
            l2_index_mask: l2_entries - 1,
            l2_index_shift: l2_entries.trailing_zeros().try_into().unwrap(),
            l2_slice_index_shift: l2_slice_entries.trailing_zeros().try_into().unwrap(),
            rb_index_mask: rb_entries - 1,
            rb_index_shift: rb_entries.trailing_zeros().try_into().unwrap(),
            block_size_shift,
            l2_slice_bits,
            l2_cache_cnt: l2_cache_cnt.try_into().unwrap(),
            rb_cache_cnt: rb_cache_cnt.try_into().unwrap(),
            flags: if ro { Qcow2Info::READ_ONLY } else { 0 }
                | if h.backing_filename().is_some() {
                    Qcow2Info::HAS_BACK_FILE
                } else {
                    0
                }
                | if p.is_backing_dev() {
                    Qcow2Info::BACK_FILE
                } else {
                    0
                },
            rb_slice_bits,
            rb_slice_index_shift: rb_slice_entries.trailing_zeros().try_into().unwrap(),
        })
    }

    #[inline(always)]
    pub fn rb_entries(&self) -> usize {
        (self.cluster_size() << 3) >> self.refcount_order
    }

    #[inline(always)]
    pub fn l2_entries(&self) -> usize {
        self.cluster_size() / std::mem::size_of::<u64>()
    }

    #[inline(always)]
    pub fn virtual_size(&self) -> u64 {
        self.virtual_size
    }

    #[inline(always)]
    pub fn in_cluster_offset(&self, offset: u64) -> usize {
        offset as usize & self.in_cluster_offset_mask
    }

    /// Round `offset` down to the start of its cluster
    #[inline(always)]
    pub(crate) fn cluster_round_down(&self, offset: u64) -> u64 {
        offset & !(self.in_cluster_offset_mask as u64)
    }

    /// Round `offset` up to the next cluster boundary
    #[inline(always)]
    pub(crate) fn cluster_round_up(&self, offset: u64) -> u64 {
        self.cluster_round_down(offset + self.in_cluster_offset_mask as u64)
    }

    #[inline(always)]
    pub fn cluster_size(&self) -> usize {
        1 << self.cluster_shift
    }

    #[inline(always)]
    pub fn cluster_bits(&self) -> usize {
        self.cluster_shift as usize
    }

    #[inline(always)]
    pub fn refcount_order(&self) -> u8 {
        self.refcount_order
    }

    #[inline]
    pub(crate) fn __max_l1_entries(size: u64, cluster_bits: usize, l2_entries: usize) -> usize {
        let size_per_entry = (l2_entries as u64) << cluster_bits;
        let max_entries = Qcow2Header::MAX_L1_SIZE as usize / size_of::<u64>();
        let entries = size.div_ceil(size_per_entry) as usize;

        std::cmp::min(entries, max_entries)
    }

    #[inline]
    pub(crate) fn get_max_l1_entries(size: u64, cluster_bits: usize) -> usize {
        let l2_entries = (1usize << cluster_bits) / size_of::<u64>();

        Self::__max_l1_entries(size, cluster_bits, l2_entries)
    }

    #[inline(always)]
    pub(crate) fn max_l1_entries(&self) -> usize {
        Self::__max_l1_entries(
            self.virtual_size,
            self.cluster_shift as usize,
            self.l2_entries(),
        )
    }

    #[inline]
    pub(crate) fn __max_l1_size(max_l1_entries: usize, bs: usize) -> usize {
        (max_l1_entries * size_of::<u64>()).align_up(bs).unwrap()
    }

    pub(crate) fn __max_refcount_table_size(
        size: u64,
        cluster_size: usize,
        refcount_order: u8,
        bs: usize,
    ) -> usize {
        let rb_entries = (cluster_size as u64) * 8 / (1 << refcount_order);
        let rt_entry_size = rb_entries * (cluster_size as u64);

        let rc_table_entries = size.div_ceil(rt_entry_size);
        let rc_table_size = (rc_table_entries as usize * std::mem::size_of::<u64>())
            .align_up(bs)
            .unwrap();

        std::cmp::min(rc_table_size, 8usize << 20)
    }

    #[inline(always)]
    pub(crate) fn rb_slice_entries(&self) -> u32 {
        (1 << (self.rb_slice_bits + 3)) >> self.refcount_order
    }

    #[inline(always)]
    pub(crate) fn is_read_only(&self) -> bool {
        self.flags & Qcow2Info::READ_ONLY != 0
    }

    #[inline(always)]
    pub(crate) fn has_back_file(&self) -> bool {
        self.flags & Qcow2Info::HAS_BACK_FILE != 0
    }

    #[inline(always)]
    pub fn is_back_file(&self) -> bool {
        self.flags & Qcow2Info::BACK_FILE != 0
    }
}

#[derive(Debug, Clone, Default)]
pub struct Qcow2DevParams {
    pub(crate) rb_cache: Option<(u8, usize)>,
    pub(crate) l2_cache: Option<(u8, usize)>,
    bs_shift: u8,
    direct_io: bool,
    read_only: bool,
    backing: Option<bool>,
}

impl Qcow2DevParams {
    pub fn new(
        bs_bits: u8,
        rb_cache: Option<(u8, usize)>,
        l2_cache: Option<(u8, usize)>,
        ro: bool,
        dio: bool,
    ) -> Self {
        Qcow2DevParams {
            bs_shift: bs_bits,
            rb_cache,
            l2_cache,
            read_only: ro,
            direct_io: dio,
            backing: None,
        }
    }

    pub fn get_bs_bits(&self) -> u8 {
        self.bs_shift
    }

    pub fn set_read_only(&mut self, ro: bool) {
        self.read_only = ro;
    }

    pub fn is_direct_io(&self) -> bool {
        self.direct_io
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn mark_backing_dev(&mut self, backing: Option<bool>) {
        self.backing = backing;

        self.set_read_only(true);
    }

    pub fn is_backing_dev(&self) -> bool {
        self.backing.is_some()
    }
}
