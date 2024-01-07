use crate::cache::AsyncLruCache;
use crate::cache::AsyncLruCacheEntry;
use crate::error::Qcow2Result;
use crate::helpers::qcow2_type_of;
use crate::meta::{
    L1Entry, L1Table, L2Entry, L2Table, Mapping, MappingSource, Qcow2Header, RefBlock, RefTable,
    RefTableEntry, SplitGuestOffset, Table, TableEntry,
};
use crate::zero_buf;
use async_recursion::async_recursion;
#[rustversion::before(1.75)]
use async_trait::async_trait;
use futures_locks::{RwLock as AsyncRwLock, RwLockWriteGuard as LockWriteGuard};
use miniz_oxide::inflate::core::{decompress as inflate, DecompressorOxide};
use miniz_oxide::inflate::TINFLStatus;
use std::cell::RefCell;
use std::collections::HashMap;
use std::mem::size_of;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// How read/write/discard are implemented, so that qcow2-rs can be
/// used with multiple io engine.
///
/// these methods are called for reading data from image, writing data
/// to image, and discarding range.
#[rustversion::attr(before(1.75), async_trait(?Send))]
#[rustversion::attr(since(1.75), allow(async_fn_in_trait))]
pub trait Qcow2IoOps {
    async fn read_to(&self, offset: u64, buf: &mut [u8]) -> Qcow2Result<usize>;
    async fn write_from(&self, offset: u64, buf: &[u8]) -> Qcow2Result<()>;
    async fn discard_range(&self, offset: u64, len: usize, flags: i32) -> Qcow2Result<()>;
    async fn fsync(&self, offset: u64, len: usize, flags: i32) -> Qcow2Result<()>;
}

/// all readable Qcow2 info, make it into single cache line
#[derive(Debug)]
pub struct Qcow2Info {
    // min block size for writing out data to image, it is usually
    // logical block size of the disk for storing this image, so
    // all meta data has to be aligned with this block size
    pub block_size_shift: u8,
    pub cluster_shift: u8,
    pub l2_index_shift: u8,
    pub l2_slice_index_shift: u8,
    pub l2_slice_bits: u8,
    pub refcount_order: u8,
    pub rb_slice_bits: u8,
    pub rb_index_shift: u8,
    pub rb_slice_index_shift: u8,

    pub flags: u16,
    pub l2_slice_entries: u32,
    pub in_cluster_offset_mask: usize,
    pub l2_index_mask: usize,
    pub rb_index_mask: usize,

    pub l2_cache_cnt: u32,
    pub rb_cache_cnt: u32,
    pub virtual_size: u64,
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
            .ok_or_else(|| format!("cluster_bits={} is too large", cluster_shift))?;
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
    pub fn __max_l1_entries(size: u64, cluster_bits: usize, l2_entries: usize) -> usize {
        let size_per_entry = (l2_entries as u64) << cluster_bits;
        let max_entries = Qcow2Header::MAX_L1_SIZE as usize / size_of::<u64>();
        let entries = ((size + size_per_entry - 1) / size_per_entry) as usize;

        std::cmp::min(entries, max_entries)
    }

    #[inline]
    pub fn get_max_l1_entries(size: u64, cluster_bits: usize) -> usize {
        let l2_entries = (1usize << cluster_bits) / size_of::<u64>();

        Self::__max_l1_entries(size, cluster_bits, l2_entries)
    }

    #[inline(always)]
    pub fn max_l1_entries(&self) -> usize {
        Self::__max_l1_entries(
            self.virtual_size,
            self.cluster_shift as usize,
            self.l2_entries(),
        )
    }

    #[inline]
    pub fn __max_l1_size(max_l1_entries: usize, bs: usize) -> usize {
        let entries = max_l1_entries;

        (entries * size_of::<u64>() + bs - 1) & !(bs - 1)
    }

    #[inline(always)]
    pub fn max_l1_size(&self) -> usize {
        let entries = self.max_l1_entries();

        Self::__max_l1_size(entries, 1 << self.block_size_shift)
    }

    pub fn __max_refcount_table_size(
        size: u64,
        cluster_size: usize,
        refcount_order: u8,
        bs: usize,
    ) -> usize {
        let rb_entries = cluster_size * 8 / (1 << refcount_order);
        let rt_entry_size = rb_entries * cluster_size;

        let rc_table_entries = (size + rt_entry_size as u64 - 1) / rt_entry_size as u64;
        let rc_table_size =
            ((rc_table_entries as usize * std::mem::size_of::<u64>()) + bs - 1) & !(bs - 1);

        std::cmp::min(rc_table_size as usize, 8usize << 20)
    }

    #[inline(always)]
    fn rb_slice_entries(&self) -> u32 {
        (1 << (self.rb_slice_bits + 3)) >> self.refcount_order
    }

    #[inline(always)]
    fn is_read_only(&self) -> bool {
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

/// for cluster allocator
#[derive(Debug, Clone)]
struct HostCluster(u64);

impl HostCluster {
    #[inline(always)]
    fn cluster_off_from_slice(&self, info: &Qcow2Info, idx: usize) -> u64 {
        self.rb_slice_host_start(info) + ((idx as u64) << info.cluster_shift)
    }

    #[inline(always)]
    fn rt_index(&self, info: &Qcow2Info) -> usize {
        let bits = info.rb_index_shift + info.cluster_bits() as u8;

        (self.0 >> bits).try_into().unwrap()
    }

    #[inline(always)]
    fn rb_index(&self, info: &Qcow2Info) -> usize {
        let cluster_idx = self.0 >> info.cluster_shift;

        cluster_idx as usize & info.rb_index_mask
    }

    #[inline(always)]
    fn rb_slice_index(&self, info: &Qcow2Info) -> usize {
        let off = self.0 >> info.cluster_shift;
        off as usize & ((info.rb_slice_entries() - 1) as usize)
    }

    #[inline(always)]
    fn rb_slice_key(&self, info: &Qcow2Info) -> usize {
        (self.0 >> (info.cluster_shift + info.rb_slice_index_shift)) as usize
    }

    #[inline(always)]
    fn rb_slice_host_start(&self, info: &Qcow2Info) -> u64 {
        self.0 & !((1 << (info.cluster_shift + info.rb_slice_index_shift)) - 1)
    }

    #[inline(always)]
    fn rb_slice_host_end(&self, info: &Qcow2Info) -> u64 {
        self.rb_slice_host_start(info) + (info.rb_slice_entries() << info.cluster_bits()) as u64
    }

    #[inline(always)]
    fn rb_host_start(&self, info: &Qcow2Info) -> u64 {
        self.0 & !((1 << (info.cluster_shift + info.rb_index_shift)) - 1)
    }

    #[inline(always)]
    fn rb_host_end(&self, info: &Qcow2Info) -> u64 {
        self.rb_host_start(info) + (info.rb_entries() << info.cluster_bits()) as u64
    }

    #[inline(always)]
    fn rb_slice_off_in_table(&self, info: &Qcow2Info) -> usize {
        let rb_idx = self.rb_index(info);

        (rb_idx >> info.rb_slice_index_shift) << info.rb_slice_bits
    }
}

#[derive(Debug, Clone, Default)]
pub struct Qcow2DevParams {
    pub(crate) rb_cache: Option<(u8, usize)>,
    pub(crate) l2_cache: Option<(u8, usize)>,
    bs_shift: u8,
    direct_io: bool,
    read_only: RefCell<bool>,
    backing: RefCell<Option<bool>>,
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
            read_only: std::cell::RefCell::new(ro),
            direct_io: dio,
            backing: std::cell::RefCell::new(None),
        }
    }

    pub fn get_bs_bits(&self) -> u8 {
        self.bs_shift
    }

    pub fn set_read_only(&self, ro: bool) {
        *self.read_only.borrow_mut() = ro;
    }

    pub fn is_direct_io(&self) -> bool {
        self.direct_io
    }

    pub fn is_read_only(&self) -> bool {
        *self.read_only.borrow()
    }

    pub fn mark_backing_dev(&self, backing: Option<bool>) {
        *self.backing.borrow_mut() = backing;

        self.set_read_only(true);
    }

    pub fn is_backing_dev(&self) -> bool {
        match *self.backing.borrow() {
            None => false,
            Some(_) => true,
        }
    }
}

type L2TableHandle = AsyncRwLock<L2Table>;

pub struct Qcow2Dev<T> {
    path: PathBuf,
    header: AsyncRwLock<Qcow2Header>,

    // mapping table
    l1table: AsyncRwLock<L1Table>,
    l2cache: AsyncLruCache<usize, L2TableHandle>,

    // splices share single cluster, so before flushing any cluster
    // which is used for slices, discard this cluster first, then any
    // new slice stored in this cluster can loaded with correct data
    //
    // true value means this cluster isn't discarded yet, and false
    // means the cluster has been discarded
    //
    // used by both mapping table and allocator
    // false: not discarded, true: being discarded
    new_cluster: AsyncRwLock<HashMap<u64, AsyncRwLock<bool>>>,

    // allocator
    free_cluster_offset: AtomicU64,
    reftable: AsyncRwLock<RefTable>,
    refblock_cache: AsyncLruCache<usize, AsyncRwLock<RefBlock>>,

    // set in case that any dirty meta is made
    need_flush: AtomicBool,

    file: T,
    backing_file: Option<Box<Qcow2Dev<T>>>,
    pub info: Qcow2Info,
}

impl<T> std::fmt::Debug for Qcow2Dev<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = write!(f, "Image path {:?}\ninfo {:?}\n", &self.path, &self.info);
        let _ = match &self.backing_file {
            Some(b) => write!(f, "backing {:?}", b),
            _ => write!(f, "backing None"),
        };
        write!(f, "\n")
    }
}

impl<T: Qcow2IoOps> Qcow2Dev<T> {
    pub fn new(
        path: &PathBuf,
        header: Qcow2Header,
        params: &Qcow2DevParams,
        file: T,
    ) -> Qcow2Result<Self> {
        let h = &header;
        let bs_shift = params.get_bs_bits();

        debug_assert!(bs_shift >= 9 && bs_shift <= 12);
        let info = Qcow2Info::new(&h, params)?;

        let l2_cache_cnt = info.l2_cache_cnt as usize;
        let rb_cache_cnt = info.rb_cache_cnt as usize;
        let l1_size = Qcow2Info::__max_l1_size(
            Qcow2Info::get_max_l1_entries(h.size(), h.cluster_bits().try_into().unwrap()),
            1 << bs_shift,
        );
        let rt_size = h.reftable_clusters() << h.cluster_bits();
        let l1_entries = h.l1_table_entries() as u32;

        log::info!(
            "l2 slice cache(bits: {} count {}), rb cache(bits: {} count {})",
            info.l2_slice_bits,
            l2_cache_cnt,
            info.rb_slice_bits,
            rb_cache_cnt,
        );

        let dev = Qcow2Dev {
            path: path.clone(),
            header: AsyncRwLock::new(header),
            file,
            backing_file: None,
            info,
            l1table: AsyncRwLock::new(L1Table::new(None, l1_size, l1_entries, bs_shift)),
            l2cache: AsyncLruCache::new(l2_cache_cnt),
            free_cluster_offset: AtomicU64::new(0),
            reftable: AsyncRwLock::new(RefTable::new(None, rt_size, bs_shift)),
            refblock_cache: AsyncLruCache::new(rb_cache_cnt),
            new_cluster: AsyncRwLock::new(Default::default()),
            need_flush: AtomicBool::new(false),
        };

        Ok(dev)
    }

    async fn cluster_is_new(&self, cluster: u64) -> bool {
        let map = self.new_cluster.read().await;

        map.contains_key(&cluster)
    }

    async fn mark_new_cluster(&self, cluster: u64) {
        let mut map = self.new_cluster.write().await;

        map.insert(cluster, AsyncRwLock::new(false));
    }

    async fn clear_new_cluster(&self, cluster: u64) {
        let mut map = self.new_cluster.write().await;

        map.remove(&cluster);
    }

    /// Setup the backing Qcow2 device
    pub fn set_backing_dev(&mut self, back: Box<Qcow2Dev<T>>) {
        self.backing_file = Some(back);
    }

    #[inline]
    async fn call_read(&self, offset: u64, buf: &mut [u8]) -> Qcow2Result<usize> {
        log::trace!("read_to off {:x} len {}", offset, buf.len());
        self.file.read_to(offset, buf).await
    }

    #[inline]
    async fn call_write(&self, offset: u64, buf: &[u8]) -> Qcow2Result<()> {
        log::trace!("write_from off {:x} len {}", offset, buf.len());
        self.file.write_from(offset, buf).await
    }

    #[inline]
    async fn call_discard(&self, offset: u64, len: usize, flags: i32) -> Qcow2Result<()> {
        log::trace!("discard_range off {:x} len {}", offset, len);
        let res = self.file.discard_range(offset, len, flags).await;
        match res {
            Err(_) => {
                let mut zero_data = crate::page_aligned_vec!(u8, len);
                zero_buf!(zero_data);

                log::trace!("discard fallback off {:x} len {}", offset, len);
                self.call_write(offset, &zero_data).await
            }
            Ok(_) => Ok(()),
        }
    }

    /// flush data range in (offset, len) to disk
    #[inline]
    async fn call_fsync(&self, offset: u64, len: usize, flags: i32) -> Qcow2Result<()> {
        log::trace!("fsync off {:x} len {} flags {}", offset, len, flags);
        self.file.fsync(offset, len, flags).await
    }

    async fn load_top_table<B: Table>(&self, top: &AsyncRwLock<B>, off: u64) -> Qcow2Result<usize> {
        let mut t = top.write().await;

        if t.is_update() {
            return Ok(0);
        }

        t.set_offset(Some(off));
        let buf = unsafe { std::slice::from_raw_parts_mut(t.as_mut_ptr(), t.byte_size()) };
        let size = self.call_read(off, buf).await?;
        Ok(size as usize)
    }

    async fn load_refcount_table(&self) -> Qcow2Result<usize> {
        let h = self.header.read().await;
        self.load_top_table(&self.reftable, h.reftable_offset())
            .await
    }

    async fn load_l1_table(&self) -> Qcow2Result<usize> {
        let h = self.header.read().await;
        self.load_top_table(&self.l1table, h.l1_table_offset())
            .await
    }

    async fn get_l1_entry(&self, split: &SplitGuestOffset) -> Qcow2Result<L1Entry> {
        let l1_index = split.l1_index(&self.info);
        let res = {
            let handle = self.l1table.read().await;
            if handle.is_update() {
                Some(handle.get(l1_index))
            } else {
                None
            }
        };

        let l1_entry = match res {
            None => self.l1table.read().await.get(l1_index),
            Some(entry) => entry,
        };

        Ok(l1_entry)
    }

    #[inline]
    async fn add_l2_slice(
        &self,
        l1_e: &L1Entry,
        key: usize,
        slice_off: usize,
        slice: L2Table,
    ) -> Qcow2Result<()> {
        match self
            .add_cache_slice(&self.l2cache, l1_e, key, slice_off, slice)
            .await?
        {
            Some(to_kill) => {
                log::warn!("add_l2_slice: cache eviction, slices {}", to_kill.len());
                // figure exact dependency on refcount cache & reftable entries
                self.flush_refcount().await?;
                self.flush_cache_entries(to_kill).await
            }
            _ => Ok(()),
        }
    }

    #[inline]
    async fn get_l2_slice_slow(
        &self,
        l1_e: &L1Entry,
        split: &SplitGuestOffset,
    ) -> Qcow2Result<AsyncLruCacheEntry<AsyncRwLock<L2Table>>> {
        let info = &self.info;
        let key = split.l2_slice_key(info);
        let l2_cache = &self.l2cache;

        log::debug!(
            "get_l2_slice_slow: l1_e {:x} virt_addr {:x}",
            l1_e.get_value(),
            split.guest_addr(),
        );

        self.add_l2_slice(
            l1_e,
            key,
            split.l2_slice_off_in_table(info),
            L2Table::new(None, 1 << info.l2_slice_bits, info.cluster_bits()),
        )
        .await?;

        if let Some(entry) = l2_cache.get(key) {
            Ok(entry)
        } else {
            Err("Fail to load l2 table".into())
        }
    }

    #[inline]
    async fn get_l2_slice(
        &self,
        split: &SplitGuestOffset,
    ) -> Qcow2Result<AsyncLruCacheEntry<AsyncRwLock<L2Table>>> {
        let key = split.l2_slice_key(&self.info);

        match self.l2cache.get(key) {
            Some(entry) => Ok(entry),
            None => {
                let l1_e = self.get_l1_entry(split).await?;
                self.get_l2_slice_slow(&l1_e, split).await
            }
        }
    }

    async fn flush_cache_entries<B: Table>(
        &self,
        v: Vec<(usize, AsyncLruCacheEntry<AsyncRwLock<B>>)>,
    ) -> Qcow2Result<()> {
        let info = &self.info;
        let tv = &v;
        let mut f_vec = Vec::new();

        // Track 'new' clusters used in refcount/map table slice, any one
        // inserted to this set, it is being discarded. Once the discard is
        // completed, flush related slices in this cluster.
        //
        // The order does matter.
        //
        // We have to guarantee that new cluster has to be discarded once, and
        // exactly once before flushing any dirty slice.
        let mut cluster_map = HashMap::new();

        // For holding each rb/l2 read lock during write, so cache update
        // can't be prevented when flushing this dirty cache.
        //
        // But new cluster can't be removed from self.new_cluster() set
        // until the discard is done, so any new cache loading can be done
        // from in-flight during discarding new cluster.
        //
        let mut cache_vec = Vec::new();

        log::info!("flush caches: count {}", v.len());

        //discard first
        {
            for (_, e) in tv {
                if e.is_dirty() {
                    // For any cache update and set_dirty(true), write lock
                    // has to be obtained
                    let cache = e.value().read().await;

                    // clearing dirty now since cache update won't happen now,
                    // and dirty is only used for flushing cache.
                    e.set_dirty(false);

                    match cache.get_offset() {
                        Some(cache_off) => {
                            let key = cache_off >> info.cluster_bits();

                            if !cluster_map.contains_key(&key) {
                                if self.cluster_is_new(key).await {
                                    let cls_map = self.new_cluster.read().await;
                                    // keep this cluster locked, so that concurrent discard can
                                    // be avoided
                                    let mut locked_cls = cls_map.get(&key).unwrap().write().await;

                                    log::debug!(
                                        "flush_cache_entries: discard cluster {:x} done {}",
                                        cache_off & !((1 << info.cluster_bits()) - 1),
                                        *locked_cls
                                    );
                                    if *locked_cls == false {
                                        // mark it as discarded, so others can observe it after
                                        // grabbing write lock
                                        *locked_cls = true;
                                        if cls_map.contains_key(&key) {
                                            f_vec.push(self.call_discard(
                                                cache_off & !((1 << info.cluster_bits()) - 1),
                                                1 << info.cluster_bits(),
                                                0,
                                            ));
                                            cluster_map.insert(key, locked_cls);
                                        }
                                    }
                                }
                            }
                        }
                        _ => {
                            eprintln!("flush cache: dirty cache without offset");
                        }
                    }
                    // holding this cache's read block until this flush is done
                    cache_vec.push(cache);
                }
            }
        }

        futures::future::join_all(f_vec).await;

        {
            let mut cls_map = self.new_cluster.write().await;

            for (cls_key, _locked_cls) in cluster_map {
                cls_map.remove(&cls_key);

                // _locked_cls drops after this entry is removed from
                // new cluster map
            }
        }

        let mut f_vec = Vec::new();
        for cache in cache_vec.iter() {
            let off = cache.get_offset().unwrap();
            let buf = unsafe { std::slice::from_raw_parts(cache.as_ptr(), cache.byte_size()) };
            log::debug!(
                "flush_cache_entries: cache {} offset {:x}",
                qcow2_type_of(cache),
                off
            );
            f_vec.push(self.call_write(off, buf));
        }

        let res = futures::future::join_all(f_vec).await;
        for r in res {
            if r.is_err() {
                eprintln!("cache slice write failed {:?}\n", r);
                return r;
            }
        }

        //each cache's read lock drops here

        Ok(())
    }

    async fn flush_cache<C: Table>(
        &self,
        cache: &AsyncLruCache<usize, AsyncRwLock<C>>,
        start: usize,
        end: usize,
    ) -> Qcow2Result<bool> {
        let entries = cache.get_dirty_entries(start, end);

        if !entries.is_empty() {
            log::debug!(
                "flush_cache: type {} {:x} - {:x}",
                qcow2_type_of(cache),
                start,
                end,
            );

            self.flush_cache_entries(entries).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn flush_table<B: Table>(&self, t: &B, start: u32, size: usize) -> Qcow2Result<()> {
        let off = t.get_offset().unwrap() + start as u64;
        let buf = unsafe {
            std::slice::from_raw_parts(((t.as_ptr() as u64) + start as u64) as *const u8, size)
        };
        self.call_write(off, buf).await
    }

    async fn flush_top_table<B: Table>(&self, rt: &B) -> Qcow2Result<()> {
        loop {
            match rt.pop_dirty_blk_idx(None) {
                Some(idx) => {
                    let start = idx << self.info.block_size_shift;
                    let size = 1 << self.info.block_size_shift;
                    self.flush_table(rt, start, size).await?
                }
                None => break,
            }
        }

        Ok(())
    }

    async fn __flush_meta<A: Table + std::fmt::Debug, B: Table, F>(
        &self,
        rt: &A,
        cache: &AsyncLruCache<usize, AsyncRwLock<B>>,
        key_fn: F,
    ) -> Qcow2Result<bool>
    where
        F: Fn(u64) -> usize,
    {
        let bs_bits = self.info.block_size_shift;

        if let Some(idx) = rt.pop_dirty_blk_idx(None) {
            let start = key_fn((idx as u64) << bs_bits);
            let end = key_fn(((idx + 1) as u64) << bs_bits);

            if self.flush_cache(&cache, start, end).await? {
                // order cache flush and the upper layer table
                self.call_fsync(0, usize::MAX, 0).await?;
            }
            self.flush_table(rt, idx << bs_bits, 1 << bs_bits).await?;
            return Ok(false);
        } else {
            // flush cache without holding top table read lock
            if self.flush_cache(&cache, 0, usize::MAX).await? {
                self.call_fsync(0, usize::MAX, 0).await?;
            }
            return Ok(true);
        }
    }

    //// flush refcount table and block dirty data to disk
    async fn flush_refcount(&self) -> Qcow2Result<()> {
        let info = &self.info;

        loop {
            let rt = &*self.reftable.read().await;
            let done = self
                .__flush_meta(rt, &self.refblock_cache, |off| {
                    let rt_idx: u64 = off >> 3;
                    let host_cls = (rt_idx << info.rb_index_shift) << info.cluster_bits();
                    let k = HostCluster(host_cls);
                    k.rb_slice_key(info)
                })
                .await?;
            if done {
                break;
            }
        }
        Ok(())
    }

    pub async fn flush_meta(&self) -> Qcow2Result<()> {
        let info = &self.info;

        loop {
            // read lock prevents update on l1 table, meantime
            // normal read and cache-hit write can go without any
            // problem
            let l1 = &*self.l1table.read().await;

            // refcount is usually small size & continuous, so simply
            // flush all
            self.flush_refcount().await?;

            let done = self
                .__flush_meta(l1, &self.l2cache, |off| {
                    let l1_idx: u64 = off >> 3;
                    let virt_addr = (l1_idx << info.l2_index_shift) << info.cluster_bits();
                    let k = SplitGuestOffset(virt_addr);
                    k.l2_slice_key(info)
                })
                .await?;
            if done {
                self.mark_need_flush(false);
                break;
            }
        }
        Ok(())
    }

    // if we are running out of reftable, allocate more clusters and replace
    // current refcount table with new one
    //
    // All dirty refblock tables need to be flushed before flushing out the new
    // reftable.
    //
    // Very slow code path.
    async fn grow_reftable(
        &self,
        reftable: &LockWriteGuard<RefTable>,
        grown_rt: &mut RefTable,
    ) -> Qcow2Result<()> {
        let info = &self.info;
        let new_rt_clusters = grown_rt.cluster_count(info);
        if new_rt_clusters >= info.rb_entries() - 1 {
            // 1 entry stays free so we can allocate this refblock by putting its refcount into
            // itself
            // TODO: Implement larger allocations
            return Err(format!(
                "The reftable needs to grow to {} bytes, but we can allocate only {} -- try \
                     increasing the cluster size",
                new_rt_clusters * info.cluster_size(),
                (info.rb_entries() - 1) * info.cluster_size(),
            )
            .into());
        }

        // Allocate new reftable, put its refcounts in a completely new refblock
        let old_rt_offset = reftable.get_offset().unwrap();
        let old_rt_clusters = reftable.cluster_count(info);

        let rb_size = 1 << info.rb_slice_bits;
        let mut new_refblock = RefBlock::new(info.refcount_order(), rb_size, None);

        let refblock_offset =
            (reftable.entries() as u64) << (info.rb_index_shift + info.cluster_shift);
        new_refblock.set_offset(Some(refblock_offset));
        let rt_offset = refblock_offset + info.cluster_size() as u64;
        grown_rt.set_offset(Some(rt_offset));

        // Reference for the refblock
        new_refblock.increment(0).unwrap();
        // References for the reftable
        for i in 1..(new_rt_clusters + 1) {
            new_refblock.increment(i).unwrap();
        }

        let cls = HostCluster(refblock_offset);

        let rb_before = self.call_discard(
            cls.rb_slice_host_start(info),
            (refblock_offset - cls.rb_slice_host_start(info))
                .try_into()
                .unwrap(),
            0,
        );
        let rb = self.flush_table(&new_refblock, 0, new_refblock.byte_size());
        let rb_after = self.call_discard(
            refblock_offset + rb_size as u64,
            (cls.rb_slice_host_end(info) as usize - refblock_offset as usize - rb_size)
                .try_into()
                .unwrap(),
            0,
        );
        let (res0, res1, res2) = futures::join!(rb_before, rb, rb_after);
        if res0.is_err() || res1.is_err() || res2.is_err() {
            return Err("Failed to flush refcount block or discard other parts".into());
        }

        //todo: write all dirty refcount_block

        grown_rt.set_refblock_offset(reftable.entries(), refblock_offset);
        self.flush_top_table(grown_rt).await?;

        // write header
        {
            let mut h = self.header.write().await;

            h.set_reftable(
                grown_rt.get_offset().unwrap(),
                grown_rt.cluster_count(&self.info),
            )?;

            let buf = h.serialize_to_buf()?;
            if let Err(err) = self.call_write(0, &buf).await {
                h.set_reftable(old_rt_offset, old_rt_clusters).unwrap();
                return Err(err);
            }
        }

        self.free_clusters(old_rt_offset, old_rt_clusters).await?;

        Ok(())
    }

    async fn get_reftable_entry(&self, rt_idx: usize) -> RefTableEntry {
        let reftable = self.reftable.read().await;
        reftable.get(rt_idx)
    }

    /// free allocated clusters
    pub async fn free_clusters(&self, mut host_cluster: u64, mut count: usize) -> Qcow2Result<()> {
        let info = &self.info;
        let mut first_zero = true;

        log::info!("free_clusters start {:x} num {}", host_cluster, count);
        while count > 0 {
            let cls = HostCluster(host_cluster);
            let mut rt_e = self.get_reftable_entry(cls.rt_index(info)).await;

            if rt_e.is_zero() {
                rt_e = self.get_reftable_entry(cls.rt_index(info)).await;
            }

            let rb_handle = match self.get_refblock(&cls, &rt_e).await {
                Ok(handle) => handle,
                Err(_) => {
                    let next_cls = cls.rb_slice_host_end(info);
                    if next_cls - host_cluster >= count as u64 {
                        return Err("Fail to load refblock in freeing cluster".into());
                    }
                    let skip = next_cls - host_cluster;
                    count -= skip as usize;
                    host_cluster = next_cls;
                    continue;
                }
            };

            let mut refblock = rb_handle.value().write().await;
            let end = cls.rb_slice_host_end(info);

            log::debug!(
                "free host_cls {:x} start {:x} end {:x} count {}",
                cls.0,
                cls.rb_slice_host_start(info),
                end,
                count
            );

            while count > 0 && host_cluster < end {
                let cls = HostCluster(host_cluster);
                let slice_idx = cls.rb_slice_index(info);

                refblock.decrement(slice_idx).unwrap();
                if refblock.get(slice_idx).is_zero() && first_zero {
                    self.free_cluster_offset
                        .fetch_min(host_cluster, Ordering::Relaxed);
                    first_zero = false;
                }
                count -= 1;
                host_cluster += 1 << info.cluster_bits();
            }
            rb_handle.set_dirty(true);
            self.mark_need_flush(true);
        }

        Ok(())
    }

    async fn add_cache_slice<B: Table + std::fmt::Debug, E: TableEntry>(
        &self,
        cache: &AsyncLruCache<usize, AsyncRwLock<B>>,
        top_e: &E,
        key: usize,
        slice_off: usize,
        slice: B,
    ) -> Qcow2Result<Option<Vec<(usize, AsyncLruCacheEntry<AsyncRwLock<B>>)>>> {
        let info = &self.info;

        log::trace!(
            "add slice: entry {:x} slice key 0x{:<x} update {} type {} off {:x}",
            top_e.get_value(),
            key,
            slice.is_update(),
            crate::helpers::qcow2_type_of(&slice),
            slice_off
        );

        // may return entry added in other code paths, but it is guaranteed that
        // we can get one entry here
        let entry = cache.put_into_wmap_with(key, || AsyncRwLock::new(slice));

        // hold write lock, so anyone can't get this entry
        // and the whole cache lock isn't required, so lock wait is just on
        // this entry
        let mut slice = entry.value().write().await;

        // if rb becomes update, it has been committed in read map already
        if !slice.is_update() {
            let off = top_e.get_value() + slice_off as u64;
            slice.set_offset(Some(off));

            if !self.cluster_is_new(off >> info.cluster_bits()).await {
                let buf = unsafe {
                    std::slice::from_raw_parts_mut(slice.as_mut_ptr(), slice.byte_size())
                };
                self.call_read(off, buf).await?;
                log::trace!("add_cache_slice: load from disk");
            } else {
                entry.set_dirty(true);
                self.mark_need_flush(true);
                log::trace!("add_cache_slice: build from inflight");
            }

            //commit all populated caches and make them visible
            Ok(cache.commit_wmap())
        } else {
            log::trace!("add_cache_slice: slice is already update");
            Ok(None)
        }
    }

    #[inline]
    async fn add_rb_slice(
        &self,
        rt_e: &RefTableEntry,
        key: usize,
        slice_off: usize,
        slice: RefBlock,
    ) -> Qcow2Result<()> {
        match self
            .add_cache_slice(&self.refblock_cache, rt_e, key, slice_off, slice)
            .await?
        {
            Some(to_kill) => {
                log::warn!("add_rb_slice: cache eviction, slices {}", to_kill.len());
                self.flush_cache_entries(to_kill).await
            }
            _ => Ok(()),
        }
    }

    async fn get_refblock(
        &self,
        cls: &HostCluster,
        rt_e: &RefTableEntry,
    ) -> Qcow2Result<AsyncLruCacheEntry<AsyncRwLock<RefBlock>>> {
        let info = &self.info;
        let key = cls.rb_slice_key(info);
        let rb_cache = &self.refblock_cache;

        // fast path
        if let Some(entry) = rb_cache.get(key) {
            return Ok(entry);
        }

        self.add_rb_slice(
            rt_e,
            key,
            cls.rb_slice_off_in_table(info),
            RefBlock::new(info.refcount_order, 1 << info.rb_slice_bits, None),
        )
        .await?;

        if let Some(entry) = rb_cache.get(key) {
            Ok(entry)
        } else {
            Err("Fail to load refcount block".into())
        }
    }

    /// make sure reftable entry points to valid refcount block
    async fn ensure_refblock_offset(&self, cls: &HostCluster) -> Qcow2Result<RefTableEntry> {
        let info = &self.info;

        let rt_index = cls.rt_index(info);
        {
            let reftable = self.reftable.read().await;
            let rt_entry = reftable.get(rt_index);
            if !rt_entry.is_zero() {
                return Ok(rt_entry);
            }
        }

        let rt_clusters = {
            let h = self.header.read().await;
            h.reftable_clusters()
        };

        let mut reftable = self.reftable.write().await;
        log::info!(
            "ensure rt entry: rt_idx {} rt_entries {} host_cluster {:x}",
            rt_index,
            reftable.entries(),
            cls.0
        );
        if !reftable.in_bounds(rt_index) {
            let mut grown_rt = reftable.clone_and_grow(rt_index, rt_clusters, info.cluster_size());
            if !grown_rt.is_update() {
                self.grow_reftable(&reftable, &mut grown_rt).await?;
            }
            *reftable = grown_rt;
        }

        // Retry before allocating, maybe something has changed in the meantime
        let rt_entry = reftable.get(rt_index);
        if !rt_entry.is_zero() {
            return Ok(rt_entry);
        }

        // always run background flushing
        let refblock_offset = (rt_index as u64) << (info.rb_index_shift + info.cluster_shift);
        reftable.set_refblock_offset(rt_index, refblock_offset);
        self.mark_need_flush(true);

        // `new` flag means two points:
        //
        // - the pointed refblock needn't to be loaded from disk, and can be built from
        // inflight
        //
        // - when flushing refblock slice, the pointed cluster for storing the refblock
        // need to be discarded first
        self.mark_new_cluster(refblock_offset >> info.cluster_bits())
            .await;

        let rt_e = reftable.get(rt_index);

        log::debug!("allocate new refblock offset {:x}", refblock_offset);
        let mut new_refblock = RefBlock::new(info.refcount_order(), 1 << info.rb_slice_bits, None);
        new_refblock.increment(0).unwrap();

        //add this refblock into cache directly
        //
        //We have to add slice here because the reference needs to be held
        self.add_rb_slice(
            &rt_e,
            cls.rb_slice_key(info),
            cls.rb_slice_off_in_table(info),
            new_refblock,
        )
        .await?;

        log::debug!("ensure_refblock: done");

        Ok(rt_e)
    }

    // `fixed_start` means we can't change the specified allocation position
    // and count; otherwise, we may return the tail free clusters of this
    // slice.
    async fn try_alloc_from_rb_slice(
        &self,
        rt_e: &RefTableEntry,
        cls: &HostCluster,
        count: usize,
        fixed_start: bool,
    ) -> Qcow2Result<Option<(u64, usize)>> {
        let info = &self.info;
        let slice_entries = info.rb_slice_entries() as usize;
        let rb_slice_index = cls.rb_slice_index(info);
        if rb_slice_index + count > slice_entries {
            // Do not cross refblock boundaries; caller should look into the next refblock
            return Ok(None);
        }

        let rb_handle = self.get_refblock(&cls, &rt_e).await?;
        let mut rb = rb_handle.value().write().await;

        match rb.get_free_range(rb_slice_index, count) {
            Some(r) => {
                rb.alloc_range(r.start, r.end)?;
                rb_handle.set_dirty(true);
                self.mark_need_flush(true);
                Ok(Some((cls.cluster_off_from_slice(info, r.start), r.len())))
            }
            _ => {
                if fixed_start {
                    Ok(None)
                } else {
                    match rb.get_tail_free_range() {
                        Some(r) => {
                            rb.alloc_range(r.start, r.end)?;
                            rb_handle.set_dirty(true);
                            self.mark_need_flush(true);
                            Ok(Some((cls.cluster_off_from_slice(info, r.start), r.len())))
                        }
                        _ => Ok(None),
                    }
                }
            }
        }
    }

    /// Try to allocate `count` clusters starting somewhere at or after `host_cluster`, but in the
    /// same refblock.  This function cannot cross refblock boundaries.
    async fn try_allocate_from(
        &self,
        mut host_cluster: u64,
        mut count: usize,
    ) -> Qcow2Result<Option<(u64, usize)>> {
        assert!(count > 0);

        let info = &self.info;
        let cls = HostCluster(host_cluster);
        let rt_entry = self.ensure_refblock_offset(&cls).await?;
        let mut out_off = 0;
        let mut done = 0;

        // run cross-refblock-slice allocation, and we are allowed to return clusters
        // less than requested
        while count > 0 && host_cluster < cls.rb_host_end(info) {
            let cls = HostCluster(host_cluster);
            let curr_cnt = std::cmp::min(count, info.rb_slice_entries() as usize);

            // run non-fixed allocation for the 1st one, and other allocation has
            // to be continuous for keeping the whole range continuous
            match self
                .try_alloc_from_rb_slice(&rt_entry, &cls, curr_cnt, done != 0)
                .await?
            {
                Some(off) => {
                    //println!("alloc: done {} off {} cnt {}", done, off.0, off.1);
                    if done == 0 {
                        out_off = off.0;
                    } else {
                        assert!(host_cluster == off.0);
                    }
                    host_cluster = off.0 + ((off.1 as u64) << info.cluster_bits());
                    count -= off.1;
                    done += off.1;
                }
                None => {
                    // not started, so try next slice since nothing is available from
                    // current slice; otherwise return anything allocated
                    if done == 0 {
                        host_cluster = cls.rb_slice_host_end(info);
                    } else {
                        break;
                    }
                }
            }
        }

        if done != 0 {
            Ok(Some((out_off, done)))
        } else {
            Ok(None)
        }
    }

    /// Allocate clusters, so far the allocation can't cross each refblock boundary.
    /// But may return clusters less than requested.
    pub async fn allocate_clusters(&self, count: usize) -> Qcow2Result<Option<(u64, usize)>> {
        let info = &self.info;
        let mut host_offset = self.free_cluster_offset.load(Ordering::Relaxed);

        loop {
            match self.try_allocate_from(host_offset, count).await? {
                Some(a) => {
                    if count == 1 {
                        // Update the free cluster index only for `count == 1`, because otherwise
                        // (`count > 1`) we might have the index skip holes where single clusters
                        // could still fit
                        self.free_cluster_offset
                            .fetch_max(a.0 + info.cluster_size() as u64, Ordering::Relaxed);
                    }

                    log::trace!(
                        "allocate_clusters: requested {:x}/{} allocated {:x} {:x}/{}",
                        count,
                        count,
                        a.0,
                        a.1,
                        a.1
                    );

                    return Ok(Some(a));
                }

                None => {
                    host_offset = HostCluster(host_offset).rb_host_end(info);
                }
            }
        }
    }

    pub async fn allocate_cluster(&self) -> Qcow2Result<Option<(u64, usize)>> {
        self.allocate_clusters(1).await
    }

    async fn count_rb_slice_alloc_clusters(
        &self,
        rt_e: &RefTableEntry,
        cls: &HostCluster,
    ) -> Qcow2Result<usize> {
        let rb_h = self.get_refblock(&cls, &rt_e).await?;
        let rb = rb_h.value().write().await;
        let mut total = 0;

        for i in 0..rb.entries() {
            if !rb.get(i).is_zero() {
                total += 1;
            }
        }

        Ok(total)
    }

    async fn count_rt_entry_alloc_clusters(&self, cls: &HostCluster) -> Qcow2Result<Option<usize>> {
        let info = &self.info;
        let rt = self.reftable.read().await;
        let rt_idx = cls.rt_index(info);
        let rt_e = rt.get(rt_idx);
        let mut offset = cls.0;
        let mut total = 0;

        if rt_e.is_zero() {
            return Ok(None);
        }

        for _ in 0..(1 << (info.cluster_bits() - info.rb_slice_bits as usize)) {
            let cls = HostCluster(offset);
            let cnt = self.count_rb_slice_alloc_clusters(&rt_e, &cls).await?;

            total += cnt;
            offset += (info.rb_slice_entries() as u64) << info.cluster_bits();
        }

        Ok(Some(total))
    }

    pub async fn count_alloc_clusters(&self) -> Qcow2Result<usize> {
        let info = &self.info;
        let mut offset = 0_u64;
        let mut total = 0;

        loop {
            let cls = HostCluster(offset);

            match self.count_rt_entry_alloc_clusters(&cls).await? {
                Some(res) => total += res,
                None => break,
            }

            offset += (info.rb_entries() as u64) << info.cluster_bits();
        }

        Ok(total)
    }

    pub async fn get_mapping(&self, virtual_offset: u64) -> Qcow2Result<Mapping> {
        let split = SplitGuestOffset(virtual_offset & !(self.info.in_cluster_offset_mask as u64));
        let entry = self.get_l2_entry(virtual_offset).await?;

        Ok(entry.into_mapping(&self.info, &split))
    }

    #[inline]
    pub async fn get_l2_entry(&self, virtual_offset: u64) -> Qcow2Result<L2Entry> {
        let info = &self.info;
        let split = SplitGuestOffset(virtual_offset);
        let key = split.l2_slice_key(info);

        // fast path
        if let Some(res) = self.l2cache.get(key) {
            let l2_slice = res.value().read().await;
            Ok(l2_slice.get_entry(info, &split))
        } else {
            let l1_entry = self.get_l1_entry(&split).await?;

            if l1_entry.is_zero() {
                Ok(L2Entry(0))
            } else {
                let entry = self.get_l2_slice_slow(&l1_entry, &split).await?;
                let l2_slice = entry.value().read().await;
                Ok(l2_slice.get_entry(info, &split))
            }
        }
    }

    #[inline]
    pub async fn get_l2_entres(&self, off: u64, len: usize) -> Qcow2Result<Vec<L2Entry>> {
        let info = &self.info;
        let start = off & (!(info.in_cluster_offset_mask) as u64);
        let end = (off + ((len + info.cluster_size()) as u64) - 1)
            & (!(info.in_cluster_offset_mask) as u64);
        let mut entries = Vec::new();
        let mut voff = start;

        while voff < end {
            let split = SplitGuestOffset(voff);
            let key = split.l2_slice_key(info);

            // fast path
            let l2_slice = match self.l2cache.get(key) {
                Some(res) => res.value().read().await,
                None => {
                    let l1_entry = self.get_l1_entry(&split).await?;

                    if l1_entry.is_zero() {
                        entries.push(L2Entry(0));
                        voff += info.cluster_size() as u64;
                        continue;
                    } else {
                        let entry = self.get_l2_slice_slow(&l1_entry, &split).await?;
                        entry.value().read().await
                    }
                }
            };

            let this_end = {
                let l2_slice_idx = split.l2_slice_index(info) as u32;
                std::cmp::min(
                    end,
                    voff + (((info.l2_slice_entries - l2_slice_idx) as u64) << info.cluster_bits()),
                )
            };

            for this_off in (voff..this_end).step_by(info.cluster_size()) {
                let s = SplitGuestOffset(this_off);
                entries.push(l2_slice.get_entry(info, &s));
            }
            voff = this_end;
        }

        Ok(entries)
    }

    async fn do_read_compressed(
        &self,
        mapping: Mapping,
        off_in_cls: usize,
        buf: &mut [u8],
    ) -> Qcow2Result<usize> {
        let info = &self.info;
        let compressed_offset = mapping.cluster_offset.unwrap();
        let compressed_length = mapping.compressed_length.unwrap();

        // for supporting dio, we have to run aligned IO
        let bs = 1 << info.block_size_shift;
        let bs_mask = !((1_u64 << info.block_size_shift) - 1);
        let aligned_off = compressed_offset & bs_mask;
        let pad = (compressed_offset - aligned_off) as usize;
        let aligned_len = (pad + compressed_length + bs - 1) & (bs_mask as usize);

        let mut _compressed_data = crate::page_aligned_vec!(u8, aligned_len);
        let res = self.call_read(aligned_off, &mut _compressed_data).await?;
        if res != aligned_len {
            return Err("do_read_compressed: short read compressed data".into());
        }
        let compressed_data = &_compressed_data[pad..(pad + compressed_length)];

        let mut dec_ox = DecompressorOxide::new();
        if buf.len() == info.cluster_size() {
            let (status, _read, _written) = inflate(&mut dec_ox, compressed_data, buf, 0, 0);
            if status != TINFLStatus::Done && status != TINFLStatus::HasMoreOutput {
                return Err(format!(
                    "Failed to decompress cluster (host offset 0x{:x}+{}): {:?}",
                    compressed_offset, compressed_length, status
                )
                .into());
            }
        } else {
            let mut uncompressed_data = vec![0; info.cluster_size()];

            let (status, _read, _written) =
                inflate(&mut dec_ox, compressed_data, &mut uncompressed_data, 0, 0);
            if status != TINFLStatus::Done && status != TINFLStatus::HasMoreOutput {
                return Err(format!(
                    "Failed to decompress cluster (host offset 0x{:x}+{}): {:?}",
                    compressed_offset, compressed_length, status
                )
                .into());
            }
            buf.copy_from_slice(&uncompressed_data[off_in_cls..(off_in_cls + buf.len())]);
        };

        Ok(buf.len())
    }

    #[inline]
    async fn do_read_backing(
        &self,
        mapping: Mapping,
        off_in_cls: usize,
        buf: &mut [u8],
    ) -> Qcow2Result<usize> {
        match self.backing_file.as_ref() {
            Some(backing) => match mapping.cluster_offset {
                Some(off) => {
                    backing
                        .read_at_for_backing(buf, off + off_in_cls as u64)
                        .await
                }
                None => Err("Backing mapping: None offset None".into()),
            },
            None => {
                zero_buf!(buf);
                Ok(buf.len())
            }
        }
    }

    #[inline]
    async fn do_read_zero(
        &self,
        _mapping: Mapping,
        _off_in_cls: usize,
        buf: &mut [u8],
    ) -> Qcow2Result<usize> {
        zero_buf!(buf);
        Ok(buf.len())
    }

    #[inline]
    async fn do_read_data_file(
        &self,
        mapping: Mapping,
        off_in_cls: usize,
        buf: &mut [u8],
    ) -> Qcow2Result<usize> {
        match mapping.cluster_offset {
            Some(off) => self.call_read(off + off_in_cls as u64, buf).await,
            None => Err("DataFile mapping: None offset None".into()),
        }
    }

    #[inline]
    async fn do_read(&self, entry: L2Entry, offset: u64, buf: &mut [u8]) -> Qcow2Result<usize> {
        let off_in_cls = (offset as usize) & self.info.in_cluster_offset_mask;
        let split = SplitGuestOffset(offset - (off_in_cls as u64));
        let mapping = entry.into_mapping(&self.info, &split);

        log::trace!(
            "do_read: {} off_in_cls {} len {}",
            mapping,
            off_in_cls,
            buf.len()
        );
        match mapping.source {
            MappingSource::DataFile => self.do_read_data_file(mapping, off_in_cls, buf).await,
            MappingSource::Zero | MappingSource::Unallocated => {
                let mapping = self.get_mapping(offset).await?;
                self.do_read_zero(mapping, off_in_cls, buf).await
            }
            MappingSource::Backing => {
                let mapping = self.get_mapping(offset).await?;
                self.do_read_backing(mapping, off_in_cls, buf).await
            }
            MappingSource::Compressed => self.do_read_compressed(mapping, off_in_cls, buf).await,
        }
    }

    #[inline]
    async fn __read_at(&self, buf: &mut [u8], mut offset: u64) -> Qcow2Result<usize> {
        let info = &self.info;
        let bs = 1 << info.block_size_shift;
        let bs_mask = bs - 1;
        let vsize = info.virtual_size();
        let mut len = buf.len();
        let old_offset = offset;
        let old_len = len;
        let need_join =
            (offset >> info.cluster_bits()) != ((offset + (len as u64) - 1) >> info.cluster_bits());
        let mut extra = 0;

        if offset >= vsize {
            if !info.is_back_file() {
                return Err("read_at eof".into());
            } else {
                // the top device is asking for read, which is usually
                // caused by top device resize, so simply fake we provide
                // data requested
                return Ok(buf.len());
            }
        }

        if len == 0 {
            return Ok(0);
        }

        if (len & bs_mask) != 0 {
            return Err("un-aligned buffer length".into());
        }

        if (offset & (bs_mask as u64)) != 0 {
            return Err("un-aligned offset".into());
        }

        log::trace!("read_at: offset {:x} len {} >>>", offset, buf.len());

        if offset + (len as u64) > vsize {
            len = ((offset + (len as u64) - vsize + bs as u64 - 1) as usize) & !bs_mask;
            if info.is_back_file() {
                extra = buf.len() - len;
            }
        }
        debug_assert!((len & bs_mask) == 0);

        let mut reads = Vec::new();
        let mut remain = buf;
        let mut first_len = 0;
        let mut last_len = 0;
        let mut s = 0;
        let mut idx = 0;
        let l2_entries = if need_join {
            self.get_l2_entres(offset, len).await?
        } else {
            vec![self.get_l2_entry(offset).await?]
        };

        while len > 0 {
            let in_cluster_offset = offset as usize & info.in_cluster_offset_mask;
            let curr_len = std::cmp::min(info.cluster_size() - in_cluster_offset, len);
            let (iobuf, b) = remain.split_at_mut(curr_len);
            remain = b;

            if first_len == 0 {
                first_len = curr_len;
            }

            if need_join {
                reads.push(self.do_read(l2_entries[idx], offset, iobuf));
            } else {
                s = self.do_read(l2_entries[idx], offset, iobuf).await?;
            }

            offset += curr_len as u64;
            len -= curr_len;

            if len == 0 {
                last_len = curr_len;
            }
            idx += 1;
        }

        if need_join {
            let res = futures::future::join_all(reads).await;
            for i in 0..res.len() {
                let exp = if i == 0 {
                    first_len
                } else if i - 1 == res.len() {
                    last_len
                } else {
                    info.cluster_size()
                };

                match res[i] {
                    Ok(r) => {
                        s += r;
                        if r != exp {
                            break;
                        }
                    }
                    Err(_) => break,
                };
            }
        }
        log::trace!(
            "read_at: offset {:x} len {} res {} <<<",
            old_offset,
            old_len,
            s
        );
        Ok(s + extra)
    }

    #[async_recursion(?Send)]
    async fn read_at_for_backing(&self, buf: &mut [u8], offset: u64) -> Qcow2Result<usize> {
        self.__read_at(buf, offset).await
    }

    pub async fn read_at(&self, buf: &mut [u8], offset: u64) -> Qcow2Result<usize> {
        self.__read_at(buf, offset).await
    }

    async fn flush_header_for_l1_table(
        &self,
        l1_offset: u64,
        l1_entries: usize,
    ) -> Qcow2Result<()> {
        let info = &self.info;

        log::info!(
            "ensure_l2_offset: flush header for updating l1 offset {:x} entries {}",
            l1_offset,
            l1_entries
        );

        assert!(info.in_cluster_offset(l1_offset) == 0);
        assert!(l1_entries <= info.max_l1_entries());

        let mut h = self.header.write().await;
        let old_entries = h.l1_table_entries();
        let old_offset = h.l1_table_offset();

        h.set_l1_table(l1_offset, l1_entries)?;
        let buf = h.serialize_to_buf()?;
        if let Err(err) = self.call_write(0, &buf).await {
            h.set_l1_table(old_offset, old_entries).unwrap();
            return Err(err);
        }
        Ok(())
    }

    /// for fill up l1 entry
    async fn ensure_l2_offset(&self, split: &SplitGuestOffset) -> Qcow2Result<L1Entry> {
        let info = &self.info;
        let l1_entry = self.get_l1_entry(&split).await?;
        if !l1_entry.is_zero() {
            return Ok(l1_entry);
        }

        let l1_index = split.l1_index(info);
        let mut l1_table = self.l1table.write().await;

        // check if the current index is in bound of header l1 entries
        if !l1_table.in_bounds(l1_index) {
            if l1_index >= l1_table.entries() {
                let old_l1_offset = l1_table.get_offset().unwrap();
                let old_l1_clusters = l1_table.cluster_count(info);

                let mut new_l1_table = l1_table.clone_and_grow(l1_index, info.cluster_size());
                let new_l1_clusters = new_l1_table.cluster_count(info);
                let allocated = self.allocate_clusters(new_l1_clusters).await.unwrap();

                // fixme: allocated may return less clusters, here has to cover this
                // case
                match allocated {
                    None => return Err("nothing allocated for new l1 table".into()),
                    Some(res) => {
                        log::info!("ensure_l2_offset: write new allocated l1 table");
                        self.flush_meta().await?;
                        new_l1_table.set_offset(Some(res.0));
                        self.flush_top_table(&mut new_l1_table).await?;

                        self.flush_header_for_l1_table(res.0, new_l1_table.entries())
                            .await?;
                    }
                };

                *l1_table = new_l1_table;
                self.free_clusters(old_l1_offset, old_l1_clusters).await?;
            } else {
                let l1_off = {
                    let h = self.header.read().await;
                    h.l1_table_offset()
                };
                let l1_entries = std::cmp::min(info.max_l1_entries(), l1_table.entries());

                // update l1 entries
                self.flush_header_for_l1_table(l1_off, l1_entries).await?;
                l1_table.update_header_entries(l1_entries.try_into().unwrap());
            }
        }

        // Retry before allocating, maybe something has changed in the meantime
        let l1_e = l1_table.get(l1_index);
        if !l1_e.is_zero() {
            return Ok(l1_e);
        }

        let allocated = self.allocate_cluster().await?;
        match allocated {
            Some(res) => {
                let l2_offset = res.0;

                // this is one new cluster
                self.mark_new_cluster(l2_offset >> info.cluster_bits())
                    .await;
                l1_table.map_l2_offset(l1_index, l2_offset);
                self.mark_need_flush(true);

                Ok(l1_table.get(l1_index))
            }
            None => Err("nothing allocated for l2 table".into()),
        }
    }

    #[inline(always)]
    async fn do_compressed_cow(
        &self,
        off_in_cls: usize,
        buf: &[u8],
        host_off: u64,
        compressed_mapping: &Mapping,
    ) -> Qcow2Result<()> {
        let mut cbuf = crate::page_aligned_vec!(u8, self.info.cluster_size());

        // copy & write
        self.do_read_compressed(compressed_mapping.clone(), 0, &mut cbuf)
            .await?;
        cbuf[off_in_cls..off_in_cls + buf.len()].copy_from_slice(buf);
        self.call_write(host_off, &cbuf).await
    }

    #[inline(always)]
    async fn do_back_cow(
        &self,
        virt_off: u64,
        off_in_cls: usize,
        buf: &[u8],
        host_off: u64,
    ) -> Qcow2Result<()> {
        match self.backing_file.as_ref() {
            Some(backing) => {
                let mut cbuf = crate::page_aligned_vec!(u8, self.info.cluster_size());

                // copy & write
                backing
                    .read_at(&mut cbuf, virt_off - (off_in_cls as u64))
                    .await?;
                cbuf[off_in_cls..off_in_cls + buf.len()].copy_from_slice(buf);
                self.call_write(host_off, &cbuf).await
            }
            None => Err("No backing device found for COW".into()),
        }
    }

    /// discard this part iff the pointed host cluster is new
    #[inline]
    async fn do_write_data_file(
        &self,
        virt_off: u64,
        mapping: &Mapping,
        cow_mapping: Option<&Mapping>,
        buf: &[u8],
    ) -> Qcow2Result<()> {
        let info = &self.info;
        let off_in_cls = (virt_off & (info.in_cluster_offset_mask as u64)) as usize;
        let may_cow = cow_mapping.is_some();

        let host_off = match mapping.cluster_offset {
            Some(off) => off,
            None => return Err("DataFile mapping: None offset None".into()),
        };

        log::trace!(
            "do_write_data_file off_in_cls {:x} len {} virt_off {:x} cow {} mapping {}",
            off_in_cls,
            buf.len(),
            virt_off,
            may_cow,
            &mapping,
        );

        let f_write = self.call_write(host_off + off_in_cls as u64, buf);
        let key = host_off >> info.cluster_bits();

        let mut discard = None;
        let cluster_lock = if self.cluster_is_new(key).await {
            let cls_map = self.new_cluster.read().await;
            // keep this cluster locked, so that concurrent discard can
            // be avoided

            if cls_map.contains_key(&key) {
                let mut lock = cls_map.get(&key).unwrap().write().await;

                // don't handle discard any more if someone else has done
                // that, otherwise mark this cluster is being handled.
                //
                // use this per-cluster lock for covering backign COW too,
                // the whole cluster is copied to top image with this write
                // lock covered, so any concurrent write has to be started
                // after the copy is done
                if *lock == false {
                    *lock = true;

                    discard = Some(self.call_discard(host_off, info.cluster_size(), 0));
                    Some(lock)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        if let Some(lock) = cluster_lock {
            match discard {
                Some(df) => df.await?,
                None => {}
            };

            let cow_res = match cow_mapping {
                None => Ok(()),
                Some(m) => match m.source {
                    MappingSource::Compressed => {
                        self.do_compressed_cow(off_in_cls, buf, host_off, m).await
                    }
                    MappingSource::Backing => {
                        self.do_back_cow(virt_off, off_in_cls, buf, host_off).await
                    }
                    _ => Ok(()),
                },
            };

            /*
             * Another write on this new cluster may hold the read lock
             * and we won't move on, so drop write lock first given
             * we have marked that this new cluster is being discarded.
             */
            drop(lock);
            self.clear_new_cluster(key).await;
            if may_cow {
                // make sure data flushed before updating mapping
                self.call_fsync(host_off, info.cluster_size(), 0).await?;
                return cow_res;
            }
        };

        f_write.await
    }

    async fn do_write_cow(&self, off: u64, mapping: &Mapping, buf: &[u8]) -> Qcow2Result<()> {
        let info = &self.info;
        let split = SplitGuestOffset(off);
        let compressed = mapping.source == MappingSource::Compressed;

        log::trace!(
            "do_write_cow off_in_cls {:x} len {} mapping {}",
            off,
            buf.len(),
            &mapping,
        );

        // compressed image does have l1 ready, but backing dev may not
        if !compressed {
            let _ = self.ensure_l2_offset(&split).await?;
        }
        let l2_handle = self.get_l2_slice(&split).await?;

        // hold l2_table write lock, so that new mapping won't be flushed
        // to disk until cow is done
        let mut l2_table = l2_handle.value().write().await;

        // someone may jump on this cluster at the same time,
        // just let _one_ of them to handle COW for compressed image
        let data_mapping = match l2_table.get_mapping(info, &split).source {
            MappingSource::Compressed | MappingSource::Backing => {
                let mapping = self.alloc_and_map_cluster(&split, &mut l2_table).await?;

                l2_handle.set_dirty(true);
                self.mark_need_flush(true);

                mapping
            }
            _ => {
                drop(l2_table);
                return self.write_at_for_cow(buf, off).await;
            }
        };

        match self
            .do_write_data_file(off, &data_mapping, Some(mapping), buf)
            .await
        {
            Err(e) => {
                log::error!("do_write_cow: data write failed");
                // recover to previous compressed mapping & free allocated
                // clusters
                let allocated_cls = data_mapping.cluster_offset.unwrap();
                self.free_clusters(allocated_cls, 1).await?;
                self.clear_new_cluster(allocated_cls >> info.cluster_bits())
                    .await;

                l2_table.set(
                    split.l2_slice_index(info),
                    crate::meta::L2Entry::from_mapping(mapping.clone(), info.cluster_bits() as u32),
                );

                Err(e)
            }
            Ok(_) => {
                // respect meta update order, flush refcount meta,
                // then flush this l2 table, then decrease the
                // old cluster's reference count in ram

                // flush refcount change, which is often small
                // change
                self.flush_refcount().await?;

                // flush mapping table in-place update
                let off = l2_table.get_offset().unwrap();
                let buf =
                    unsafe { std::slice::from_raw_parts(l2_table.as_ptr(), l2_table.byte_size()) };
                self.call_write(off, buf).await?;
                l2_handle.set_dirty(false);

                // release l2 table, so that this new mapping can be flushed
                // to disk
                drop(l2_table);

                if compressed {
                    // free clusters in original compressed mapping
                    // finally, this update needn't be flushed immediately,
                    // and can be update in ram
                    let l2_e = crate::meta::L2Entry::from_mapping(
                        mapping.clone(),
                        info.cluster_bits() as u32,
                    );
                    match l2_e.compressed_range(info.cluster_bits() as u32) {
                        Some((off, length)) => {
                            let mask = (!info.in_cluster_offset_mask) as u64;
                            let start = off & mask;
                            let end = (off + (length as u64)) & mask;

                            let cnt = (((end - start) as usize) >> info.cluster_bits()) + 1;
                            self.free_clusters(start, cnt).await?
                        }
                        None => {
                            eprintln!("compressed clusters leak caused by wrong mapping")
                        }
                    }
                }

                Ok(())
            }
        }
    }

    #[inline]
    async fn alloc_and_map_cluster(
        &self,
        split: &SplitGuestOffset,
        l2_table: &mut LockWriteGuard<L2Table>,
    ) -> Qcow2Result<Mapping> {
        let info = &self.info;
        let allocated = self.allocate_cluster().await?;
        match allocated {
            Some(res) => {
                let l2_offset = res.0;

                // this is one new cluster
                self.mark_new_cluster(l2_offset >> info.cluster_bits())
                    .await;

                let _ = l2_table.map_cluster(split.l2_slice_index(info), l2_offset);
                Ok(l2_table.get_mapping(info, &split))
            }
            None => return Err("DataFile mapping: None offset None".into()),
        }
    }

    #[inline]
    async fn make_single_write_mapping(&self, virt_off: u64) -> Qcow2Result<L2Entry> {
        let split = SplitGuestOffset(virt_off);
        let _ = self.ensure_l2_offset(&split).await?;
        let l2_handle = self.get_l2_slice(&split).await?;
        let mut l2_table = l2_handle.value().write().await;

        let mapping = l2_table.get_mapping(&self.info, &split);
        if mapping.plain_offset(0).is_none() {
            let _ = self.alloc_and_map_cluster(&split, &mut l2_table).await?;
            l2_handle.set_dirty(true);
            self.mark_need_flush(true);
        }
        Ok(l2_table.get_entry(&self.info, &split))
    }

    /// don't pre-populate mapping for backing & compressed cow, which
    /// have to update mapping until copy on write is completed, otherwise
    /// data loss may be caused.
    fn need_make_mapping(mapping: &Mapping, info: &Qcow2Info) -> bool {
        if mapping.plain_offset(0).is_some() {
            return false;
        }

        if mapping.source == MappingSource::Compressed {
            return false;
        }

        if info.has_back_file()
            && (mapping.source == MappingSource::Backing
                || mapping.source == MappingSource::Unallocated)
        {
            return false;
        }

        return true;
    }

    /// return how many l2 entries stored in `l2_entries`
    #[inline]
    async fn __make_multiple_write_mapping(
        &self,
        start: u64,
        end: u64,
        l2_entries: &mut Vec<L2Entry>,
    ) -> Qcow2Result<usize> {
        let info = &self.info;
        let cls_size = info.cluster_size() as u64;

        debug_assert!((start & (cls_size - 1)) == 0);

        let split = SplitGuestOffset(start);
        let _ = self.ensure_l2_offset(&split).await?;
        let l2_handle = self.get_l2_slice(&split).await?;
        let mut l2_table = l2_handle.value().write().await;

        // each time, just handle one l2 slice, so the write lock
        // is just required once
        let end = {
            let l2_slice_idx = split.l2_slice_index(info) as u32;
            std::cmp::min(
                end,
                start + (((info.l2_slice_entries - l2_slice_idx) as u64) << info.cluster_bits()),
            )
        };

        // figure out how many clusters to allocate for write
        let mut nr_clusters = 0;
        for this_off in (start..end).step_by(cls_size as usize) {
            let s = SplitGuestOffset(this_off);
            let mapping = l2_table.get_mapping(&self.info, &s);

            if Self::need_make_mapping(&mapping, info) {
                nr_clusters += 1
            }
        }

        if nr_clusters == 0 {
            for this_off in (start..end).step_by(cls_size as usize) {
                let s = SplitGuestOffset(this_off);
                let entry = l2_table.get_entry(info, &s);
                l2_entries.push(entry);
            }
            return Ok(((end - start) as usize) >> info.cluster_bits());
        }

        let (cluster_start, cluster_cnt) = match self.allocate_clusters(nr_clusters).await? {
            Some((s, c)) => (s, c),
            _ => self
                .allocate_cluster()
                .await
                .unwrap()
                .expect("running out of cluster"),
        };

        let mut this_off = start;
        let done = if cluster_cnt > 0 {
            // how many mappings are updated
            let mut idx = 0;

            while this_off < end {
                let split = SplitGuestOffset(this_off);
                let entry = l2_table.get_entry(info, &split);
                let mapping = entry.into_mapping(info, &split);

                if Self::need_make_mapping(&mapping, info) {
                    let l2_off = cluster_start + ((idx as u64) << info.cluster_bits());

                    // this is one new cluster
                    self.mark_new_cluster(l2_off >> info.cluster_bits()).await;
                    let _ = l2_table.map_cluster(split.l2_slice_index(info), l2_off);

                    //load new entry
                    let entry = l2_table.get_entry(info, &split);
                    l2_entries.push(entry);
                    idx += 1;
                } else {
                    l2_entries.push(entry)
                }

                this_off += cls_size;
                if idx >= cluster_cnt {
                    break;
                }
            }
            idx
        } else {
            0
        };

        if done > 0 {
            l2_handle.set_dirty(true);
            self.mark_need_flush(true);
        }

        Ok(((this_off - start) as usize) >> info.cluster_bits())
    }

    async fn make_multiple_write_mappings(
        &self,
        mut start: u64,
        end: u64,
    ) -> Qcow2Result<Vec<L2Entry>> {
        let info = &self.info;
        let mut l2_entries = Vec::new();
        while start < end {
            // optimize in future by getting l2 entries at batch
            let entry = self.get_l2_entry(start).await?;

            let split = SplitGuestOffset(start);
            let mapping = entry.into_mapping(info, &split);

            let done = if Self::need_make_mapping(&mapping, info) {
                self.__make_multiple_write_mapping(start, end, &mut l2_entries)
                    .await?
            } else {
                l2_entries.push(entry);
                1
            };

            start += (done as u64) << info.cluster_bits();
        }
        Ok(l2_entries)
    }

    /// populate mapping for write at batch, and this way may improve
    /// perf a lot for big sequential IO, cause all meta setup can be
    /// one in single place, then data write IO can be run concurrently
    /// without lock contention
    #[inline]
    async fn populate_mapping_for_write(
        &self,
        virt_off: u64,
        len: usize,
    ) -> Qcow2Result<Vec<L2Entry>> {
        let info = &self.info;
        let single = (virt_off >> info.cluster_bits())
            == ((virt_off + (len as u64) - 1) >> info.cluster_bits());
        if single {
            let entry = self.get_l2_entry(virt_off).await?;
            let split = SplitGuestOffset(virt_off);
            let mapping = entry.into_mapping(info, &split);

            let entry = if Self::need_make_mapping(&mapping, info) {
                self.make_single_write_mapping(virt_off).await?
            } else {
                entry
            };

            Ok(vec![entry])
        } else {
            let cls_size = info.cluster_size() as u64;
            let start = virt_off & !(cls_size - 1);
            let end = (virt_off + (len as u64) + cls_size - 1) & !(cls_size - 1);

            let entries = self.make_multiple_write_mappings(start, end).await?;

            Ok(entries)
        }
    }

    async fn do_write(&self, l2_e: L2Entry, off: u64, buf: &[u8]) -> Qcow2Result<()> {
        let info = &self.info;
        let split = SplitGuestOffset(off & !(info.in_cluster_offset_mask as u64));
        let mapping = l2_e.into_mapping(info, &split);

        log::trace!(
            "do_write: offset {:x} len {} mapping {}",
            off,
            buf.len(),
            &mapping,
        );

        match mapping.source {
            MappingSource::DataFile => self.do_write_data_file(off, &mapping, None, buf).await,
            MappingSource::Compressed => self.do_write_cow(off, &mapping, buf).await,
            MappingSource::Backing | MappingSource::Unallocated if info.has_back_file() => {
                self.do_write_cow(off, &mapping, buf).await
            }
            _ => {
                eprintln!(
                    "invalid mapping {:?}, has_back_file {} offset {:x} len {}",
                    mapping.source,
                    info.has_back_file(),
                    off,
                    buf.len()
                );
                Err("invalid mapping built".into())
            }
        }
    }

    #[inline]
    async fn __write_at(&self, buf: &[u8], mut offset: u64) -> Qcow2Result<()> {
        use futures::stream::{FuturesUnordered, StreamExt};

        let info = &self.info;
        let bs = 1 << info.block_size_shift;
        let bs_mask = bs - 1;
        let mut len = buf.len();
        let old_offset = offset;
        let need_join =
            (offset >> info.cluster_bits()) != ((offset + (len as u64) - 1) >> info.cluster_bits());

        log::trace!("write_at offset {:x} len {} >>>", offset, buf.len());

        if offset
            .checked_add(buf.len() as u64)
            .map(|end| end > info.virtual_size())
            != Some(false)
        {
            return Err("Cannot write beyond the end of a qcow2 image".into());
        }

        if (len & bs_mask) != 0 {
            return Err("write_at: un-aligned buffer length".into());
        }

        if (offset & (bs_mask as u64)) != 0 {
            return Err("write_at: un-aligned offset".into());
        }

        if info.is_read_only() {
            return Err("write_at: write to read-only image".into());
        }

        let writes = FuturesUnordered::new();
        let mut remain = buf;
        let mut idx = 0;
        let l2_entries = self.populate_mapping_for_write(offset, len).await?;
        while len > 0 {
            let in_cluster_offset = offset as usize & info.in_cluster_offset_mask;
            let curr_len = std::cmp::min(info.cluster_size() - in_cluster_offset, len);
            let (iobuf, b) = remain.split_at(curr_len);
            remain = b;

            if need_join {
                writes.push(self.do_write(l2_entries[idx], offset, iobuf));
            } else {
                self.do_write(l2_entries[idx], offset, iobuf).await?;
            }

            offset += curr_len as u64;
            len -= curr_len;
            idx += 1;
        }

        if need_join {
            let res: Vec<_> = writes.collect().await;
            for r in res {
                if r.is_err() {
                    return Err("write_at: one write failed".into());
                }
            }
        }

        log::trace!("write_at offset {:x} len {} <<<", old_offset, buf.len());
        Ok(())
    }

    #[async_recursion(?Send)]
    async fn write_at_for_cow(&self, buf: &[u8], offset: u64) -> Qcow2Result<()> {
        self.__write_at(buf, offset).await
    }

    pub async fn write_at(&self, buf: &[u8], offset: u64) -> Qcow2Result<()> {
        self.__write_at(buf, offset).await
    }

    #[inline(always)]
    fn mark_need_flush(&self, val: bool) {
        self.need_flush.store(val, Ordering::Relaxed);
    }

    #[inline]
    pub fn need_flush_meta(&self) -> bool {
        self.need_flush.load(Ordering::Relaxed)
    }

    fn add_used_cluster_to_set(ranges: &mut HashMap<u64, RangeInclusive<u64>>, num: u64) {
        let mut start = num;
        let mut end = num;

        if num > 0 {
            if let Some(range) = ranges.remove(&(num - 1)) {
                start = *range.start();
                ranges.remove(&start);
            }
        }

        if let Some(range) = ranges.remove(&(num + 1)) {
            end = *range.end();
            ranges.remove(&end);
        }

        if let Some(range) = ranges.remove(&num) {
            start = start.min(*range.start());
            end = end.max(*range.end());
        }

        ranges.insert(start, start..=end);
        ranges.insert(end, start..=end);
    }

    async fn add_table_clusters<B: Table>(
        &self,
        table: &AsyncRwLock<B>,
        ranges: &mut HashMap<u64, RangeInclusive<u64>>,
    ) {
        let t = table.read().await;

        for i in 0..t.entries() {
            let e = t.get(i);

            if e.get_value() != 0 {
                Self::add_used_cluster_to_set(ranges, e.get_value() >> self.info.cluster_bits());
            }
        }
    }

    async fn add_refcount_table_clusters(
        &self,
        ranges: &mut HashMap<u64, RangeInclusive<u64>>,
    ) -> Qcow2Result<()> {
        let info = &self.info;
        let rt_range = {
            let h = self.header.read().await;

            h.reftable_offset()
                ..(h.reftable_offset() + (h.reftable_clusters() << info.cluster_bits()) as u64)
        };

        for c in rt_range {
            Self::add_used_cluster_to_set(ranges, c >> self.info.cluster_bits());
        }

        Ok(())
    }
    async fn add_l1_table_clusters(
        &self,
        ranges: &mut HashMap<u64, RangeInclusive<u64>>,
    ) -> Qcow2Result<()> {
        let info = &self.info;
        let cls_size = info.cluster_size();
        let l1_range = {
            let h = self.header.read().await;
            let l1_size = (self.l1table.read().await.byte_size() + cls_size - 1) & !(cls_size - 1);

            h.l1_table_offset()..((h.l1_table_offset() + l1_size as u64) as u64)
        };

        for c in l1_range {
            Self::add_used_cluster_to_set(ranges, c >> self.info.cluster_bits());
        }

        Ok(())
    }

    async fn add_data_clusters(
        &self,
        ranges: &mut HashMap<u64, RangeInclusive<u64>>,
    ) -> Qcow2Result<(usize, usize)> {
        let info = &self.info;
        let end = info.virtual_size();
        let mut allocated = 0;
        let mut compressed = 0;

        for start in (0..end).step_by(1 << info.cluster_bits()) {
            let mapping = self.get_mapping(start).await?;

            match mapping.source {
                MappingSource::Zero | MappingSource::Unallocated | MappingSource::Backing => {}
                MappingSource::DataFile => match mapping.cluster_offset {
                    Some(off) => {
                        allocated += 1;
                        Self::add_used_cluster_to_set(ranges, off >> self.info.cluster_bits());
                    }
                    _ => {}
                },
                MappingSource::Compressed => match mapping.cluster_offset {
                    Some(off) => {
                        let start = off >> info.cluster_bits();
                        let end = (off + (mapping.compressed_length.unwrap() as u64))
                            >> info.cluster_bits();
                        for off in start..=end {
                            Self::add_used_cluster_to_set(ranges, off);
                        }
                        allocated += 1;
                        compressed += 1;
                    }
                    _ => {}
                },
            }
        }
        Ok((allocated, compressed))
    }

    fn is_allocated_cluster_in_use(set: &Vec<&RangeInclusive<u64>>, cluster: u64) -> bool {
        for range in set {
            if range.contains(&cluster) {
                return true;
            }
        }
        return false;
    }

    pub async fn qcow2_cluster_usage<F>(&self, cls_usage: F) -> Qcow2Result<()>
    where
        F: Fn(&str, &Vec<&RangeInclusive<u64>>, Option<(usize, usize)>),
    {
        let mut set: HashMap<u64, RangeInclusive<u64>> = HashMap::new();
        self.add_refcount_table_clusters(&mut set).await?;
        let mut this_res: Vec<_> = set.values().collect();
        this_res.sort_by_key(|range| *range.start());
        this_res.dedup();
        cls_usage("refcount_table", &this_res, None);

        let mut set: HashMap<u64, RangeInclusive<u64>> = HashMap::new();
        self.add_l1_table_clusters(&mut set).await?;
        let mut this_res: Vec<_> = set.values().collect();
        this_res.sort_by_key(|range| *range.start());
        this_res.dedup();
        cls_usage("l1_table", &this_res, None);

        let mut set: HashMap<u64, RangeInclusive<u64>> = HashMap::new();
        self.add_table_clusters(&self.l1table, &mut set).await;
        let mut this_res: Vec<_> = set.values().collect();
        this_res.sort_by_key(|range| *range.start());
        this_res.dedup();
        cls_usage("l2_tables", &this_res, None);

        let mut set: HashMap<u64, RangeInclusive<u64>> = HashMap::new();
        self.add_table_clusters(&self.reftable, &mut set).await;
        let mut this_res: Vec<_> = set.values().collect();
        this_res.sort_by_key(|range| *range.start());
        this_res.dedup();
        cls_usage("refblock_tables", &this_res, None);

        let mut set: HashMap<u64, RangeInclusive<u64>> = HashMap::new();
        let stat_res = self.add_data_clusters(&mut set).await?;
        let mut this_res: Vec<_> = set.values().collect();
        this_res.sort_by_key(|range| *range.start());
        this_res.dedup();
        cls_usage("data", &this_res, Some(stat_res));

        Ok(())
    }

    /// check if any cluster is leaked
    async fn check_cluster_leak(&self) -> Qcow2Result<bool> {
        let info = &self.info;
        let mut set: HashMap<u64, RangeInclusive<u64>> = HashMap::new();
        let mut res = false;

        //add header cluster into set
        Self::add_used_cluster_to_set(&mut set, 0);

        self.add_refcount_table_clusters(&mut set).await?;
        self.add_l1_table_clusters(&mut set).await?;
        self.add_table_clusters(&self.l1table, &mut set).await;
        self.add_table_clusters(&self.reftable, &mut set).await;
        let _ = self.add_data_clusters(&mut set).await?;

        let mut result: Vec<_> = set.values().collect();
        result.sort_by_key(|range| *range.start());
        result.dedup();

        for range in &result {
            log::debug!("{:?}", range);
        }

        let max_allocated: u64 = {
            let rt = self.reftable.read().await;
            let mut idx = 0;

            while idx < rt.entries() {
                if rt.get(idx).is_zero() {
                    break;
                }
                idx += 1;
            }

            ((idx + 1) as u64) << ((info.rb_index_shift as usize) + info.cluster_bits())
        };

        log::debug!(
            "start leak check: virt size {:x} max_allocted {:x}",
            info.virtual_size(),
            max_allocated
        );
        for start in (0..max_allocated).step_by(1 << info.cluster_bits()) {
            let allocated = self.cluster_is_allocated(start).await?;
            if !allocated {
                continue;
            }

            if !Self::is_allocated_cluster_in_use(&result, start >> info.cluster_bits()) {
                eprintln!(
                    "cluster {:x}/{} is leaked",
                    start,
                    start >> info.cluster_bits()
                );
                res = true;
            }
        }

        Ok(res)
    }

    async fn cluster_is_allocated(&self, host_cluster: u64) -> Qcow2Result<bool> {
        let cls = HostCluster(host_cluster);
        let rt_entry = {
            let rt_index = cls.rt_index(&self.info);
            let reftable = self.reftable.read().await;
            reftable.get(rt_index)
        };

        if rt_entry.is_zero() {
            return Ok(false);
        }

        let rb_handle = self.get_refblock(&cls, &rt_entry).await?;
        let rb = rb_handle.value().read().await;

        if rb.get(cls.rb_slice_index(&self.info)).is_zero() {
            Ok(false)
        } else {
            Ok(true)
        }
    }

    async fn check_cluster(&self, virt_off: u64, cluster: Option<u64>) -> Qcow2Result<()> {
        match cluster {
            None => Ok(()),
            Some(host_cluster) => {
                match self.cluster_is_allocated(host_cluster).await? {
                    false => {
                        eprintln!(
                            "virt_offset {:x} pointed to non-allocated cluster {:x}",
                            virt_off, host_cluster
                        );
                    }
                    true => {}
                }
                Ok(())
            }
        }
    }

    /// no need to check backing & compressed, which is readonly
    async fn check_single_mapping(&self, off: u64, mapping: Mapping) -> Qcow2Result<()> {
        match mapping.source {
            MappingSource::Zero
            | MappingSource::Unallocated
            | MappingSource::Backing
            | MappingSource::Compressed => Ok(()),
            MappingSource::DataFile => self.check_cluster(off, mapping.cluster_offset).await,
        }
    }

    /// check if every cluster pointed by mapping is valid
    async fn check_mapping(&self) -> Qcow2Result<()> {
        let info = &self.info;
        let end = info.virtual_size();

        for start in (0..end).step_by(1 << info.cluster_bits()) {
            let mapping = self.get_mapping(start).await?;

            self.check_single_mapping(start, mapping).await?;
        }
        Ok(())
    }

    /// Qcow2 meta integrity check
    pub async fn check(&self) -> Qcow2Result<()> {
        self.check_mapping().await?;

        if self.check_cluster_leak().await? {
            return Err("check: cluster leak".into());
        }
        Ok(())
    }

    pub async fn __qcow2_prep_io(&self) -> Qcow2Result<()> {
        self.load_l1_table().await?;
        self.load_refcount_table().await?;

        Ok(())
    }

    /// Called before starting any qcow2 IO
    #[async_recursion(?Send)]
    pub async fn qcow2_prep_io(&self) -> Qcow2Result<()> {
        match &self.backing_file {
            Some(back) => back.qcow2_prep_io().await?,
            None => {}
        };
        self.__qcow2_prep_io().await
    }
}
