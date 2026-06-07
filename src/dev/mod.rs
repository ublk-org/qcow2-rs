use crate::cache::AsyncLruCache;
use crate::cache::AsyncLruCacheEntry;
use crate::error::Qcow2Result;
use crate::helpers::{qcow2_type_of, Qcow2IoBuf};
use crate::meta::{
    L1Entry, L1Table, L2Table, Qcow2Header, RefBlock, RefTable, SplitGuestOffset, Table, TableEntry,
};
use crate::ops::*;
use async_recursion::async_recursion;
use futures_locks::{Mutex as AsyncMutex, RwLock as AsyncRwLock};
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

mod alloc;
mod check;
mod discard;
mod info;
mod read;
mod write;
use self::alloc::HostCluster;
pub use self::info::{Qcow2DevParams, Qcow2Info};

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
    flush_lock: AsyncMutex<()>,

    file: T,
    backing_file: Option<Box<Qcow2Dev<T>>>,
    pub info: Qcow2Info,
}

impl<T> std::fmt::Debug for Qcow2Dev<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = write!(f, "Image path {:?}\ninfo {:?}\n", &self.path, &self.info);
        let _ = match &self.backing_file {
            Some(b) => write!(f, "backing {b:?}"),
            _ => write!(f, "backing None"),
        };
        writeln!(f)
    }
}

impl<T: Qcow2IoOps> Qcow2Dev<T> {
    pub fn new(
        path: &Path,
        header: Qcow2Header,
        params: &Qcow2DevParams,
        file: T,
    ) -> Qcow2Result<Self> {
        let h = &header;
        let bs_shift = params.get_bs_bits();

        debug_assert!((9..=12).contains(&bs_shift));
        let info = Qcow2Info::new(h, params)?;

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
            path: path.to_path_buf(),
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
            flush_lock: AsyncMutex::new(()),
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
    async fn call_fallocate(&self, offset: u64, len: usize, flags: u32) -> Qcow2Result<()> {
        log::trace!("fallocate off {:x} len {}", offset, len);
        let res = self.file.fallocate(offset, len, flags).await;
        match res {
            Err(_) => {
                let mut zero_data = Qcow2IoBuf::<u8>::new(len);

                log::trace!("discard fallback off {:x} len {}", offset, len);
                zero_data.zero_buf();
                self.call_write(offset, &zero_data).await
            }
            Ok(_) => Ok(()),
        }
    }

    /// flush data range in (offset, len) to disk
    #[inline]
    async fn call_fsync(&self, offset: u64, len: usize, flags: u32) -> Qcow2Result<()> {
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
        self.call_read(off, buf).await
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

                            if !cluster_map.contains_key(&key) && self.cluster_is_new(key).await {
                                let cls_map = self.new_cluster.read().await;
                                // keep this cluster locked, so that concurrent discard can
                                // be avoided
                                let mut locked_cls = cls_map.get(&key).unwrap().write().await;

                                log::debug!(
                                    "flush_cache_entries: discard cluster {:x} done {}",
                                    cache_off & !((1 << info.cluster_bits()) - 1),
                                    *locked_cls
                                );
                                if !(*locked_cls) {
                                    // mark it as discarded, so others can observe it after
                                    // grabbing write lock
                                    *locked_cls = true;
                                    if cls_map.contains_key(&key) {
                                        f_vec.push(self.call_fallocate(
                                            cache_off & !((1 << info.cluster_bits()) - 1),
                                            1 << info.cluster_bits(),
                                            Qcow2OpsFlags::FALLOCATE_ZERO_RAGE,
                                        ));
                                        cluster_map.insert(key, locked_cls);
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
            log::trace!(
                "flush_cache_entries: cache {} offset {:x}",
                qcow2_type_of(cache),
                off
            );
            f_vec.push(self.call_write(off, buf));
        }

        let res = futures::future::join_all(f_vec).await;
        for r in res {
            if r.is_err() {
                eprintln!("cache slice write failed {r:?}\n");
                return r;
            }
        }

        //each cache's read lock drops here

        Ok(())
    }

    /// if the refblock cache for holding refcount block slice is empty
    pub fn refblock_cache_is_empty(&self) -> bool {
        self.refblock_cache.is_empty()
    }

    /// if the l2 cache for holding l2 slice is empty
    pub fn l2_cache_is_empty(&self) -> bool {
        self.l2cache.is_empty()
    }

    /// shrink both refblock and l2 caches, so the memory can be
    /// released, often called when qcow2 device is idle
    pub async fn shrink_caches(&self) -> Qcow2Result<()> {
        self.flush_meta().await?;
        self.refblock_cache.shrink();
        self.l2cache.shrink();

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
        while let Some(idx) = rt.pop_dirty_blk_idx(None) {
            let start = idx << self.info.block_size_shift;
            let size = 1 << self.info.block_size_shift;
            self.flush_table(rt, start, size).await?
        }

        Ok(())
    }

    // Flush one kind of meta data, l2 tables & l1, or refcount blocks with
    // refcount table
    //
    // It is one generic helper, so named as flush_meta_generic()
    async fn flush_meta_generic<A: Table + std::fmt::Debug, B: Table, F>(
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

            if self.flush_cache(cache, start, end).await? {
                // order cache flush and the upper layer table
                self.call_fsync(0, usize::MAX, 0).await?;
            }
            self.flush_table(rt, idx << bs_bits, 1 << bs_bits).await?;
            Ok(false)
        } else {
            // flush cache without holding top table read lock
            if self.flush_cache(cache, 0, usize::MAX).await? {
                self.call_fsync(0, usize::MAX, 0).await?;
            }
            Ok(true)
        }
    }

    //// flush refcount table and block dirty data to disk
    async fn flush_refcount(&self) -> Qcow2Result<()> {
        let info = &self.info;

        loop {
            let rt = &*self.reftable.read().await;
            let done = self
                .flush_meta_generic(rt, &self.refblock_cache, |off| {
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

    //// flush mapping cache
    async fn flush_mapping(&self, l1: &L1Table) -> Qcow2Result<()> {
        let info = &self.info;

        loop {
            let done = self
                .flush_meta_generic(l1, &self.l2cache, |off| {
                    let l1_idx: u64 = off >> 3;
                    let virt_addr = (l1_idx << info.l2_index_shift) << info.cluster_bits();
                    let k = SplitGuestOffset(virt_addr);
                    k.l2_slice_key(info)
                })
                .await?;
            if done {
                break;
            }
        }
        Ok(())
    }

    /// for flushing data in the qcow2 virtual range to disk
    pub async fn fsync_range(&self, off: u64, len: usize) -> Qcow2Result<()> {
        self.call_fsync(off, len, 0).await
    }

    /// flush meta data in ram to disk
    pub async fn flush_meta(&self) -> Qcow2Result<()> {
        let info = &self.info;
        let _flush_lock = self.flush_lock.lock().await;

        log::debug!("flush_meta: entry");
        loop {
            // refcount is usually small size & continuous, so simply
            // flush all
            self.flush_refcount().await?;

            // read lock prevents update on l1 table, meantime
            // normal read and cache-hit write can go without any
            // problem
            let l1 = &*self.l1table.read().await;

            let done = self
                .flush_meta_generic(l1, &self.l2cache, |off| {
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
        log::debug!("flush_meta: exit");
        Ok(())
    }
    #[inline(always)]
    fn mark_need_flush(&self, val: bool) {
        self.need_flush.store(val, Ordering::Relaxed);
    }

    /// Helper for checking if there is dirty meta data which needs
    /// to be flushed to disk
    #[inline]
    pub fn need_flush_meta(&self) -> bool {
        self.need_flush.load(Ordering::Relaxed)
    }

    /// Prepare everything(loading l1/refcount table) for handling any qcow2 IO
    #[async_recursion(?Send)]
    pub async fn qcow2_prep_io(&self) -> Qcow2Result<()> {
        if let Some(back) = &self.backing_file {
            back.qcow2_prep_io().await?
        };
        self.__qcow2_prep_io().await
    }
}

#[cfg(test)]
mod tests {
    use crate::dev::*;
    use crate::helpers::Qcow2IoBuf;
    use crate::qcow2_default_params;
    use crate::tokio_io::Qcow2IoTokio;
    use crate::utils::{make_temp_qcow2_img, qcow2_setup_dev_tokio};
    use std::path::PathBuf;
    use tokio::runtime::Runtime;

    #[test]
    fn test_qcow2_dev_io() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 64_u64 << 20;
            let img_file = make_temp_qcow2_img(size, 16, 4);
            let io = Qcow2IoTokio::new(&img_file.path().to_path_buf(), true, false).await;
            let mut buf = Qcow2IoBuf::<u8>::new(4096);
            let _ = io.read_to(0, &mut buf).await;
            let header = Qcow2Header::from_buf(&buf).unwrap();

            assert!(header.size() == size);
            assert!(header.cluster_bits() == 16);
        });
    }
}
