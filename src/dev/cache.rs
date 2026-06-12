use super::*;
use crate::cache::AsyncLruCache;
use crate::cache::AsyncLruCacheEntry;
use crate::error::Qcow2Result;
use crate::helpers::qcow2_type_of;
use crate::meta::{L1Entry, L1Table, L2Table, SplitGuestOffset, Table, TableEntry};
use futures_locks::{RwLock as AsyncRwLock, RwLockWriteGuard as LockWriteGuard};
use std::collections::hash_map::Entry;
use std::collections::HashMap;

impl<T: Qcow2IoOps> Qcow2Dev<T> {
    #[inline]
    pub(crate) async fn call_read(&self, offset: u64, buf: &mut [u8]) -> Qcow2Result<usize> {
        log::trace!("read_to off {:x} len {}", offset, buf.len());
        self.file.read_to(offset, buf).await
    }

    #[inline]
    pub(crate) async fn call_write(&self, offset: u64, buf: &[u8]) -> Qcow2Result<()> {
        log::trace!("write_from off {:x} len {}", offset, buf.len());
        self.file.write_from(offset, buf).await
    }

    #[inline]
    pub(crate) async fn call_fallocate(
        &self,
        offset: u64,
        len: usize,
        flags: u32,
    ) -> Qcow2Result<()> {
        log::trace!("fallocate off {:x} len {}", offset, len);
        let res = self.file.fallocate(offset, len, flags).await;
        match res {
            Err(_) => {
                log::trace!("discard fallback off {:x} len {}", offset, len);
                let zero_data = zeroed_io_buf(len);
                self.call_write(offset, &zero_data).await
            }
            Ok(_) => Ok(()),
        }
    }

    /// Write the (already updated) header out; on failure run `rollback`
    /// to restore the in-ram header so ram & disk stay consistent
    pub(crate) async fn commit_header<F>(
        &self,
        h: &mut LockWriteGuard<Qcow2Header>,
        rollback: F,
    ) -> Qcow2Result<()>
    where
        F: FnOnce(&mut Qcow2Header),
    {
        let buf = h.serialize_to_buf()?;
        if let Err(err) = self.call_write(0, &buf).await {
            rollback(h);
            return Err(err);
        }
        Ok(())
    }

    /// flush data range in (offset, len) to disk
    #[inline]
    pub(crate) async fn call_fsync(&self, offset: u64, len: usize, flags: u32) -> Qcow2Result<()> {
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

    pub(crate) async fn load_refcount_table(&self) -> Qcow2Result<usize> {
        let h = self.header.read().await;
        self.load_top_table(&self.reftable, h.reftable_offset())
            .await
    }

    pub(crate) async fn load_l1_table(&self) -> Qcow2Result<usize> {
        let h = self.header.read().await;
        self.load_top_table(&self.l1table, h.l1_table_offset())
            .await
    }

    pub(crate) async fn get_l1_entry(&self, split: &SplitGuestOffset) -> Qcow2Result<L1Entry> {
        let l1_index = split.l1_index(&self.info);

        Ok(self.l1table.read().await.get(l1_index))
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
    pub(crate) async fn get_l2_slice_slow(
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
    pub(crate) async fn get_l2_slice(
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

    pub(crate) async fn flush_cache_entries<B: Table>(
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

                            if let Entry::Vacant(slot) = cluster_map.entry(key) {
                                let cls_map = self.new_cluster.read().await;
                                // keep this cluster locked, so that concurrent discard can
                                // be avoided
                                if let Some(cluster) = cls_map.get(&key) {
                                    let mut locked_cls = cluster.write().await;

                                    log::debug!(
                                        "flush_cache_entries: discard cluster {:x} done {}",
                                        info.cluster_round_down(cache_off),
                                        *locked_cls
                                    );
                                    if !(*locked_cls) {
                                        // mark it as discarded, so others can observe it after
                                        // grabbing write lock
                                        *locked_cls = true;
                                        f_vec.push(self.call_fallocate(
                                            info.cluster_round_down(cache_off),
                                            info.cluster_size(),
                                            Qcow2OpsFlags::FALLOCATE_ZERO_RANGE,
                                        ));
                                        slot.insert(locked_cls);
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
            log::trace!(
                "flush_cache_entries: cache {} offset {:x}",
                qcow2_type_of(cache),
                cache.get_offset().unwrap()
            );
            f_vec.push(self.flush_table(&**cache, 0, cache.byte_size()));
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

    pub(crate) async fn flush_table<B: Table>(
        &self,
        t: &B,
        start: u32,
        size: usize,
    ) -> Qcow2Result<()> {
        let off = t.get_offset().unwrap() + start as u64;
        let buf = unsafe {
            std::slice::from_raw_parts(((t.as_ptr() as u64) + start as u64) as *const u8, size)
        };
        self.call_write(off, buf).await
    }

    pub(crate) async fn flush_top_table<B: Table>(&self, rt: &B) -> Qcow2Result<()> {
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

    /// Map a byte offset inside the reftable to the cache key of the first
    /// refblock slice covered by that reftable entry (inverse of
    /// `HostCluster::rb_slice_key`)
    fn rb_slice_key_of_rt_off(&self, off: u64) -> usize {
        let info = &self.info;
        let rt_idx: u64 = off >> 3;
        let host_cls = (rt_idx << info.rb_index_shift) << info.cluster_bits();

        HostCluster(host_cls).rb_slice_key(info)
    }

    /// Map a byte offset inside the l1 table to the cache key of the first
    /// l2 slice covered by that l1 entry (inverse of
    /// `SplitGuestOffset::l2_slice_key`)
    fn l2_slice_key_of_l1_off(&self, off: u64) -> usize {
        let info = &self.info;
        let l1_idx: u64 = off >> 3;
        let virt_addr = (l1_idx << info.l2_index_shift) << info.cluster_bits();

        SplitGuestOffset(virt_addr).l2_slice_key(info)
    }

    //// flush refcount table and block dirty data to disk
    pub(crate) async fn flush_refcount(&self) -> Qcow2Result<()> {
        loop {
            let rt = &*self.reftable.read().await;
            let done = self
                .flush_meta_generic(rt, &self.refblock_cache, |off| {
                    self.rb_slice_key_of_rt_off(off)
                })
                .await?;
            if done {
                break;
            }
        }
        Ok(())
    }

    //// flush mapping cache
    pub(crate) async fn flush_mapping(&self, l1: &L1Table) -> Qcow2Result<()> {
        loop {
            let done = self
                .flush_meta_generic(l1, &self.l2cache, |off| self.l2_slice_key_of_l1_off(off))
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
                .flush_meta_generic(l1, &self.l2cache, |off| self.l2_slice_key_of_l1_off(off))
                .await?;
            if done {
                self.mark_need_flush(false);
                break;
            }
        }
        log::debug!("flush_meta: exit");
        Ok(())
    }
}
