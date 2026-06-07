use crate::cache::AsyncLruCache;
use crate::cache::AsyncLruCacheEntry;
use crate::error::Qcow2Result;
use crate::meta::{RefBlock, RefTable, RefTableEntry, Table, TableEntry};
use crate::ops::*;
use futures_locks::{RwLock as AsyncRwLock, RwLockWriteGuard as LockWriteGuard};
use std::sync::atomic::Ordering;

use super::*;

/// for cluster allocator
#[derive(Debug, Clone)]
pub(crate) struct HostCluster(pub(crate) u64);

impl HostCluster {
    #[inline(always)]
    pub(crate) fn cluster_off_from_slice(&self, info: &Qcow2Info, idx: usize) -> u64 {
        self.rb_slice_host_start(info) + ((idx as u64) << info.cluster_shift)
    }

    #[inline(always)]
    pub(crate) fn rt_index(&self, info: &Qcow2Info) -> usize {
        let bits = info.rb_index_shift + info.cluster_bits() as u8;

        (self.0 >> bits).try_into().unwrap()
    }

    #[inline(always)]
    pub(crate) fn rb_index(&self, info: &Qcow2Info) -> usize {
        let cluster_idx = self.0 >> info.cluster_shift;

        cluster_idx as usize & info.rb_index_mask
    }

    #[inline(always)]
    pub(crate) fn rb_slice_index(&self, info: &Qcow2Info) -> usize {
        let off = self.0 >> info.cluster_shift;
        off as usize & ((info.rb_slice_entries() - 1) as usize)
    }

    #[inline(always)]
    pub(crate) fn rb_slice_key(&self, info: &Qcow2Info) -> usize {
        (self.0 >> (info.cluster_shift + info.rb_slice_index_shift)) as usize
    }

    #[inline(always)]
    pub(crate) fn rb_slice_host_start(&self, info: &Qcow2Info) -> u64 {
        self.0 & !((1 << (info.cluster_shift + info.rb_slice_index_shift)) - 1)
    }

    #[inline(always)]
    pub(crate) fn rb_slice_host_end(&self, info: &Qcow2Info) -> u64 {
        self.rb_slice_host_start(info) + (info.rb_slice_entries() << info.cluster_bits()) as u64
    }

    #[inline(always)]
    pub(crate) fn rb_host_start(&self, info: &Qcow2Info) -> u64 {
        self.0 & !((1 << (info.cluster_shift + info.rb_index_shift)) - 1)
    }

    #[inline(always)]
    pub(crate) fn rb_host_end(&self, info: &Qcow2Info) -> u64 {
        self.rb_host_start(info) + (info.rb_entries() << info.cluster_bits()) as u64
    }

    #[inline(always)]
    pub(crate) fn rb_slice_off_in_table(&self, info: &Qcow2Info) -> usize {
        let rb_idx = self.rb_index(info);

        (rb_idx >> info.rb_slice_index_shift) << info.rb_slice_bits
    }
}

impl<T: Qcow2IoOps> Qcow2Dev<T> {
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

        let rb_before = self.call_fallocate(
            cls.rb_slice_host_start(info),
            (refblock_offset - cls.rb_slice_host_start(info))
                .try_into()
                .unwrap(),
            Qcow2OpsFlags::FALLOCATE_ZERO_RAGE,
        );
        let rb = self.flush_table(&new_refblock, 0, new_refblock.byte_size());
        let rb_after = self.call_fallocate(
            refblock_offset + rb_size as u64,
            cls.rb_slice_host_end(info) as usize - refblock_offset as usize - rb_size,
            Qcow2OpsFlags::FALLOCATE_ZERO_RAGE,
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
    pub(crate) async fn free_clusters(
        &self,
        mut host_cluster: u64,
        mut count: usize,
    ) -> Qcow2Result<()> {
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

    pub(crate) async fn add_cache_slice<B: Table + std::fmt::Debug, E: TableEntry>(
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

    pub(crate) async fn get_refblock(
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

        let rb_handle = self.get_refblock(cls, rt_e).await?;
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
        alloc_cnt: usize,
    ) -> Qcow2Result<Option<(u64, usize)>> {
        assert!(alloc_cnt > 0);

        let info = &self.info;
        let cls = HostCluster(host_cluster);
        let rt_entry = self.ensure_refblock_offset(&cls).await?;
        let mut out_off = 0;
        let mut done = 0;
        let mut count = alloc_cnt;

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
                        // can't make a big & continuous ranges, skip the small part
                        // in previous loop, and retry from current host_cluster
                        if host_cluster != off.0 {
                            log::debug!(
                                "try_allocate_from: fragment found and retry, free ({:x} {}) ({:x} {})",
                                out_off,
                                done,
                                off.0,
                                off.1
                            );
                            self.free_clusters(out_off, done).await?;
                            self.free_clusters(off.0, off.1).await?;
                            done = 0;
                            count = alloc_cnt;
                            continue;
                        }
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
    pub(crate) async fn allocate_clusters(
        &self,
        count: usize,
    ) -> Qcow2Result<Option<(u64, usize)>> {
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

                    log::debug!(
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

    pub(crate) async fn allocate_cluster(&self) -> Qcow2Result<Option<(u64, usize)>> {
        self.allocate_clusters(1).await
    }

    async fn count_rb_slice_alloc_clusters(
        &self,
        rt_e: &RefTableEntry,
        cls: &HostCluster,
    ) -> Qcow2Result<usize> {
        let rb_h = self.get_refblock(cls, rt_e).await?;
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

    #[allow(dead_code)]
    pub(crate) async fn count_alloc_clusters(&self) -> Qcow2Result<usize> {
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
    fn test_qcow2_dev_allocater_small() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let to_alloc = 180;
            let size = 64_u64 << 20;
            let cluster_bits = 16;
            let img_file = make_temp_qcow2_img(size, cluster_bits, 4);
            let path = PathBuf::from(img_file.path());
            let params = qcow2_default_params!(false, false);

            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();
            let allocated = dev.count_alloc_clusters().await.unwrap();
            assert!(allocated >= 3);

            let res = dev.allocate_clusters(to_alloc).await.unwrap().unwrap();
            dev.flush_meta().await.unwrap();

            let dev2 = qcow2_setup_dev_tokio(&path, &params).await.unwrap();
            let curr = dev2.count_alloc_clusters().await.unwrap();

            // count and see if anything is expected
            assert!(allocated + res.1 == curr);

            // free last allocation
            dev.free_clusters(res.0, res.1).await.unwrap();
            dev.flush_meta().await.unwrap();

            let dev3 = qcow2_setup_dev_tokio(&path, &params).await.unwrap();
            let curr = dev3.count_alloc_clusters().await.unwrap();

            //check if the last free is done successfully
            assert!(allocated == curr);
        });
    }

    #[test]
    fn test_qcow2_dev_allocater_big() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 256_u64 << 20;
            let cluster_bits = 16;
            let img_file = make_temp_qcow2_img(size, cluster_bits, 4);
            let path = PathBuf::from(img_file.path());
            let params = qcow2_default_params!(false, false);

            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();
            let allocated = dev.count_alloc_clusters().await.unwrap();
            assert!(allocated >= 3);

            let to_alloc = dev.info.rb_entries();

            let res = dev.allocate_clusters(to_alloc).await.unwrap().unwrap();
            dev.flush_meta().await.unwrap();

            let dev2 = qcow2_setup_dev_tokio(&path, &params).await.unwrap();
            let curr = dev2.count_alloc_clusters().await.unwrap();

            /*
            println!(
                "original {} allocated {}/{} now_allocated {}",
                allocated, to_alloc, res.1, curr
            );
            */

            // count and see if anything is expected
            assert!(allocated + res.1 == curr);

            // free last allocation
            dev.free_clusters(res.0, res.1).await.unwrap();
            if dev.need_flush_meta() {
                dev.flush_meta().await.unwrap();
            }

            let dev3 = qcow2_setup_dev_tokio(&path, &params).await.unwrap();
            let curr = dev3.count_alloc_clusters().await.unwrap();

            //check if the last free is done successfully
            assert!(allocated == curr);
        });
    }

    #[test]
    fn test_qcow2_dev_allocater_single() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 256_u64 << 20;
            let cluster_bits = 16;
            let img_file = make_temp_qcow2_img(size, cluster_bits, 4);
            let path = PathBuf::from(img_file.path());
            let params = qcow2_default_params!(false, false);

            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();
            let allocated = dev.count_alloc_clusters().await.unwrap();
            assert!(allocated >= 3);

            let to_alloc = dev.info.rb_entries();
            for _ in 0..to_alloc {
                let res = dev.allocate_clusters(1).await.unwrap().unwrap();

                assert!(res.1 == 1);
            }
            if dev.need_flush_meta() {
                dev.flush_meta().await.unwrap();
            }

            let dev2 = qcow2_setup_dev_tokio(&path, &params).await.unwrap();
            let curr = dev2.count_alloc_clusters().await.unwrap();

            // 1 extra cluster is for refblock
            assert!(allocated + to_alloc + 1 == curr);
        });
    }
}
