use super::*;
use crate::error::Qcow2Result;
use crate::helpers::Qcow2IoBuf;
use crate::meta::{L1Entry, L2Entry, L2Table, Mapping, MappingSource, SplitGuestOffset, Table};
use async_recursion::async_recursion;
use futures_locks::RwLockWriteGuard as LockWriteGuard;

impl<T: Qcow2IoOps> Qcow2Dev<T> {
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
        let l1_entry = self.get_l1_entry(split).await?;
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
                let allocated = self.allocate_clusters(new_l1_clusters).await?;

                // fixme: allocated may return less clusters, here has to cover this
                // case
                match allocated {
                    None => return Err("nothing allocated for new l1 table".into()),
                    Some(res) => {
                        log::info!("ensure_l2_offset: write new allocated l1 table");
                        self.flush_refcount().await?;
                        self.flush_mapping(&l1_table).await?;
                        new_l1_table.set_offset(Some(res.0));
                        self.flush_top_table(&new_l1_table).await?;

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
        let mut cbuf = Qcow2IoBuf::<u8>::new(self.info.cluster_size());

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
                let mut cbuf = Qcow2IoBuf::<u8>::new(self.info.cluster_size());

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
                if !(*lock) {
                    *lock = true;

                    discard = Some(self.call_fallocate(host_off, info.cluster_size(), 0));
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
            if let Some(df) = discard {
                df.await?
            }

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
                Ok(l2_table.get_mapping(info, split))
            }
            None => Err("DataFile mapping: None offset None".into()),
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

        true
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
            None => match self.allocate_cluster().await? {
                Some(res) => res,
                None => return Err("running out of cluster space".into()),
            },
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

    async fn populate_single_write_mapping(&self, virt_off: u64) -> Qcow2Result<L2Entry> {
        let info = &self.info;
        let entry = self.get_l2_entry(virt_off).await?;
        let split = SplitGuestOffset(virt_off);
        let mapping = entry.into_mapping(info, &split);

        let entry = if Self::need_make_mapping(&mapping, info) {
            self.make_single_write_mapping(virt_off).await?
        } else {
            entry
        };

        Ok(entry)
    }

    /// populate mapping for write at batch, and this way may improve
    /// perf a lot for big sequential IO, cause all meta setup can be
    /// one in single place, then data write IO can be run concurrently
    /// without lock contention
    #[inline]
    async fn populate_write_mappings(
        &self,
        virt_off: u64,
        len: usize,
    ) -> Qcow2Result<Vec<L2Entry>> {
        let info = &self.info;
        let cls_size = info.cluster_size() as u64;
        let start = virt_off & !(cls_size - 1);
        let end = (virt_off + (len as u64) + cls_size - 1) & !(cls_size - 1);

        let entries = self.make_multiple_write_mappings(start, end).await?;

        Ok(entries)
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
        let single =
            (offset >> info.cluster_bits()) == ((offset + (len as u64) - 1) >> info.cluster_bits());

        log::debug!("write_at offset {:x} len {} >>>", offset, buf.len());

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

        if single {
            let l2_entry = self.populate_single_write_mapping(offset).await?;
            self.do_write(l2_entry, offset, buf).await?;
        } else {
            let writes = FuturesUnordered::new();
            let mut remain = buf;
            let mut idx = 0;
            let l2_entries = self.populate_write_mappings(offset, len).await?;
            while len > 0 {
                let in_cluster_offset = offset as usize & info.in_cluster_offset_mask;
                let curr_len = std::cmp::min(info.cluster_size() - in_cluster_offset, len);
                let (iobuf, b) = remain.split_at(curr_len);
                remain = b;

                writes.push(self.do_write(l2_entries[idx], offset, iobuf));

                offset += curr_len as u64;
                len -= curr_len;
                idx += 1;
            }

            let res: Vec<_> = writes.collect().await;
            for r in res {
                if r.is_err() {
                    return Err("write_at: one write failed".into());
                }
            }
        }

        log::debug!("write_at offset {:x} len {} <<<", old_offset, buf.len());
        Ok(())
    }

    #[async_recursion(?Send)]
    async fn write_at_for_cow(&self, buf: &[u8], offset: u64) -> Qcow2Result<()> {
        self.__write_at(buf, offset).await
    }

    /// Write data in `buf` to the virtual `offset` of this qcow2 image
    pub async fn write_at(&self, buf: &[u8], offset: u64) -> Qcow2Result<()> {
        self.__write_at(buf, offset).await
    }
}
