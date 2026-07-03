use super::*;
use crate::error::Qcow2Result;
use crate::helpers::IntAlignment;
use crate::meta::{Mapping, MappingSource, Table, TableEntry};
use futures_locks::RwLock as AsyncRwLock;
use std::collections::HashMap;
use std::ops::RangeInclusive;

/// Collect the cluster ranges built by `add_used_cluster_to_set` into a
/// sorted, deduplicated list
fn sorted_ranges(set: &HashMap<u64, RangeInclusive<u64>>) -> Vec<&RangeInclusive<u64>> {
    let mut res: Vec<_> = set.values().collect();
    res.sort_by_key(|range| *range.start());
    res.dedup();
    res
}

impl<T: Qcow2IoOps> Qcow2Dev<T> {
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

        for c in rt_range.step_by(info.cluster_size()) {
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
            let l1_size = self
                .l1table
                .read()
                .await
                .byte_size()
                .align_up(cls_size)
                .unwrap();

            h.l1_table_offset()..(h.l1_table_offset() + l1_size as u64)
        };

        for c in l1_range.step_by(cls_size) {
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

        for start in (0..end).step_by(info.cluster_size()) {
            let mapping = self.get_mapping(start).await?;

            match mapping.source {
                MappingSource::Zero | MappingSource::Unallocated | MappingSource::Backing => {}
                MappingSource::DataFile => {
                    if let Some(off) = mapping.cluster_offset {
                        allocated += 1;
                        Self::add_used_cluster_to_set(ranges, off >> self.info.cluster_bits());
                    }
                }
                MappingSource::Compressed => {
                    if let Some(off) = mapping.cluster_offset {
                        let start = off >> info.cluster_bits();
                        let end = (off + (mapping.compressed_length.unwrap() as u64))
                            >> info.cluster_bits();
                        for off in start..=end {
                            Self::add_used_cluster_to_set(ranges, off);
                        }
                        allocated += 1;
                        compressed += 1;
                    }
                }
            }
        }
        Ok((allocated, compressed))
    }

    fn is_allocated_cluster_in_use(set: &Vec<&RangeInclusive<u64>>, cluster: u64) -> bool {
        set.iter().any(|range| range.contains(&cluster))
    }

    /// Return Host Cluster usage, such as, allocated clusters, how many of them
    /// are compressed, ...
    pub async fn qcow2_cluster_usage<F>(&self, cls_usage: F) -> Qcow2Result<()>
    where
        F: Fn(&str, &Vec<&RangeInclusive<u64>>, Option<(usize, usize)>),
    {
        let mut set: HashMap<u64, RangeInclusive<u64>> = HashMap::new();
        self.add_refcount_table_clusters(&mut set).await?;
        cls_usage("refcount_table", &sorted_ranges(&set), None);

        let mut set: HashMap<u64, RangeInclusive<u64>> = HashMap::new();
        self.add_l1_table_clusters(&mut set).await?;
        cls_usage("l1_table", &sorted_ranges(&set), None);

        let mut set: HashMap<u64, RangeInclusive<u64>> = HashMap::new();
        self.add_table_clusters(&self.l1table, &mut set).await;
        cls_usage("l2_tables", &sorted_ranges(&set), None);

        let mut set: HashMap<u64, RangeInclusive<u64>> = HashMap::new();
        self.add_table_clusters(&self.reftable, &mut set).await;
        cls_usage("refblock_tables", &sorted_ranges(&set), None);

        let mut set: HashMap<u64, RangeInclusive<u64>> = HashMap::new();
        let stat_res = self.add_data_clusters(&mut set).await?;
        cls_usage("data", &sorted_ranges(&set), Some(stat_res));

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

        let result = sorted_ranges(&set);

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
        for start in (0..max_allocated).step_by(info.cluster_size()) {
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

        Ok(!rb.get(cls.rb_slice_index(&self.info)).is_zero())
    }

    async fn check_cluster(&self, virt_off: u64, cluster: Option<u64>) -> Qcow2Result<()> {
        match cluster {
            None => Ok(()),
            Some(host_cluster) => {
                if !self.cluster_is_allocated(host_cluster).await? {
                    eprintln!(
                        "virt_offset {virt_off:x} pointed to non-allocated cluster {host_cluster:x}"
                    );
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

        for start in (0..end).step_by(info.cluster_size()) {
            let mapping = self.get_mapping(start).await?;

            self.check_single_mapping(start, mapping).await?;
        }
        Ok(())
    }

    /// Check Qcow2 meta integrity and cluster leak
    pub async fn check(&self) -> Qcow2Result<()> {
        self.check_mapping().await?;

        if self.check_cluster_leak().await? {
            return Err("check: cluster leak".into());
        }
        Ok(())
    }

    pub(crate) async fn __qcow2_prep_io(&self) -> Qcow2Result<()> {
        self.load_l1_table().await?;
        self.load_refcount_table().await?;

        Ok(())
    }
}
