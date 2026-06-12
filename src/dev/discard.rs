use super::*;
use crate::error::Qcow2Result;
use crate::meta::{L2Entry, SplitGuestOffset, Table};

impl<T: Qcow2IoOps> Qcow2Dev<T> {
    /// Discard the guest range `[virtual_offset, virtual_offset + len)`.
    ///
    /// For every fully-covered guest cluster in the range, the L2 mapping
    /// is cleared to "unallocated", the host cluster's refcount is
    /// decremented via `free_clusters`, and the host file extent is
    /// punched via `call_fallocate(FALLOCATE_ZERO_RANGE)`. After the call
    /// returns, reads from the discarded range return zero (per qcow2
    /// §"L2 table entry" — an L2 entry of 0 is the "unallocated" state,
    /// which reads as zero) and the underlying host file shrinks on
    /// filesystems that support hole-punching.
    ///
    /// Partial-cluster head/tail ranges (guest_offset not aligned to
    /// cluster_size, or guest_offset+len not aligned) are silently
    /// skipped — discard is advisory and a partial-cluster mutation
    /// would require allocating/keeping the cluster anyway. Callers
    /// wanting per-byte-precise behavior should issue a zero-write for
    /// the head/tail in addition to this call.
    ///
    /// Compressed clusters are silently skipped: compressed clusters
    /// can share host sectors with adjacent compressed clusters, so
    /// punching the host extent risks corrupting a neighbor. The
    /// cluster stays referenced and subsequent reads still decompress
    /// correctly.
    ///
    /// Already-unallocated and zero-flagged clusters are no-ops.
    ///
    /// As with `write_at`, dirty meta (L2 slice + refcount block) is
    /// left in cache; call `flush_meta()` (or rely on the next eviction)
    /// to land the changes on disk.
    pub async fn discard(&self, virtual_offset: u64, len: u64) -> Qcow2Result<()> {
        let info = &self.info;
        let cluster_size = info.cluster_size() as u64;

        if len == 0 {
            return Ok(());
        }

        // Clip to the device's virtual size — out-of-range bytes are a
        // no-op rather than an error.
        let virt_size = info.virtual_size();
        let end_unclipped = virtual_offset.saturating_add(len);
        let end = end_unclipped.min(virt_size);
        if virtual_offset >= end {
            return Ok(());
        }

        // Round inward to whole-cluster boundaries.
        let start = info.cluster_round_up(virtual_offset);
        let stop = info.cluster_round_down(end);
        if start >= stop {
            return Ok(());
        }

        log::trace!(
            "discard guest [{:x}, {:x}) -> whole-cluster [{:x}, {:x})",
            virtual_offset,
            end,
            start,
            stop
        );

        let mut guest = start;
        while guest < stop {
            self.__discard_one_cluster(guest).await?;
            guest += cluster_size;
        }

        Ok(())
    }

    /// Discard a single guest cluster at `guest_offset` (cluster-aligned).
    ///
    /// Returns `Ok(())` for every non-fatal case: already-unallocated,
    /// zero-flagged, compressed, or L2-slice-absent ranges all silently
    /// no-op. The only errors are propagated from `free_clusters` /
    /// `call_fallocate` failures (genuine IO errors on the host file
    /// or refcount metadata).
    async fn __discard_one_cluster(&self, guest_offset: u64) -> Qcow2Result<()> {
        let info = &self.info;
        debug_assert_eq!(info.in_cluster_offset(guest_offset), 0);
        let split = SplitGuestOffset(guest_offset);

        // Fast path: no L2 slice exists for this region; nothing to free.
        let l1_e = self.get_l1_entry(&split).await?;
        if l1_e.is_zero() {
            return Ok(());
        }

        let l2_handle = self.get_l2_slice(&split).await?;
        let mut l2_table = l2_handle.value().write().await;

        let entry = l2_table.get_entry(info, &split);

        // Compressed clusters share host sectors; punching could corrupt
        // a neighbor. Leave them mapped.
        if entry.is_compressed() {
            return Ok(());
        }

        let allocation = entry.allocation(info.cluster_bits() as u32);
        let Some((host_cluster, host_count)) = allocation else {
            // Unallocated or zero-flagged-only entry — nothing to release.
            return Ok(());
        };

        // Clear the L2 entry to all zeros (unallocated state, reads-as-zero).
        let idx = split.l2_slice_index(info);
        l2_table.set(idx, L2Entry(0));
        l2_handle.set_dirty(true);
        self.mark_need_flush(true);
        drop(l2_table);

        // Refcount-release the host cluster(s). For ordinary (non-
        // compressed) entries this is always a single cluster, but we
        // pass `host_count` through to mirror the existing free_clusters
        // call sites in the COW path.
        self.free_clusters(host_cluster, host_count).await?;

        // Punch the host file so the OS reclaims the bytes. The
        // FALLOCATE_ZERO_RANGE flag asks for both hole-punch + reads-as-
        // zero semantics. On filesystems that don't support either,
        // call_fallocate falls back to writing zeros (see `call_fallocate`
        // implementation), so the LBPRZ-equivalent contract still holds.
        let punch_len = host_count * info.cluster_size();
        self.call_fallocate(host_cluster, punch_len, Qcow2OpsFlags::FALLOCATE_ZERO_RANGE)
            .await?;

        Ok(())
    }
}
