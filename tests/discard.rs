//! `Qcow2Dev::discard` behavior.
//!
//! Verifies that `pub async fn discard(virtual_offset, len)` releases
//! host clusters, clears L2 entries, makes reads return zero, and
//! produces an image that `qemu-img check` accepts (byte-format
//! conformance with the reference implementation).
//!
//! All tests use the default `Qcow2IoTokio` backend with 64 KiB clusters
//! (cluster_bits = 16) and refcount_order = 4 — the most common shape
//! produced by `qemu-img create`.
//!
//! The `qemu-img check` test is gated on the binary being present on
//! PATH; CI on Linux has `qemu-utils`, dev hosts on macOS install via
//! `brew install qemu`. When unavailable the assertion is skipped with
//! a stderr note rather than failing.

#[cfg(test)]
mod discard {
    use qcow2_rs::dev::*;
    use qcow2_rs::helpers::Qcow2IoBuf;
    use qcow2_rs::qcow2_default_params;
    use qcow2_rs::utils::{make_temp_qcow2_img, qcow2_setup_dev_tokio};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use tokio::runtime::Runtime;

    const CLUSTER_BITS: usize = 16;
    const CLUSTER_SIZE: usize = 1 << CLUSTER_BITS;

    /// Spin a small image, return (tempfile, path).
    fn fresh_image(virt_size: u64) -> (tempfile::NamedTempFile, PathBuf) {
        let img = make_temp_qcow2_img(virt_size, CLUSTER_BITS, 4);
        let p = img.path().to_path_buf();
        (img, p)
    }

    /// Allocated 512-byte sectors of the host file (`st_blocks`).
    fn host_blocks(path: &Path) -> u64 {
        std::fs::metadata(path).unwrap().blocks()
    }

    /// Shell out to `qemu-img check -q <path>`. Asserts exit 0 if
    /// `qemu-img` is on PATH; silently skips otherwise. This is the
    /// cross-tool byte-format gate — proves our L2/refcount mutations
    /// produce an image that the QEMU reference implementation accepts.
    fn qemu_img_check_or_skip(path: &Path) {
        let out = match Command::new("qemu-img")
            .args(["check", "-q"])
            .arg(path)
            .output()
        {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("qemu-img not on PATH; skipping byte-format check");
                return;
            }
            Err(e) => panic!("qemu-img invocation failed: {e}"),
        };
        assert!(
            out.status.success(),
            "qemu-img check failed on {}\nstdout: {}\nstderr: {}",
            path.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    /// Fill an `Qcow2IoBuf` with a non-zero pattern so allocations are
    /// actually visible in the host file's `st_blocks`.
    fn nonzero_buf(len: usize, pattern: u8) -> Qcow2IoBuf<u8> {
        let mut buf = Qcow2IoBuf::<u8>::new(len);
        for b in &mut buf[..] {
            *b = pattern;
        }
        buf
    }

    /// T1 — whole-cluster discard releases the L2 mapping and refcount.
    /// We assert the user-visible contract: post-discard, the host file
    /// has not grown (cf. accidental allocation while discarding) and a
    /// subsequent `flush_meta()` succeeds. The actual host-byte
    /// reclamation depends on the platform's `fallocate` implementation
    /// (Linux always punches; non-Linux falls back to zero-writes that
    /// preserve byte count). The reads-as-zero contract is checked in T2.
    #[test]
    fn discard_releases_host_cluster() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let virt_size = 1 << 20; // 1 MiB image
            let (_keep, path) = fresh_image(virt_size);

            let params = qcow2_default_params!(false, false);
            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

            let blocks_before_write = host_blocks(&path);
            let buf = nonzero_buf(CLUSTER_SIZE, 0xAB);
            dev.write_at(&buf, 0).await.unwrap();
            dev.flush_meta().await.unwrap();
            let blocks_after_write = host_blocks(&path);
            assert!(
                blocks_after_write > blocks_before_write,
                "write must allocate host blocks: {blocks_before_write} -> {blocks_after_write}",
            );

            dev.discard(0, CLUSTER_SIZE as u64).await.unwrap();
            dev.flush_meta().await.unwrap();
            let blocks_after_discard = host_blocks(&path);
            assert!(
                blocks_after_discard <= blocks_after_write,
                "discard must not grow the host file: {blocks_after_write} -> {blocks_after_discard}",
            );

            // On Linux, `fallocate(PUNCH_HOLE)` actually releases the
            // host extent; the file should shrink. On other platforms
            // the fallback writes zeros over the cluster, which leaves
            // the byte count unchanged — that's still correct (reads
            // return zero via the on-disk bytes), just less optimal.
            #[cfg(target_os = "linux")]
            assert!(
                blocks_after_discard < blocks_after_write,
                "Linux fallocate(PUNCH_HOLE) should release host blocks: \
                 {blocks_after_write} -> {blocks_after_discard}",
            );

            qemu_img_check_or_skip(&path);
        });
    }

    /// T2 — after discard, the range reads as all zeros (per qcow2
    /// "L2 entry of 0 reads as zero" semantics).
    #[test]
    fn discard_then_read_returns_zeros() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let virt_size = 1 << 20;
            let (_keep, path) = fresh_image(virt_size);
            let params = qcow2_default_params!(false, false);
            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

            let buf = nonzero_buf(CLUSTER_SIZE, 0xCD);
            dev.write_at(&buf, 0).await.unwrap();
            dev.flush_meta().await.unwrap();
            // Sanity: pre-discard, the read returns 0xCD.
            let mut pre = Qcow2IoBuf::<u8>::new(CLUSTER_SIZE);
            dev.read_at(&mut pre, 0).await.unwrap();
            assert!(pre.iter().all(|&b| b == 0xCD));

            dev.discard(0, CLUSTER_SIZE as u64).await.unwrap();
            dev.flush_meta().await.unwrap();

            let mut post = Qcow2IoBuf::<u8>::new(CLUSTER_SIZE);
            dev.read_at(&mut post, 0).await.unwrap();
            assert!(
                post.iter().all(|&b| b == 0),
                "post-discard read must return zeros (L2 entry of 0 reads as zero)",
            );

            qemu_img_check_or_skip(&path);
        });
    }

    /// T3 — sub-cluster (partial-cluster) range is a no-op. Discarding
    /// 1 KiB inside a 64 KiB cluster doesn't release the cluster.
    /// Caller wanting per-byte semantics should issue a zero-write.
    #[test]
    fn sub_cluster_range_is_noop() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let virt_size = 1 << 20;
            let (_keep, path) = fresh_image(virt_size);
            let params = qcow2_default_params!(false, false);
            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

            let buf = nonzero_buf(CLUSTER_SIZE, 0xEE);
            dev.write_at(&buf, 0).await.unwrap();
            dev.flush_meta().await.unwrap();
            let blocks_after_write = host_blocks(&path);

            // 1 KiB at offset 1 KiB — entirely inside cluster 0, but
            // neither offset nor length is cluster-aligned.
            dev.discard(1024, 1024).await.unwrap();
            dev.flush_meta().await.unwrap();
            let blocks_after_subdiscard = host_blocks(&path);
            assert_eq!(
                blocks_after_subdiscard, blocks_after_write,
                "sub-cluster discard must NOT release host blocks",
            );

            // Data still readable as 0xEE — no corruption from the no-op.
            let mut buf = Qcow2IoBuf::<u8>::new(CLUSTER_SIZE);
            dev.read_at(&mut buf, 0).await.unwrap();
            assert!(buf.iter().all(|&b| b == 0xEE));

            qemu_img_check_or_skip(&path);
        });
    }

    /// T4 — discard spanning multiple clusters: all clusters in the
    /// range become unallocated and read as zero. We don't assert
    /// specific host-byte release counts (platform-dependent — see T1).
    #[test]
    fn discard_multi_cluster_range() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let virt_size = 1 << 20;
            let (_keep, path) = fresh_image(virt_size);
            let params = qcow2_default_params!(false, false);
            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

            // Write four contiguous clusters.
            let total = 4 * CLUSTER_SIZE;
            let buf = nonzero_buf(total, 0x77);
            dev.write_at(&buf, 0).await.unwrap();
            dev.flush_meta().await.unwrap();
            let blocks_after_write = host_blocks(&path);

            dev.discard(0, total as u64).await.unwrap();
            dev.flush_meta().await.unwrap();
            let blocks_after_discard = host_blocks(&path);

            assert!(
                blocks_after_discard <= blocks_after_write,
                "multi-cluster discard must not grow the host file: {blocks_after_write} -> {blocks_after_discard}",
            );

            // All four clusters read as zero — this is the contract.
            let mut rb = Qcow2IoBuf::<u8>::new(total);
            dev.read_at(&mut rb, 0).await.unwrap();
            assert!(rb.iter().all(|&b| b == 0));

            #[cfg(target_os = "linux")]
            assert!(
                blocks_after_discard < blocks_after_write,
                "Linux fallocate(PUNCH_HOLE) should release 4 clusters: \
                 {blocks_after_write} -> {blocks_after_discard}",
            );

            qemu_img_check_or_skip(&path);
        });
    }

    /// T5 — discarding an already-unallocated range is a no-op success.
    #[test]
    fn discard_unallocated_is_noop() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let virt_size = 1 << 20;
            let (_keep, path) = fresh_image(virt_size);
            let params = qcow2_default_params!(false, false);
            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

            // Image is freshly formatted — no allocations.
            let blocks_before = host_blocks(&path);
            // Discard a multi-cluster range that has never been written.
            dev.discard(0, (4 * CLUSTER_SIZE) as u64).await.unwrap();
            dev.flush_meta().await.unwrap();
            let blocks_after = host_blocks(&path);

            // Allocated host blocks should not have grown (we shouldn't
            // have lazily allocated any L2 slice just to discard it).
            assert!(
                blocks_after <= blocks_before,
                "discard of unallocated range must not grow the file: {blocks_before} -> {blocks_after}",
            );

            // Read still returns zeros.
            let mut rb = Qcow2IoBuf::<u8>::new(CLUSTER_SIZE);
            dev.read_at(&mut rb, 0).await.unwrap();
            assert!(rb.iter().all(|&b| b == 0));

            qemu_img_check_or_skip(&path);
        });
    }

    /// T6 — discard followed by a re-write to the same range allocates
    /// fresh clusters and reads back the new data correctly.
    #[test]
    fn discard_then_rewrite_reallocates() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let virt_size = 1 << 20;
            let (_keep, path) = fresh_image(virt_size);
            let params = qcow2_default_params!(false, false);
            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

            // Write -> discard -> write a different pattern.
            let buf_a = nonzero_buf(CLUSTER_SIZE, 0x11);
            dev.write_at(&buf_a, 0).await.unwrap();
            dev.flush_meta().await.unwrap();
            dev.discard(0, CLUSTER_SIZE as u64).await.unwrap();
            dev.flush_meta().await.unwrap();
            let buf_b = nonzero_buf(CLUSTER_SIZE, 0x22);
            dev.write_at(&buf_b, 0).await.unwrap();
            dev.flush_meta().await.unwrap();

            let mut rb = Qcow2IoBuf::<u8>::new(CLUSTER_SIZE);
            dev.read_at(&mut rb, 0).await.unwrap();
            assert!(
                rb.iter().all(|&b| b == 0x22),
                "after discard+rewrite the new pattern must be readable",
            );

            qemu_img_check_or_skip(&path);
        });
    }

    /// T7 — partial-range head/tail are skipped, middle whole-cluster
    /// portion is released. Verifies the rounding logic inside
    /// `discard()`: start rounded up, stop rounded down. With a discard
    /// from offset 1 KiB to offset 3*cluster_size + 1 KiB, only the
    /// inner two clusters (1 and 2) should be released; cluster 0
    /// (partial head) and cluster 3 (partial tail) stay allocated.
    #[test]
    fn partial_range_only_releases_whole_inner_clusters() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let virt_size = 1 << 20;
            let (_keep, path) = fresh_image(virt_size);
            let params = qcow2_default_params!(false, false);
            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

            // Fill clusters 0..=3 with a distinct pattern each.
            for (i, pat) in [0xA1, 0xA2, 0xA3, 0xA4].iter().enumerate() {
                let buf = nonzero_buf(CLUSTER_SIZE, *pat);
                dev.write_at(&buf, (i * CLUSTER_SIZE) as u64).await.unwrap();
            }
            dev.flush_meta().await.unwrap();

            // Discard from 1 KiB into cluster 0 through 1 KiB into
            // cluster 3 (total spanning ~3 clusters of guest range).
            // Whole-aligned subrange: [cluster_size .. 3*cluster_size)
            // i.e. clusters 1 and 2.
            let start = 1024_u64;
            let len = (3 * CLUSTER_SIZE) as u64;
            dev.discard(start, len).await.unwrap();
            dev.flush_meta().await.unwrap();

            // Cluster 0 unchanged.
            let mut rb = Qcow2IoBuf::<u8>::new(CLUSTER_SIZE);
            dev.read_at(&mut rb, 0).await.unwrap();
            assert!(rb.iter().all(|&b| b == 0xA1));

            // Clusters 1 and 2 read as zero.
            dev.read_at(&mut rb, CLUSTER_SIZE as u64).await.unwrap();
            assert!(rb.iter().all(|&b| b == 0));
            dev.read_at(&mut rb, (2 * CLUSTER_SIZE) as u64)
                .await
                .unwrap();
            assert!(rb.iter().all(|&b| b == 0));

            // Cluster 3 unchanged.
            dev.read_at(&mut rb, (3 * CLUSTER_SIZE) as u64)
                .await
                .unwrap();
            assert!(rb.iter().all(|&b| b == 0xA4));

            qemu_img_check_or_skip(&path);
        });
    }
}
