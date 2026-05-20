//! `AsyncLruCacheEntryInner::drop` behavior on dirty cache entries.
//!
//! Verifies that dropping a `Qcow2Dev` whose internal LRU caches still
//! have dirty entries does not panic. Previously this asserted, which
//! turned a silent missed-flush bug into a hostile drop-time panic
//! (and during async runtime teardown, a process abort).
//!
//! The new behavior is to log at WARN level and continue. The data is
//! still lost — we cannot recover from `Drop` — but the program does
//! not abort, callers above us in the stack can finish cleanly, and
//! the operator finds the missing-flush bug from the WARN message
//! rather than from a panic with no async backtrace.
//!
//! These tests run on every platform; no cfg gates needed.

#[cfg(test)]
mod drop_behavior {
    use qcow2_rs::dev::*;
    use qcow2_rs::helpers::Qcow2IoBuf;
    use qcow2_rs::qcow2_default_params;
    use qcow2_rs::utils::{make_temp_qcow2_img, qcow2_setup_dev_tokio};
    use tokio::runtime::Runtime;

    const CLUSTER_BITS: usize = 16;
    const CLUSTER_SIZE: usize = 1 << CLUSTER_BITS;

    fn nonzero_buf(len: usize, pattern: u8) -> Qcow2IoBuf<u8> {
        let mut buf = Qcow2IoBuf::<u8>::new(len);
        for b in &mut buf[..] {
            *b = pattern;
        }
        buf
    }

    /// T1 — happy path: write, flush_meta, drop. The flush clears all
    /// dirty bits before drop, so the drop path takes the no-warn
    /// branch. This is the existing canonical usage pattern and the
    /// regression anchor that the new Drop impl doesn't break it.
    #[test]
    fn flush_meta_then_drop_is_clean() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let virt_size = 1 << 20;
            let img = make_temp_qcow2_img(virt_size, CLUSTER_BITS, 4);
            let path = img.path().to_path_buf();
            let params = qcow2_default_params!(false, false);
            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

            let buf = nonzero_buf(CLUSTER_SIZE, 0x55);
            dev.write_at(&buf, 0).await.unwrap();
            dev.flush_meta().await.unwrap();

            // dev drops here at end of block. Cache entries are clean
            // (flush_meta cleared dirty), so the drop is a no-op.
        });
    }

    /// T2 — dirty-drop path: write, SKIP flush_meta, drop. Previously
    /// this hit `assert!(!self.is_dirty())` inside the LRU cache entry's
    /// Drop and the test would panic. With the new behavior the drop
    /// emits a `log::warn!` and continues; the test framework's normal
    /// panic-catching reports nothing wrong, so the test passes.
    ///
    /// The data on disk is still lost (drop can't recover writes), but
    /// the program doesn't abort. That's the contract we're testing:
    /// "missing-flush is a warning, not a panic."
    #[test]
    fn dirty_drop_does_not_panic() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let virt_size = 1 << 20;
            let img = make_temp_qcow2_img(virt_size, CLUSTER_BITS, 4);
            let path = img.path().to_path_buf();
            let params = qcow2_default_params!(false, false);
            let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

            let buf = nonzero_buf(CLUSTER_SIZE, 0x99);
            dev.write_at(&buf, 0).await.unwrap();
            // Deliberately skip flush_meta — cache entries stay dirty.

            // dev drops here at end of block. The Drop impl logs a warn
            // about the dirty entries; the test must complete without
            // panicking.
        });
    }

    /// T3 — repeated dirty drops in the same process work. Verifies the
    /// new Drop behavior is stateless (no global flag that could trip
    /// on the second invocation) and that running this test alongside
    /// other tests in the same binary is safe.
    #[test]
    fn repeated_dirty_drops_are_independent() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            for round in 0..3 {
                let virt_size = 1 << 20;
                let img = make_temp_qcow2_img(virt_size, CLUSTER_BITS, 4);
                let path = img.path().to_path_buf();
                let params = qcow2_default_params!(false, false);
                let dev = qcow2_setup_dev_tokio(&path, &params).await.unwrap();

                let buf = nonzero_buf(CLUSTER_SIZE, 0x10 + round as u8);
                dev.write_at(&buf, 0).await.unwrap();
                // Skip flush_meta on every iteration.
            }
        });
    }
}
