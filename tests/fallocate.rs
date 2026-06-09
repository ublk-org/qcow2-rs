//! `Qcow2IoTokio::fallocate` cross-platform behavior.
//!
//! Verifies that the file-level hole-punch primitive actually shrinks
//! the host file's allocated block count on Linux (`fallocate(2)
//! FALLOC_FL_PUNCH_HOLE`) and macOS (`fcntl F_PUNCHHOLE`), and that the
//! macOS APFS sub-block-alignment soft-fail falls back to a zero-write
//! cleanly without corrupting the file.
//!
//! Tests are platform-gated; CI on Linux runs the Linux test, dev hosts
//! on macOS run the macOS tests. Other targets fall through to the
//! existing zero-write path (no test here — there's nothing platform-
//! specific to verify beyond what `basic.rs` already covers).

#![cfg(any(target_os = "linux", target_os = "macos"))]

use qcow2_rs::ops::{Qcow2IoOps, Qcow2OpsFlags};
use qcow2_rs::tokio_io::Qcow2IoTokio;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use tokio::runtime::Runtime;

/// Allocate the test file, fill it with non-zero bytes so that the
/// filesystem actually maps backing extents, and return the `st_blocks`
/// count (in 512-byte sectors) before any punch happens.
async fn prefill(path: &Path, size: usize, pattern: u8) -> u64 {
    let data = vec![pattern; size];
    tokio::fs::write(path, &data).await.unwrap();
    // Force the FS to fully allocate by syncing.
    let f = tokio::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .await
        .unwrap();
    f.sync_all().await.unwrap();
    drop(f);
    std::fs::metadata(path).unwrap().blocks()
}

#[cfg(target_os = "linux")]
#[test]
fn fallocate_punch_hole_shrinks_st_blocks_on_linux() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fallocate-linux.bin");
        let size = 64 * 1024;
        let blocks_before = prefill(&path, size, 0xAB).await;

        let io = Qcow2IoTokio::new(&path, false, false).await;
        // Some CI filesystems (notably overlay-backed layouts seen on
        // GitHub-hosted Ubuntu runners) return EOPNOTSUPP for
        // `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE` — the combo this
        // call uses when `FALLOCATE_ZERO_RANGE` is set. Production code
        // (`Qcow2Dev::call_fallocate`) has a write-zeros fallback for
        // exactly this case, so the qcow2 caller's reads-as-zero
        // contract is preserved; the file just doesn't shrink for that
        // one call. The test mirrors the production semantics: try the
        // punch, accept the soft-fail, and skip the strict shrinkage
        // assertion. The read-as-zero check below still validates the
        // user-facing contract on both paths.
        let punched = match io
            .fallocate(16 * 1024, 32 * 1024, Qcow2OpsFlags::FALLOCATE_ZERO_RANGE)
            .await
        {
            Ok(()) => true,
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("EOPNOTSUPP")
                    || msg.contains("Operation not supported")
                    || msg.contains("Unsupported")
                {
                    eprintln!("note: fallocate not supported on this filesystem ({e})");
                    eprintln!("      production code falls back to write-zeros for this case;");
                    eprintln!("      skipping strict shrinkage assertion");
                    false
                } else {
                    panic!("unexpected fallocate error: {e}");
                }
            }
        };
        io.fsync(0, 0, 0).await.unwrap();

        let blocks_after = std::fs::metadata(&path).unwrap().blocks();
        if punched {
            assert!(
                blocks_after < blocks_before,
                "punch_hole must shrink allocated blocks: before={blocks_before} after={blocks_after}",
            );
        } else {
            // Production code (`Qcow2Dev::call_fallocate`) falls back to
            // write-zeros when the underlying fallocate is unsupported.
            // `Qcow2IoTokio::fallocate` is the raw IO layer and has no
            // such fallback, so replicate it here — otherwise the range
            // is still the 0xAB prefill and the reads-as-zero assertion
            // below would (correctly) fail. Suggested by @ming1 in
            // review of PR #11.
            let zero_buf = vec![0u8; 32 * 1024];
            io.write_from(16 * 1024, &zero_buf).await.unwrap();
            io.fsync(0, 0, 0).await.unwrap();
        }
        // Either way: logical file size unchanged, punched/zeroed range
        // reads as zero, surrounding bytes untouched.
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size as u64);

        let mut buf = vec![0u8; 32 * 1024];
        let n = io.read_to(16 * 1024, &mut buf).await.unwrap();
        assert_eq!(n, buf.len());
        assert!(buf.iter().all(|&b| b == 0));

        let mut head = vec![0u8; 4096];
        let n = io.read_to(0, &mut head).await.unwrap();
        assert_eq!(n, head.len());
        assert!(head.iter().all(|&b| b == 0xAB));
    });
}

#[cfg(target_os = "macos")]
#[test]
fn fallocate_punch_hole_shrinks_st_blocks_on_macos() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fallocate-macos.bin");
        let size = 64 * 1024;
        let blocks_before = prefill(&path, size, 0xAB).await;

        let io = Qcow2IoTokio::new(&path, false, false).await;
        // 16 KiB offset, 32 KiB length — both 4-KiB-aligned, so APFS
        // accepts the punch.
        io.fallocate(16 * 1024, 32 * 1024, Qcow2OpsFlags::FALLOCATE_ZERO_RANGE)
            .await
            .expect("macOS F_PUNCHHOLE on 4-KiB-aligned range should succeed");
        io.fsync(0, 0, 0).await.unwrap();

        let blocks_after = std::fs::metadata(&path).unwrap().blocks();
        assert!(
            blocks_after < blocks_before,
            "F_PUNCHHOLE must shrink allocated blocks on APFS: before={blocks_before} after={blocks_after}",
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size as u64);

        let mut buf = vec![0u8; 32 * 1024];
        let n = io.read_to(16 * 1024, &mut buf).await.unwrap();
        assert_eq!(n, buf.len());
        assert!(buf.iter().all(|&b| b == 0));

        let mut head = vec![0u8; 4096];
        let n = io.read_to(0, &mut head).await.unwrap();
        assert_eq!(n, head.len());
        assert!(head.iter().all(|&b| b == 0xAB));
    });
}

#[cfg(target_os = "macos")]
#[test]
fn fallocate_sub_block_range_falls_back_to_zero_write_on_macos() {
    // APFS rejects F_PUNCHHOLE on offset/length that isn't a multiple
    // of the volume block size (4096) with EINVAL. The implementation
    // catches that and falls back to writing zeros at the requested
    // range, so the SCSI/qcow2 caller still observes "reads as zero"
    // semantics. We can't assert the file shrinks (it doesn't on this
    // path), but we can assert: no error, range reads as zero, bytes
    // outside the range are untouched.
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fallocate-macos-unaligned.bin");
        let size = 8 * 1024;
        prefill(&path, size, 0xAB).await;

        let io = Qcow2IoTokio::new(&path, false, false).await;
        // 1 KiB offset, 1 KiB length — neither is a multiple of 4 KiB.
        io.fallocate(1024, 1024, Qcow2OpsFlags::FALLOCATE_ZERO_RANGE)
            .await
            .expect("unaligned macOS range must soft-fail to zero-write, not propagate EINVAL");
        io.fsync(0, 0, 0).await.unwrap();

        // Range now reads as zeros.
        let mut buf = vec![0u8; 1024];
        let n = io.read_to(1024, &mut buf).await.unwrap();
        assert_eq!(n, buf.len());
        assert!(
            buf.iter().all(|&b| b == 0),
            "range must read as zero after soft-fallback"
        );

        // Bytes outside the range still 0xAB.
        let mut head = vec![0u8; 1024];
        let n = io.read_to(0, &mut head).await.unwrap();
        assert_eq!(n, head.len());
        assert!(head.iter().all(|&b| b == 0xAB));

        let mut tail = vec![0u8; 1024];
        let n = io.read_to(2048, &mut tail).await.unwrap();
        assert_eq!(n, tail.len());
        assert!(tail.iter().all(|&b| b == 0xAB));
    });
}
