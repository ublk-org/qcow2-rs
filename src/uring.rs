use crate::error::Qcow2Result;
use crate::ops::*;
#[rustversion::before(1.75)]
use async_trait::async_trait;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use tokio_uring::buf::{IoBuf, IoBufMut};
use tokio_uring::fs::{File, OpenOptions};

/// A borrowed buffer wrapper for tokio-uring operations.
///
/// This type wraps a raw pointer and length, implementing tokio-uring's buffer
/// traits without taking ownership. It does NOT free memory on drop since the
/// caller retains ownership of the underlying buffer.
///
/// # Safety
///
/// This type is only safe to use when:
/// 1. The underlying buffer outlives all io-uring operations using this wrapper
/// 2. The wrapper is not used after the underlying buffer is dropped
///
/// This is enforced by keeping this type private and only using it within
/// async functions where the borrow is guaranteed to be valid.
struct SliceMutBuf {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: The pointer is stable for the lifetime of the io-uring operation,
// and the caller ensures the underlying buffer outlives the operation.
unsafe impl IoBuf for SliceMutBuf {
    fn stable_ptr(&self) -> *const u8 {
        self.ptr
    }

    fn bytes_init(&self) -> usize {
        self.len
    }

    fn bytes_total(&self) -> usize {
        self.len
    }
}

// SAFETY: Same as IoBuf - the caller ensures the buffer outlives the operation.
unsafe impl IoBufMut for SliceMutBuf {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    unsafe fn set_init(&mut self, _pos: usize) {
        // No-op: the buffer is already fully initialized by the caller
    }
}

/// A borrowed immutable buffer wrapper for tokio-uring write operations.
struct SliceBuf {
    ptr: *const u8,
    len: usize,
}

// SAFETY: The pointer is stable for the lifetime of the io-uring operation.
unsafe impl IoBuf for SliceBuf {
    fn stable_ptr(&self) -> *const u8 {
        self.ptr
    }

    fn bytes_init(&self) -> usize {
        self.len
    }

    fn bytes_total(&self) -> usize {
        self.len
    }
}

#[derive(Debug)]
pub struct Qcow2IoUring {
    file: File,
}

impl Qcow2IoUring {
    pub async fn new(path: &Path, ro: bool, dio: bool) -> Qcow2IoUring {
        let file = OpenOptions::new()
            .read(true)
            .write(!ro)
            .open(path.to_path_buf())
            .await
            .unwrap();

        if dio {
            crate::ops::set_direct_io(file.as_raw_fd());
        }
        Qcow2IoUring { file }
    }
}

#[rustversion::attr(before(1.75), async_trait(?Send))]
impl Qcow2IoOps for Qcow2IoUring {
    async fn read_to(&self, offset: u64, buf: &mut [u8]) -> Qcow2Result<usize> {
        let ubuf = SliceMutBuf {
            ptr: buf.as_mut_ptr(),
            len: buf.len(),
        };
        let (res, _) = self.file.read_at(ubuf, offset).await;

        match res {
            Err(_) => Err("tokio-uring read failed".into()),
            Ok(r) => Ok(r),
        }
    }

    async fn write_from(&self, offset: u64, buf: &[u8]) -> Qcow2Result<()> {
        let ubuf = SliceBuf {
            ptr: buf.as_ptr(),
            len: buf.len(),
        };

        let (res, _) = self.file.write_at(ubuf, offset).submit().await;

        match res {
            Err(_) => Err("tokio-uring write failed".into()),
            Ok(_) => Ok(()),
        }
    }

    async fn fallocate(&self, offset: u64, len: usize, flags: u32) -> Qcow2Result<()> {
        // tokio-uring (0.5) still has no async fallocate, so fall back to the
        // shared synchronous nix fallocate() syscall on the raw fd.
        crate::ops::linux_punch_hole(self.file.as_raw_fd(), offset, len, flags)
    }

    async fn fsync(&self, _offset: u64, _len: usize, _flags: u32) -> Qcow2Result<()> {
        self.file.sync_all().await?;
        Ok(())
    }
}
