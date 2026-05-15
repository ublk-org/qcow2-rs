// This crate belongs to binary utility of `qcow2`
use crate::error::Qcow2Result;
use crate::ops::*;
#[rustversion::before(1.75)]
use async_trait::async_trait;
#[cfg(target_os = "linux")]
use nix::fcntl::{fallocate, FallocateFlags};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::AsRawFd;
use std::path::Path;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
pub struct Qcow2IoTokio {
    file: tokio::sync::Mutex<File>,
    fd: i32,
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[derive(Debug)]
pub struct Qcow2IoTokio {
    file: tokio::sync::Mutex<File>,
}

impl Qcow2IoTokio {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub async fn new(path: &Path, ro: bool, dio: bool) -> Qcow2IoTokio {
        let file = OpenOptions::new()
            .read(true)
            .write(!ro)
            .open(path.to_path_buf())
            .await
            .unwrap();

        assert!(!dio);

        let fd = file.as_raw_fd();
        Qcow2IoTokio {
            file: tokio::sync::Mutex::new(file),
            fd,
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub async fn new(path: &Path, ro: bool, dio: bool) -> Qcow2IoTokio {
        let file = OpenOptions::new()
            .read(true)
            .write(!ro)
            .open(path.to_path_buf())
            .await
            .unwrap();

        assert!(!dio);

        Qcow2IoTokio {
            file: tokio::sync::Mutex::new(file),
        }
    }

    async fn write_at(&self, offset: u64, buf: &[u8]) -> Qcow2Result<()> {
        let mut file = self.file.lock().await;

        file.seek(SeekFrom::Start(offset)).await?;
        let res = file.write(buf).await?;

        assert!(res == buf.len());

        Ok(())
    }
}

#[rustversion::attr(before(1.75), async_trait(?Send))]
impl Qcow2IoOps for Qcow2IoTokio {
    async fn read_to(&self, offset: u64, buf: &mut [u8]) -> Qcow2Result<usize> {
        let mut file = self.file.lock().await;

        file.seek(SeekFrom::Start(offset)).await?;
        let res = file.read(buf).await?;

        Ok(res)
    }

    async fn write_from(&self, offset: u64, buf: &[u8]) -> Qcow2Result<()> {
        self.write_at(offset, buf).await
    }

    #[cfg(target_os = "linux")]
    async fn fallocate(&self, offset: u64, len: usize, flags: u32) -> Qcow2Result<()> {
        let f = if (flags & Qcow2OpsFlags::FALLOCATE_ZERO_RAGE) != 0 {
            FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_ZERO_RANGE
        } else {
            FallocateFlags::FALLOC_FL_PUNCH_HOLE
        };

        Ok(fallocate(
            self.fd,
            f,
            offset as libc::off_t,
            len as libc::off_t,
        )?)
    }

    /// macOS hole-punch via `fcntl(F_PUNCHHOLE, &fpunchhole_t)` (available
    /// since macOS 10.10). The kernel requires `fp_offset` and `fp_length`
    /// to be multiples of the volume's logical block size (4096 on APFS);
    /// sub-block ranges return `EINVAL`. We treat `EINVAL`/`EOPNOTSUPP`/
    /// `ENOSYS` as soft fails and fall back to the zero-write path so
    /// callers still get the reads-as-zero guarantee they expect from
    /// `FALLOCATE_ZERO_RAGE` semantics — the host file just doesn't shrink
    /// for that one call.
    #[cfg(target_os = "macos")]
    async fn fallocate(&self, offset: u64, len: usize, _flags: u32) -> Qcow2Result<()> {
        let arg = libc::fpunchhole_t {
            fp_flags: 0,
            reserved: 0,
            fp_offset: offset as libc::off_t,
            fp_length: len as libc::off_t,
        };
        // SAFETY: `fcntl` with F_PUNCHHOLE takes a `*const fpunchhole_t`
        // variadic argument. `arg` lives on this stack frame and outlives
        // the synchronous call.
        let res = unsafe { libc::fcntl(self.fd, libc::F_PUNCHHOLE, &arg) };
        if res == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINVAL) | Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) => {
                let mut data = crate::helpers::Qcow2IoBuf::<u8>::new(len);
                data.zero_buf();
                self.write_at(offset, &data).await
            }
            _ => Err(err.into()),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    async fn fallocate(&self, offset: u64, len: usize, _flags: u32) -> Qcow2Result<()> {
        let mut data = crate::helpers::Qcow2IoBuf::<u8>::new(len);

        data.zero_buf();
        self.write_at(offset, &data).await
    }

    async fn fsync(&self, _offset: u64, _len: usize, _flags: u32) -> Qcow2Result<()> {
        let file = self.file.lock().await;
        file.sync_all().await?;

        Ok(())
    }
}
