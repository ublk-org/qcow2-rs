use crate::error::Qcow2Result;
use crate::helpers::slice_to_vec;
use crate::ops::*;
#[rustversion::before(1.75)]
use async_trait::async_trait;
use nix::fcntl::{fallocate, FallocateFlags};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use tokio_uring::fs::{File, OpenOptions};

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
            unsafe {
                libc::fcntl(file.as_raw_fd(), libc::F_SETFL, libc::O_DIRECT);
            }
        }
        Qcow2IoUring { file }
    }
}

#[rustversion::attr(before(1.75), async_trait(?Send))]
impl Qcow2IoOps for Qcow2IoUring {
    async fn read_to(&self, offset: u64, buf: &mut [u8]) -> Qcow2Result<usize> {
        let ubuf = slice_to_vec::<u8>(buf);
        let (res, ubuf) = self.file.read_at(ubuf, offset).await;

        std::mem::forget(ubuf);
        match res {
            Err(_) => Err("tokio-uring read failed".into()),
            Ok(r) => Ok(r),
        }
    }

    async fn write_from(&self, offset: u64, buf: &[u8]) -> Qcow2Result<()> {
        let ubuf = slice_to_vec::<u8>(buf);

        //let (res, ubuf) = self.file.write_at(ubuf, offset).submit().await; //tokio-uring github
        let (res, ubuf) = self.file.write_at(ubuf, offset).await;

        std::mem::forget(ubuf);
        match res {
            Err(_) => Err("tokio-uring write failed".into()),
            Ok(_) => Ok(()),
        }
    }

    async fn fallocate(&self, offset: u64, len: usize, flags: u32) -> Qcow2Result<()> {
        // tokio-uring github fallocate
        /*
        let res = self
            .file
            .fallocate(offset, len.try_into().unwrap(), flags)
            .await;
        match res {
            Err(_) => Err("tokio-uring fallocate failed".into()),
            Ok(_) => Ok(()),
        }*/

        // the latest tokio-uring crate(0.4) doesn't support fallocate yet, so use
        // sync nix fallocate() syscall
        let f = if (flags & Qcow2OpsFlags::FALLOCATE_ZERO_RAGE) != 0 {
            FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_ZERO_RANGE
        } else {
            FallocateFlags::FALLOC_FL_PUNCH_HOLE
        };

        Ok(fallocate(
            self.file.as_raw_fd(),
            f,
            offset as i64,
            len as i64,
        )?)
    }

    async fn fsync(&self, _offset: u64, _len: usize, _flags: u32) -> Qcow2Result<()> {
        self.file.sync_all().await?;
        Ok(())
    }
}
