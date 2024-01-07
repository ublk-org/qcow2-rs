use crate::dev::Qcow2IoOps;
use crate::error::Qcow2Result;
use crate::helpers::slice_to_vec;
#[rustversion::before(1.75)]
use async_trait::async_trait;
use nix::fcntl::{fallocate, FallocateFlags};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use tokio_uring::fs::{File, OpenOptions};

#[derive(Debug)]
pub struct Qcow2IoUring {
    file: File,
}

impl Qcow2IoUring {
    pub async fn new(path: &PathBuf, ro: bool, dio: bool) -> Qcow2IoUring {
        let file = OpenOptions::new()
            .read(true)
            .write(!ro)
            .open(path.clone())
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

    async fn discard_range(&self, offset: u64, len: usize, _flags: i32) -> Qcow2Result<()> {
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
        let res = fallocate(
            self.file.as_raw_fd(),
            FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_ZERO_RANGE,
            offset as i64,
            len as i64,
        )?;

        Ok(res)
    }

    async fn fsync(&self, _offset: u64, _len: usize, _flags: i32) -> Qcow2Result<()> {
        self.file.sync_all().await?;
        Ok(())
    }
}
