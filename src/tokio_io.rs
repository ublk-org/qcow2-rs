// This crate belongs to binary utility of `qcow2`
use crate::error::Qcow2Result;
use crate::ops::*;
use nix::fcntl::{fallocate, FallocateFlags};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};

#[derive(Debug)]
pub struct Qcow2IoTokio {
    file: tokio::sync::Mutex<File>,
    fd: i32,
}

impl Qcow2IoTokio {
    pub async fn new(path: &PathBuf, ro: bool, dio: bool) -> Qcow2IoTokio {
        let file = OpenOptions::new()
            .read(true)
            .write(!ro)
            .open(path.clone())
            .await
            .unwrap();

        assert!(!dio);

        let fd = file.as_raw_fd();
        Qcow2IoTokio {
            file: tokio::sync::Mutex::new(file),
            fd,
        }
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
        let mut file = self.file.lock().await;

        file.seek(SeekFrom::Start(offset)).await?;
        file.write(buf).await?;

        Ok(())
    }

    async fn fallocate(&self, offset: u64, len: usize, flags: u32) -> Qcow2Result<()> {
        let f = if (flags & Qcow2OpsFlags::FALLOCATE_ZERO_RAGE) != 0 {
            FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_ZERO_RANGE
        } else {
            FallocateFlags::FALLOC_FL_PUNCH_HOLE
        };

        let res = fallocate(self.fd, f, offset as i64, len as i64)?;
        Ok(res)
    }

    async fn fsync(&self, _offset: u64, _len: usize, _flags: u32) -> Qcow2Result<()> {
        let file = self.file.lock().await;
        file.sync_all().await?;

        Ok(())
    }
}
