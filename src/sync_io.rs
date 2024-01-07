use crate::dev::Qcow2IoOps;
use crate::error::Qcow2Result;
#[rustversion::before(1.75)]
use async_trait::async_trait;
use nix::fcntl::{fallocate, FallocateFlags};
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

#[derive(Debug)]
pub struct Qcow2IoSync {
    _file: RefCell<File>,
    fd: i32,
}

impl Qcow2IoSync {
    pub fn new(path: &PathBuf, ro: bool, dio: bool) -> Qcow2IoSync {
        let file = OpenOptions::new()
            .read(true)
            .write(!ro)
            .open(path.clone())
            .unwrap();

        if dio {
            unsafe {
                libc::fcntl(file.as_raw_fd(), libc::F_SETFL, libc::O_DIRECT);
            }
        }

        let fd = file.as_raw_fd();
        Qcow2IoSync {
            _file: RefCell::new(file),
            fd,
        }
    }
}

#[rustversion::attr(before(1.75), async_trait(?Send))]
impl Qcow2IoOps for Qcow2IoSync {
    async fn read_to(&self, offset: u64, buf: &mut [u8]) -> Qcow2Result<usize> {
        let res = unsafe {
            libc::pread(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                offset as i64,
            )
        };

        if res < 0 {
            return Err("libc::pread failed".into());
        } else {
            if (res as usize) != buf.len() {
                eprintln!(
                    "short read: ask for {}, read {}, offset {:x}",
                    buf.len(),
                    res,
                    offset
                );
            }
            return Ok(res as usize);
        }
    }

    async fn write_from(&self, offset: u64, buf: &[u8]) -> Qcow2Result<()> {
        let res = unsafe {
            libc::pwrite(
                self.fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                offset as i64,
            )
        };

        if res < 0 {
            return Err("libc::pwrite failed".into());
        } else {
            if (res as usize) != buf.len() {
                eprintln!(
                    "short write: ask for {}, read {}, offset {:x}",
                    buf.len(),
                    res,
                    offset
                );
            }
            return Ok(());
        }
    }

    async fn discard_range(&self, offset: u64, len: usize, _flags: i32) -> Qcow2Result<()> {
        let res = fallocate(
            self.fd,
            FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_KEEP_SIZE,
            offset as i64,
            len as i64,
        )?;

        Ok(res)
    }

    async fn fsync(&self, _offset: u64, _len: usize, _flags: i32) -> Qcow2Result<()> {
        let res = nix::unistd::fsync(self.fd)?;

        Ok(res)
    }
}
