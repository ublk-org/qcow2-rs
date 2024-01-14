use crate::error::Qcow2Result;
#[rustversion::before(1.75)]
use async_trait::async_trait;

/// How read/write/discard are implemented, so that qcow2-rs can be
/// used with multiple io engine.
///
/// these methods are called for reading data from image, writing data
/// to image, and discarding range.
#[rustversion::attr(before(1.75), async_trait(?Send))]
#[rustversion::attr(since(1.75), allow(async_fn_in_trait))]
pub trait Qcow2IoOps {
    async fn read_to(&self, offset: u64, buf: &mut [u8]) -> Qcow2Result<usize>;
    async fn write_from(&self, offset: u64, buf: &[u8]) -> Qcow2Result<()>;
    async fn fallocate(&self, offset: u64, len: usize, flags: u32) -> Qcow2Result<()>;
    async fn fsync(&self, offset: u64, len: usize, flags: u32) -> Qcow2Result<()>;
}
