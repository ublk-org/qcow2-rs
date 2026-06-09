use crate::error::Qcow2Result;
#[rustversion::before(1.75)]
use async_trait::async_trait;

pub struct Qcow2OpsFlags {}

impl Qcow2OpsFlags {
    pub const FALLOCATE_ZERO_RANGE: u32 = 1_u32 << 0;
}

/// Map qcow2 fallocate flags to a host hole-punch and issue the
/// (synchronous) `nix` fallocate syscall. Shared by every backend whose
/// underlying fd supports `FALLOC_FL_PUNCH_HOLE`; `tokio-uring` has no
/// async fallocate of its own, so it also goes through this path.
#[cfg(target_os = "linux")]
pub(crate) fn linux_punch_hole(fd: i32, offset: u64, len: usize, _flags: u32) -> Qcow2Result<()> {
    use nix::fcntl::{fallocate, FallocateFlags};

    // PUNCH_HOLE deallocates the range (shrinking the host file's block
    // count) and makes it read back as zero, covering both the discard and
    // FALLOCATE_ZERO_RANGE contracts; it must be ORed with KEEP_SIZE so the
    // logical file size is preserved. This matches the macOS backend, which
    // always issues F_PUNCHHOLE regardless of flags. Combining PUNCH_HOLE
    // with ZERO_RANGE is rejected by the kernel, and ZERO_RANGE alone does
    // not free blocks on every filesystem, so neither reclaims space.
    let f = FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_KEEP_SIZE;

    fallocate(fd, f, offset as libc::off_t, len as libc::off_t)?;
    Ok(())
}

/// A freshly allocated, zero-filled IO buffer used by the discard fallback
/// path on platforms/fds without hole-punch support.
#[cfg(not(target_os = "linux"))]
pub(crate) fn zeroed_io_buf(len: usize) -> crate::helpers::Qcow2IoBuf<u8> {
    let mut data = crate::helpers::Qcow2IoBuf::<u8>::new(len);
    data.zero_buf();
    data
}

/// Enable `O_DIRECT` on `fd`. A no-op on macOS, which has no `O_DIRECT`.
#[cfg(not(target_os = "windows"))]
pub(crate) fn set_direct_io(fd: i32) {
    #[cfg(not(target_os = "macos"))]
    // SAFETY: `F_SETFL` with `O_DIRECT` only updates the fd's status flags.
    unsafe {
        libc::fcntl(fd, libc::F_SETFL, libc::O_DIRECT);
    }
    #[cfg(target_os = "macos")]
    let _ = fd;
}

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
