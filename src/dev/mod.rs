use crate::cache::AsyncLruCache;
use crate::error::Qcow2Result;
use crate::meta::{L1Table, L2Table, Qcow2Header, RefBlock, RefTable};
use crate::ops::*;
use async_recursion::async_recursion;
use futures_locks::{Mutex as AsyncMutex, RwLock as AsyncRwLock};
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

mod alloc;
mod cache;
mod check;
mod discard;
mod info;
mod read;
mod write;
use self::alloc::HostCluster;
pub use self::info::{Qcow2DevParams, Qcow2Info};

type L2TableHandle = AsyncRwLock<L2Table>;

pub struct Qcow2Dev<T> {
    path: PathBuf,
    header: AsyncRwLock<Qcow2Header>,

    // mapping table
    l1table: AsyncRwLock<L1Table>,
    l2cache: AsyncLruCache<usize, L2TableHandle>,

    // splices share single cluster, so before flushing any cluster
    // which is used for slices, discard this cluster first, then any
    // new slice stored in this cluster can loaded with correct data
    //
    // true value means this cluster isn't discarded yet, and false
    // means the cluster has been discarded
    //
    // used by both mapping table and allocator
    // false: not discarded, true: being discarded
    new_cluster: AsyncRwLock<HashMap<u64, AsyncRwLock<bool>>>,

    // allocator
    free_cluster_offset: AtomicU64,
    reftable: AsyncRwLock<RefTable>,
    refblock_cache: AsyncLruCache<usize, AsyncRwLock<RefBlock>>,

    // set in case that any dirty meta is made
    need_flush: AtomicBool,
    flush_lock: AsyncMutex<()>,

    file: T,
    backing_file: Option<Box<Qcow2Dev<T>>>,
    pub info: Qcow2Info,
}

impl<T> std::fmt::Debug for Qcow2Dev<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = write!(f, "Image path {:?}\ninfo {:?}\n", &self.path, &self.info);
        let _ = match &self.backing_file {
            Some(b) => write!(f, "backing {b:?}"),
            _ => write!(f, "backing None"),
        };
        writeln!(f)
    }
}

impl<T: Qcow2IoOps> Qcow2Dev<T> {
    pub fn new(
        path: &Path,
        header: Qcow2Header,
        params: &Qcow2DevParams,
        file: T,
    ) -> Qcow2Result<Self> {
        let h = &header;
        let bs_shift = params.get_bs_bits();

        debug_assert!((9..=12).contains(&bs_shift));
        let info = Qcow2Info::new(h, params)?;

        let l2_cache_cnt = info.l2_cache_cnt as usize;
        let rb_cache_cnt = info.rb_cache_cnt as usize;
        let l1_size = Qcow2Info::__max_l1_size(info.max_l1_entries(), 1 << bs_shift);
        let rt_size = h.reftable_clusters() << h.cluster_bits();
        let l1_entries = h.l1_table_entries() as u32;

        log::info!(
            "l2 slice cache(bits: {} count {}), rb cache(bits: {} count {})",
            info.l2_slice_bits,
            l2_cache_cnt,
            info.rb_slice_bits,
            rb_cache_cnt,
        );

        let dev = Qcow2Dev {
            path: path.to_path_buf(),
            header: AsyncRwLock::new(header),
            file,
            backing_file: None,
            info,
            l1table: AsyncRwLock::new(L1Table::new(None, l1_size, l1_entries, bs_shift)),
            l2cache: AsyncLruCache::new(l2_cache_cnt),
            free_cluster_offset: AtomicU64::new(0),
            reftable: AsyncRwLock::new(RefTable::new(None, rt_size, bs_shift)),
            refblock_cache: AsyncLruCache::new(rb_cache_cnt),
            new_cluster: AsyncRwLock::new(Default::default()),
            need_flush: AtomicBool::new(false),
            flush_lock: AsyncMutex::new(()),
        };

        Ok(dev)
    }

    async fn cluster_is_new(&self, cluster: u64) -> bool {
        let map = self.new_cluster.read().await;

        map.contains_key(&cluster)
    }

    async fn mark_new_cluster(&self, cluster: u64) {
        let mut map = self.new_cluster.write().await;

        map.insert(cluster, AsyncRwLock::new(false));
    }

    async fn clear_new_cluster(&self, cluster: u64) {
        let mut map = self.new_cluster.write().await;

        map.remove(&cluster);
    }

    /// Setup the backing Qcow2 device
    pub fn set_backing_dev(&mut self, back: Box<Qcow2Dev<T>>) {
        self.backing_file = Some(back);
    }

    #[inline(always)]
    fn mark_need_flush(&self, val: bool) {
        self.need_flush.store(val, Ordering::Relaxed);
    }

    /// Helper for checking if there is dirty meta data which needs
    /// to be flushed to disk
    #[inline]
    pub fn need_flush_meta(&self) -> bool {
        self.need_flush.load(Ordering::Relaxed)
    }

    /// Prepare everything(loading l1/refcount table) for handling any qcow2 IO
    #[async_recursion(?Send)]
    pub async fn qcow2_prep_io(&self) -> Qcow2Result<()> {
        if let Some(back) = &self.backing_file {
            back.qcow2_prep_io().await?
        };
        self.__qcow2_prep_io().await
    }
}

#[cfg(test)]
mod tests {
    use crate::dev::*;
    use crate::helpers::Qcow2IoBuf;
    use crate::tokio_io::Qcow2IoTokio;
    use crate::utils::make_temp_qcow2_img;
    use tokio::runtime::Runtime;

    #[test]
    fn test_qcow2_dev_io() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let size = 64_u64 << 20;
            let img_file = make_temp_qcow2_img(size, 16, 4);
            let io = Qcow2IoTokio::new(img_file.path(), true, false).await;
            let mut buf = Qcow2IoBuf::<u8>::new(4096);
            let _ = io.read_to(0, &mut buf).await;
            let header = Qcow2Header::from_buf(&buf).unwrap();

            assert!(header.size() == size);
            assert!(header.cluster_bits() == 16);
        });
    }
}
