use futures_locks::{
    Mutex as AsyncMutex, RwLock as AsyncRwLock, RwLockWriteGuard as LockWriteGuard,
};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

pub struct AsyncLruCacheEntryInner<V> {
    value: V,
    lru: AtomicUsize,
    dirty: AtomicBool,
}

pub type AsyncLruCacheEntry<V> = Arc<AsyncLruCacheEntryInner<V>>;

/// LRU cache
///
/// Use lru_timer(counter) to simulate use timestamp, this way should
/// be good for single context.
pub struct AsyncLruCache<K: Clone + PartialEq + Eq + Hash + std::fmt::Debug, V> {
    rmap: AsyncRwLock<HashMap<K, AsyncLruCacheEntry<V>>>,
    wmap: AsyncMutex<HashMap<K, AsyncLruCacheEntry<V>>>,
    limit: usize,
    lru_timer: AtomicUsize,
}

impl<K: Clone + PartialEq + Eq + Hash + std::fmt::Debug + std::cmp::PartialOrd, V>
    AsyncLruCache<K, V>
{
    pub fn new(size: usize) -> Self {
        AsyncLruCache {
            rmap: Default::default(),
            wmap: Default::default(),
            limit: size,
            lru_timer: AtomicUsize::new(0),
        }
    }

    /// todo: replace val with closure to build value
    pub async fn put_into_wmap_with<F: FnOnce() -> V>(&self, key: K, f: F) {
        let mut w = self.wmap.lock().await;

        let entry = Arc::new(AsyncLruCacheEntryInner::new(f()));
        w.entry(key).or_insert(entry);
    }

    pub async fn get_from_wmap(&self, key: K) -> Option<AsyncLruCacheEntry<V>> {
        let w = self.wmap.lock().await;

        if let Some(entry) = w.get(&key) {
            Some(Arc::clone(entry))
        } else {
            None
        }
    }

    /// Flush key/value pairs from wmap to rmap
    pub async fn commit_wmap(&self) -> Option<Vec<(K, AsyncLruCacheEntry<V>)>> {
        let mut w = self.wmap.lock().await;
        let mut r = self.rmap.write().await;
        let mut vec = Vec::new();

        let wlen = w.len();

        while r.len() + wlen > self.limit {
            let res = self.__pop_lru(&mut r);

            if let Some(val) = res {
                log::warn!(
                    "lru cache eviction, type {} dirty {}",
                    crate::helpers::qcow2_type_of(&val.1),
                    val.1.is_dirty()
                );
                if val.1.is_dirty() {
                    vec.push(val);
                }
            }
        }

        for (key, value) in w.drain() {
            r.insert(key, value);
        }

        if vec.len() == 0 {
            None
        } else {
            log::debug!(
                "cache evict: wlen {} cache {}, limit {}",
                wlen,
                r.len(),
                self.limit,
            );

            Some(vec)
        }
    }

    #[inline(always)]
    fn update_lru(&self, entry: &AsyncLruCacheEntryInner<V>) {
        let curr = self.lru_timer.load(Ordering::Relaxed);

        entry.lru.store(curr + 1, Ordering::Relaxed);

        // let's live with concurrent store conflict
        self.lru_timer.store(curr + 1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub async fn get(&self, key: K) -> Option<AsyncLruCacheEntry<V>> {
        let map = self.rmap.read().await;
        if let Some(entry) = map.get(&key) {
            self.update_lru(&entry);
            Some(Arc::clone(entry))
        } else {
            None
        }
    }

    pub async fn get_dirty_entries(&self, start: K, end: K) -> Vec<(K, AsyncLruCacheEntry<V>)> {
        let map = self.rmap.read().await;
        let mut vec = Vec::new();

        for (key, value) in map.iter() {
            let k = key.clone();
            if k >= start && k < end && value.is_dirty() {
                vec.push((k, Arc::clone(value)));
            }
        }
        vec
    }

    fn __pop_lru(
        &self,
        map: &mut LockWriteGuard<HashMap<K, AsyncLruCacheEntry<V>>>,
    ) -> Option<(K, AsyncLruCacheEntry<V>)> {
        let (_, mut key_out) =
            map.iter()
                .fold((usize::MAX, None), |(minl, key_out), (key, entry)| {
                    // Cannot drop entries that are in use
                    if Arc::strong_count(entry) > 1 {
                        (minl, key_out)
                    } else {
                        let l = entry.lru.load(Ordering::Relaxed);
                        if l < minl {
                            (l, Some(key.clone()))
                        } else {
                            (minl, key_out)
                        }
                    }
                });

        if key_out.is_none() {
            // it is safe to remove cache entry with active user, since the
            // user holds the reference
            (_, key_out) = map
                .iter()
                .fold((usize::MAX, None), |(min, key_out), (key, entry)| {
                    let l = entry.lru.load(Ordering::Relaxed);
                    if l < min {
                        (l, Some(key.clone()))
                    } else {
                        (min, key_out)
                    }
                });
        }

        if key_out.is_none() {
            None
        } else {
            let key = key_out.take().unwrap();
            let entry = map.remove(&key).unwrap();
            Some((key.clone(), entry))
        }
    }
}

impl<V> AsyncLruCacheEntryInner<V> {
    pub fn new(val: V) -> Self {
        AsyncLruCacheEntryInner {
            value: val,
            lru: AtomicUsize::new(0),
            dirty: AtomicBool::new(false),
        }
    }

    #[inline(always)]
    pub fn value(&self) -> &V {
        &self.value
    }

    #[inline(always)]
    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Relaxed)
    }

    pub fn set_dirty(&self, val: bool) {
        self.dirty.store(val, Ordering::Relaxed)
    }
}

impl<V> Drop for AsyncLruCacheEntryInner<V> {
    fn drop(&mut self) {
        assert!(!self.is_dirty());
    }
}
