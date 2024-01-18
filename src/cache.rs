use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

pub(crate) struct AsyncLruCacheEntryInner<V> {
    value: V,
    lru: AtomicUsize,
    dirty: AtomicBool,
}

pub(crate) type AsyncLruCacheEntry<V> = Arc<AsyncLruCacheEntryInner<V>>;

/// LRU cache
///
/// Use lru_timer(counter) to simulate use timestamp, this way should
/// be good for single context.
pub(crate) struct AsyncLruCache<K: Clone + PartialEq + Eq + Hash + std::fmt::Debug, V> {
    rmap: std::sync::RwLock<HashMap<K, AsyncLruCacheEntry<V>>>,
    wmap: std::sync::Mutex<HashMap<K, AsyncLruCacheEntry<V>>>,
    limit: usize,
    lru_timer: AtomicUsize,
}

impl<K: Clone + PartialEq + Eq + Hash + std::fmt::Debug + std::cmp::PartialOrd, V>
    AsyncLruCache<K, V>
{
    pub(crate) fn new(size: usize) -> Self {
        AsyncLruCache {
            rmap: Default::default(),
            wmap: Default::default(),
            limit: size,
            lru_timer: AtomicUsize::new(0),
        }
    }

    pub(crate) fn put_into_wmap_with<F: FnOnce() -> V>(
        &self,
        key: K,
        f: F,
    ) -> AsyncLruCacheEntry<V> {
        let mut w = self.wmap.lock().unwrap();
        let r = self.rmap.read().unwrap();

        let entry = if !r.contains_key(&key) {
            let entry = Arc::new(AsyncLruCacheEntryInner::new(f()));
            w.entry(key.clone()).or_insert(entry);
            w.get(&key).unwrap()
        } else {
            r.get(&key).unwrap()
        };

        Arc::clone(entry)
    }

    /// Flush key/value pairs from wmap to rmap
    pub(crate) fn commit_wmap(&self) -> Option<Vec<(K, AsyncLruCacheEntry<V>)>> {
        let mut w = self.wmap.lock().unwrap();
        let mut r = self.rmap.write().unwrap();
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

        if vec.is_empty() {
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
    pub(crate) fn get(&self, key: K) -> Option<AsyncLruCacheEntry<V>> {
        let map = self.rmap.read().unwrap();
        if let Some(entry) = map.get(&key) {
            self.update_lru(entry);
            Some(Arc::clone(entry))
        } else {
            None
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        let map = self.rmap.read().unwrap();

        map.is_empty()
    }

    pub(crate) fn shrink(&self) {
        let mut map = self.rmap.write().unwrap();
        let mut k_vec = Vec::new();

        for (key, value) in map.iter() {
            let k = key.clone();
            if Arc::strong_count(value) <= 1 && !value.is_dirty() {
                k_vec.push(k);
            }
        }
        for k in k_vec {
            map.remove(&k);
        }
    }

    pub(crate) fn get_dirty_entries(&self, start: K, end: K) -> Vec<(K, AsyncLruCacheEntry<V>)> {
        let map = self.rmap.read().unwrap();
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
        map: &mut std::sync::RwLockWriteGuard<HashMap<K, AsyncLruCacheEntry<V>>>,
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
    pub(crate) fn new(val: V) -> Self {
        AsyncLruCacheEntryInner {
            value: val,
            lru: AtomicUsize::new(0),
            dirty: AtomicBool::new(false),
        }
    }

    #[inline(always)]
    pub(crate) fn value(&self) -> &V {
        &self.value
    }

    #[inline(always)]
    pub(crate) fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Relaxed)
    }

    pub(crate) fn set_dirty(&self, val: bool) {
        self.dirty.store(val, Ordering::Relaxed)
    }
}

impl<V> Drop for AsyncLruCacheEntryInner<V> {
    fn drop(&mut self) {
        assert!(!self.is_dirty());
    }
}
