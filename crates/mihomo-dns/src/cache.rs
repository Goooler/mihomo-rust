use lru::LruCache;
use parking_lot::Mutex;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

struct CacheEntry {
    ips: Vec<IpAddr>,
    expire_at: Instant,
}

pub struct DnsCache {
    cache: Mutex<LruCache<String, CacheEntry>>,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1024).unwrap()),
            )),
        }
    }

    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let mut cache = self.cache.lock();
        if let Some(entry) = cache.get(domain) {
            if entry.expire_at > Instant::now() {
                return Some(entry.ips.clone());
            }
            // Expired, but don't remove here to avoid borrow issues
        }
        cache.pop(domain);
        None
    }

    pub fn put(&self, domain: &str, ips: Vec<IpAddr>, ttl: Duration) {
        let entry = CacheEntry {
            ips,
            expire_at: Instant::now() + ttl,
        };
        self.cache.lock().put(domain.to_string(), entry);
    }

    pub fn clear(&self) {
        self.cache.lock().clear();
    }
}
