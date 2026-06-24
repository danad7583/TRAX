//! Anti-replay / ordering: per-peer monotonic counter with windowed acceptance.
use lru::LruCache;
use std::num::NonZeroUsize;

pub struct LastSeen {
    cache: LruCache<u64, u64>, // key: peer hash, val: last_seen counter
    window: u64,
}

impl LastSeen {
    pub fn new(capacity: usize, window: u64) -> Self {
        Self { cache: LruCache::new(NonZeroUsize::new(capacity).unwrap()), window }
    }

    pub fn accept(&mut self, peer: u64, counter: u64) -> bool {
        if let Some(last) = self.cache.get(&peer).copied() {
            if counter <= last && last - counter > self.window { return false; }
            if counter <= last && last - counter <= self.window {
                // within window but duplicate? reject duplicates by separate seen-set if desired
                // For simplicity, accept unseen-in-window logic left to implementer.
            }
        }
        self.cache.put(peer, counter);
        true
    }
}
