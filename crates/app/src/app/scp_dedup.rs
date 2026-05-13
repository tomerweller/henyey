//! In-flight SCP envelope dedup cache with RAII auto-expiring entries.
//!
//! Mirrors stellar-core's `mScheduledMessages`
//! (`OverlayManagerImpl.cpp:326, 1190-1212`). Uses a
//! [`RandomEvictionCache`](henyey_crypto::RandomEvictionCache) with
//! `Weak<()>` values that auto-expire when the associated `Arc<()>` token
//! (stored in [`PipelinedIntake`](henyey_herder::scp_verify::PipelinedIntake))
//! is dropped. No explicit removal API is needed — entry lifetime is tied
//! to the intake's lifetime.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use henyey_common::Hash256;
use henyey_crypto::RandomEvictionCache;

/// Capacity matching stellar-core's `mScheduledMessages(100000)`
/// (OverlayManagerImpl.cpp:326).
const CAPACITY: usize = 100_000;

/// In-flight SCP envelope scheduling cache with auto-expiring entries.
///
/// Entries are inserted eagerly on `check_and_insert` (matching stellar-core's
/// `checkScheduledAndCache` which calls `mScheduledMessages.put()` immediately).
/// Each entry stores a `Weak<()>`; the corresponding `Arc<()>` lives in
/// `PipelinedIntake::inflight_token`. When the intake is consumed or dropped
/// (success, channel closure, panic), the `Arc` drops, the `Weak` expires,
/// and subsequent lookups treat the entry as absent.
pub(crate) struct ScpScheduledCache {
    cache: Mutex<RandomEvictionCache<Hash256, Weak<()>>>,
    dedup_count: AtomicU64,
}

impl ScpScheduledCache {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(RandomEvictionCache::new(CAPACITY)),
            dedup_count: AtomicU64::new(0),
        }
    }

    /// Check whether `hash` is in-flight and insert if not.
    ///
    /// Returns `None` if the hash is already in-flight (duplicate) — the
    /// caller should drop the envelope. Increments the dedup counter.
    ///
    /// Returns `Some(Arc<()>)` if the hash is new or its previous token
    /// expired. The caller must store this `Arc` in `PipelinedIntake::inflight_token`
    /// to keep the cache entry alive for the duration of processing.
    ///
    /// Matches stellar-core's `checkScheduledAndCache`
    /// (OverlayManagerImpl.cpp:1190-1212): eager insert, weak-ref auto-expire.
    pub fn check_and_insert(&self, hash: Hash256) -> Option<Arc<()>> {
        let mut cache = self.cache.lock().unwrap();

        // Check for existing live entry.
        if let Some(weak) = cache.get(&hash) {
            if weak.upgrade().is_some() {
                // Token still alive → duplicate. get() already refreshed
                // generation (recency), matching stellar-core's behavior.
                drop(cache);
                self.dedup_count.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            // Weak expired → tombstone. Remove before re-inserting.
            cache.remove(&hash);
        }

        // Insert new entry with fresh Arc/Weak pair.
        let arc = Arc::new(());
        let weak = Arc::downgrade(&arc);
        cache.put(hash, weak);
        Some(arc)
    }

    /// Number of envelopes rejected by the dedup check since startup.
    pub fn dedup_count(&self) -> u64 {
        self.dedup_count.load(Ordering::Relaxed)
    }

    /// Number of entries in the cache (includes expired tombstones not yet
    /// evicted or cleaned on access).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }
}

// ───────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u8) -> Hash256 {
        let mut h = [0u8; 32];
        h[0] = n;
        Hash256(h)
    }

    #[test]
    fn test_new_entry_returns_token() {
        let cache = ScpScheduledCache::new();
        let token = cache.check_and_insert(hash(1));
        assert!(token.is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_duplicate_rejected_while_token_alive() {
        let cache = ScpScheduledCache::new();
        let _token = cache.check_and_insert(hash(1)).unwrap();

        // Same hash while token alive → rejected.
        assert!(cache.check_and_insert(hash(1)).is_none());
        assert_eq!(cache.dedup_count(), 1);
    }

    #[test]
    fn test_token_drop_allows_reinsert() {
        let cache = ScpScheduledCache::new();
        let token = cache.check_and_insert(hash(1)).unwrap();

        // Drop the token (simulates intake consumed/dropped).
        drop(token);

        // Same hash now passes — entry expired.
        let token2 = cache.check_and_insert(hash(1));
        assert!(token2.is_some());
    }

    #[test]
    fn test_prefilter_reject_no_poison() {
        let cache = ScpScheduledCache::new();
        // check_and_insert inserts eagerly, but if we drop the token
        // immediately (pre-filter reject), the entry expires.
        let token = cache.check_and_insert(hash(1)).unwrap();
        drop(token);

        // Not poisoned — next check passes.
        assert!(cache.check_and_insert(hash(1)).is_some());
    }

    #[test]
    fn test_distinct_hashes_independent() {
        let cache = ScpScheduledCache::new();
        let _t1 = cache.check_and_insert(hash(1)).unwrap();
        let _t2 = cache.check_and_insert(hash(2)).unwrap();

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.dedup_count(), 0);
    }

    #[test]
    fn test_multiple_duplicates_counted() {
        let cache = ScpScheduledCache::new();
        let _token = cache.check_and_insert(hash(1)).unwrap();

        for _ in 0..5 {
            assert!(cache.check_and_insert(hash(1)).is_none());
        }
        assert_eq!(cache.dedup_count(), 5);
    }

    #[test]
    fn test_capacity_eviction() {
        // Use a small-capacity cache to test eviction.
        let cache = ScpScheduledCache {
            cache: Mutex::new(RandomEvictionCache::new(5)),
            dedup_count: AtomicU64::new(0),
        };

        // Insert 6 entries (exceeds capacity of 5).
        let mut tokens = Vec::new();
        for i in 0..6u8 {
            tokens.push(cache.check_and_insert(hash(i)).unwrap());
        }

        // One entry was evicted.
        assert_eq!(cache.len(), 5);
    }

    #[test]
    fn test_expired_tombstone_cleaned_on_access() {
        let cache = ScpScheduledCache::new();
        let token = cache.check_and_insert(hash(1)).unwrap();
        assert_eq!(cache.len(), 1);

        // Drop token — entry becomes a tombstone.
        drop(token);

        // Re-check same hash — tombstone is cleaned, new entry inserted.
        let _token2 = cache.check_and_insert(hash(1)).unwrap();
        // len() is 1 (tombstone was removed, fresh entry inserted).
        assert_eq!(cache.len(), 1);
    }
}
