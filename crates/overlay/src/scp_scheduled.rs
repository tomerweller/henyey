//! Overlay-side SCP envelope in-flight scheduling cache.
//!
//! Mirrors stellar-core's `mScheduledMessages`
//! (OverlayManagerImpl.h:223, OverlayManagerImpl.cpp:1190-1212).
//!
//! This cache is **separate from FloodGate** — FloodGate's `RelayRecord`
//! is deliberately private and not used as a drop signal (c6118f2c / #2317
//! safety invariant). The scheduling cache only suppresses duplicate SCP
//! envelopes while the same message is in-flight between the peer loop
//! and the event loop.
//!
//! # Lifecycle
//!
//! 1. Peer loop calls [`ScpScheduledCache::check_and_insert`] with the
//!    full `StellarMessage` blake2 hash (same as [`compute_message_hash`]).
//! 2. If the hash is new, it returns `true` and the message proceeds.
//! 3. If the hash is already present, it returns `false` — duplicate.
//! 4. The event loop calls [`ScpScheduledCache::remove`] after processing.
//!
//! [`compute_message_hash`]: crate::flood::compute_message_hash

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

use henyey_common::Hash256;
use parking_lot::Mutex;

/// Default capacity for the scheduling cache.
///
/// Well above the steady-state window (24 validators × ~10 SCP messages
/// per slot) but prevents unbounded growth under pathological conditions.
const DEFAULT_CAPACITY: usize = 10_000;

/// In-flight SCP envelope scheduling cache.
///
/// Tracks `StellarMessage` blake2 hashes of SCP envelopes that have been
/// dispatched to the SCP subscriber channel but not yet consumed by the
/// event loop. Duplicate envelopes are rejected at the overlay layer,
/// avoiding unnecessary channel sends and event-loop processing.
pub struct ScpScheduledCache {
    cache: Mutex<HashSet<Hash256>>,
    capacity: usize,
    /// Number of duplicates suppressed since startup.
    dedup_count: AtomicU64,
}

impl ScpScheduledCache {
    /// Create a new cache with the default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Create a new cache with a custom capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            cache: Mutex::new(HashSet::with_capacity(capacity.min(1024))),
            capacity,
            dedup_count: AtomicU64::new(0),
        }
    }

    /// Atomically check whether `hash` is in the cache and insert it if not.
    ///
    /// Returns `true` if the hash was newly inserted (message should proceed).
    /// Returns `false` if the hash was already present (duplicate — drop).
    ///
    /// When the cache is at capacity, the oldest entry is not evicted —
    /// the new entry is silently accepted to avoid stalling. This matches
    /// the "bounded but best-effort" semantics: the cache is a performance
    /// optimization, not a correctness mechanism.
    pub fn check_and_insert(&self, hash: Hash256) -> bool {
        let mut guard = self.cache.lock();
        if guard.contains(&hash) {
            self.dedup_count.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        // Accept even at capacity — see doc comment.
        guard.insert(hash);
        // Prune if significantly over capacity (2× threshold) to prevent
        // unbounded growth. This is a coarse heuristic; most entries will
        // be removed by explicit `remove` calls.
        if guard.len() > self.capacity * 2 {
            // Can't do LRU with HashSet, so clear and re-insert the
            // current entry. This is a pathological case (e.g., event
            // loop not consuming) and the worst outcome is a few
            // duplicates slipping through.
            tracing::warn!(
                cache_size = guard.len(),
                capacity = self.capacity,
                "SCP scheduling cache exceeded 2× capacity, clearing"
            );
            guard.clear();
            guard.insert(hash);
        }
        true
    }

    /// Remove a hash from the cache.
    ///
    /// Called by the event loop after processing an SCP envelope.
    pub fn remove(&self, hash: &Hash256) {
        self.cache.lock().remove(hash);
    }

    /// Remove all entries from the cache.
    ///
    /// Called during graceful shutdown.
    pub fn clear(&self) {
        self.cache.lock().clear();
    }

    /// Number of duplicates suppressed since startup.
    pub fn dedup_count(&self) -> u64 {
        self.dedup_count.load(Ordering::Relaxed)
    }

    /// Current number of entries in the cache.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.cache.lock().len()
    }
}

impl Default for ScpScheduledCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u8) -> Hash256 {
        let mut h = [0u8; 32];
        h[0] = n;
        Hash256(h)
    }

    #[test]
    fn test_check_and_insert_new_returns_true() {
        let cache = ScpScheduledCache::new();
        assert!(cache.check_and_insert(hash(1)));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_check_and_insert_duplicate_returns_false() {
        let cache = ScpScheduledCache::new();
        assert!(cache.check_and_insert(hash(1)));
        assert!(!cache.check_and_insert(hash(1)));
        assert_eq!(cache.dedup_count(), 1);
    }

    #[test]
    fn test_remove_allows_reinsert() {
        let cache = ScpScheduledCache::new();
        assert!(cache.check_and_insert(hash(1)));
        cache.remove(&hash(1));
        assert_eq!(cache.len(), 0);
        assert!(cache.check_and_insert(hash(1)));
    }

    #[test]
    fn test_clear_empties_cache() {
        let cache = ScpScheduledCache::new();
        assert!(cache.check_and_insert(hash(1)));
        assert!(cache.check_and_insert(hash(2)));
        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.check_and_insert(hash(1)));
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        let cache = Arc::new(ScpScheduledCache::new());
        let h = hash(42);

        let mut handles = vec![];
        for _ in 0..10 {
            let cache = Arc::clone(&cache);
            handles.push(std::thread::spawn(move || cache.check_and_insert(h)));
        }

        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let inserted_count = results.iter().filter(|&&r| r).count();
        assert_eq!(inserted_count, 1, "exactly one thread should insert");
        assert_eq!(cache.dedup_count(), 9, "9 duplicates suppressed");
    }

    #[test]
    fn test_capacity_overflow_clears() {
        let cache = ScpScheduledCache::with_capacity(5);
        // Insert 11 entries (> 2× capacity of 5)
        for i in 0..11 {
            cache.check_and_insert(hash(i));
        }
        // Cache was cleared when it exceeded 2×5=10
        assert_eq!(
            cache.len(),
            1,
            "cache cleared at overflow, last entry remains"
        );
    }
}
