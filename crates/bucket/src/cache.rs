//! Random eviction cache for frequently-accessed bucket entries.
//!
//! This module provides an LRU-style cache for bucket entries that are
//! frequently accessed during transaction validation. The cache is particularly
//! useful for account entries, which are accessed repeatedly.
//!
//! # Design
//!
//! The cache uses a simple LRU eviction strategy with random sampling to
//! maintain bounded memory usage. Only certain entry types (primarily accounts)
//! are cached, as they are the most frequently accessed.
//!
//! # Thread Safety
//!
//! The cache uses a `Mutex` for thread-safe access. All operations are
//! synchronized to prevent data races.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use stellar_xdr::curr::{LedgerEntry, LedgerEntryData, LedgerKey};

use crate::entry::BucketEntry;

/// Default maximum cache size in bytes (100 MB).
pub const DEFAULT_MAX_CACHE_BYTES: usize = 100 * 1024 * 1024;

/// Default maximum number of entries in the cache.
pub const DEFAULT_MAX_CACHE_ENTRIES: usize = 100_000;

/// Minimum bucket list size (in entries) before cache is initialized.
/// Below this threshold, the bucket list is small enough that caching
/// provides minimal benefit.
pub const MIN_BUCKET_LIST_SIZE_FOR_CACHE: usize = 1_000_000;

// ============================================================================
// Cache Entry
// ============================================================================

/// A cached bucket entry with access metadata.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The cached entry.
    entry: Arc<BucketEntry>,
    /// Estimated size in bytes.
    size_bytes: usize,
    /// Access counter for LRU tracking.
    access_count: u64,
}

impl CacheEntry {
    /// Creates a new cache entry.
    fn new(entry: BucketEntry, access_count: u64) -> Self {
        let size_bytes = Self::estimate_size(&entry);
        Self {
            entry: Arc::new(entry),
            size_bytes,
            access_count,
        }
    }

    /// Estimates the memory size of a bucket entry.
    fn estimate_size(entry: &BucketEntry) -> usize {
        // Base size of the enum variant
        let base_size = std::mem::size_of::<BucketEntry>();

        // Add estimated size of contained data
        let data_size = match entry {
            BucketEntry::Live(e) | BucketEntry::Init(e) => Self::estimate_ledger_entry_size(e),
            BucketEntry::Dead(_) => 64, // LedgerKey is relatively small
            BucketEntry::Metadata(_) => 32,
        };

        base_size + data_size
    }

    /// Estimates the size of a ledger entry.
    fn estimate_ledger_entry_size(entry: &LedgerEntry) -> usize {
        match &entry.data {
            LedgerEntryData::Account(acc) => {
                // Account entry: ~200 bytes base + signers
                200 + acc.signers.len() * 72
            }
            LedgerEntryData::Trustline(_) => 150,
            LedgerEntryData::Offer(_) => 200,
            LedgerEntryData::Data(data) => 100 + data.data_value.len(),
            LedgerEntryData::ClaimableBalance(cb) => 200 + cb.claimants.len() * 100,
            LedgerEntryData::LiquidityPool(_) => 300,
            LedgerEntryData::ContractData(_) => {
                // Contract data can be large - use a conservative estimate
                // since ScVal doesn't easily report its size
                500
            }
            LedgerEntryData::ContractCode(cc) => {
                // Contract code is often large
                100 + cc.code.len()
            }
            LedgerEntryData::ConfigSetting(_) => 500,
            LedgerEntryData::Ttl(_) => 50,
        }
    }
}

// ============================================================================
// Random Eviction Cache
// ============================================================================

/// An LRU cache with random eviction for bucket entries.
///
/// This cache stores frequently-accessed bucket entries to reduce disk I/O
/// during transaction validation. It uses a combination of LRU tracking and
/// random sampling for eviction decisions.
///
/// # Entry Type Filtering
///
/// Only certain entry types are cached:
/// - Account entries: Most frequently accessed, cached by default
/// - Other types can be optionally cached via configuration
///
/// # Memory Management
///
/// The cache tracks both entry count and estimated memory usage. Eviction
/// is triggered when either limit is exceeded.
pub struct RandomEvictionCache {
    /// The cache storage, protected by a mutex.
    inner: Mutex<CacheInner>,
    /// Maximum cache size in bytes.
    max_bytes: usize,
    /// Maximum number of entries.
    max_entries: usize,
    /// Current cache size in bytes (atomic for lock-free reads).
    current_bytes: AtomicUsize,
    /// Whether the cache is initialized and active.
    active: AtomicUsize,
}

/// Inner cache state protected by mutex.
struct CacheInner {
    /// Maps keys to cached entries.
    entries: HashMap<LedgerKey, CacheEntry>,
    /// Global access counter for LRU tracking.
    access_counter: u64,
    /// Cache hit count for statistics.
    hits: u64,
    /// Cache miss count for statistics.
    misses: u64,
}

impl RandomEvictionCache {
    /// Creates a new cache with default settings.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_CACHE_BYTES, DEFAULT_MAX_CACHE_ENTRIES)
    }

    /// Creates a new cache with custom limits.
    pub fn with_limits(max_bytes: usize, max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(CacheInner {
                entries: HashMap::new(),
                access_counter: 0,
                hits: 0,
                misses: 0,
            }),
            max_bytes,
            max_entries,
            current_bytes: AtomicUsize::new(0),
            active: AtomicUsize::new(0), // Not active initially
        }
    }

    /// Initializes the cache based on bucket list size.
    ///
    /// The cache is only activated if the bucket list is large enough
    /// to benefit from caching.
    pub fn maybe_initialize(&self, bucket_list_entry_count: usize) {
        if bucket_list_entry_count >= MIN_BUCKET_LIST_SIZE_FOR_CACHE {
            self.active.store(1, Ordering::Release);
        }
    }

    /// Checks if the cache is active.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire) != 0
    }

    /// Activates the cache.
    pub fn activate(&self) {
        self.active.store(1, Ordering::Release);
    }

    /// Deactivates the cache and clears all entries.
    pub fn deactivate(&self) {
        self.active.store(0, Ordering::Release);
        self.clear();
    }

    /// Checks if an entry type should be cached.
    ///
    /// Currently only Account entries are cached, as they are the most
    /// frequently accessed entry type.
    pub fn is_cached_type(key: &LedgerKey) -> bool {
        matches!(key, LedgerKey::Account(_))
    }

    /// Gets an entry from the cache.
    ///
    /// Returns `None` if the entry is not cached or if the cache is not active.
    pub fn get(&self, key: &LedgerKey) -> Option<Arc<BucketEntry>> {
        if !self.is_active() || !Self::is_cached_type(key) {
            return None;
        }

        let mut inner = self.inner.lock();
        inner.access_counter += 1;
        let current_counter = inner.access_counter;

        if let Some(entry) = inner.entries.get_mut(key) {
            entry.access_count = current_counter;
            let result = Arc::clone(&entry.entry);
            inner.hits += 1;
            Some(result)
        } else {
            inner.misses += 1;
            None
        }
    }

    /// Inserts an entry into the cache.
    ///
    /// If the cache is at capacity, random eviction is performed to make room.
    /// Does nothing if the cache is not active or if the entry type should not
    /// be cached.
    pub fn insert(&self, key: LedgerKey, entry: BucketEntry) {
        if !self.is_active() || !Self::is_cached_type(&key) {
            return;
        }

        let mut inner = self.inner.lock();
        inner.access_counter += 1;

        let cache_entry = CacheEntry::new(entry, inner.access_counter);
        let entry_size = cache_entry.size_bytes;

        // Check if we need to evict
        let current_bytes = self.current_bytes.load(Ordering::Relaxed);
        let should_evict =
            inner.entries.len() >= self.max_entries || current_bytes + entry_size > self.max_bytes;

        if should_evict {
            self.evict_entries(&mut inner);
        }

        // Update size tracking
        if let Some(old_entry) = inner.entries.insert(key, cache_entry) {
            // Replace existing entry - adjust size
            let size_diff = entry_size as isize - old_entry.size_bytes as isize;
            if size_diff > 0 {
                self.current_bytes
                    .fetch_add(size_diff as usize, Ordering::Relaxed);
            } else {
                self.current_bytes
                    .fetch_sub((-size_diff) as usize, Ordering::Relaxed);
            }
        } else {
            // New entry
            self.current_bytes.fetch_add(entry_size, Ordering::Relaxed);
        }
    }

    /// Removes an entry from the cache.
    pub fn remove(&self, key: &LedgerKey) {
        if !self.is_active() {
            return;
        }

        let mut inner = self.inner.lock();
        if let Some(entry) = inner.entries.remove(key) {
            self.current_bytes
                .fetch_sub(entry.size_bytes, Ordering::Relaxed);
        }
    }

    /// Clears all entries from the cache.
    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.entries.clear();
        inner.hits = 0;
        inner.misses = 0;
        self.current_bytes.store(0, Ordering::Relaxed);
    }

    /// Evicts entries to make room for new insertions.
    ///
    /// Uses random sampling to find entries to evict, preferring entries
    /// with lower access counts (LRU behavior).
    fn evict_entries(&self, inner: &mut CacheInner) {
        // Target: evict ~10% of entries or enough to free space
        let target_count = std::cmp::max(inner.entries.len() / 10, 1);
        let target_bytes = self.max_bytes / 10;

        let mut to_evict = Vec::with_capacity(target_count);
        let mut bytes_to_free = 0usize;

        // Sample entries and find candidates with low access counts
        // We use a simple strategy: find entries below median access count
        let median_access = if inner.access_counter > 0 {
            inner.access_counter / 2
        } else {
            0
        };

        for (key, entry) in inner.entries.iter() {
            if entry.access_count < median_access {
                to_evict.push(key.clone());
                bytes_to_free += entry.size_bytes;

                if to_evict.len() >= target_count || bytes_to_free >= target_bytes {
                    break;
                }
            }
        }

        // If we didn't find enough old entries, take any entries
        if to_evict.len() < target_count {
            for key in inner.entries.keys() {
                if !to_evict.contains(key) {
                    to_evict.push(key.clone());
                    if to_evict.len() >= target_count {
                        break;
                    }
                }
            }
        }

        // Remove evicted entries
        for key in to_evict {
            if let Some(entry) = inner.entries.remove(&key) {
                self.current_bytes
                    .fetch_sub(entry.size_bytes, Ordering::Relaxed);
            }
        }
    }

    /// Returns cache statistics.
    pub fn stats(&self) -> CacheStats {
        let inner = self.inner.lock();
        CacheStats {
            entry_count: inner.entries.len(),
            size_bytes: self.current_bytes.load(Ordering::Relaxed),
            max_bytes: self.max_bytes,
            max_entries: self.max_entries,
            hits: inner.hits,
            misses: inner.misses,
            hit_rate: if inner.hits + inner.misses > 0 {
                inner.hits as f64 / (inner.hits + inner.misses) as f64
            } else {
                0.0
            },
            active: self.is_active(),
        }
    }

    /// Returns the current number of cached entries.
    pub fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }

    /// Checks if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().entries.is_empty()
    }

    /// Returns the current cache size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.current_bytes.load(Ordering::Relaxed)
    }
}

impl Default for RandomEvictionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RandomEvictionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stats = self.stats();
        f.debug_struct("RandomEvictionCache")
            .field("entry_count", &stats.entry_count)
            .field("size_bytes", &stats.size_bytes)
            .field("max_bytes", &stats.max_bytes)
            .field("hit_rate", &format!("{:.2}%", stats.hit_rate * 100.0))
            .field("active", &stats.active)
            .finish()
    }
}

// ============================================================================
// Cache Statistics
// ============================================================================

/// Statistics about cache performance.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of entries currently in the cache.
    pub entry_count: usize,
    /// Current size in bytes.
    pub size_bytes: usize,
    /// Maximum size in bytes.
    pub max_bytes: usize,
    /// Maximum number of entries.
    pub max_entries: usize,
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Hit rate (hits / total requests).
    pub hit_rate: f64,
    /// Whether the cache is active.
    pub active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::BucketEntry; // Use our BucketEntry, not the XDR one
    use stellar_xdr::curr::*;

    fn make_account_id(byte: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32])))
    }

    fn make_account_entry(byte: u8) -> BucketEntry {
        BucketEntry::Live(LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Account(AccountEntry {
                account_id: make_account_id(byte),
                balance: 100,
                seq_num: SequenceNumber(1),
                num_sub_entries: 0,
                inflation_dest: None,
                flags: 0,
                home_domain: String32::default(),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: vec![].try_into().unwrap(),
                ext: AccountEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        })
    }

    fn make_account_key(byte: u8) -> LedgerKey {
        LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id(byte),
        })
    }

    #[test]
    fn test_cache_basic_operations() {
        let cache = RandomEvictionCache::new();
        cache.activate();

        let key = make_account_key(1);
        let entry = make_account_entry(1);

        // Initially empty
        assert!(cache.get(&key).is_none());

        // Insert and retrieve
        cache.insert(key.clone(), entry);
        assert!(cache.get(&key).is_some());

        // Remove
        cache.remove(&key);
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_cache_not_active() {
        let cache = RandomEvictionCache::new();
        // Don't activate the cache

        let key = make_account_key(1);
        let entry = make_account_entry(1);

        cache.insert(key.clone(), entry);
        assert!(cache.get(&key).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_only_accounts() {
        let cache = RandomEvictionCache::new();
        cache.activate();

        // Account key should be cached
        assert!(RandomEvictionCache::is_cached_type(&make_account_key(1)));

        // Trustline key should not be cached
        let trustline_key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: make_account_id(1),
            asset: TrustLineAsset::Native,
        });
        assert!(!RandomEvictionCache::is_cached_type(&trustline_key));
    }

    #[test]
    fn test_cache_eviction() {
        // Create cache with small limits
        let cache = RandomEvictionCache::with_limits(10_000, 5);
        cache.activate();

        // Insert more entries than max
        for i in 0..10u8 {
            let key = make_account_key(i);
            let entry = make_account_entry(i);
            cache.insert(key, entry);
        }

        // Cache should have evicted some entries
        assert!(cache.len() <= 5);
    }

    #[test]
    fn test_cache_stats() {
        let cache = RandomEvictionCache::new();
        cache.activate();

        let key = make_account_key(1);
        let entry = make_account_entry(1);

        // Miss
        cache.get(&key);

        // Insert
        cache.insert(key.clone(), entry);

        // Hit
        cache.get(&key);

        let stats = cache.stats();
        assert_eq!(stats.entry_count, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_cache_clear() {
        let cache = RandomEvictionCache::new();
        cache.activate();

        for i in 0..5u8 {
            cache.insert(make_account_key(i), make_account_entry(i));
        }

        assert_eq!(cache.len(), 5);

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.size_bytes(), 0);
    }

    #[test]
    fn test_cache_maybe_initialize() {
        let cache = RandomEvictionCache::new();
        assert!(!cache.is_active());

        // Below threshold
        cache.maybe_initialize(100);
        assert!(!cache.is_active());

        // Above threshold
        cache.maybe_initialize(MIN_BUCKET_LIST_SIZE_FOR_CACHE);
        assert!(cache.is_active());
    }

    #[test]
    fn test_cache_update_existing() {
        let cache = RandomEvictionCache::new();
        cache.activate();

        let key = make_account_key(1);
        let entry1 = make_account_entry(1);
        let entry2 = make_account_entry(1);

        cache.insert(key.clone(), entry1);
        let size1 = cache.size_bytes();

        cache.insert(key.clone(), entry2);
        let size2 = cache.size_bytes();

        // Size should be similar (same entry type)
        assert!((size1 as isize - size2 as isize).abs() < 100);
        assert_eq!(cache.len(), 1);
    }
}
