# RFC-003: BucketListDB Point Lookups

**Status:** Approved  
**Created:** 2026-01-27  
**Target:** Phase 3 of Mainnet Support (Bucket List DB Revamp)  
**Estimated Duration:** 2 weeks  
**Dependencies:** RFC-001 (Streaming Iterator) - Completed, RFC-002 (SQL-Backed Offers) - In Progress

## Summary

Implement on-demand point lookups directly from bucket files, replacing the need to load all
entries into memory during catchup. This is the core of the BucketListDB architecture that
enables mainnet support with bounded memory.

## Motivation

### Current Problem

During catchup, we currently load all live entries into memory:

```rust
// In initialize_all_caches()
for entry in bucket_list.live_entries_iter() {
    // Load into in-memory structures
    account_cache.insert(key, entry);
    trustline_cache.insert(key, entry);
    // etc.
}
```

**Memory Impact:**
- Mainnet accounts alone: ~60M entries * ~200 bytes = ~12 GB
- All entry types combined: 50+ GB

### C++ Architecture (What We're Matching)

C++ stellar-core uses a dual-index strategy:

1. **InMemoryIndex** - For small buckets (< `BUCKETLIST_DB_INDEX_CUTOFF` MB, default 20 MB)
   - Stores all entries in a `HashSet<LedgerKey, BucketEntry>`
   - Fast O(1) lookup, no disk I/O needed

2. **DiskIndex** - For large buckets (>= cutoff)
   - Stores a **range index**: `Vec<(RangeEntry, file_offset)>`
   - Uses a **Binary Fuse Filter** (bloom filter variant) to quickly reject missing keys
   - Returns a file offset range for binary search within the bucket file

3. **RandomEvictionCache** - Per-bucket LRU cache for frequently accessed entries
   - Only caches ACCOUNT entries (used during TX validation/flooding)
   - Configurable memory budget via `BUCKETLIST_DB_MEMORY_FOR_CACHING`

Key lookup flow:
```
BucketList.load(key) ->
  for each level (newest to oldest):
    for each bucket (curr, snap):
      if InMemoryIndex: return direct lookup
      if DiskIndex:
        check cache -> return if hit
        check bloom filter -> skip if definite miss
        binary search range index -> get file offset range
        seek & read bucket file -> find entry
        add to cache -> return entry
```

## Design

### Index Architecture

#### Two Index Types

```rust
/// Index for a single bucket file.
pub enum BucketIndex {
    /// For small buckets: all entries cached in memory.
    InMemory(InMemoryIndex),
    /// For large buckets: range-based index with disk lookups.
    Disk(DiskIndex),
}

impl BucketIndex {
    /// Create appropriate index based on bucket size.
    pub fn new(bucket_path: &Path, config: &Config) -> Result<Self, BucketError> {
        let bucket_size = std::fs::metadata(bucket_path)?.len();
        let cutoff = config.bucketlist_db_index_cutoff_mb * 1024 * 1024;
        
        if bucket_size < cutoff {
            Ok(BucketIndex::InMemory(InMemoryIndex::build(bucket_path)?))
        } else {
            Ok(BucketIndex::Disk(DiskIndex::build(bucket_path, config)?))
        }
    }
    
    /// Look up a key, returning the entry if found.
    pub fn lookup(&self, key: &LedgerKey) -> Result<Option<BucketEntry>, BucketError>;
}
```

#### InMemoryIndex (Small Buckets)

For buckets smaller than the cutoff (~20 MB), we can afford to keep everything in memory:

```rust
use std::collections::HashMap;

/// In-memory index for small buckets.
pub struct InMemoryIndex {
    /// All entries keyed by LedgerKey.
    entries: HashMap<LedgerKey, Arc<BucketEntry>>,
    /// Asset to PoolID mapping for liquidity pool queries.
    asset_to_pool_ids: HashMap<Asset, Vec<PoolId>>,
    /// Entry counts by type.
    counters: BucketEntryCounters,
    /// File offset ranges by entry type.
    type_ranges: HashMap<LedgerEntryType, (u64, u64)>,
}

impl InMemoryIndex {
    pub fn build(bucket_path: &Path) -> Result<Self, BucketError> {
        let mut entries = HashMap::new();
        let mut asset_to_pool_ids = HashMap::new();
        let mut counters = BucketEntryCounters::default();
        
        for entry in BucketReader::new(bucket_path)? {
            let entry = entry?;
            if let Some(key) = entry.ledger_key() {
                counters.count(&entry);
                
                // Track liquidity pool asset mappings
                if let BucketEntry::Init(le) | BucketEntry::Live(le) = &entry {
                    if let LedgerEntryData::LiquidityPool(pool) = &le.data {
                        let params = &pool.body.constant_product().params;
                        asset_to_pool_ids
                            .entry(params.asset_a.clone())
                            .or_default()
                            .push(key.liquidity_pool().liquidity_pool_id);
                        asset_to_pool_ids
                            .entry(params.asset_b.clone())
                            .or_default()
                            .push(key.liquidity_pool().liquidity_pool_id);
                    }
                }
                
                entries.insert(key, Arc::new(entry));
            }
        }
        
        Ok(Self { entries, asset_to_pool_ids, counters, type_ranges })
    }
    
    pub fn lookup(&self, key: &LedgerKey) -> Option<Arc<BucketEntry>> {
        self.entries.get(key).cloned()
    }
}
```

#### DiskIndex (Large Buckets)

For large buckets, we use a space-efficient range index:

```rust
use binary_fuse_filter::BinaryFuse16;

/// Range entry mapping key bounds to file offset.
#[derive(Clone, Debug, PartialEq)]
pub struct RangeEntry {
    pub lower_bound: LedgerKey,
    pub upper_bound: LedgerKey,
}

/// Disk-based index for large buckets.
pub struct DiskIndex {
    /// Page size in bytes.
    page_size: u64,
    /// Range index: sorted list of (key_range, file_offset).
    keys_to_offset: Vec<(RangeEntry, u64)>,
    /// Bloom filter for fast negative lookups.
    filter: Option<BinaryFuse16>,
    /// Asset to PoolID mapping.
    asset_to_pool_ids: HashMap<Asset, Vec<PoolId>>,
    /// Entry counts by type.
    counters: BucketEntryCounters,
    /// File offset ranges by entry type.
    type_ranges: HashMap<LedgerEntryType, (u64, u64)>,
    /// Path to bucket file for disk reads.
    bucket_path: PathBuf,
}

impl DiskIndex {
    pub fn build(bucket_path: &Path, config: &Config) -> Result<Self, BucketError> {
        let file_size = std::fs::metadata(bucket_path)?.len();
        let page_size = Self::compute_page_size(config, file_size);
        
        let mut keys_to_offset = Vec::new();
        let mut key_hashes = Vec::new();
        let mut current_page_end = 0u64;
        
        let mut reader = BucketReader::new(bucket_path)?;
        while let Some((entry, offset)) = reader.next_with_offset()? {
            if let Some(key) = entry.ledger_key() {
                // Collect key hash for bloom filter
                key_hashes.push(hash_ledger_key(&key));
                
                // Update range index at page boundaries
                if offset >= current_page_end {
                    current_page_end = (offset / page_size + 1) * page_size;
                    keys_to_offset.push((
                        RangeEntry { lower_bound: key.clone(), upper_bound: key.clone() },
                        offset,
                    ));
                } else {
                    // Extend upper bound of current page
                    keys_to_offset.last_mut().unwrap().0.upper_bound = key;
                }
            }
        }
        
        // Build bloom filter (requires at least 2 keys)
        let filter = if key_hashes.len() > 1 {
            Some(BinaryFuse16::try_from(&key_hashes)?)
        } else {
            None
        };
        
        Ok(Self {
            page_size,
            keys_to_offset,
            filter,
            asset_to_pool_ids: HashMap::new(), // Populated during build
            counters: BucketEntryCounters::default(),
            type_ranges: HashMap::new(),
            bucket_path: bucket_path.to_path_buf(),
        })
    }
    
    /// Look up a key, returning file offset range if potentially present.
    pub fn scan(&self, key: &LedgerKey) -> Option<u64> {
        // Check bloom filter first
        if let Some(ref filter) = self.filter {
            if !filter.contains(&hash_ledger_key(key)) {
                return None; // Definite miss
            }
        }
        
        // Binary search the range index
        let idx = self.keys_to_offset
            .binary_search_by(|(range, _)| {
                if key < &range.lower_bound {
                    std::cmp::Ordering::Greater
                } else if key > &range.upper_bound {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()?;
        
        Some(self.keys_to_offset[idx].1)
    }
    
    /// Read entry from disk at given offset range.
    pub fn read_entry(&self, key: &LedgerKey, start_offset: u64) -> Result<Option<BucketEntry>, BucketError> {
        let file = File::open(&self.bucket_path)?;
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(start_offset))?;
        
        // Read entries until we find the key or pass it
        loop {
            match read_bucket_entry(&mut reader)? {
                Some(entry) => {
                    if let Some(entry_key) = entry.ledger_key() {
                        if &entry_key == key {
                            return Ok(Some(entry));
                        }
                        if &entry_key > key {
                            return Ok(None); // Passed it, not found
                        }
                    }
                }
                None => return Ok(None), // EOF
            }
        }
    }
    
    fn compute_page_size(config: &Config, bucket_size: u64) -> u64 {
        // Match C++ logic: larger buckets get larger pages
        // Default: 4KB pages, scaled by bucket size
        config.bucketlist_db_page_size_kb as u64 * 1024
    }
}
```

### Per-Bucket Cache (ACCOUNT Entries Only)

```rust
use lru::LruCache;
use parking_lot::RwLock;

/// Cache for frequently accessed entries.
/// Only caches ACCOUNT entries (used during TX validation).
pub struct BucketCache {
    cache: RwLock<LruCache<LedgerKey, Arc<BucketEntry>>>,
    max_size: usize,
}

impl BucketCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: RwLock::new(LruCache::new(
                std::num::NonZeroUsize::new(max_entries.max(1)).unwrap()
            )),
            max_size: max_entries,
        }
    }
    
    /// Check if entry type should be cached.
    fn should_cache(key: &LedgerKey) -> bool {
        matches!(key, LedgerKey::Account(_))
    }
    
    pub fn get(&self, key: &LedgerKey) -> Option<Arc<BucketEntry>> {
        if !Self::should_cache(key) {
            return None;
        }
        self.cache.write().get(key).cloned()
    }
    
    pub fn put(&self, key: LedgerKey, entry: Arc<BucketEntry>) {
        if Self::should_cache(&key) {
            self.cache.write().put(key, entry);
        }
    }
}
```

### LiveBucketIndex (Combined Interface)

```rust
/// Combined index for a live bucket with optional caching.
pub struct LiveBucketIndex {
    index: BucketIndex,
    cache: Option<BucketCache>,
}

impl LiveBucketIndex {
    pub fn new(bucket_path: &Path, config: &Config) -> Result<Self, BucketError> {
        let index = BucketIndex::new(bucket_path, config)?;
        
        // Only create cache for DiskIndex buckets
        let cache = match &index {
            BucketIndex::Disk(_) if config.bucketlist_db_memory_for_caching_mb > 0 => {
                // Cache size proportional to bucket's share of total accounts
                Some(BucketCache::new(config.bucket_cache_entries))
            }
            _ => None,
        };
        
        Ok(Self { index, cache })
    }
    
    /// Look up a single key.
    pub fn lookup(&self, key: &LedgerKey) -> Result<Option<Arc<BucketEntry>>, BucketError> {
        // Check cache first
        if let Some(ref cache) = self.cache {
            if let Some(entry) = cache.get(key) {
                return Ok(Some(entry));
            }
        }
        
        // Look up in index
        let result = match &self.index {
            BucketIndex::InMemory(idx) => idx.lookup(key),
            BucketIndex::Disk(idx) => {
                if let Some(offset) = idx.scan(key) {
                    idx.read_entry(key, offset)?.map(Arc::new)
                } else {
                    None
                }
            }
        };
        
        // Add to cache on miss
        if let (Some(ref cache), Some(ref entry)) = (&self.cache, &result) {
            cache.put(key.clone(), entry.clone());
        }
        
        Ok(result)
    }
}
```

### BucketList Point Lookup API

```rust
impl BucketList {
    /// Load a single entry by key, searching newest to oldest.
    ///
    /// Returns:
    /// - `Ok(Some(entry))` if found as INIT/LIVE
    /// - `Ok(None)` if found as DEAD or not present
    pub fn load(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>, BucketError> {
        // OFFERs are not supported by BucketListDB (use SQL)
        if matches!(key, LedgerKey::Offer(_)) {
            return Err(BucketError::OfferNotSupported);
        }
        
        // Search from newest to oldest
        for level in &self.levels {
            // Check curr bucket first (newer)
            if let Some(entry) = level.curr.index.lookup(key)? {
                return match entry.as_ref() {
                    BucketEntry::Live(le) | BucketEntry::Init(le) => Ok(Some(le.clone())),
                    BucketEntry::Dead(_) => Ok(None), // Deleted
                    BucketEntry::Metadata(_) => Ok(None),
                };
            }
            
            // Check snap bucket
            if let Some(entry) = level.snap.index.lookup(key)? {
                return match entry.as_ref() {
                    BucketEntry::Live(le) | BucketEntry::Init(le) => Ok(Some(le.clone())),
                    BucketEntry::Dead(_) => Ok(None),
                    BucketEntry::Metadata(_) => Ok(None),
                };
            }
        }
        
        Ok(None) // Not found in any bucket
    }
    
    /// Load multiple entries by key (batched for efficiency).
    pub fn load_batch(&self, keys: &[LedgerKey]) -> Result<Vec<Option<LedgerEntry>>, BucketError> {
        keys.iter().map(|k| self.load(k)).collect()
    }
}
```

### Integration with LedgerManager

Replace in-memory caches with BucketList lookups:

```rust
impl LedgerManager {
    /// Load an account entry.
    pub fn load_account(&self, account_id: &AccountId) -> Result<Option<AccountEntry>, Error> {
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: account_id.clone(),
        });
        
        match self.bucket_list.load(&key)? {
            Some(LedgerEntry { data: LedgerEntryData::Account(account), .. }) => {
                Ok(Some(account))
            }
            _ => Ok(None),
        }
    }
    
    /// Load a trustline entry.
    pub fn load_trustline(
        &self,
        account_id: &AccountId,
        asset: &TrustLineAsset,
    ) -> Result<Option<TrustLineEntry>, Error> {
        let key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: account_id.clone(),
            asset: asset.clone(),
        });
        
        match self.bucket_list.load(&key)? {
            Some(LedgerEntry { data: LedgerEntryData::Trustline(tl), .. }) => {
                Ok(Some(tl))
            }
            _ => Ok(None),
        }
    }
    
    // Similar methods for other entry types...
}
```

## Configuration

```toml
[bucketlist_db]
# Buckets smaller than this are fully cached in memory (MB)
index_cutoff_mb = 20

# Memory budget for ACCOUNT entry caching (MB)
# Set to 0 to disable caching
memory_for_caching_mb = 1024

# Page size for range index (KB)
page_size_kb = 4

# Whether to persist DiskIndex to .index files
persist_index = true
```

## Implementation Plan

### Week 1: Index Infrastructure

| Day | Task |
|-----|------|
| 1 | Create `InMemoryIndex` struct with build and lookup |
| 2 | Create `DiskIndex` struct with range index and bloom filter |
| 3 | Implement `BucketIndex` enum and factory logic |
| 4 | Add `BucketCache` with LRU eviction |
| 5 | Create `LiveBucketIndex` combining index + cache |

### Week 2: Integration

| Day | Task |
|-----|------|
| 1 | Add `BucketList::load()` API |
| 2 | Integrate indexes into `Bucket` struct |
| 3 | Update `LedgerManager` to use point lookups |
| 4 | Remove in-memory entry caches |
| 5 | Integration tests, benchmarks |

## Files to Create/Modify

| File | Action |
|------|--------|
| `crates/stellar-core-bucket/src/in_memory_index.rs` | **Create** |
| `crates/stellar-core-bucket/src/disk_index.rs` | **Create** |
| `crates/stellar-core-bucket/src/bucket_index.rs` | **Create** - enum + factory |
| `crates/stellar-core-bucket/src/bucket_cache.rs` | **Create** |
| `crates/stellar-core-bucket/src/live_bucket_index.rs` | **Create** |
| `crates/stellar-core-bucket/src/bucket.rs` | Add index field |
| `crates/stellar-core-bucket/src/bucket_list.rs` | Add `load()` API |
| `crates/stellar-core-ledger/src/manager.rs` | Use point lookups |

## Memory Impact

| Component | Before | After |
|-----------|--------|-------|
| Account cache (60M entries) | ~12 GB | 0 MB (on-demand) |
| Trustline cache | ~8 GB | 0 MB (on-demand) |
| Data cache | ~20 GB | 0 MB (on-demand) |
| InMemoryIndex (small buckets) | 0 | ~500 MB |
| DiskIndex (range index) | 0 | ~200 MB |
| BucketCache (accounts) | 0 | ~1 GB (configurable) |
| **Total** | **50+ GB** | **~1.7 GB** |

## Performance Considerations

### Bloom Filter
- False positive rate: ~0.4% (BinaryFuse16)
- Avoids ~99.6% of unnecessary disk reads for missing keys

### Range Index
- Binary search: O(log n) where n = bucket_size / page_size
- For 1GB bucket with 4KB pages: ~18 comparisons

### Caching Strategy
- Only ACCOUNT entries cached (used during TX validation/flooding)
- LRU eviction prevents memory growth
- Cache hit rate expected: 80-90% for hot accounts

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Disk I/O latency | Bloom filter + cache reduce reads by 90%+ |
| Cache memory growth | Fixed-size LRU with configurable limit |
| Index build time | Parallelize across buckets; persist to disk (RFC-004) |

## Testing Strategy

1. **Unit tests**: Each index type in isolation
2. **Integration tests**: BucketList.load() returns correct entries
3. **Stress tests**: Concurrent lookups with cache contention
4. **Parity tests**: Results match C++ stellar-core
5. **Memory tests**: Verify bounded memory under load

## Success Criteria

1. Point lookups work for all entry types (except OFFER)
2. Memory usage bounded regardless of ledger size
3. Lookup latency < 10ms for cached entries, < 100ms for disk
4. No regression in ledger close performance

## References

- C++ Implementation: `.upstream-v25/src/bucket/LiveBucketIndex.h/cpp`
- C++ DiskIndex: `.upstream-v25/src/bucket/DiskIndex.h/cpp`
- C++ InMemoryIndex: `.upstream-v25/src/bucket/InMemoryIndex.h`
- RFC-001: Streaming Iterator (completed)
- RFC-002: SQL-Backed Offers (in progress)
