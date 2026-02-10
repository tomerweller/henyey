# Comprehensive Plan: BucketList Parity with stellar-core

## Executive Summary

This plan addresses the full lifecycle of bucket list operations at mainnet scale (~60M entries):
1. **Population**: Fast bucket loading from history archives with index/cache initialization
2. **Lookup**: Efficient entry queries with minimal disk I/O using indexes and caches

The plan is organized into **phases** with clear dependencies, each containing specific implementation tasks.

---

## Phase 1: Index Architecture Alignment

**Goal**: Align our indexing with upstream's two-tier index system (InMemoryIndex for small buckets, DiskIndex with page ranges for large buckets).

### Current Gap Analysis

| Feature | stellar-core | Our Rust | Gap |
|---------|-------------|----------|-----|
| In-Memory Index | Full entries in `unordered_set` | Key-to-offset `BTreeMap` | ✅ Similar |
| Disk Index | Page-based range index | 8-byte key hash index | ⚠️ Different design |
| Index Cutoff | 20 MB bucket size | 10,000 entries | ⚠️ Different threshold |
| Binary Fuse Filter | Per-bucket, SipHash24 | Per-disk-bucket | ✅ Similar |
| Index Persistence | Serialized to `.index` files | Not persisted | ❌ Missing |

### Tasks

#### 1.1: Page-Based DiskIndex (High Priority)
**Files**: `crates/henyey-bucket/src/index.rs`, `disk_bucket.rs`

Replace the 8-byte key hash index with upstream's page-based range index:

```
Current: hash(key)[0:8] → (offset, length)
Upstream: [lower_key, upper_key] → page_start_offset
```

**Implementation**:
- Add `RangeIndex` type: `Vec<(RangeEntry, u64)>` mapping key ranges to file offsets
- Configure page size via `BUCKETLIST_DB_INDEX_PAGE_SIZE_EXPONENT` (default 2^14 = 16 KB)
- Lookup: Binary search to find candidate page, then scan page for exact key
- Benefits: Smaller index size, matches upstream semantics exactly

**Estimated effort**: 2-3 days

#### 1.2: Index Cutoff by Size (Medium Priority)
**Files**: `index.rs`

Change index type selection from entry count to bucket file size:

```rust
// Current
if entry_count < 10_000 { InMemoryIndex } else { DiskIndex }

// Upstream-aligned
if bucket_file_size_mb < BUCKETLIST_DB_INDEX_CUTOFF { InMemoryIndex } else { DiskIndex }
```

**Estimated effort**: 0.5 days

#### 1.3: Index Persistence (Medium Priority)
**Files**: `index.rs`, new `index_serialization.rs`

Persist DiskIndex to `.index` files for faster restarts:

- Serialize: `(version, page_size, range_index, bloom_filter, counters, type_ranges)`
- Version check on load; rebuild if version mismatch
- Config: `BUCKETLIST_DB_PERSIST_INDEX` (default: true)

**Benefits**: Eliminates index rebuild time on restart (seconds → milliseconds per bucket)

**Estimated effort**: 2 days

---

## Phase 2: Cache Integration

**Goal**: Integrate `RandomEvictionCache` into bucket lookups to reduce disk I/O for frequently-accessed entries.

### Current Gap Analysis

| Feature | stellar-core | Our Rust | Gap |
|---------|-------------|----------|-----|
| Cache Location | Per-bucket in `LiveBucketIndex` | Implemented but not integrated | ❌ Missing integration |
| Cached Types | ACCOUNT only | ACCOUNT only | ✅ Same |
| Cache Sizing | Proportional to bucket's share of total accounts | Fixed max entries/bytes | ⚠️ Different |
| Cache Population | On cache miss after disk read | N/A | ❌ Not integrated |

### Tasks

#### 2.1: Per-Bucket Cache Integration (High Priority)
**Files**: `bucket.rs`, `disk_bucket.rs`, `cache.rs`

Add cache to `DiskBucket` (or `LiveBucketIndex`):

```rust
pub struct DiskBucket {
    // ... existing fields ...
    cache: Option<RandomEvictionCache>,
}

impl DiskBucket {
    pub fn get(&self, key: &LedgerKey) -> Result<Option<BucketEntry>> {
        // 1. Check cache first
        if let Some(entry) = self.cache.as_ref().and_then(|c| c.get(key)) {
            return Ok(Some((*entry).clone()));
        }
        
        // 2. Check bloom filter
        if !self.bloom_filter_may_contain(key) {
            return Ok(None);
        }
        
        // 3. Disk lookup
        let entry = self.load_from_disk(key)?;
        
        // 4. Populate cache on miss
        if let Some(ref cache) = self.cache {
            if let Some(ref e) = entry {
                cache.maybe_add_to_cache(key, e.clone());
            }
        }
        
        Ok(entry)
    }
}
```

**Estimated effort**: 1-2 days

#### 2.2: Proportional Cache Sizing (Medium Priority)
**Files**: `cache.rs`, `bucket_list.rs`

Match upstream's cache sizing algorithm:

```rust
pub fn maybe_initialize_cache(&self, total_bucket_list_account_bytes: usize, config: &Config) {
    if self.is_in_memory() { return; } // No need
    
    let accounts_in_this_bucket = self.index.account_count();
    let max_cache_bytes = config.bucketlist_db_memory_for_caching * 1024 * 1024;
    
    if total_bucket_list_account_bytes < max_cache_bytes {
        // Cache all accounts in this bucket
        self.cache = Some(RandomEvictionCache::with_limits(accounts_in_this_bucket, max_cache_bytes));
    } else {
        // Proportional allocation
        let fraction = self.account_bytes() as f64 / total_bucket_list_account_bytes as f64;
        let bytes_for_this_bucket = (max_cache_bytes as f64 * fraction) as usize;
        let avg_account_size = self.account_bytes() / accounts_in_this_bucket;
        let accounts_to_cache = bytes_for_this_bucket / avg_account_size;
        self.cache = Some(RandomEvictionCache::with_limits(accounts_to_cache, bytes_for_this_bucket));
    }
}
```

**Estimated effort**: 1 day

#### 2.3: BucketList Cache Initialization Hook (Medium Priority)
**Files**: `bucket_list.rs`, `manager.rs`

Call `maybe_initialize_cache()` after bucket list is populated:

```rust
impl BucketList {
    pub fn initialize_caches(&self, config: &Config) {
        let total_account_bytes = self.sum_account_entry_bytes();
        for level in &self.levels {
            level.curr.maybe_initialize_cache(total_account_bytes, config);
            level.snap.maybe_initialize_cache(total_account_bytes, config);
        }
    }
}
```

**Estimated effort**: 0.5 days

---

## Phase 3: Streaming Merge Implementation

**Goal**: Implement streaming bucket merges to reduce memory usage from O(entries) to O(1).

### Current Gap Analysis

| Feature | stellar-core | Our Rust | Gap |
|---------|-------------|----------|-----|
| Merge Memory | O(1) via streaming | O(entries) - loads all into Vec | ❌ Major gap |
| Output Iterator | `BucketOutputIterator` with single-entry buffer | Implemented but not used in merge | ⚠️ Exists but not integrated |
| Hash Computation | Incremental during write | Post-merge on full Vec | ⚠️ Different |

### Tasks

#### 3.1: Streaming Merge Function (High Priority)
**Files**: `merge.rs`, `iterator.rs`

Replace in-memory merge with streaming merge:

```rust
pub fn merge_buckets_streaming(
    old_path: &Path,
    new_path: &Path,
    output_path: &Path,
    keep_dead_entries: bool,
    max_protocol_version: u32,
    normalize_init_entries: bool,
) -> Result<(PathBuf, Hash256)> {
    let old_iter = BucketInputIterator::open(old_path)?;
    let new_iter = BucketInputIterator::open(new_path)?;
    let mut output = BucketOutputIterator::new(output_path, max_protocol_version, keep_dead_entries)?;
    
    // Two-way merge with streaming write
    merge_with_iterators(old_iter, new_iter, &mut output, normalize_init_entries)?;
    
    output.finish()
}
```

**Critical**: This was attempted before and caused a regression. The key is to ensure:
1. Hash computation is identical (XDR record marking format)
2. Entry ordering is identical
3. CAP-0020 merge semantics are preserved exactly

**Risk mitigation**: Implement as new function, don't replace existing merge until thoroughly tested.

**Estimated effort**: 3-4 days (including extensive testing)

#### 3.2: Streaming Merge Integration (Medium Priority)
**Files**: `bucket_list.rs`, `future_bucket.rs`

Use streaming merge for disk-based merges at levels 1+:

```rust
impl FutureBucket {
    fn start_merge_streaming(&mut self, ...) {
        // For disk-backed buckets, use streaming merge
        if old_bucket.is_disk_backed() && new_bucket.is_disk_backed() {
            // Use merge_buckets_streaming
        } else {
            // Fall back to in-memory merge
        }
    }
}
```

**Estimated effort**: 1-2 days

---

## Phase 4: Parallel Bucket Loading

**Goal**: Speed up bucket list population from history archives via parallel bucket loading.

### Current Gap Analysis

| Feature | stellar-core | Our Rust | Gap |
|---------|-------------|----------|-----|
| Parallel Downloads | Yes (via WorkScheduler) | Yes (via tokio) | ✅ Similar |
| Parallel Index Building | Background threads | Sequential in main thread | ⚠️ Gap |
| Parallel Cache Init | Background via asio | Sequential | ⚠️ Gap |

### Tasks

#### 4.1: Parallel Index Building (High Priority)
**Files**: `manager.rs`, `bucket.rs`

Build indexes in parallel when loading buckets from archive:

```rust
pub async fn import_buckets_parallel(
    bucket_hashes: &[Hash256],
    bucket_dir: &Path,
) -> Result<Vec<Bucket>> {
    let handles: Vec<_> = bucket_hashes.iter().map(|hash| {
        let path = bucket_dir.join(format!("{}.bucket.gz", hash));
        tokio::task::spawn_blocking(move || {
            Bucket::load_from_file(&path)
        })
    }).collect();
    
    let mut buckets = Vec::with_capacity(handles.len());
    for handle in handles {
        buckets.push(handle.await??);
    }
    Ok(buckets)
}
```

**Estimated effort**: 1-2 days

#### 4.2: Background Index Building During Merge (Medium Priority)
**Files**: `future_bucket.rs`

Build index asynchronously when merge completes:

```rust
// After merge produces new bucket file
let bucket_path = merge_result.path();
let index_future = tokio::task::spawn_blocking(move || {
    DiskIndex::build_from_file(&bucket_path)
});
// Index builds while other work continues
```

**Estimated effort**: 1 day

---

## Phase 5: Merge Deduplication Integration

**Goal**: Integrate `BucketMergeMap` and `LiveMergeFutures` to avoid redundant merges.

### Current Gap Analysis

Already implemented but not integrated (documented in KNOWN_ISSUES.md P1).

### Tasks

#### 5.1: Integrate LiveMergeFutures (Medium Priority)
**Files**: `manager.rs`, `bucket_list.rs`

```rust
impl BucketManager {
    live_merge_futures: LiveMergeFutures,
    finished_merges: BucketMergeMap,
    
    pub fn get_merge_future(&self, key: &MergeKey) -> Option<SharedFuture<Bucket>> {
        // Check in-progress merges
        if let Some(future) = self.live_merge_futures.get(key) {
            return Some(future.clone());
        }
        // Check completed merges
        if let Some(output_hash) = self.finished_merges.get_output(key) {
            return self.get_bucket_by_hash(&output_hash).map(|b| ready(b).shared());
        }
        None
    }
    
    pub fn put_merge_future(&mut self, key: MergeKey, future: SharedFuture<Bucket>) {
        self.live_merge_futures.insert(key.clone(), future);
    }
    
    pub fn record_merge(&mut self, key: MergeKey, output: &Bucket) {
        self.finished_merges.record_merge(key, output.hash());
    }
}
```

**Estimated effort**: 2 days

---

## Phase 6: Configuration Parity

**Goal**: Add configuration options matching upstream for tuning performance.

### Tasks

#### 6.1: Add BucketList Configuration (Low Priority)
**Files**: new `config.rs` or in `lib.rs`

```rust
pub struct BucketListConfig {
    /// Buckets smaller than this use in-memory index (MB)
    pub bucketlist_db_index_cutoff: usize,  // default: 20
    
    /// Page size for disk index = 2^this (bytes)
    pub bucketlist_db_index_page_size_exponent: u8,  // default: 14 (16 KB)
    
    /// Whether to persist disk indexes to .index files
    pub bucketlist_db_persist_index: bool,  // default: true
    
    /// Memory allocated for bucket caching (MB, 0 = disabled)
    pub bucketlist_db_memory_for_caching: usize,  // default: 0
}
```

**Estimated effort**: 0.5 days

---

## Phase 7: Testing and Validation

**Goal**: Ensure all changes maintain hash parity with stellar-core and don't cause regressions.

### Tasks

#### 7.1: Streaming Merge Parity Tests (High Priority)
- Compare merge output hashes between `merge_buckets()` and `merge_buckets_streaming()`
- Test all CAP-0020 edge cases
- Verify with testnet bucket data

#### 7.2: Index Parity Tests (High Priority)
- Verify index lookup returns same results as full scan
- Test page boundary cases
- Verify bloom filter false positive rate

#### 7.3: Cache Correctness Tests (Medium Priority)
- Verify cache doesn't return stale data
- Test cache eviction behavior
- Verify cache stats match expected

#### 7.4: Integration Tests (High Priority)
- `verify-execution` on testnet range with new code
- Compare bucket list hashes at checkpoints
- Memory usage profiling at mainnet scale

**Estimated effort**: 3-5 days

---

## Implementation Order (Recommended)

```
Phase 1.1: Page-Based DiskIndex ──────────────────────────────────┐
Phase 1.2: Index Cutoff by Size ──────┬───────────────────────────┤
Phase 1.3: Index Persistence ─────────┘                           │
                                                                  ▼
Phase 2.1: Per-Bucket Cache Integration ──────────────────────────┤
Phase 2.2: Proportional Cache Sizing ─────┬───────────────────────┤
Phase 2.3: Cache Initialization Hook ─────┘                       │
                                                                  ▼
Phase 3.1: Streaming Merge Function ──────────────────────────────┤
Phase 3.2: Streaming Merge Integration ───────────────────────────┤
                                                                  ▼
Phase 4.1: Parallel Index Building ───────────────────────────────┤
Phase 4.2: Background Index Building ─────────────────────────────┤
                                                                  ▼
Phase 5.1: Integrate LiveMergeFutures ────────────────────────────┤
                                                                  ▼
Phase 6.1: Add BucketList Configuration ──────────────────────────┤
                                                                  ▼
Phase 7: Testing and Validation ──────────────────────────────────┘
```

---

## Total Estimated Effort

| Phase | Effort |
|-------|--------|
| Phase 1: Index Architecture | 4.5-5.5 days |
| Phase 2: Cache Integration | 2.5-3.5 days |
| Phase 3: Streaming Merge | 4-6 days |
| Phase 4: Parallel Loading | 2-3 days |
| Phase 5: Merge Deduplication | 2 days |
| Phase 6: Configuration | 0.5 days |
| Phase 7: Testing | 3-5 days |
| **Total** | **18.5-25.5 days** |

---

## Risk Mitigation

### High-Risk Items

1. **Streaming Merge (Phase 3.1)**
   - **Risk**: Hash computation differences cause bucket list hash divergence
   - **Mitigation**: 
     - Implement as separate function, keep existing merge
     - Extensive hash comparison tests before integration
     - Run `verify-execution` on testnet before switching

2. **Page-Based DiskIndex (Phase 1.1)**
   - **Risk**: Lookup semantics differ from current implementation
   - **Mitigation**:
     - Keep both implementations during transition
     - A/B test lookups to verify identical results

### Medium-Risk Items

3. **Cache Integration (Phase 2.1)**
   - **Risk**: Cache returns stale data or causes subtle bugs
   - **Mitigation**: Cache is read-only optimization; can be disabled if issues arise

4. **Index Persistence (Phase 1.3)**
   - **Risk**: Serialization format changes break compatibility
   - **Mitigation**: Version field allows graceful fallback to rebuild

---

## Success Criteria

1. **Functional Parity**
   - `verify-execution` passes on testnet with 0 mismatches
   - Bucket list hashes match stellar-core at all checkpoint ledgers

2. **Performance Targets (Mainnet Scale)**
   - Bucket list population: < 30 minutes for full archive
   - Single key lookup: < 10ms average (with warm cache)
   - Memory usage: < 16 GB for full bucket list with indexes and caches

3. **Regression Safety**
   - All existing tests pass
   - No bucket list hash divergence on testnet
