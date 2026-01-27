# RFC-001: Streaming Iterator for Bucket List Live Entries

**Status:** Approved  
**Created:** 2026-01-27  
**Target:** Phase 1 of Mainnet Support (Bucket List DB Revamp)

## Summary

Replace the memory-intensive `live_entries()` method with a streaming `LiveEntriesIterator` that yields entries one-at-a-time without materializing the full `Vec<LedgerEntry>`. This is the critical first step toward mainnet support.

## Motivation

### Current Problem

The `BucketList::live_entries()` method (`bucket_list.rs:566-608`) materializes ALL live ledger entries into a `Vec<LedgerEntry>`:

```rust
pub fn live_entries(&self) -> Result<Vec<LedgerEntry>> {
    let mut seen: HashSet<Vec<u8>> = HashSet::new();  // O(n) memory for keys
    let mut entries = Vec::new();                       // O(n) memory for entries
    // ... iterates all buckets, collects everything ...
    Ok(entries)
}
```

**Memory Impact:**

| Scale | Entries | Key HashSet | Entry Vec | Total |
|-------|---------|-------------|-----------|-------|
| Testnet | ~70k | ~5 MB | ~400 MB | ~405 MB |
| Mainnet | ~60M | ~2.4 GB | ~50 GB | **~52 GB** |

This makes mainnet operation impossible.

### Proposed Solution

A streaming iterator that:
1. Never materializes the full entry list
2. Uses `HashSet<LedgerKey>` for deduplication (matching C++ upstream)
3. Yields entries one-at-a-time for immediate processing

## Design

### C++ Upstream Behavior (What We're Matching)

C++ stellar-core uses `unordered_set<LedgerKey>` for deduplication during bucket iteration:

```cpp
// From BucketApplicator.cpp
std::unordered_set<LedgerKey>& mSeenKeys;

// Usage:
auto [_, wasInserted] = mSeenKeys.emplace(LedgerEntryKey(e.liveEntry()));
if (!wasInserted) {
    continue;  // Skip - already seen
}
```

Key observations:
- **No bloom filter** - C++ uses a direct `unordered_set<LedgerKey>`
- **Typed keys** - Uses actual `LedgerKey` objects, not serialized bytes
- **Streaming pattern** - Callback-based iteration, not materialization

### New Type: `LiveEntriesIterator`

```rust
// crates/stellar-core-bucket/src/live_iterator.rs

/// Streaming iterator over live bucket list entries.
/// Matches C++ BucketApplicator's iteration pattern.
pub struct LiveEntriesIterator<'a> {
    /// Reference to the bucket list
    bucket_list: &'a BucketList,
    
    /// Current level (0-10)
    current_level: usize,
    
    /// Current phase: Curr (0) or Snap (1)
    current_phase: usize,
    
    /// Iterator over the current bucket
    bucket_iter: Option<BucketIter<'a>>,
    
    /// Deduplication set matching C++ unordered_set<LedgerKey>
    seen_keys: HashSet<LedgerKey>,
    
    /// Statistics
    entries_yielded: usize,
    entries_skipped: usize,
}
```

### Iterator Implementation

```rust
impl<'a> Iterator for LiveEntriesIterator<'a> {
    type Item = Result<LedgerEntry>;
    
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Initialize or advance to next bucket as needed
            // ...
            
            match entry {
                BucketEntry::Live(e) | BucketEntry::Init(e) => {
                    let key = ledger_entry_to_key(&e)?;
                    
                    // C++ pattern: mSeenKeys.emplace(key).second
                    if !self.seen_keys.insert(key) {
                        self.entries_skipped += 1;
                        continue;
                    }
                    
                    self.entries_yielded += 1;
                    return Some(Ok(e));
                }
                BucketEntry::Dead(key) => {
                    // Mark dead keys as seen (shadows older live entries)
                    self.seen_keys.insert(key);
                    continue;
                }
                BucketEntry::Metadata(_) => continue,
            }
        }
    }
}
```

### API Changes

**Add to `BucketList`:**

```rust
impl BucketList {
    /// Returns a streaming iterator over live entries.
    ///
    /// This is memory-efficient compared to `live_entries()` and should
    /// be preferred for large bucket lists (mainnet scale).
    pub fn live_entries_iter(&self) -> LiveEntriesIterator<'_> {
        LiveEntriesIterator::new(self)
    }
    
    /// Deprecated: Materializes all live entries into memory.
    /// 
    /// For new code, prefer `live_entries_iter()` which streams entries.
    #[deprecated(since = "0.2.0", note = "Use live_entries_iter() for memory efficiency")]
    pub fn live_entries(&self) -> Result<Vec<LedgerEntry>> {
        // Keep existing implementation for backwards compatibility
    }
}
```

## Memory Budget

### Deduplication Set Analysis

`LedgerKey` is a Rust enum sized to its largest variant (`LedgerKeyContractData` = 120 bytes):

| Item | Value |
|------|-------|
| LedgerKey size | 120 bytes |
| HashSet overhead per entry | ~24 bytes |
| **Effective per entry** | **~144 bytes** |

### Total Memory Estimate (16GB Target)

| Component | Estimated Size |
|-----------|----------------|
| Deduplication HashSet<LedgerKey> | ~8.6 GB (for 60M entries) |
| Bucket indexes | ~0.5 GB |
| Module cache | ~0.5 GB |
| Operating overhead | ~2 GB |
| **Total** | **~11.6 GB** |

Leaves ~4.4 GB headroom within the 16GB target.

## Call Site Migrations

### `initialize_all_caches()` (manager.rs)

**Before:**
```rust
let live_entries = bucket_list.live_entries()?;
let entry_count = live_entries.len();
for entry in live_entries { ... }
```

**After:**
```rust
let mut entry_count = 0;
for entry_result in bucket_list.live_entries_iter() {
    let entry = entry_result?;
    entry_count += 1;
    match &entry.data {
        LedgerEntryData::Offer(_) => offers.push(entry),
        LedgerEntryData::ContractCode(_) => { ... }
        // etc
    }
}
```

### `compute_soroban_state_size_from_bucket_list()` (execution.rs)

**Before:**
```rust
let entries = bucket_list.read().live_entries()?;
for entry in &entries {
    // compute sizes
}
```

**After:**
```rust
for entry_result in bucket_list.read().live_entries_iter() {
    let entry = entry_result?;
    // compute sizes - no collection needed
}
```

## Files to Modify

| File | Action |
|------|--------|
| `crates/stellar-core-bucket/src/live_iterator.rs` | **Create** - LiveEntriesIterator |
| `crates/stellar-core-bucket/src/lib.rs` | Add `pub mod live_iterator` |
| `crates/stellar-core-bucket/src/bucket_list.rs` | Add `live_entries_iter()`, deprecate `live_entries()` |
| `crates/stellar-core-ledger/src/manager.rs` | Migrate `initialize_all_caches()` |
| `crates/stellar-core-ledger/src/execution.rs` | Migrate `compute_soroban_state_size_from_bucket_list()` |
| `crates/rs-stellar-core/src/main.rs` | Migrate CLI commands |

## Implementation Timeline

| Task | Duration |
|------|----------|
| Create `LiveEntriesIterator` | 1 day |
| Unit tests | 1 day |
| Migrate `initialize_all_caches()` | 1 day |
| Migrate other call sites | 1 day |
| Integration tests + profiling | 1 day |
| **Total** | **5 days** |

## Success Criteria

1. All tests pass
2. Memory usage during cache init < 10GB (profiled)
3. Iteration produces identical entries as `live_entries()` (verified by hash)
4. No regression in ledger close time

## Alternatives Considered

### Alternative 1: Bloom Filter + Hash-only Set

Use a two-tier approach with bloom filter pre-screening and 8-byte hash storage.

**Pros:** Lower memory (~615MB)  
**Cons:** Doesn't match C++ behavior, adds complexity, potential for rare false positives

**Decision:** Match C++ upstream with `HashSet<LedgerKey>` for consistency and correctness.

### Alternative 2: Index-based Deduplication

Query bucket indexes to check if a key exists at a higher level before yielding.

**Pros:** No additional data structures needed  
**Cons:** Requires index to be built first (chicken-and-egg), much slower due to index lookups

**Decision:** `HashSet<LedgerKey>` approach is faster and works without pre-built indexes.

### Alternative 3: No Deduplication

Let consumers handle duplicates.

**Pros:** Simplest and fastest  
**Cons:** Changes semantics, breaks existing consumers, inconsistent behavior

**Decision:** Maintain current semantics for backwards compatibility.

## Future Work

This RFC is Phase 1 of the Bucket List DB Revamp. Subsequent phases:

- **Phase 2:** SQL-backed offers (match C++ `LedgerTxnOfferSQL`)
- **Phase 3:** BucketListDB on-demand lookups with caching
- **Phase 4:** Index persistence

See `docs/MAINNET_GAPS.md` for the complete roadmap.

## References

- C++ BucketApplicator: `.upstream-v25/src/bucket/BucketApplicator.cpp`
- C++ loadInflationWinners: `.upstream-v25/src/bucket/SearchableBucketList.cpp`
- Mainnet gaps analysis: `docs/MAINNET_GAPS.md`
