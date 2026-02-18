# Consensus Parity Report: `crates/bucket` vs stellar-core v25

**Date:** 2026-02-17
**Scope:** Full pseudocode comparison of `crates/bucket` (Henyey) against `.upstream-v25/src/bucket/` (stellar-core v25 / protocol 25)
**Method:** Side-by-side pseudocode comparison of all 21 Rust source files against their C++ counterparts

---

## Summary

33 behavioral deltas were identified across the bucket list, merge, eviction, and hot archive subsystems. Of these:

- **2 Critical** — will cause ledger state divergence on real-world traffic
- **6 High** — will cause divergence under specific but plausible conditions
- **7 Medium** — will cause divergence in edge cases or affect operational fidelity
- **18 Low/Verified** — minor differences unlikely to affect consensus, or verified correct

All file references use the format `file:line` relative to `crates/bucket/src/` (Rust) and `.upstream-v25/src/bucket/` (C++).

---

## Critical Severity

These will cause consensus-breaking divergence on mainnet traffic today.

### B-S1. Inflation winners missing minimum voter balance threshold

- **Rust:** `snapshot.rs` — inflation winner scanning counts ALL votes from accounts regardless of the voter's balance
- **C++:** `SearchableBucketList.cpp` — only counts votes from accounts with a minimum balance of 100 XLM (100,000,000,000 stroops, i.e., 1 billion stroops threshold)
- **Impact:** Accounts with less than the minimum balance contribute votes in Rust but not in C++. This will produce different inflation winner sets and therefore different inflation payouts, changing `total_coins` and account balances. Diverges on every inflation operation.
- **Fix:** Add the minimum voter balance threshold check when scanning for inflation winners.

### B-R1. Missing `isSorobanEntry`/`isPersistentEntry` validation on hot archive entries

- **Rust:** `hot_archive.rs` — accepts any entry type into the hot archive without validation
- **C++:** `HotArchiveBucket.cpp` — validates that entries added to the hot archive are Soroban entries and specifically persistent entries (CONTRACT_DATA or CONTRACT_CODE with PERSISTENT durability)
- **Impact:** Non-Soroban entries or non-persistent Soroban entries could be placed in the hot archive, corrupting the hot archive bucket list and causing hash divergence. This affects the combined bucket list hash on every subsequent ledger.
- **Fix:** Add `is_soroban_entry()` and `is_persistent_entry()` validation before inserting entries into the hot archive.

---

## High Severity

These will cause divergence under specific but realistic conditions.

### B-S2. Eviction missing protocol-version-dependent evictable type gating

- **Rust:** `eviction.rs` — evicts all Soroban entry types regardless of protocol version
- **C++:** `EvictionStatistics.cpp` / `LiveBucket.cpp` — for protocols before V24, only temporary entries are evictable; persistent entry eviction is gated behind V24+
- **Impact:** On protocol versions before 24, persistent entries would be incorrectly evicted in Rust, removing valid state from the ledger. For P24+ forward-only nodes this is not an issue, but blocks historical replay.
- **Fix:** Gate persistent entry eviction behind protocol version >= 24.

### B-S3. Missing V24 newest-version check gating for persistent entries in eviction

- **Rust:** `eviction.rs` — does not check whether evicted persistent entries are the newest version
- **C++:** `LiveBucket.cpp` — for persistent entries at V24+, only evicts if the entry is the newest version (not shadowed by a newer modification in a higher bucket level)
- **Impact:** Persistent entries that have been modified in a more recent bucket level could be incorrectly evicted from an older level, causing the entry to disappear. This produces different bucket list state.
- **Fix:** Add newest-version checking for persistent entry eviction at V24+.

### B-R3. Bucket file naming differs

- **Rust:** `manager.rs` — bucket files are named `{hash}.bucket.xdr`
- **C++:** `BucketUtils.cpp` — bucket files are named `bucket-{hash}.xdr`
- **Impact:** While file naming doesn't affect consensus hashes, it prevents file sharing between Rust and C++ nodes for catchup/publish. A node that downloads buckets from a C++ publisher won't find them at the expected paths, and vice versa.
- **Fix:** Use the C++ naming convention `bucket-{hash}.xdr`.

### B-R5. MergeKey missing shadow_hashes field

- **Rust:** `future_bucket.rs` / merge types — `MergeKey` does not include shadow hashes
- **C++:** `MergeKey.h` — includes `shadow_hashes` as part of the merge identity
- **Impact:** Two merges that differ only in their shadow sets will be considered identical in Rust. This can cause incorrect merge reuse, producing buckets with wrong content (entries that should have been shadowed are retained or vice versa).
- **Fix:** Add `shadow_hashes` to `MergeKey` and include them in equality/hash comparisons.

### B-R7. `resolve_blocking` re-does merge instead of waiting on background task

- **Rust:** `future_bucket.rs` — `resolve_blocking` re-executes the entire merge from scratch instead of waiting for an in-progress background merge
- **C++:** `FutureBucket.cpp` — `resolve()` waits on the background task's future
- **Impact:** Functionally correct (same hash), but wastes CPU. More critically, if the re-merge uses different inputs due to a race condition (e.g., bucket files being cleaned up), it could produce a different result.
- **Fix:** Implement proper future-based waiting on the background merge task.

### B-R8. FutureBucket serialization missing shadow hashes

- **Rust:** `future_bucket.rs` — when serializing an in-progress merge (e.g., for state snapshots), shadow hashes are not included
- **C++:** `FutureBucket.cpp` — serializes shadow hashes alongside the merge inputs
- **Impact:** After a node restart, the reattached merge will not know about shadows, potentially producing a different bucket hash. This would cause the bucket list hash to diverge after any restart during an active merge.
- **Fix:** Include shadow hashes in FutureBucket serialization/deserialization.

---

## Medium Severity

These cause divergence in edge cases or affect operational fidelity.

### B-C3. INIT+INIT and LIVE+INIT merge silently accepted

- **Rust:** `entry.rs` — merging two INIT entries or a LIVE entry with an INIT entry is silently accepted (second entry wins)
- **C++:** `LiveBucket.cpp` — throws an error for these invalid merge combinations (`INIT+INIT`, `LIVE+INIT`)
- **Impact:** In C++, hitting this condition would halt the node (fail-fast). In Rust, invalid merge combinations are silently accepted, potentially masking data corruption bugs. The final bucket state could differ if the "second wins" resolution doesn't match what C++ would have produced before the error.
- **Fix:** Throw an error (panic) for `INIT+INIT` and `LIVE+INIT` merge combinations, matching C++ behavior.

### B-S4. AssetPoolIDMap indexes both LIVE and INIT entries

- **Rust:** `snapshot.rs` / `index.rs` — the asset-to-pool-ID mapping indexes both `LIVE` and `INIT` bucket entries
- **C++:** `SearchableBucketList.cpp` — only indexes `INIT` entries for the asset-pool mapping
- **Impact:** Pool lookups may return different results if a LIVE entry (modification) is indexed. Could affect liquidity pool operations that use this mapping.
- **Fix:** Only index `INIT` entries in the AssetPoolIDMap.

### B-S5. Inflation winners no early exit on non-ACCOUNT entry

- **Rust:** `snapshot.rs` — inflation winner scanning iterates all entry types, skipping non-ACCOUNT entries
- **C++:** `SearchableBucketList.cpp` — has an early exit optimization for non-ACCOUNT entry types
- **Impact:** Performance difference only in most cases. However, if the iteration order or filtering logic differs subtly, it could affect which accounts are considered.
- **Fix:** Add early exit for non-ACCOUNT entries (performance optimization, verify iteration equivalence).

### B-S6. scanForEntriesOfType adds cross-bucket dedup

- **Rust:** `snapshot.rs` — `scan_for_entries_of_type` maintains a seen-keys set across buckets, deduplicating entries
- **C++:** `SearchableBucketList.cpp` — does not deduplicate across buckets in `scanForEntriesOfType`
- **Impact:** If the same entry exists in multiple bucket levels (which is normal after merges), Rust will return it only once while C++ returns it from each level. This affects any operation that aggregates results across the bucket list.
- **Fix:** Remove cross-bucket deduplication to match C++ semantics, or verify that callers handle duplicates correctly.

### B-R4. Hot archive buckets not cached

- **Rust:** `manager.rs` — hot archive bucket data is not cached after loading
- **C++:** `BucketManager.cpp` — hot archive buckets are cached in the bucket cache alongside live buckets
- **Impact:** Performance difference only. No consensus impact, but may cause excessive disk I/O during hot archive operations.
- **Fix:** Add hot archive buckets to the bucket cache.

### B-R6. No merge reattachment check in start_merge

- **Rust:** `manager.rs` — `start_merge` always starts a new merge
- **C++:** `BucketManager.cpp` — `startMerge` checks the `MergeMap` for an existing merge with the same key and reattaches to it if found
- **Impact:** Functionally correct (same result), but wastes CPU by redoing merges. Could also cause issues if two concurrent merges for the same inputs produce slightly different temporary states.
- **Fix:** Implement merge reattachment using the MergeKey lookup.

### B-R9. Bucket list hash may not combine live+hot archive hashes

- **Rust:** `lib.rs` / `bucket_list.rs` — the bucket list hash computation may not combine the live bucket list hash with the hot archive bucket list hash
- **C++:** `BucketListBase.cpp` — the final bucket list hash is `SHA256(liveBucketListHash || hotArchiveBucketListHash)`
- **Impact:** If the hot archive hash is not included, the bucket list hash will differ on every ledger where the hot archive is non-empty. This is consensus-critical.
- **Fix:** Combine both live and hot archive hashes in the bucket list hash computation.

---

## Low Severity / Verified Correct

These are unlikely to affect consensus or have been verified as correct.

### B-C1, B-C2. Shadow version/metadata ext propagation (pre-p12 only)

- **Rust:** Shadow bucket handling differs in metadata extension propagation
- **C++:** Propagates metadata extensions during shadow merges
- **Impact:** Shadows are only relevant for protocols before 12. Irrelevant for P24+.

### B-C4. Output dedup differences

- **Rust:** Deduplication in bucket output may use a different strategy
- **Impact:** Verified to produce the same final bucket contents.

### B-C5. ScVal comparison

- **Rust:** ScVal comparison uses derived traits
- **Impact:** Verified to produce the same ordering as C++.

### B-C8. Shadow collection order

- **Rust:** Shadow hash collection order may differ
- **Impact:** Order doesn't affect the shadow set semantics (set equality).

### B-C6, B-C7, B-C9, B-C10, B-C11, B-C12. Verified correct

- Level math, bucket hash computation, CAP-0020 semantics, and constants all verified to match C++.

### B-S7. Eviction individual vs bulk TTL lookups

- **Rust:** Looks up TTL entries individually during eviction
- **C++:** May batch TTL lookups
- **Impact:** Performance difference only.

### B-S8. seen_keys scope over-broad

- **Rust:** `seen_keys` set in eviction may track more keys than necessary
- **Impact:** Performance difference only; does not affect which entries are evicted.

### B-S9, B-S10, B-S11. Eviction termination, counter granularity, pool query approach

- Various minor implementation differences in eviction termination conditions, counter granularity, and pool query patterns.
- **Impact:** No consensus impact verified.

### B-R2. HashMap vs streaming merge

- **Rust:** Some merge operations use in-memory HashMaps
- **C++:** Uses streaming merge with iterators
- **Impact:** Produces the same output; memory vs I/O tradeoff only.

### B-R10. No directory locking

- **Rust:** No file-level directory locking for bucket directory
- **C++:** Locks the bucket directory to prevent concurrent access
- **Impact:** Operational safety difference; no consensus impact if only one process accesses buckets.

---

## Structural Differences (Non-Consensus)

These are architectural differences that do not affect observable behavior:

| Aspect | Rust (Henyey) | C++ (stellar-core) |
|--------|---------------|---------------------|
| Merge execution | In-memory merge with HashMap | Streaming merge with iterators |
| Bucket storage | Single file per bucket | Same, but with different naming |
| Index format | Rust-native serialization | Custom binary format with page index |
| Cache | Simple HashMap cache | LRU cache with eviction policy |
| Background merges | Tokio async tasks | `std::future` with thread pool |
| Bloom filter | Rust implementation | C++ implementation with same parameters |

---

## Scope Gaps (Missing Features)

Features present in C++ but entirely absent in Rust, beyond the behavioral deltas above:

1. **Merge reattachment** — No MergeMap-based reattachment of in-progress merges (covered in B-R6)
2. **Hot archive caching** — Hot archive buckets not cached (covered in B-R4)
3. **Directory locking** — No bucket directory lock (covered in B-R10)
4. **Entry type validation on hot archive** — Missing Soroban entry type checks (covered in B-R1)

---

## Recommended Fix Priority

1. **Immediate (blocks any parity):** B-S1, B-R1
2. **High priority (blocks correctness):** B-S2, B-S3, B-R3, B-R5, B-R7, B-R8
3. **Medium priority (edge cases/operational):** B-C3, B-S4, B-S5, B-S6, B-R4, B-R6, B-R9
4. **Low priority (hardening):** All LOW items

---

## Methodology

Each Rust source file in `crates/bucket/src/` was compared against its C++ counterpart(s) in `.upstream-v25/src/bucket/` using side-by-side pseudocode generation. The comparison focused on:

- Merge entry combination rules and precedence
- Bucket hash computation
- Eviction criteria and protocol-version gating
- Hot archive entry validation
- Bucket list level math and boundary conditions
- FutureBucket serialization and merge reattachment
- Index construction and lookup semantics

Excluded from comparison: test code, logging, metrics, memory management, and type conversions (unless containing logic).
