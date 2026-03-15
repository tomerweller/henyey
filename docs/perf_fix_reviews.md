# Performance Fix Reviews (Mar 9–15, 2026)

27 performance optimization commits applied to the ledger close hot path.

## Summary Table

| # | Commit | Lines | Description |
|---|--------|-------|-------------|
| 1 | `f901afb` | +134/−43 | Cache TTL key hashes to avoid rehashing per TX |
| 2 | `b74e111` | +108/−93 | Track mutations incrementally instead of diffing full state |
| 3 | `3b48532` | +83/−227 | Simplify meta construction for hot archive entry changes |
| 4 | `0edb0d4` | +236/−77 | Split offer/non-offer metadata maps for O(1) clear |
| 5 | `87e7c2e` | +91/−2 | Add global ed25519 signature verification cache |
| 6 | `d95e7e2` | +100/−60 | Skip ed25519 point decompression on cache hits |
| 7 | `cd10876` | +29/−5 | O(1) length snapshot for TX rollback instead of O(N) delta clone |
| 8 | `7460dd7` | +233/−194 | Eliminate ~39 unnecessary `.clone()` calls on XDR types |
| 9 | `a0cdeae` | +3/−2 | Switch sig cache key hash from SHA-256 to BLAKE2 |
| 10 | `beba273` | +256/−38 | Pre-compute TX hashes, eliminate O(n log n) redundant hashing in prepare |
| 11 | `f0fabc5` | +72/−28 | Cache hashes and eliminate clones in TX set build (+77% TPS) |
| 12 | `2c50ca5` | +23/−6 | Structural ScAddress compare in bucket entries (−23% add_batch) |
| 13 | `bae9e05` | +43/−5 | Streaming XDR hashing and TX set hash caching |
| 14 | `98bbce4` | +93/−59 | Structural key comparison for bucket dedup instead of XDR serialization |
| 15 | `e7fde6b` | +3/−2 | Reuse TTL key cache across TXs, zero-alloc ValDeser charging |
| 16 | `0c66a74` | +242/−221 | Wrap TransactionFrame envelope in `Arc` for cheap cloning |
| 17 | `3beef9f` | +44/−16 | Thread `Arc<TransactionEnvelope>` through hot execution path |
| 18 | `1e915d7` | +80/−15 | Optimize merge hash computation, reduce per-TX envelope clones |
| 19 | `066299f` | +68/−53 | Replace allocating XDR serialization with counting writer for size checks |
| 20 | `022f0ba` | +66/−1 | Fix O(n²) contract cache scan in per-TX commit path (+21% TPS) |
| 21 | `aeea796` | +150/−38 | Parallelize TX hash computation, optimize merge paths |
| 22 | `06a0b3d` | +19/−11 | RwLock sig cache + skip redundant verification |
| 23 | `1067f46` | +141/−71 | Single-pass delta categorization, commit_close fast-path |
| 24 | `0bfec57` | +75/−26 | Eliminate clones in meta building, cache TX hash across phases |
| 25 | `1952c77` | +70/−18 | Skip redundant dedup in add_batch, cache sort keys |
| 26 | `3bc76a2` | +4/−0 | Drop delta on background thread in commit_close |
| 27 | `011a745` | +462/−380 | LedgerKey HashMap, async persist, drain delta, presorted prepare (+13.5% TPS) |

## Individual Fixes

### 1. `f901afb` — Cache TTL key hashes

Cache the hash of each `LedgerKey` used for TTL lookups so it is computed once
and reused across the per-TX footprint loading, eviction, and commit paths.
Previously every TTL access re-serialized and re-hashed the key.

**Crates**: henyey-tx, henyey-ledger

### 2. `b74e111` — Incremental mutation tracking

Replace the "diff old vs new state" approach with incremental tracking of which
entries were actually modified during TX execution. Avoids scanning the entire
entry store on every TX commit.

**Crates**: henyey-tx, henyey-ledger

### 3. `3b48532` — Simplify meta construction

Rewrite `build_entry_changes_with_hot_archive` to remove redundant
intermediate data structures and iterations. Net deletion of 144 lines while
producing the same `LedgerEntryChanges` output.

**Crates**: henyey-ledger

### 4. `0edb0d4` — Split offer/non-offer metadata maps

Separate the ledger delta into offer and non-offer maps so that clearing
offer-specific tracking on ledger advance is O(1) rather than scanning the
full map and filtering by entry type.

**Crates**: henyey-ledger, henyey-tx

### 5. `87e7c2e` — Ed25519 signature verification cache

Add a global LRU cache for ed25519 signature verifications keyed by
`(public_key, message, signature)`. Avoids re-verifying the same signature
when a TX appears in the pending set and again during apply.

**Crates**: henyey-crypto

### 6. `d95e7e2` — Skip point decompression on cache hits

Change the cache lookup to happen before ed25519 point decompression
(the most expensive step of verification). Previously the cache was checked
after decompression, wasting the main cost on cache hits.

**Crates**: henyey-crypto, henyey-tx

### 7. `cd10876` — O(1) snapshot for TX rollback

Replace cloning the entire `LedgerDelta` (O(N) in entries) before each TX with
recording a length snapshot. Rollback truncates back to the snapshot rather
than restoring a full clone. 29-line change with large impact on per-TX
overhead.

**Crates**: henyey-ledger, henyey-tx

### 8. `7460dd7` — Eliminate ~39 unnecessary `.clone()` calls

Audit and remove ~39 redundant `.clone()` calls on XDR types throughout the
execution path. Replaces clones with borrows or moves where the value is not
used after the call site.

**Crates**: henyey-ledger, henyey-tx, henyey-bucket, henyey-common

### 9. `a0cdeae` — BLAKE2 sig cache key

Switch the signature verification cache key hash from SHA-256 to BLAKE2b for
faster hashing. 3-line change — just swaps the hash function.

**Crates**: henyey-crypto

### 10. `beba273` — Pre-compute TX hashes

Compute transaction hashes once during TX set construction and thread them
through prepare, apply, and meta-building. Previously hashes were recomputed
at each stage, and the prepare phase sorted by hash using O(n log n)
re-hashing comparisons.

**Crates**: henyey-herder, henyey-ledger, henyey-tx

### 11. `f0fabc5` — Cache hashes in TX set build (+77% TPS)

Use `sort_by_cached_key` instead of `sort_by_key` when building the
transaction set, and eliminate envelope clones during the sort. The uncached
sort was re-hashing every comparison.

**Crates**: henyey-herder, henyey-ledger

### 12. `2c50ca5` — Structural ScAddress compare (−23% add_batch)

Implement a structural comparison for `ScAddress` in bucket entries instead of
serializing both sides to XDR bytes and comparing. Avoids allocation and
serialization on every bucket entry comparison.

**Crates**: henyey-bucket

### 13. `bae9e05` — Streaming XDR hashing

Hash XDR values by streaming serialization directly into the hasher rather
than serializing to a `Vec<u8>` first and then hashing. Also cache the TX set
hash.

**Crates**: henyey-common, henyey-ledger

### 14. `98bbce4` — Structural key comparison for bucket dedup

Replace XDR-serialize-and-compare with structural `Ord`/`Eq` implementations
for `LedgerKey` comparisons during bucket dedup. Eliminates per-comparison
allocations.

**Crates**: henyey-bucket

### 15. `e7fde6b` — Reuse TTL key cache across TXs

Persist the TTL key hash cache across transaction boundaries within the same
ledger close instead of rebuilding it for each TX. 3-line change.

**Crates**: henyey-tx

### 16. `0c66a74` — `Arc<TransactionEnvelope>`

Wrap `TransactionEnvelope` inside `TransactionFrame` with `Arc` so that
cloning a frame is a pointer bump instead of a deep copy of the full envelope.
Large mechanical refactor (27 files) but straightforward.

**Crates**: henyey-tx, henyey-ledger, henyey-herder, henyey-simulation, henyey-overlay

### 17. `3beef9f` — Thread `Arc` through hot path

Pass the `Arc<TransactionEnvelope>` directly into the execution pipeline
instead of re-wrapping. Avoids 1–2 extra Arc clones per TX in the inner loop.

**Crates**: henyey-tx, henyey-ledger

### 18. `1e915d7` — Optimize merge hash + reduce envelope clones

Compute the merge hash incrementally during bucket merge output instead of
hashing the entire output at the end. Also eliminate remaining envelope clones
in the per-TX path.

**Crates**: henyey-bucket, henyey-ledger

### 19. `066299f` — Counting writer for size checks

Replace `xdr_to_vec().len()` (which allocates a full XDR buffer just to
measure its size) with a `CountingWriter` that counts bytes without
allocating.

**Crates**: henyey-common, henyey-tx

### 20. `022f0ba` — Fix O(n²) contract cache scan (+21% TPS)

The per-TX Soroban commit path was linearly scanning the contract data cache
to find modified entries. Add an index to make lookups O(1), fixing an O(n²)
loop over all cached entries × all modified entries.

**Crates**: henyey-tx, henyey-ledger

### 21. `aeea796` — Parallelize TX hash computation

Compute transaction hashes in parallel using `rayon` during TX set
preparation. Also optimize merge paths to reduce unnecessary intermediate
copies.

**Crates**: henyey-ledger, henyey-herder, henyey-bucket

### 22. `06a0b3d` — RwLock sig cache + skip redundant check

Switch the signature cache from `Mutex` to `RwLock` for concurrent reads.
Skip signature verification entirely when the TX has already been verified
during nomination/validation.

**Crates**: henyey-crypto, henyey-tx

### 23. `1067f46` — Single-pass delta categorization

Replace multiple passes over the delta (one per category: created, updated,
removed) with a single pass that categorizes entries in one loop. Also add a
fast-path for `commit_close` when there are no offers.

**Crates**: henyey-ledger

### 24. `0bfec57` — Eliminate meta clones + cache TX hash

Remove clones of `TransactionResultMeta` during meta building and cache the
TX hash on the `TransactionFrame` so it is never recomputed across execution
phases (apply, fee deduction, meta).

**Crates**: henyey-tx, henyey-ledger

### 25. `1952c77` — Skip redundant dedup in add_batch

The bucket `add_batch` was deduplicating entries that were already guaranteed
unique by the delta construction. Skip the dedup and instead cache sort keys
to avoid recomputing them during the sort.

**Crates**: henyey-bucket

### 26. `3bc76a2` — Drop delta on background thread

Move the `LedgerDelta` drop (which frees large hash maps) to a background
thread so it doesn't block the ledger close critical path. 4-line change.

**Crates**: henyey-ledger

### 27. `011a745` — LedgerKey HashMap, async persist, drain delta, presorted prepare (+13.5% TPS)

Multi-part optimization: replace `BTreeMap<LedgerKey>` with `HashMap` in the
delta (faster lookup/insert), move SQLite persistence to a background task,
drain the delta instead of cloning it during commit, and mark TX sets as
presorted to skip redundant sorting in prepare.

**Crates**: henyey-ledger, henyey-tx, henyey-herder, henyey-db
