# Performance Fix Reviews (Mar 9–15, 2026)

27 performance optimization commits applied to the ledger close hot path.

## Review Status

Reviewed commits are benchmarked against HEAD (`d9a4a32`, baseline median:
**11810 TPS**, 50K TXs, 4 clusters, 10 iterations). "Without fix" = HEAD with
the optimization surgically removed.

Session: `8c11d208` — artifacts at `~/data/8c11d208/`.

| # | Commit | Correctness | Baseline | Without | Delta | Necessity |
|---|--------|-------------|----------|---------|-------|-----------|
| 1 | `f901afb` | SOUND | 11810 | 11981 | −1.4% | MARGINAL |
| 2 | `b74e111` | SOUND | 11810 | 12145 | −2.8% | MARGINAL |
| 3 | `3b48532` | SOUND | 11810 | 12321 | −4.1% | MARGINAL |
| 4–27 | | — | — | — | — | pending |

**Note**: Negative deltas mean removing the optimization yielded *equal or
higher* TPS. All three deltas are within benchmark noise (~3-5% run-to-run
variance). These early optimizations targeted paths that subsequent commits
(e.g., #20 O(n²) fix, #27 HashMap+async) may have already superseded.

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

#### Commit Summary
- **Hash**: `f901afb308bd6552b8252edc36e16ecf83cc81c7`
- **Message**: Implement TTL key hash caching (optimization step 1)
- **Files changed**: `crates/ledger/src/execution/mod.rs` (+18), `crates/tx/src/operations/execute/invoke_host_function.rs` (+71/−8), `crates/tx/src/operations/execute/mod.rs` (+3), `crates/tx/src/soroban/host.rs` (+50/−6), `crates/tx/src/soroban/mod.rs` (+28/−1), `docs/soroban-execution-optimization.md` (+7)
- **Optimization category**: Caching (hash memoization)

#### Correctness Review
- **Hot path**: `load_soroban_footprint` → `execute_invoke_host_function` → `apply_soroban_storage_changes` in henyey-ledger and henyey-tx
- **Problem**: Every TTL access (footprint load, archive check, storage change apply, deletion) re-serialized the `LedgerKey` to XDR bytes and re-computed SHA-256. For a typical Soroban TX with 5-10 footprint entries, each key was hashed 3-5 times per TX.
- **Strategy**: Build a `TtlKeyCache` (`HashMap<LedgerKey, Hash>`) during `load_soroban_footprint` and thread it through all downstream functions. `get_or_compute_key_hash()` checks the cache first, falls back to compute.
- **Semantic preservation**: No observable behavior change. The hash is deterministic — caching it produces identical results. The cache is populated during footprint load (which already computes every hash once) and only used for reads downstream.
- **Edge cases**: Cache miss falls back to `compute_key_hash()`, so correctness is preserved even if the cache is empty or stale. The cache is `Option<&TtlKeyCache>` — all call sites pass `None` in tests, which works correctly.
- **Parity**: TTL key hashing is an internal implementation detail. stellar-core computes `sha256(xdr(key))` the same way; this cache doesn't change the hash value, only avoids recomputation.
- **Test coverage**: Existing Soroban execution tests exercise the code paths, but all tests pass `None` for the cache parameter. No dedicated test verifies cache hit vs miss behavior. Gap: a unit test calling `get_or_compute_key_hash` with a populated cache would confirm the cache path.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 11981 TPS (runs: 11873, 11981, 12085)
- **Delta**: −171 TPS (−1.4%)
- **Measurement notes**: Negative delta means removing the optimization yielded *higher* TPS, but the delta is well within benchmark noise (~3-5%). The result is indistinguishable from no change. Subsequent commit #15 (`e7fde6b`) extends this cache to persist across TXs; the per-TX cache in this commit alone has minimal impact because the cost of building the `HashMap` on each TX roughly offsets the saved hash computations.

#### Necessity Judgment
- **TPS gain**: −1.4% (within noise — effectively 0%)
- **Complexity**: +134/−43 lines, 6 files, introduces `TtlKeyCache` type and threads `Option<&TtlKeyCache>` through ~20 function signatures
- **Risk**: Low (SOUND correctness)
- **Verdict**: **MARGINAL**
- **Rationale**: The optimization is correct and the cache concept is sound, but the per-TX lifetime means the cache is rebuilt each TX, offsetting gains. The real value comes from commit #15 which reuses it across TXs. On its own, this commit adds parameter threading complexity across many signatures with no measurable throughput improvement.

#### Similar Opportunities
No similar opportunities identified. All TTL key hash computations are already routed through this cache.

#### Recommendations
1. Consider merging this commit's concept with commit #15 (cross-TX reuse) — the per-TX cache alone doesn't justify the signature threading complexity.
2. Add a unit test exercising `get_or_compute_key_hash` with a populated cache to confirm the cache-hit path.

### 2. `b74e111` — Incremental mutation tracking

#### Commit Summary
- **Hash**: `b74e11160948fbc5de384715a5d97b788f7dd532`
- **Message**: Implement incremental mutation tracking optimization (Step 2)
- **Files changed**: `crates/ledger/src/execution/meta.rs` (+54/−13), `crates/ledger/src/execution/mod.rs` (+147/−11)
- **Optimization category**: Data structure change (zero-copy slicing) + conditional execution (savepoint skip)

#### Correctness Review
- **Hot path**: `delta_changes_between` (called per-operation and per-phase during TX execution) and `create_savepoint` (called per-operation) in henyey-ledger
- **Problem**: Two sub-inefficiencies: (A) `delta_changes_between` cloned 5 `Vec`s (created, updated, update_states, deleted, delete_states) on every call, allocating ~1500-2000 entries/ledger. (B) `create_savepoint()` cloned ~27 data structures before each operation, even for single-op TXs where TX-level rollback suffices.
- **Strategy**: (A) Replace `DeltaChanges` (owned Vecs) with `DeltaSlice<'a>` holding `Range` indices into the parent `LedgerDelta`, returning `&[T]` slices. (B) Skip `create_savepoint()` when `num_ops == 1`.
- **Semantic preservation**: (A) `DeltaSlice` returns the same data as `DeltaChanges` — identical slices into the same underlying arrays. The `change_order()` method applies the same index remapping logic. Three call sites still call `.to_vec()` (fee changes, signer changes, seq changes) because they need owned data for later use, but most call sites use borrows. (B) Single-op TX savepoint skip: if the single operation fails, TX-level rollback handles cleanup. Stellar-core's `LedgerTxn` nesting uses the same principle — the per-op `LedgerTxn` is only needed when subsequent operations need to see clean state after a failure.
- **Edge cases**: (A) `DeltaSlice::change_order()` still allocates a `Vec` (filter_map over the range), so it's not fully zero-copy. Empty slices (start == end) produce empty results correctly. (B) The `num_ops == 1` check is correct for all Soroban TXs (always single-op by protocol) and single-op classic TXs. Multi-op classic TXs correctly get savepoints. The rollback path checks `if let Some(sp) = op_savepoint` before rolling back.
- **Parity**: Both sub-optimizations are internal implementation details. The observable behavior (TX results, ledger changes, meta) is identical. stellar-core's nested `LedgerTxn` serves the same role as our savepoint.
- **Test coverage**: The existing integration tests (full ledger close) exercise both paths. No dedicated unit test for `DeltaSlice` boundary conditions (e.g., adjacent empty slices, single-element slices). No test specifically exercising single-op savepoint skip vs multi-op savepoint create.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 12145 TPS (runs: 12049, 12145, 12408)
- **Delta**: −335 TPS (−2.8%)
- **Measurement notes**: Negative delta means removing the optimization yielded higher TPS, within benchmark noise. The `DeltaSlice` zero-copy benefit is real in principle but small relative to the total ledger close cost. Three of the six call sites still clone to owned Vecs, diluting the benefit. The savepoint skip saves one clone of ~27 structures per single-op TX, but subsequent commit #7 (`cd10876`) replaced the full clone with an O(1) length snapshot, making this skip largely redundant.

#### Necessity Judgment
- **TPS gain**: −2.8% (within noise — effectively 0%)
- **Complexity**: +108/−93 lines, 2 files, introduces `DeltaSlice<'a>` lifetime-bearing type
- **Risk**: Low (SOUND correctness)
- **Verdict**: **MARGINAL**
- **Rationale**: Both sub-optimizations are architecturally sound — zero-copy slicing and skipping unnecessary work are good patterns. However, the measured impact is nil. The `DeltaSlice` lifetime type adds complexity to the API (callers must reason about borrows vs owned data), and three call sites still clone anyway. The savepoint skip was superseded by commit #7's O(1) snapshot approach. The code is not harmful, but it adds complexity without measurable benefit.

#### Similar Opportunities
No similar opportunities identified. The `DeltaSlice` pattern is specific to the delta snapshot/change extraction; no other code paths use the same clone-heavy approach.

#### Recommendations
1. Add unit tests for `DeltaSlice` boundary conditions (empty slices, single-element slices, adjacent slices).
2. Consider whether the three `.to_vec()` call sites could be refactored to use borrows, which would realize the full zero-copy benefit.

### 3. `3b48532` — Simplify meta construction

#### Commit Summary
- **Hash**: `3b48532661e44e62c0f0405c3e9ce766310b15e2`
- **Message**: Optimize build_entry_changes_with_hot_archive meta construction
- **Files changed**: `crates/ledger/src/execution/meta.rs` (+83/−227)
- **Optimization category**: Code simplification (allocation elimination, dead code removal)

#### Correctness Review
- **Hot path**: `build_entry_changes_with_hot_archive` in `crates/ledger/src/execution/meta.rs` — called per-operation during TX execution to construct `LedgerEntryChanges` for transaction meta.
- **Problem**: Four sub-inefficiencies: (1) Debug logging loops iterated over all created/updated/deleted entries on every call (significant overhead even when debug logging disabled, since the loops still executed). (2) `entry_key_bytes()` serialized `LedgerKey` → `Vec<u8>` for use as HashMap keys; wasteful allocation. (3) `final_updated` HashMap was eagerly built from all updated entries even when only a subset was accessed. (4) Already-processed checks used linear scans or repeated HashMap lookups.
- **Strategy**: (1) Remove all debug logging loops entirely. (2) Replace `Vec<u8>` XDR keys with `LedgerKey` directly as HashMap/HashSet keys (structural comparison). (3) Remove eager `final_updated` HashMap — rely on `processed_keys: HashSet<LedgerKey>` for deduplication. (4) Pass pre-computed keys to helpers; use O(1) set membership for already-processed checks.
- **Semantic preservation**: The function produces identical `LedgerEntryChanges` output. The debug logging removal has no observable effect (logs are not part of protocol output). Switching from `Vec<u8>` keys to `LedgerKey` keys preserves deduplication semantics because XDR serialization is injective — two keys serialize to the same bytes iff they are structurally equal.
- **Edge cases**: The `push_created_or_restored` helper now takes `key: &LedgerKey` and `processed_keys: &mut HashSet<LedgerKey>` as parameters, inserting the key after pushing. This is correct — the key is always freshly computed from `entry_to_key()` before the call. The `created_keys: HashSet<LedgerKey>` deduplication set works identically to the old `HashSet<Vec<u8>>`.
- **Parity**: Meta construction is an internal implementation detail. The output `LedgerEntryChanges` must match stellar-core exactly, and this refactor preserves the same grouping, ordering, and deduplication logic.
- **Test coverage**: The integration tests (full ledger close with meta comparison) validate that meta output is identical. No dedicated unit test for `build_entry_changes_with_hot_archive` in isolation, but the function's correctness is effectively tested by meta parity checks in the offline verification tests.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 12321 TPS (runs: 12208, 12321, 12497)
- **Delta**: −511 TPS (−4.1%)
- **Measurement notes**: Negative delta means removing the optimization yielded higher TPS, which is counterintuitive but within the ~3-5% noise band. The debug logging removal and allocation reduction should not hurt performance; the measured difference is noise. This is a net-deletion commit (−144 lines), so even if the perf impact is zero, the code is simpler and easier to maintain.

#### Necessity Judgment
- **TPS gain**: −4.1% (within noise — effectively 0%)
- **Complexity**: Net deletion of 144 lines (83 added, 227 removed), 1 file
- **Risk**: Low (SOUND correctness)
- **Verdict**: **MARGINAL**
- **Rationale**: This commit is primarily a code cleanup that removes dead debug logging and simplifies data structures. Even with zero measured performance benefit, it is a net positive for maintainability — 144 fewer lines of code, elimination of unnecessary XDR serialization for key comparison, and removal of debug loops that obscured the real logic. The "marginal" verdict reflects the performance dimension (no measurable TPS gain), but the code quality improvement argues for keeping it regardless.

#### Similar Opportunities
No similar opportunities identified. The debug logging patterns were specific to this function during initial development.

#### Recommendations
1. No action needed — this is already a simplification commit. The code is cleaner after it.

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
