# Performance Fix Reviews (Mar 9–15, 2026)

27 performance optimization commits applied to the ledger close hot path.

## Review Status

Reviewed commits are benchmarked against HEAD (`d9a4a32`). "Without fix" =
HEAD with the optimization surgically removed.

Session: `8c11d208` — artifacts at `~/data/8c11d208/`.

### Baseline calibration

Two baseline measurement sessions were conducted:

| Session | Date | Median | Runs |
|---------|------|--------|------|
| Original | Mar 15 21:22 | **11810** | 11792, 11810, 11917 |
| Recheck | Mar 16 13:50 | **12564** | 13047, 12533, 12564 |

The **6.4% gap** between sessions (same binary, same command, same machine)
reveals significant environmental variance. The recheck was conducted when
the machine was under less load. Both sessions ran with a mainnet validator
consuming ~22% CPU in the background.

**Impact on analysis**: The "without" binaries for commits #1–22 were
benchmarked concurrently with each other (batch of 3 runs per commit,
running back-to-back, but multiple commits ran in the same session). The
"without" binaries for #20, #23–27 were benchmarked serially with no other
benchmarks running. Comparing concurrent "without" measurements against the
concurrent original baseline (11810) is internally consistent. Comparing
serial "without" measurements (#20, #23–27) against the recheck baseline
(12564) is more accurate.

The table below uses the **recheck baseline (12564)** for commits measured
serially (#20, #23–27), and the **original baseline (11810)** for those
measured in the concurrent batch (#1–19, #21–22). This ensures each delta
compares measurements taken under similar conditions.

| # | Commit | Correctness | Baseline | Without | Delta | Necessity |
|---|--------|-------------|----------|---------|-------|-----------|
| 1 | `f901afb` | SOUND | 11810 | 11981 | −1.4% | MARGINAL |
| 2 | `b74e111` | SOUND | 11810 | 12145 | −2.8% | MARGINAL |
| 3 | `3b48532` | SOUND | 11810 | 12321 | −4.1% | MARGINAL |
| 4 | `0edb0d4` | SOUND | — | — | — | SUPERSEDED |
| 5 | `87e7c2e` | SOUND | 11810 | 10189 | +15.9% | **ESSENTIAL** |
| 6 | `d95e7e2` | SOUND | 11810 | 12264 | −3.7% | MARGINAL |
| 7 | `cd10876` | SOUND | 11810 | ~357† | ~3200% | **ESSENTIAL** |
| 8 | `7460dd7` | SOUND | 11810 | 11930 | −1.0% | MARGINAL |
| 9 | `a0cdeae` | SOUND | 11810 | 12309 | −4.1% | MARGINAL |
| 10 | `beba273` | SOUND | 11810 | 12137 | −2.7% | MARGINAL |
| 11 | `f0fabc5` | SOUND | 11810 | 12040 | −1.9% | MARGINAL |
| 12 | `2c50ca5` | SOUND | — | — | — | SUPERSEDED |
| 13 | `bae9e05` | SOUND | 11810 | 12065 | −2.1% | MARGINAL |
| 14 | `98bbce4` | SOUND | 11810 | 12142 | −2.7% | MARGINAL |
| 15 | `e7fde6b` | SOUND | 11810 | 12088 | −2.3% | MARGINAL |
| 16 | `0c66a74` | SOUND | — | — | — | WORTHWHILE‡ |
| 17 | `3beef9f` | SOUND | — | — | — | WORTHWHILE‡ |
| 18 | `1e915d7` | SOUND | 11810 | 11479 | +2.9% | MARGINAL |
| 19 | `066299f` | SOUND | 11810 | 12745 | −7.3% | MARGINAL |
| 20 | `022f0ba` | SOUND | **12564** | 10382 | **+21.0%** | **ESSENTIAL** |
| 21 | `aeea796` | SOUND | 11810 | 11951 | −1.2% | MARGINAL |
| 22 | `06a0b3d` | SOUND | 11810 | 12364 | −4.5% | MARGINAL |
| 23 | `1067f46` | SOUND | **12564** | 11082 | **+13.4%** | **ESSENTIAL** |
| 24 | `0bfec57` | SOUND | **12564** | 11367 | **+10.5%** | **WORTHWHILE** |
| 25 | `1952c77` | SOUND | **12564** | 9636 | **+30.4%** | **ESSENTIAL** |
| 26 | `3bc76a2` | SOUND | **12564** | 10391 | **+20.9%** | **ESSENTIAL** |
| 27 | `011a745` | SOUND | **12564** | 10106 | **+24.3%** | **ESSENTIAL** |

† Commit #7: first ledger took 140s vs 4s; benchmark timed out at 300s.
‡ Commits #16/#17: unable to isolate (Arc deeply integrated across 27 files); qualitative review only.

**Baseline caveat for commits #1–19, #21–22**: These "without" benchmarks
were measured in a concurrent batch session alongside the original baseline
(11810). If we instead use the recheck baseline (12564), several MARGINAL
commits shift to small positive deltas (+2–5%). This suggests many of them
*do* contribute measurably, but the effect is small and the measurement
uncertainty is too high to distinguish individual contributions.

**Verdict summary**: 7 ESSENTIAL, 3 WORTHWHILE, 15 MARGINAL, 2 SUPERSEDED.
All 27 commits are **SOUND** — no correctness concerns found.

## Phase 4 Re-measurement (Session `7212e6cb`)

The original Phase 2/3 measurements suffered from 5-7% environmental drift between
baseline and "without" runs (a background mainnet validator consumed variable CPU).
Phase 4 re-measures all REVERT and CONSIDER REVERTING commits with strict protocol:

- **Same-session baseline**: 3 runs, take median, measured immediately before/after each commit
- **Surgical isolation**: Remove the optimization from HEAD, build, benchmark, restore
- **Baseline**: **12224 TPS** (runs: 12194, 12269, 12224; confirmed at 12231, 12257, 12179)
- **Artifacts**: `~/data/7212e6cb/`

### Phase 4 Results

| # | Commit | Without TPS | Baseline | Delta | Phase 2 Delta | Verdict |
|---|--------|-------------|----------|-------|---------------|---------|
| 21 | `aeea796` | 12186 | 12224 | **+0.3%** | −1.2% | NOISE — no measurable gain |
| 15 | `e7fde6b` | 12073 | 12224 | **+1.2%** | −2.3% | NOISE/MARGINAL — borderline |
| 1 | `f901afb` | 12075 | 12224 | **+1.2%** | −1.4% | NOISE/MARGINAL — borderline |
| 14 | `98bbce4` | 12193 | 12224 | **+0.3%** | −2.7% | NOISE — no measurable gain |
| 18 | `1e915d7` | 12291 | 12224 | **−0.5%** | +2.9% | NOISE — no measurable gain |
| 13 | `bae9e05` | 12164 | 12224 | **+0.5%** | −2.1% | NOISE — no measurable gain |
| 10 | `beba273` | — | — | — | −2.7% | NOT ISOLATABLE — qualitative only |
| 4 | `0edb0d4` | — | — | — | −5.6% | SUPERSEDED by OfferStore |

**Key finding**: With same-session baseline measurement, **none** of the MARGINAL
commits show a statistically significant gain. The largest delta is +1.2% for
commits #1 and #15, which is at the boundary of measurement noise (~2-3%).

**Benchmark path caveat**: The `apply-load` benchmark uses `prepare_presorted`
(from commit #27) which **skips hashing and sorting**. Commits that optimize the
`prepare_with_hash` / `sort_parallel_stages` path (#21 parallel hashing, #10 hash
pre-computation) are invisible to the benchmark. Their value is on the production
path only.

## Revert Recommendations

For the 15 MARGINAL commits, we assessed whether each should be reverted based
on complexity cost (lines added, conceptual complexity, maintenance burden) and
whether it has been superseded by later commits. Phase 4 re-measurement with
same-session baselines showed that **none** of the MARGINAL commits have a
statistically significant benchmark gain. All deltas are within noise (≤1.2%).

The three categories are:

- **REVERT**: Complexity outweighs value. Remove.
- **CONSIDER REVERTING**: Borderline — moderate complexity for no measured gain. Review case-by-case.
- **KEEP**: Low complexity, good code quality, or provides production-path value even without benchmark gain.

### REVERT (3 commits)

| Commit | # | Lines | Phase 4 Δ | Reason |
|--------|---|-------|-----------|--------|
| `aeea796` | 21 | +150/−38 | +0.3% (noise) | Manual `std::thread::scope` parallelization of TX hash computation. Superseded by #27's `prepare_presorted` which skips hashing entirely. Adds concurrency complexity for no measured gain on either benchmark or production path. |
| `1e915d7` | 18 | +80/−15 | −0.5% (noise) | `IncrementalMergeOutput` abstraction for streaming merge hashing. Adds a new struct/API layer with no measured gain. The streaming hash pattern from #13 already handles the general case. |
| `98bbce4` | 14 | +93/−59 | +0.3% (noise) | Structural key comparison for bucket dedup via sort+dedup. Superseded by #25's `add_batch_unique` which skips dedup on the hot path. The old HashMap dedup at line 1072 is kept as dead code — reverting is mechanical. |

### CONSIDER REVERTING (3 commits)

| Commit | # | Lines | Phase 4 Δ | Reason |
|--------|---|-------|-----------|--------|
| `f901afb` | 1 | +134/−43 | +1.2% (borderline) | Threads `Option<&TtlKeyCache>` through ~15 function signatures across 6 files. Phase 4 shows +1.2% gain — borderline significant. Combined with #15 (which depends on it), the pair contributes ~1.2%. The signature threading complexity is the main cost. |
| `e7fde6b` | 15 | +3/−2 | +1.2% (borderline) | Reuses TTL cache across TXs. Depends on #1 — if #1 is reverted, this must go too. Trivially simple on its own, but the measured benefit (+1.2%) is borderline. |
| `beba273` | 10 | +256/−38 | not isolatable | ~60% is perf-logging infrastructure. Hash pre-computation targets production `prepare_with_hash` path (bypassed by benchmark). Cannot cleanly measure. Consider extracting perf logging and reverting hash table. |

### KEEP (9 commits — includes #4 and #13 moved from prior categories)

| Commit | # | Lines | Reason |
|--------|---|-------|--------|
| `0edb0d4` | 4 | +236/−77 | **SUPERSEDED** — entirely replaced by OfferStore. Code is dead but harmless; will be removed when OfferStore lands. |
| `bae9e05` | 13 | +43/−5 | Phase 4: +0.5% (noise). But `Sha256Writer` is reused by #24 (WORTHWHILE). `OnceCell` TX set hash caching provides correctness value on production path. Low complexity, keep. |
| `3b48532` | 3 | +83/−227 | Net −144 lines. Pure cleanup: removes dead debug logging, simplifies data structures. Code is better after this commit regardless of performance. |
| `7460dd7` | 8 | +233/−194 | Mechanical `.clone()` removal. More idiomatic Rust, better move semantics. Net +39 lines but purely mechanical. |
| `b74e111` | 2 | +108/−93 | `DeltaSlice<'a>` zero-copy abstraction. Genuine API improvement — callers work with slices instead of cloned Vecs. Savepoint skip superseded by #7 but slice type is still valuable. |
| `d95e7e2` | 6 | +100/−60 | Skip ed25519 point decompression on cache hits. Architecturally correct (matches stellar-core), simplifies call sites by passing raw bytes. |
| `f0fabc5` | 11 | +72/−28 | `sort_by_cached_key` in TX set builder. Idiomatic Rust stdlib usage. Essential for production herder path even though benchmark bypasses it. |
| `066299f` | 19 | +68/−53 | `CountingWriter` for XDR size checks. Eliminates 8 allocation-to-measure sites. Clean API improvement. |
| `a0cdeae` | 9 | +3/−2 | 5-line change: SHA-256 → BLAKE2 for cache key. Trivial, matches stellar-core, zero maintenance cost. |

### Summary

- **3 REVERT** commits total **+323/−112 lines** of complexity with no measured gain. Removing them simplifies the codebase.
- **3 CONSIDER REVERTING** commits total **+393/−83 lines**. Commits #1+#15 show borderline +1.2% gain — keep if the 25-signature threading complexity is acceptable. #10 cannot be measured.
- **9 KEEP** commits are net-positive for code quality regardless of performance (includes 2 SUPERSEDED).

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
- **Phase 4 re-measurement** (session `7212e6cb`): Without: 12075 (runs: 12113, 12075, 12026), Baseline: 12224 → **+1.2% (borderline)**. Surgical isolation: made `get_or_compute_key_hash` always ignore the cache (bypass lookup, always compute). Same-session measurement shows a small but borderline gain.
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

#### Commit Summary
- **Hash**: `0edb0d4851dddd983eb8b02297ccc510efd76585`
- **Message**: Split offer/non-offer metadata maps for O(1) clear on ledger advance
- **Files changed**: `crates/tx/src/state/entries.rs`, `crates/tx/src/state/mod.rs`, `crates/tx/src/state/sponsorship.rs` (+236/−77)
- **Optimization category**: Data structure split (O(n) scan → O(1) clear)

#### Correctness Review
- **Hot path**: `clear_cached_entries_preserving_offers` in `LedgerStateManager`, called on ledger advance to clear non-offer cached state while preserving offer data for the order book.
- **Problem**: `entry_sponsorships`, `entry_sponsorship_ext`, and `entry_last_modified` were single maps containing both offer and non-offer entries. Clearing non-offer entries required `.retain(|k, _| is_offer_key(k))` — an O(n) scan of every entry.
- **Strategy**: Split each map into offer-specific and non-offer variants. Route all inserts/gets/removes through an `is_offer_key()` helper. On clear, just call `.clear()` on the non-offer maps (O(1)) while leaving offer maps intact.
- **Semantic preservation**: All 9 accessor methods route through the same `is_offer_key()` discriminant. The combined view is identical to the single-map approach. The rollback paths (Phase 6 and op-level) were updated to route through the same `is_offer_key` checks.
- **Edge cases**: Rollback paths collect snapshots into `Vec` before draining to satisfy the borrow checker — this is a correctness fix for the new split structure. The `is_offer_key()` check matches `LedgerKey::Offer(_)` only, consistent with stellar-core's `OfferFrame` check.
- **Parity**: Internal implementation detail. The offer preservation semantics match stellar-core's `LedgerTxn::seal()` which also preserves offer state across ledger closes.
- **Test coverage**: Covered by integration tests (full ledger close). No dedicated unit test for the split map behavior.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 12513 TPS (runs: 12106, 12513, 12591)
- **Delta**: −703 TPS (−5.6%)
- **Measurement notes**: Negative delta (removing the optimization yields higher TPS) is at the edge of benchmark noise (~3-5%). The SAC-transfer-only benchmark workload has no offer entries, so the `.retain()` scan operates on an empty or very small map. In production with offers, this optimization would have a real impact. The benchmark result is effectively neutral.

#### Necessity Judgment
- **TPS gain**: −5.6% (at edge of noise, no offers in benchmark)
- **Complexity**: +236/−77 lines, 3 files, adds 6 new map fields + 9 routing methods
- **Risk**: Low (SOUND correctness)
- **Verdict**: **SUPERSEDED**
- **Phase 4 note**: The split-map optimization has been entirely replaced by the OfferStore implementation. The offer-specific and non-offer map split is now dead code. Will be removed when OfferStore lands as the production offer management solution.
- **Rationale**: The optimization targets a real production scenario (offer-heavy ledgers) but the benchmark workload has no offers, making the gain unmeasurable. The split-map approach adds significant code surface area (9 routing methods, split rollback logic). For production workloads with offers, this would be beneficial. For the benchmark workload, it's pure complexity.

#### Similar Opportunities
No similar opportunities identified.

#### Recommendations
1. Consider measuring with a mixed-workload benchmark (offers + SAC transfers) to validate the production benefit.

### 5. `87e7c2e` — Ed25519 signature verification cache

#### Commit Summary
- **Hash**: `87e7c2e82e216e6b207a8fb75cc1e07142668eac`
- **Message**: Add global ed25519 signature verification cache
- **Files changed**: `crates/crypto/Cargo.toml`, `crates/crypto/src/signature.rs` (+91/−2)
- **Optimization category**: Caching (cryptographic result memoization)

#### Correctness Review
- **Hot path**: `verify_hash()` in `crates/crypto/src/signature.rs` — called for every ed25519 signature verification across all TX validation and execution paths.
- **Problem**: ed25519 signature verification (~50µs per call) was performed from scratch on every invocation, even when the same TX is verified during nomination/validation and again during apply.
- **Strategy**: Add a global `SigVerifyCache` (FIFO, 250K entries) using `HashMap<[u8;32], ()>` + `VecDeque<[u8;32]>`. Cache key = SHA-256(pubkey || signature || message_hash). On `verify_hash()`, check cache first; on miss, verify and insert.
- **Semantic preservation**: The cache only stores verified-valid signatures. A cache hit means the signature was previously verified as valid — returning Ok(()) is correct. Cache misses fall through to the full verification path. Invalid signatures are never cached.
- **Edge cases**: The 250K FIFO eviction is approximate (HashMap + VecDeque). Under high load, recently-verified signatures could be evicted before reuse, but this only causes a performance miss, not a correctness issue. The `Mutex` lock is held only for the HashMap lookup (~50ns), not during the ed25519 verify (~50µs).
- **Parity**: Matches stellar-core's `gVerifySigCache` in `SecretKey.cpp` — same 250K-entry FIFO design, same cache-before-verify pattern.
- **Test coverage**: No dedicated cache test. Covered by existing signature verification tests which exercise the code path with cache active.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 10189 TPS (runs: 10195, 10189, 10022)
- **Delta**: +1621 TPS (+15.9%)
- **Measurement notes**: Clear and consistent improvement across all 3 runs. Removing the cache forces full ed25519 verification on every signature check, which is the dominant cost for TX validation. The +15.9% gain is well outside noise.

#### Necessity Judgment
- **TPS gain**: +15.9% (large, consistent, outside noise)
- **Complexity**: +91/−2 lines, 2 files, straightforward cache implementation
- **Risk**: Low (SOUND correctness, matches stellar-core design)
- **Verdict**: **ESSENTIAL**
- **Rationale**: The signature verification cache provides a large, consistent throughput improvement by avoiding redundant ed25519 crypto operations. The implementation is clean, matches stellar-core's design, and has minimal complexity cost. This is the highest-impact single optimization after #7.

#### Similar Opportunities
No similar opportunities — all ed25519 verification paths already route through this cache.

#### Recommendations
1. No action needed — the implementation is clean and effective.

### 6. `d95e7e2` — Skip point decompression on cache hits

#### Commit Summary
- **Hash**: `d95e7e26ee3d2cf21269822fa7b99e8d2c451b96`
- **Message**: Avoid ed25519 point decompression on signature cache hits
- **Files changed**: `crates/crypto/src/signature.rs`, `crates/herder/src/tx_queue/mod.rs`, `crates/ledger/src/execution/mod.rs`, `crates/ledger/src/execution/signatures.rs`, `crates/tx/src/lib.rs`, `crates/tx/src/signature_checker.rs`, `crates/tx/src/validation.rs` (+100/−60)
- **Optimization category**: Pipeline reordering (check cache before expensive work)

#### Correctness Review
- **Hot path**: All 4 signature verification call sites in `execution/mod.rs`, `execution/signatures.rs`, `herder/tx_queue/mod.rs`, and `signature_checker.rs`.
- **Problem**: Even on cache hits, the caller was first decompressing the 32-byte public key into an ed25519 `PublicKey` object (~35µs), then calling `verify_hash()` which checked the cache. On a cache hit, the decompression was wasted work.
- **Strategy**: Add `verify_hash_from_raw_key()` that accepts `&[u8; 32]` raw bytes, checks the cache first, and only decompresses on a cache miss. Refactor all call sites to pass raw bytes instead of decompressed `PublicKey`.
- **Semantic preservation**: The raw key bytes are the same bytes that would have been decompressed into a `PublicKey` — the cache key computation uses the raw bytes in both paths. On cache miss, the decompression happens inside `verify_hash_from_raw_key()` before the actual ed25519 verify.
- **Edge cases**: Decompression failures (invalid public key bytes) were previously caught by the `if let Ok(pk) = PublicKey::from_bytes()` guard at call sites. Now they're deferred to the cache miss path inside `verify_hash_from_raw_key()`. This is correct because: (a) on cache hit, we already know the key is valid (it was previously verified); (b) on cache miss, the decompression failure will return `CryptoError::InvalidPublicKey`.
- **Parity**: Matches stellar-core's `PubKeyUtils::verifySig` which checks the cache before touching the crypto library.
- **Test coverage**: Covered by existing signature verification tests. No dedicated test for the raw-key path vs decompressed-key path.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 12264 TPS (runs: 12264, 12096, 12630)
- **Delta**: −454 TPS (−3.7%)
- **Measurement notes**: The delta is within benchmark noise. The decompression skip matters most when the cache hit rate is high (60-80% in steady state). In the benchmark's single-shot mode with fresh cache, the hit rate is lower, diluting the benefit. The real benefit compounds with commit #5 (the cache itself).

#### Necessity Judgment
- **TPS gain**: −3.7% (within noise)
- **Complexity**: +100/−60 lines, 7 files, new `verify_hash_from_raw_key()` function + call site refactoring
- **Risk**: Low (SOUND correctness)
- **Verdict**: **MARGINAL**
- **Rationale**: The optimization is architecturally sound — checking cache before decompression is the right order of operations, matching stellar-core. However, the benchmark doesn't show a measurable gain because the cache hit rate in single-shot mode is low. In production with steady-state cache, this would save ~35µs per cached verification. The code change is moderate (7 files) but purely mechanical.

#### Similar Opportunities
No similar opportunities — the decompression skip applies only to the signature verification path.

#### Recommendations
1. No action needed — the optimization is correct and aligns with stellar-core's design.

### 7. `cd10876` — O(1) snapshot for TX rollback

#### Commit Summary
- **Hash**: `cd108768a8ec8c20452de06b4b705a8f496efdaf`
- **Message**: Replace O(N) delta clone with O(1) length snapshot for TX rollback
- **Files changed**: `crates/tx/src/apply.rs`, `crates/tx/src/state/mod.rs` (+29/−5)
- **Optimization category**: Algorithmic improvement (O(N) clone → O(1) snapshot)

#### Correctness Review
- **Hot path**: `snapshot_delta()` in `TransactionApplicator`, called before each TX execution to create a rollback point.
- **Problem**: `snapshot_delta()` cloned the entire `LedgerDelta` (all created, updated, deleted entries) before each TX. As TXs accumulate in a cluster, the delta grows and each clone becomes O(N) where N is the cumulative entry count — profiling showed 92.8ms/ledger (47.8% of soroban execution).
- **Strategy**: Since the delta is append-only between snapshot and rollback, replace the full clone with a lightweight `DeltaSnapshot` that captures just the vector lengths and `fee_charged`. On rollback, `truncate_to()` restores the pre-TX state in O(1) by truncating vectors.
- **Semantic preservation**: The append-only property of the delta between snapshot and TX execution is a key invariant. Created/updated/deleted entries are only appended during TX execution, never removed or reordered. `truncate_to()` discards exactly the entries added by the failed TX, restoring the delta to its pre-TX state. `fee_charged` is restored separately via `set_fee_charged()`.
- **Edge cases**: If the append-only invariant were violated (e.g., an entry was removed mid-TX), truncation would produce incorrect results. This invariant is maintained by the current code: `LedgerDelta::add_created()`, `add_updated()`, and `add_deleted()` only push to vectors; no remove/pop operations exist on these vectors outside of `truncate_to()`.
- **Parity**: Internal implementation detail. stellar-core uses nested `LedgerTxn` with commit/abort semantics, which is equivalent to our snapshot/rollback approach.
- **Test coverage**: Covered by integration tests (TX rollback on failure). No dedicated unit test for `DeltaSnapshot`/`truncate_to()`.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS
- **Without fix**: ~357 TPS (first ledger), then timed out at 300s — benchmark did not complete.
- **Delta**: ~**3200%** improvement
- **Measurement notes**: Without this optimization, the O(N) delta clone grows quadratically as TXs accumulate in each cluster. With 50K TXs across 4 clusters (~12.5K/cluster), each clone copies an increasingly large delta. The first ledger took ~140 seconds vs ~4 seconds with the optimization. The benchmark timed out at 300 seconds. This is the single most impactful optimization in the entire series — without it, the system is fundamentally non-viable at scale.

#### Necessity Judgment
- **TPS gain**: ~3200% (system non-functional without it)
- **Complexity**: +29/−5 lines, 2 files, minimal and elegant
- **Risk**: Low (SOUND correctness, relies on well-maintained append-only invariant)
- **Verdict**: **ESSENTIAL**
- **Rationale**: This is the most critical optimization in the series. The 29-line change eliminates a quadratic bottleneck that makes the system non-functional at scale. The approach is elegant — capturing vector lengths instead of cloning the entire data structure. The append-only invariant it relies on is naturally maintained by the delta's API. Removing this would render the system unusable for any meaningful workload.

#### Similar Opportunities
No similar opportunities — the delta snapshot was the only remaining O(N) clone in the per-TX path.

#### Recommendations
1. Consider adding a debug assertion in `truncate_to()` that verifies the vector lengths are >= the snapshot lengths, to catch any future violation of the append-only invariant.

### 8. `7460dd7` — Eliminate ~39 unnecessary `.clone()` calls

#### Commit Summary
- **Hash**: `7460dd7`
- **Message**: Eliminate ~39 unnecessary .clone() calls on XDR types
- **Files changed**: `crates/ledger/src/execution/mod.rs`, `crates/ledger/src/manager.rs`, `crates/tx/src/operations/execute/change_trust.rs`, `crates/tx/src/operations/execute/offer_utils.rs`, `crates/tx/src/state/entries.rs`, `crates/tx/src/state/mod.rs` (+233/−194)
- **Optimization category**: Clone elimination (borrows and moves)

#### Correctness Review
- **Hot path**: Multiple functions across the TX execution pipeline.
- **Problem**: ~39 `.clone()` calls on XDR types (`LedgerEntry`, `AccountEntry`, `Hash`, etc.) where the original value was not used after the clone site. Each clone deep-copies nested XDR structures (~100-500 bytes).
- **Strategy**: Replace clones with borrows (`&`), moves (reorder operations so the move happens last), `std::mem::take` for owned containers, and direct `Hash256::from_bytes` access for hash wrappers.
- **Semantic preservation**: Each elimination was verified: the cloned value was either (a) not used after the clone (replaced with move), (b) only read after the clone (replaced with borrow), or (c) extractable via `mem::take` leaving a default in the source. No behavior change.
- **Edge cases**: `std::mem::take` on `Vec` and `Option` fields leaves them as `Default::default()` — callers of those fields after the take would see empty values. The commit was careful to only take fields that are not read afterward.
- **Parity**: Internal implementation detail — no observable behavior change.
- **Test coverage**: Covered by existing tests. No new tests needed for clone elimination.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 11930 TPS (runs: 11761, 11995, 11930)
- **Delta**: −120 TPS (−1.0%)
- **Measurement notes**: Delta is well within noise. The ~39 clone eliminations save ~3µs × 39 ≈ 120µs per TX in theory, but XDR type clones are fast (memcpy of contiguous data), and the savings are spread across many call sites with small per-site impact.

#### Necessity Judgment
- **TPS gain**: −1.0% (within noise — effectively 0%)
- **Complexity**: +233/−194 lines (net +39), 6 files — mostly mechanical
- **Risk**: Low (SOUND correctness)
- **Verdict**: **MARGINAL**
- **Rationale**: The clone eliminations are individually correct and collectively make the code more idiomatic (move semantics where appropriate). However, the measurable performance impact is zero. This is a code quality improvement rather than a performance optimization.

#### Similar Opportunities
No additional low-hanging clone eliminations identified in the current codebase.

#### Recommendations
1. No action needed — the changes are already applied and improve code quality.

### 9. `a0cdeae` — BLAKE2 sig cache key

#### Commit Summary
- **Hash**: `a0cdeae`
- **Message**: Switch sig verify cache key from SHA-256 to BLAKE2
- **Files changed**: `crates/crypto/src/signature.rs` (+3/−2)
- **Optimization category**: Algorithm swap (faster hash function)

#### Correctness Review
- **Hot path**: `compute_cache_key()` in the signature verification cache, called on every cache lookup/insert.
- **Problem**: SHA-256 was used to compute the cache key from `(pubkey, signature, message_hash)`. BLAKE2b is faster for this use case.
- **Strategy**: Replace `Sha256::new()` with `Blake2b256::new()` in `compute_cache_key()`. The output is still 32 bytes.
- **Semantic preservation**: The cache key is only used for cache lookup — it's not part of any protocol output. Changing the hash function changes which bucket entries map to, but the cache is ephemeral and rebuilt each run. No observable behavior difference.
- **Edge cases**: None — the hash function is used purely internally.
- **Parity**: Matches stellar-core's use of BLAKE2 for `gVerifySigCache` key computation.
- **Test coverage**: Covered by existing signature verification tests.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 12309 TPS (runs: 12263, 12309, 12367)
- **Delta**: −499 TPS (−4.1%)
- **Measurement notes**: Within noise. The ~3.9% difference between SHA-256 and BLAKE2b cache key computation is too small to measure in the end-to-end benchmark, though micro-benchmarks showed ~0.9ms/ledger savings.

#### Necessity Judgment
- **TPS gain**: −4.1% (within noise)
- **Complexity**: +3/−2 lines, 1 file — trivial change
- **Risk**: None (SOUND correctness, 3-line change)
- **Verdict**: **MARGINAL**
- **Rationale**: The change is virtually zero-cost in complexity (3 lines) and matches stellar-core's choice of BLAKE2 for this purpose. Even with no measurable TPS gain, there's no reason to revert a 3-line improvement.

#### Similar Opportunities
No similar opportunities — this is the only internal hash computation that was using SHA-256 unnecessarily.

#### Recommendations
1. No action needed.

### 10. `beba273` — Pre-compute TX hashes

#### Commit Summary
- **Hash**: `beba273`
- **Message**: Pre-compute TX hashes to eliminate O(n log n) redundant hashing in prepare
- **Files changed**: `crates/henyey/src/main.rs`, `crates/ledger/src/close.rs`, `crates/ledger/src/execution/tx_set.rs`, `crates/ledger/src/lib.rs`, `crates/ledger/src/manager.rs`, `crates/simulation/src/applyload.rs` (+256/−38)
- **Optimization category**: Hash precomputation (O(n log n) → O(n))

#### Correctness Review
- **Hot path**: `apply_sort_cmp()` in `prepare()` and `apply_transactions()` in the ledger manager.
- **Problem**: `apply_sort_cmp()` called `tx_hash()` (XDR serialize + SHA-256) on every comparison during sort. For 25K TXs with O(n log n) sort, this caused ~375K hash computations. The same hashes were also recomputed in apply and meta-building.
- **Strategy**: Pre-compute all TX hashes into a lookup table before sorting. Pass the hash table through prepare, apply, and meta-building phases.
- **Semantic preservation**: The hash values are identical — they're just computed once instead of repeatedly. The sort order is preserved because the comparison function uses the same hash values.
- **Edge cases**: If a TX envelope is not found in the hash table, the code falls back to computing the hash on the fly. This handles any edge case where the table is incomplete.
- **Parity**: TX hash computation is deterministic. Pre-computing doesn't change values.
- **Test coverage**: Covered by integration tests. Also adds single-shot benchmark mode and per-phase perf instrumentation.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 12137 TPS (runs: 11982, 12146, 12137)
- **Delta**: −327 TPS (−2.7%)
- **Phase 4 assessment** (session `7212e6cb`): **NOT ISOLATABLE** — hash pre-computation woven into production path (`prepare_with_hash`) and performance logging across 5 files (~130 lines). Cannot safely remove. Benchmark uses `prepare_presorted` which bypasses this path entirely, so the optimization is invisible to the benchmark but important for production.
- **Measurement notes**: Within noise. The hash precomputation was a huge win in the original commit (+29% TPS at the time) because `prepare()` was doing O(n log n) hash recomputations. However, subsequent commits (#11's `sort_by_cached_key` and #27's `prepare_presorted`) largely eliminated redundant hashing in the sort path, making this commit's precomputation table redundant for the current benchmark. The prepare phase is no longer the bottleneck it was.

#### Necessity Judgment
- **TPS gain**: −2.7% (within noise — superseded by later commits)
- **Complexity**: +256/−38 lines, 6 files, introduces hash lookup table threading
- **Risk**: Low (SOUND correctness)
- **Verdict**: **MARGINAL**
- **Rationale**: This was a critical optimization when introduced (+29% TPS) but has been largely superseded by commits #11 and #27 which address the same redundant-hashing problem more directly. The hash table is still used but the incremental benefit over the current baseline is unmeasurable. The code adds moderate complexity (threading the hash table through multiple phases).

#### Similar Opportunities
No similar opportunities — all TX hash computation paths are now addressed.

#### Recommendations
1. Consider whether the hash precomputation table can be simplified or removed given that #27's `prepare_presorted` skips hashing entirely in the benchmark path.

### 11. `f0fabc5` — Cache hashes in TX set build (+77% TPS)

#### Commit Summary
- **Hash**: `f0fabc5`
- **Message**: Optimize TX set build: cache hashes and eliminate clones (+77% TPS)
- **Files changed**: `crates/herder/src/parallel_tx_set_builder.rs`, `crates/simulation/src/applyload.rs`, `docs/perf-hypotheses.md` (+72/−28)
- **Optimization category**: Sort optimization (O(n log n) hash recomputation → cached)

#### Correctness Review
- **Hot path**: `stages_to_xdr_phase()` in the parallel TX set builder, called during TX set construction.
- **Problem**: `sort_by(|a, b| a.hash().cmp(&b.hash()))` re-computed XDR serialize + SHA-256 on every comparison. For 25K TXs with ~275K comparisons, this was ~550K hash operations.
- **Strategy**: Replace `sort_by` with `sort_by_cached_key` which computes the hash once per element (O(n)) and sorts using cached values. Also change `build_two_phase_tx_set` to take owned vectors, and use `into_iter()` instead of `iter().cloned()`.
- **Semantic preservation**: `sort_by_cached_key` produces the same sort order as `sort_by` — it just caches the key. The owned-vector change eliminates a layer of cloning without affecting the output.
- **Edge cases**: `sort_by_cached_key` uses a stable sort, which is the same as `sort_by`. Order of equal-key elements is preserved.
- **Parity**: TX set canonical ordering is unchanged.
- **Test coverage**: Covered by integration tests. The +77% TPS claim was measured at the time of the commit.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 12040 TPS (runs: 12033, 12126, 12040)
- **Delta**: −230 TPS (−1.9%)
- **Measurement notes**: Within noise. The benchmark path now uses `stages_to_xdr_phase_unsorted` (added by commit #27) which skips canonical sorting entirely for the presorted prepare path. The `sort_by_cached_key` optimization in `stages_to_xdr_phase` is only exercised in the production herder path, not the benchmark. The original +77% gain was real but has been superseded.

#### Necessity Judgment
- **TPS gain**: −1.9% (within noise — benchmark path bypasses the sort)
- **Complexity**: +72/−28 lines, 3 files — moderate
- **Risk**: Low (SOUND correctness)
- **Verdict**: **MARGINAL** (for benchmark), **ESSENTIAL** (for production herder path)
- **Rationale**: The `sort_by_cached_key` optimization is critical for the production herder path where TX sets are built from nominated transactions and sorted canonically. The benchmark bypasses this path via `prepare_presorted`. In production, without this optimization, TX set construction would re-hash every comparison, causing O(n log n) × hash_cost overhead.

#### Similar Opportunities
No similar opportunities — all sort-with-hash paths have been addressed.

#### Recommendations
1. No action needed — essential for production, not exercised in benchmark.

### 12. `2c50ca5` — Structural ScAddress compare (−23% add_batch)

#### Commit Summary
- **Hash**: `2c50ca5`
- **Message**: Optimize bucket entry comparison: structural ScAddress compare (−23% add_batch)
- **Files changed**: `crates/bucket/src/entry.rs` (+23/−6)
- **Optimization category**: Comparison optimization (XDR serialization → structural)

#### Correctness Review
- **Hot path**: `compare_sc_address()` in `crates/bucket/src/entry.rs`, called during bucket entry sorting.
- **Problem**: `compare_sc_address()` serialized both `ScAddress` values to XDR bytes via `to_xdr()` and compared the byte arrays. This allocated two `Vec<u8>` per comparison.
- **Strategy**: Compare by XDR discriminant first, then by variant content structurally. Handles `Account`, `Contract`, `MuxedAccount`, `LiquidityPool` structurally; falls back to XDR for `ClaimableBalance` (rare, complex inner type).
- **Semantic preservation**: XDR serialization is order-preserving for the simple variants (discriminant + fixed-length content). The structural comparison produces the same ordering as the XDR byte comparison.
- **Edge cases**: The `MuxedAccount` comparison uses `.id.cmp().then_with(|| .ed25519.cmp())` which matches XDR field order. The `ClaimableBalance` variant retains XDR comparison for correctness (complex nested discriminant).
- **Parity**: The ordering must match stellar-core's xdrpp byte ordering. The structural comparison is equivalent for all common variants.
- **Test coverage**: Covered by bucket merge tests.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Status**: **SUPERSEDED** — The `compare_sc_address` function was completely removed by a later commit (`84062b2`) that replaced all hand-written XDR comparison with derived `Ord`. There is no code left to revert.
- **Benchmark**: N/A — unable to isolate

#### Necessity Judgment
- **Verdict**: **SUPERSEDED**
- **Rationale**: This optimization was a stepping stone — it replaced XDR-serialize-and-compare with structural comparison for `ScAddress`. A subsequent commit (`84062b2`) went further and replaced all hand-written structural comparisons (including this one) with derived `Ord` implementations. The code from this commit no longer exists in HEAD. No benchmark or further review is needed.

#### Similar Opportunities
Addressed by the subsequent commit that derived `Ord` for all XDR types.

#### Recommendations
1. No action needed — already superseded.

### 13. `bae9e05` — Streaming XDR hashing

#### Commit Summary
- **Hash**: `bae9e05`
- **Message**: Optimize XDR hashing: streaming serialization and TX set hash caching
- **Files changed**: `crates/common/src/types.rs`, `crates/ledger/src/close.rs`, `crates/ledger/src/manager.rs` (+43/−5)
- **Optimization category**: Allocation elimination (streaming hash) + caching (OnceCell)

#### Correctness Review
- **Hot path**: `Hash256::hash_xdr()` (used throughout for XDR hashing) and `LedgerCloseData::tx_set_hash()` (called during prepare and header building).
- **Problem**: `hash_xdr()` serialized the entire XDR value to a `Vec<u8>`, then hashed the buffer. For large structures like `GeneralizedTransactionSet` (25K+ TXs), this allocated a large intermediate buffer. Also, `tx_set_hash()` recomputed the hash on every call.
- **Strategy**: (1) Implement `Sha256Writer` that feeds XDR bytes directly into SHA-256 without intermediate allocation. (2) Cache the TX set hash via `OnceCell` on `LedgerCloseData`. (3) Add `prepare_with_hash()` to accept a pre-computed hash.
- **Semantic preservation**: Streaming XDR serialization produces the same byte sequence as `to_xdr()` — the SHA-256 result is identical. The `OnceCell` caches the first computation and returns the same value on subsequent calls.
- **Edge cases**: The `Sha256Writer` always reports `Ok(buf.len())` — it cannot fail. The `OnceCell` is thread-safe for the single-threaded ledger close context.
- **Parity**: The hash value is identical to the allocating version.
- **Test coverage**: Covered by integration tests (hash comparison with expected values).
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 12065 TPS (runs: 12065, 12030, 12208)
- **Delta**: −255 TPS (−2.1%)
- **Phase 4 re-measurement** (session `7212e6cb`): Without: 12164 (runs: 12121, 12164, 12197), Baseline: 12224 → **+0.5% (noise)**. Surgical isolation: made `hash_xdr` serialize to `Vec<u8>` first then hash, bypassing `Sha256Writer` streaming. Confirms no measurable gain in the benchmark.
- **Measurement notes**: Within noise. The streaming hash avoids one large allocation per `hash_xdr()` call, but the dominant cost is the SHA-256 computation itself, not the allocation. The OnceCell caching of `tx_set_hash()` saves one redundant hash but this was already a small portion of the total cost.

#### Necessity Judgment
- **TPS gain**: −2.1% (within noise)
- **Complexity**: +43/−5 lines, 3 files — moderate
- **Risk**: Low (SOUND correctness)
- **Verdict**: **MARGINAL**
- **Rationale**: The streaming hash pattern is architecturally good — it eliminates a class of unnecessary allocations for large XDR structures. The OnceCell caching prevents redundant work. However, the end-to-end TPS impact is unmeasurable.

#### Similar Opportunities
The `Sha256Writer` pattern could be reused anywhere XDR values are hashed. It was later reused in commit #24 for streaming the transaction result hash.

#### Recommendations
1. No action needed — good pattern already in use.

### 14. `98bbce4` — Structural key comparison for bucket dedup

#### Commit Summary
- **Hash**: `98bbce4`
- **Message**: Optimize bucket dedup: structural key comparison instead of XDR serialization
- **Files changed**: `crates/bucket/src/bucket_list.rs`, `docs/perf-hypotheses.md` (+93/−59)
- **Optimization category**: Deduplication optimization (XDR HashMap → sort+dedup)

#### Correctness Review
- **Hot path**: `deduplicate_entries()` / `deduplicate_keys()` in `add_batch()`, called during bucket list update at ledger close.
- **Problem**: The original `deduplicate_entries()` serialized every `LedgerKey` to XDR bytes and used a `HashSet<Vec<u8>>` for deduplication. For 75K+ entries per ledger, this caused 75K+ XDR serializations and heap allocations.
- **Strategy**: Replace with sort+dedup using structural key comparison via `compare_keys()`. Sort by key, then dedup adjacent entries. Keep last occurrence by reversing before and after dedup.
- **Semantic preservation**: The dedup produces the same unique set — same entries, same "keep last" semantics. The sort order within the deduped output may differ but bucket entries are re-sorted by `compare_entries` afterward, so the final order is identical.
- **Edge cases**: The reverse-dedup-reverse pattern correctly keeps the LAST occurrence of each key (matching stellar-core semantics). Empty and single-element inputs are handled via early return.
- **Parity**: Deduplication semantics match stellar-core's `LiveBucket.cpp:414`.
- **Test coverage**: Covered by bucket list integration tests.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 12142 TPS (runs: 12142, 11990, 12222)
- **Delta**: −332 TPS (−2.7%)
- **Phase 4 re-measurement** (session `7212e6cb`): Without: 12193 (runs: 12072, 12193, 12286), Baseline: 12224 → **+0.3% (noise)**. Surgical isolation: swapped `deduplicate_entries_by_sort` calls to old `deduplicate_entries` (HashMap-based). Confirms no measurable gain — benchmark uses `add_batch_unique` which bypasses dedup entirely.
- **Measurement notes**: Within noise. The benchmark path now uses `add_batch_unique()` (commit #25) which bypasses deduplication entirely when entries come from a coalesced delta. The structural dedup in `deduplicate_entries_by_sort()` is only exercised in non-benchmark paths.

#### Necessity Judgment
- **TPS gain**: −2.7% (within noise — benchmark path bypasses dedup)
- **Complexity**: +93/−59 lines, 2 files — moderate
- **Risk**: Low (SOUND correctness)
- **Verdict**: **MARGINAL** (for benchmark), **WORTHWHILE** (for production non-coalesced paths)
- **Rationale**: Like commit #11, this optimization is bypassed in the benchmark by a later commit (#25's `add_batch_unique`). In production paths where entries may not be pre-deduplicated, the structural sort+dedup is significantly cheaper than the XDR-HashMap approach. The code is well-structured and adds the `#[allow(dead_code)]` marker on the old function.

#### Similar Opportunities
No similar opportunities — all dedup paths have been addressed.

#### Recommendations
1. Consider removing the dead `deduplicate_entries()` function if it's no longer called.

### 15. `e7fde6b` — Reuse TTL key cache across TXs

#### Commit Summary
- **Hash**: `e7fde6b`
- **Message**: Optimize per-TX overhead: reuse TTL key cache and zero-alloc ValDeser charging
- **Files changed**: `crates/ledger/src/execution/mod.rs` (+3/−2)
- **Optimization category**: Cache reuse (per-TX → per-cluster)

#### Correctness Review
- **Hot path**: `TransactionExecutor::execute_transaction_...()` — the TTL key cache is used for SHA-256 hash lookups of contract data/code keys during Soroban TX execution.
- **Problem**: Commit #1 introduced a `TtlKeyCache` that was rebuilt for each TX. TXs within the same cluster often share footprint entries (same contracts), so the cache was being rebuilt from scratch when it could be reused.
- **Strategy**: Store the cache on `self.ttl_key_cache` and `take()` it at the start of each TX, returning it at the end. The cache persists across TXs within the same cluster execution.
- **Semantic preservation**: The cache maps `LedgerKey → Hash` deterministically. Reusing the cache means previously computed hashes are available for the next TX without recomputation. The hash values are identical whether freshly computed or cached.
- **Edge cases**: The `take().unwrap_or_default()` pattern handles the first TX (no existing cache) correctly. If the cache grows very large, it's bounded by the number of unique contract data/code keys in the cluster's footprint.
- **Parity**: Internal optimization — no observable behavior change.
- **Test coverage**: Covered by integration tests.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 12088 TPS (runs: 11923, 12088, 12104)
- **Delta**: −278 TPS (−2.3%)
- **Phase 4 re-measurement** (session `7212e6cb`): Without: 12073 (runs: 12089, 12002, 12073), Baseline: 12224 → **+1.2% (borderline)**. Surgical isolation: changed `self.ttl_key_cache.take().unwrap_or_default()` → `TtlKeyCache::new()` at `execution/mod.rs:1342`. Same-session measurement shows small but borderline gain.
- **Measurement notes**: Within noise. The cross-TX cache reuse saves hash recomputations for shared footprint entries, but the savings are small relative to the total Soroban execution cost (~420ms of which hash computation is a small fraction).

#### Necessity Judgment
- **TPS gain**: −2.3% (within noise)
- **Complexity**: +3/−2 lines, 1 file — trivial
- **Risk**: None (SOUND correctness, 3-line change)
- **Verdict**: **MARGINAL**
- **Rationale**: The change is trivially simple (3 lines), correct, and eliminates redundant work. Even with no measurable TPS gain, there's zero reason to revert a 3-line optimization. This completes the TTL key cache story started in commit #1.

#### Similar Opportunities
No similar opportunities identified.

#### Recommendations
1. No action needed.

### 16. `0c66a74` — `Arc<TransactionEnvelope>`

#### Commit Summary
- **Hash**: `0c66a74`
- **Message**: Wrap TransactionFrame envelope in Arc for cheap cloning
- **Files changed**: 22 files across henyey-tx, henyey-ledger, henyey-herder, henyey-app, henyey-history, henyey-rpc, henyey-simulation (+242/−221)
- **Optimization category**: Data structure change (deep clone → Arc refcount)

#### Correctness Review
- **Hot path**: Every `TransactionFrame` clone throughout the codebase — TX set building, execution, meta construction, and herder paths.
- **Problem**: `TransactionEnvelope` (~500 bytes XDR) was deep-cloned ~9 times per TX in tx_set.rs and ~3-6 times in execution/mod.rs. Each deep clone costs ~3µs.
- **Strategy**: Wrap the envelope in `Arc<TransactionEnvelope>`, turning deep copies into ~1ns atomic refcount bumps. Add `from_owned`/`from_owned_with_network` convenience constructors for call sites that have owned envelopes. `into_envelope()` uses `Arc::try_unwrap` to avoid cloning when there's a single reference.
- **Semantic preservation**: `TransactionFrame` was already treated as immutable after construction — the envelope is never mutated. Wrapping in `Arc` formalizes this immutability. All internal `match &self.envelope` changed to `match &*self.envelope` (deref through Arc).
- **Edge cases**: `into_envelope()` uses `Arc::try_unwrap(self.envelope).unwrap_or_else(|arc| (*arc).clone())` — if multiple references exist, it falls back to a clone. This is correct but rare in practice.
- **Parity**: Internal implementation detail — no observable behavior change.
- **Test coverage**: All 22 files compiled and existing tests pass. The change is mechanical (type wrapping).
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Status**: **Unable to isolate** — Arc wrapping is now fundamental to `TransactionFrame`'s type signature. Removing it would require reverting 22 files and all subsequent commits that depend on `Arc<TransactionEnvelope>` (commits #17, #21, #24, #27). The architectural change is too deeply integrated to surgically remove from HEAD.
- **Qualitative assessment**: Saves ~3µs × ~12 clones × 50K TXs ≈ 1.8 seconds per ledger at 50K TXs. This is a significant theoretical saving, though the per-clone cost depends on envelope size.

#### Necessity Judgment
- **TPS gain**: Unable to measure (too deeply integrated)
- **Complexity**: +242/−221 lines, 22 files — large mechanical refactor
- **Risk**: Low (SOUND correctness, formalizes existing immutability)
- **Verdict**: **WORTHWHILE**
- **Rationale**: The Arc wrapping is architecturally correct — TransactionEnvelope is immutable after construction, and sharing via Arc is the idiomatic Rust approach. The theoretical savings are significant (~1.8s/ledger), and the change enables further optimizations (commits #17, #27) that pass Arc directly through the pipeline. The large file count is misleading — 90% of the changes are mechanical type signature updates.

#### Similar Opportunities
No similar opportunities — `TransactionEnvelope` was the only large type cloned frequently.

#### Recommendations
1. No action needed — well-integrated architectural improvement.

### 17. `3beef9f` — Thread `Arc` through hot path

#### Commit Summary
- **Hash**: `3beef9f`
- **Message**: Thread Arc<TransactionEnvelope> through hot execution path
- **Files changed**: `crates/ledger/src/execution/mod.rs`, `crates/ledger/src/execution/tx_set.rs` (+44/−16)
- **Optimization category**: Pipeline optimization (avoid Arc re-wrapping)

#### Correctness Review
- **Hot path**: `execute_single_cluster()` and `run_transactions_on_executor()` — the per-TX execution loop.
- **Problem**: Even after commit #16 wrapped envelopes in Arc, the execution path was cloning the Arc-wrapped envelope and re-wrapping it: `TransactionFrame::from_owned_with_network(tx_envelope.clone(), ...)` where `tx_envelope` was already an `Arc`. This caused an unnecessary deep clone of the envelope.
- **Strategy**: Add `execute_transaction_with_arc()` and `pre_apply_arc()` that accept `Arc<TransactionEnvelope>` directly. Call sites pass `Arc::clone(tx)` (cheap refcount bump) instead of `tx.clone()` (deep copy).
- **Semantic preservation**: The execution logic is identical — only the clone mechanism changes from deep copy to Arc refcount bump.
- **Edge cases**: The old `execute_transaction()` and `pre_apply()` still exist as wrappers that create an Arc from an owned envelope. This maintains backward compatibility for call sites that don't have an Arc.
- **Parity**: Internal implementation detail.
- **Test coverage**: Covered by existing tests.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Status**: **Unable to isolate** — This commit depends on #16 (Arc wrapping) and subsequent commits (#20, #22) call `execute_transaction_with_arc` directly. Reverting would break the execution pipeline.
- **Qualitative assessment**: Eliminates 1-2 deep envelope clones per TX in the inner execution loop. At ~3µs per clone × 50K TXs, this saves ~150-300ms per ledger.

#### Necessity Judgment
- **TPS gain**: Unable to measure (depends on #16, depended on by later commits)
- **Complexity**: +44/−16 lines, 2 files — small and focused
- **Risk**: Low (SOUND correctness)
- **Verdict**: **WORTHWHILE**
- **Rationale**: This is the natural follow-up to #16 — it threads the Arc through the hot execution path where the deep clone actually happens. Without this, #16's Arc wrapping would have limited benefit because the execution loop would still deep-clone. The change is small and targeted.

#### Similar Opportunities
No similar opportunities — all hot-path envelope clones are now Arc clones.

#### Recommendations
1. No action needed.

### 18. `1e915d7` — Optimize merge hash + reduce envelope clones

#### Commit Summary
- **Hash**: `1e915d7`
- **Message**: Optimize merge hash computation, reduce per-TX envelope clones
- **Files changed**: `crates/bucket/src/merge.rs`, `crates/ledger/src/execution/mod.rs` (+80/−15)
- **Optimization category**: Hash optimization (batch → incremental) + clone elimination

#### Correctness Review
- **Hot path**: (1) `IncrementalMergeOutput` in bucket merge — computes SHA-256 hash during the merge loop rather than in a separate pass. (2) `validate_preconditions_with_frame()` in execution — accepts a pre-built `TransactionFrame` instead of creating one internally.
- **Problem**: (1) The bucket merge output hash was computed by `from_sorted_entries()` which iterated all entries again after the merge. (2) `validate_preconditions()` created a new `TransactionFrame` internally, duplicating work when the caller already had one.
- **Strategy**: (1) New `IncrementalMergeOutput` struct that feeds each entry's XDR bytes into the SHA-256 hasher as they're written, and builds the key index simultaneously. Reuses a single XDR buffer across entries. (2) Rename to `validate_preconditions_with_frame()` and accept the pre-built frame.
- **Semantic preservation**: (1) The incremental hash produces identical results to the batch hash — SHA-256 is computed over the same byte sequence. (2) The frame parameter change is purely a refactor of who creates the frame.
- **Edge cases**: (1) The incremental hasher must process entries in exactly the same order as `from_sorted_entries()` — this is guaranteed because the merge output is processed sequentially. (2) The XDR buffer reuse (`.clear()` + reuse) is safe because each entry is fully serialized before the next.
- **Parity**: Bucket merge hash computation is an internal detail.
- **Test coverage**: Covered by bucket merge tests.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 11479 TPS (runs: 11265, 11479, 12239)
- **Delta**: +331 TPS (+2.9%)
- **Phase 4 re-measurement** (session `7212e6cb`): Without: 12291 (runs: 12292, 12291, 12242), Baseline: 12224 → **−0.5% (noise)**. Surgical isolation: modified `IncrementalMergeOutput::push` to skip XDR serialization/hashing, modified `into_bucket` to call `from_sorted_entries` instead of using pre-computed hash. Confirms no measurable gain — level-0 bucket updates use `fresh_in_memory_only` which already skips hash computation.
- **Measurement notes**: Slightly positive but within noise. The wide spread in runs (11265–12239) indicates high variance. The incremental merge hash saves one full pass over merge output, but bucket merges happen in the background and may not be on the critical path for the benchmark.

#### Necessity Judgment
- **TPS gain**: +2.9% (within noise, high variance)
- **Complexity**: +80/−15 lines, 2 files — moderate
- **Risk**: Low (SOUND correctness)
- **Verdict**: **MARGINAL**
- **Rationale**: The incremental merge hash is architecturally sound — computing the hash during output avoids a second pass over potentially large merge results. The frame reuse eliminates a redundant construction. However, the benchmark shows no clear improvement because bucket merges are not the bottleneck in the single-shot benchmark.

#### Similar Opportunities
The incremental hashing pattern could be applied to other batch-then-hash operations, though most have already been addressed by the streaming hash in commit #13.

#### Recommendations
1. No action needed.

### 19. `066299f` — Counting writer for size checks

#### Commit Summary
- **Hash**: `066299f`
- **Message**: Replace allocating XDR serialization with counting writer for size checks
- **Files changed**: `crates/tx/src/operations/execute/invoke_host_function.rs`, `crates/tx/src/soroban/host.rs` (+68/−53)
- **Optimization category**: Allocation elimination (serialize-to-measure → counting writer)

#### Correctness Review
- **Hot path**: `xdr_encoded_len()` in Soroban host function execution — called multiple times per Soroban TX for footprint validation, write bytes computation, disk read metering, return value size, and contract event size calculations.
- **Problem**: 8 call sites used `value.to_xdr(Limits::none())?.len()` which allocates a full `Vec<u8>` just to measure the serialized size. For large Soroban values, these allocations are wasteful.
- **Strategy**: Implement `xdr_encoded_len()` using a `CountingWriter` that counts bytes written without allocating. The writer's `write()` method simply adds `buf.len()` to a counter and returns `Ok(buf.len())`.
- **Semantic preservation**: The `CountingWriter` reports the same byte count as `to_xdr().len()` because XDR serialization writes the same bytes regardless of the destination. The `write_xdr()` method is called with the same `Limits::none()`.
- **Edge cases**: The `CountingWriter` returns `u32` (sufficient for XDR sizes, which are bounded by `u32::MAX` in the Soroban metering). The `flush()` method is a no-op. If `write_xdr()` fails, the function propagates the error.
- **Parity**: XDR size computation is an internal optimization.
- **Test coverage**: Covered by Soroban execution tests.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 12745 TPS (runs: 12725, 12747, 12745)
- **Delta**: −935 TPS (−7.3%)
- **Measurement notes**: The −7.3% delta is at the upper edge of typical noise but remarkably consistent across all 3 runs (12725–12747, spread of only 22 TPS). This consistency suggests the measurement may be real — removing the counting writer and reverting to allocating serialization may actually have *improved* throughput slightly, or this is an unusual noise pattern. The allocating path may benefit from CPU cache effects or allocation batching that the counting writer disrupts.

#### Necessity Judgment
- **TPS gain**: −7.3% (unusual — consistently negative but potentially noise)
- **Complexity**: +68/−53 lines, 2 files — moderate
- **Risk**: Low (SOUND correctness)
- **Verdict**: **MARGINAL**
- **Rationale**: The counting writer pattern is correct and eliminates unnecessary allocations in principle. However, the benchmark shows no positive impact (possibly slightly negative). The allocating path's `Vec` may be well-optimized by the allocator (reuse, small-buffer optimization). The code change is a wash — slightly cleaner API but no measurable benefit.

#### Similar Opportunities
The counting writer pattern could be applied to any `to_xdr().len()` usage. However, the benchmark results suggest the benefit is negligible.

#### Recommendations
1. No action needed.

### 20. `022f0ba` — Fix O(n²) contract cache scan (+21% TPS)

#### Commit Summary
- **Hash**: `022f0ba`
- **Message**: Fix O(n²) contract cache scan in per-TX commit path (+21% TPS)
- **Files changed**: `crates/ledger/src/execution/mod.rs`, `crates/ledger/src/execution/tx_set.rs`, `crates/ledger/tests/transaction_execution/preconditions.rs` (+66/−1)
- **Optimization category**: Algorithmic fix (O(n²) → O(n))

#### Correctness Review
- **Hot path**: Per-TX Soroban commit path in `execution/mod.rs` — after each TX, modified contract data entries are committed to the delta.
- **Problem**: The commit path linearly scanned the entire contract data cache to find entries modified by the current TX. With N TXs each scanning a growing cache (up to M entries), the total cost was O(N × M) — effectively O(n²) for large workloads.
- **Strategy**: Track `pre_tx_created_count` before each TX, then slice `created[pre_tx_created_count..]` to scan only NEW entries added by the current TX. This makes each TX's commit O(k) where k is the number of entries it created, and total cost O(N) for all TXs.
- **Semantic preservation**: The new code scans the same set of created entries as the old code — it just skips entries from previous TXs that have already been committed. The commit produces identical results.
- **Edge cases**: If no entries are created by a TX, the slice is empty and no scan occurs. The `pre_tx_created_count` is captured before TX execution and used after, which is correct because the delta's created list is append-only within a TX.
- **Parity**: Internal optimization — no observable behavior change.
- **Test coverage**: Covered by Soroban execution tests. Also adds per-phase timing fields for better profiling.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 12564 TPS (recheck runs: 13047, 12533, 12564)
- **Without fix (serial re-run)**: 10382 TPS (runs: 10382, 10421, 10365)
- **Delta**: +2182 TPS (+21.0%)
- **Measurement notes**: Clear, consistent improvement across all 3 serial runs. Using the recheck baseline (12564) for apples-to-apples comparison with the serial "without" measurements. The O(n²) → O(n) algorithmic fix has a direct impact proportional to workload size.

#### Necessity Judgment
- **TPS gain**: +21.0% (large, consistent, outside noise)
- **Complexity**: +66/−1 lines, 3 files — small and focused
- **Risk**: Low (SOUND correctness, straightforward algorithmic fix)
- **Verdict**: **ESSENTIAL**
- **Rationale**: This fixes a genuine algorithmic bug (O(n²) scan in a hot loop). The 66-line change delivers +21.0% TPS with minimal complexity. The fix is the textbook approach — track the boundary and only scan new entries. This is one of the highest-impact optimizations in the series.

#### Similar Opportunities
No similar O(n²) patterns identified in the current codebase.

#### Recommendations
1. No action needed — clean algorithmic fix.

### 21. `aeea796` — Parallelize TX hash computation

#### Commit Summary
- **Hash**: `aeea796`
- **Message**: Parallelize TX hash computation, optimize merge paths
- **Files changed**: `crates/ledger/src/close.rs`, `crates/ledger/src/delta.rs`, `crates/ledger/src/execution/tx_set.rs`, `crates/simulation/src/applyload.rs`, `crates/henyey/src/main.rs`, `docs/perf-hypotheses.md` (+150/−38)
- **Optimization category**: Parallelization (TX hashing) + clone elimination (delta merge, cluster results)

#### Correctness Review
- **Hot path**: (1) TX hash computation in `close.rs` — parallelized via `std::thread::scope` with up to 8 threads. (2) `LedgerDelta::merge()` — now consumes `other` by removing from its map instead of cloning. (3) Cluster result merge — uses `into_iter()` (move) instead of `&iter` (borrow+clone).
- **Problem**: (1) TX hashes were computed sequentially. (2) `delta.merge()` cloned all entries from the other delta. (3) Cluster results were cloned when merging.
- **Strategy**: (1) Use `std::thread::scope` to compute hashes in parallel across up to 8 threads. (2) Use `.remove()` on the other delta's map to move entries instead of cloning. (3) Use `into_iter()` for cluster result merge.
- **Semantic preservation**: (1) TX hashes are independent — parallel computation produces identical results. Order is preserved because the parallel scope maps inputs 1:1. (2) `remove()` + `insert()` has the same semantics as `get().clone()` + `insert()` but without the clone. (3) `into_iter()` moves values instead of cloning.
- **Edge cases**: (1) Thread count is min(8, available_cores). If only 1 thread, falls back to sequential. (2) `remove()` leaves the source delta empty, which is correct since merged deltas are consumed.
- **Parity**: Internal optimizations.
- **Test coverage**: Covered by integration tests.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 11951 TPS (runs: 11961, 11613, 11951)
- **Delta**: −141 TPS (−1.2%)
- **Phase 4 re-measurement** (session `7212e6cb`): Without: 12186 (runs: 12101, 12186, 12216), Baseline: 12224 → **+0.3% (noise)**. Surgical isolation: replaced `std::thread::scope` parallel hashing with sequential loop in `close.rs:550-605`. Same-session measurement confirms no measurable gain.
- **Measurement notes**: Within noise. The parallel TX hashing is less impactful in the benchmark because commit #27's `prepare_presorted` skips per-TX hashing entirely. The delta merge and cluster result optimizations save clones but are not on the critical path.

#### Necessity Judgment
- **TPS gain**: −1.2% (within noise)
- **Complexity**: +150/−38 lines, 6 files — moderate
- **Risk**: Low (SOUND correctness)
- **Verdict**: **MARGINAL** (for benchmark), **WORTHWHILE** (for production)
- **Rationale**: The parallel TX hashing is important for the production path where `prepare_presorted` is not used (TXs from the herder need hashing for canonical ordering). The delta merge clone elimination is a clean improvement regardless of benchmark impact.

#### Similar Opportunities
No similar opportunities — the main parallelization opportunities are in TX hashing (done) and TX execution (already parallel via cluster execution).

#### Recommendations
1. No action needed.

### 22. `06a0b3d` — RwLock sig cache + skip redundant check

#### Commit Summary
- **Hash**: `06a0b3d`
- **Message**: RwLock sig cache + skip redundant verification
- **Files changed**: `crates/crypto/src/signature.rs`, `crates/ledger/src/execution/mod.rs` (+19/−11)
- **Optimization category**: Concurrency improvement (Mutex → RwLock) + redundant work elimination

#### Correctness Review
- **Hot path**: (1) `SIG_VERIFY_CACHE` in `crates/crypto/src/signature.rs` — shared across all verification threads. (2) `has_sufficient_signer_weight()` call for fee source vs inner source in execution.
- **Problem**: (1) The sig cache used `Mutex`, forcing exclusive access even for read-only cache lookups. With parallel cluster execution, threads contended on the mutex. (2) For non-fee-bump TXs, `fee_source_id == inner_source_id`, so the second `has_sufficient_signer_weight` call was redundant.
- **Strategy**: (1) Replace `Mutex<SigVerifyCache>` with `RwLock<SigVerifyCache>`. Cache lookups use `.read()` (shared), inserts use `.write()` (exclusive). (2) Skip the second signer weight check when `fee_source_id == inner_source_id`.
- **Semantic preservation**: (1) `RwLock` provides the same mutual exclusion for writes and allows concurrent reads. The cache behavior is identical. (2) The redundant check skip is correct because if `fee_source == inner_source`, verifying the fee source already verified the inner source.
- **Edge cases**: (1) The `RwLock` read-write upgrade pattern (read → miss → write) doesn't cause deadlocks because the read lock is dropped before acquiring the write lock. (2) The `fee_source_id == inner_source_id` check covers all non-fee-bump TXs and fee-bump TXs where the fee source and inner source are the same account.
- **Parity**: Internal optimization.
- **Test coverage**: Covered by existing tests.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 11810 TPS (runs: 11792, 11810, 11917)
- **Without fix**: 12364 TPS (runs: 12364, 12211, 12482)
- **Delta**: −554 TPS (−4.5%)
- **Measurement notes**: Within noise. The RwLock benefit is most significant under high contention (many threads doing cache lookups simultaneously). The benchmark's 4-cluster configuration may not generate enough contention to show a difference. The redundant check skip saves one cache lookup per non-fee-bump TX but is a small fraction of total execution time.

#### Necessity Judgment
- **TPS gain**: −4.5% (within noise)
- **Complexity**: +19/−11 lines, 2 files — small
- **Risk**: Low (SOUND correctness)
- **Verdict**: **MARGINAL**
- **Rationale**: The RwLock upgrade is the correct concurrency primitive for a read-heavy cache (cache hits far outnumber inserts). The redundant check skip is a clean micro-optimization. Both changes are small and low-risk. The benchmark doesn't show a gain because contention is low with 4 clusters, but with more clusters or higher concurrency, the RwLock would matter.

#### Similar Opportunities
No similar opportunities — the sig cache is the only shared mutable state accessed from parallel execution threads.

#### Recommendations
1. No action needed.

### 23. `1067f46` — Single-pass delta categorization

#### Commit Summary
- **Hash**: `1067f46`
- **Message**: Reduce ledger close overhead: single-pass delta categorization and commit_close fast-path
- **Files changed**: `crates/ledger/src/delta.rs` (+63/−0), `crates/ledger/src/manager.rs` (+131/−71), `crates/simulation/src/applyload.rs` (+18/−1)
- **Optimization category**: Algorithmic (reduce iteration passes) + lock contention reduction + fast-path skip

#### Correctness Review
- **Hot path**: Ledger close commit path — the phase between bucket list update and state finalization. At 50K TXs this consumed ~315ms of unaccounted "gap" time.
- **Problem**: (1) 6 separate passes over delta entries: `init_entries()`, `live_entries()`, `dead_entries()` each iterate+clone+filter, plus 3 `.filter().count()` passes for stats. With 50K+ entries, that's 6× iteration + unnecessary allocations. (2) Work happened under the bucket list write lock. (3) For SAC-transfer-heavy ledgers with no offers, `commit_close` still iterated all entries twice (offers, pool shares), calling `change.key()` (XDR field extraction) for every entry.
- **Strategy**: (1) New `categorize_for_bucket_update()` iterates once, simultaneously categorizing into init/live/dead vectors, counting created/updated/deleted, and setting `has_offers` / `has_pool_share_trustlines` flags by checking the `LedgerEntryData` discriminant. (2) Categorization moved before the bucket list write lock. (3) Fast-path in `commit_close`: when both flags are false, the entire offer/trustline iteration is skipped. (4) Uses cheap enum discriminant match instead of `change.key()`.
- **Semantic preservation**: The single-pass produces identical init/live/dead vectors and counts. `init_entries()` clones `current_entry()` for `Created` → new code does the same. `live_entries()` clones for `Updated` → same. `dead_entries()` calls `change.key()` for `Deleted` → new code calls `entry_to_key(previous)`. Offer store mutations use equivalent data sources (entry data fields vs. key fields). The fast-path is correct because `has_offers == false` means no offer entries exist.
- **Edge cases**: (1) Lock granularity changed from one lock acquisition for all entries to per-entry lock acquisition in commit_close. Functionally equivalent (single-threaded) but slightly less efficient for many-offer ledgers. Mitigated by the fast-path skipping the loop entirely for no-offer ledgers. (2) Empty delta: returns empty vecs and all-false flags, equivalent to old code.
- **Parity**: Internal bookkeeping only. Bucket list receives identical init/live/dead vectors. No observable behavior change.
- **Test coverage**: No unit tests added for `categorize_for_bucket_update()` or `DeltaCategorization`. Relies on integration tests.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 12564 TPS (recheck runs: 13047, 12533, 12564)
- **Without fix**: 11082 TPS (runs: 11082, 11113, 11060)
- **Delta**: +1482 TPS (+13.4%)
- **Measurement notes**: Consistent across 3 runs (tight 11060-11113 range). Using the recheck baseline (12564) for apples-to-apples comparison with the serial "without" measurements. The single-pass categorization removes 5 redundant iterations over 50K+ entries, moves work outside the write lock, and the commit_close fast-path eliminates `change.key()` calls for the SAC-heavy workload.

#### Necessity Judgment
- **TPS gain**: +13.4% (well above noise)
- **Complexity**: +141/−71 lines, 3 files — moderate
- **Risk**: Low (SOUND correctness)
- **Verdict**: **ESSENTIAL**
- **Rationale**: The single-pass categorization is a clean algorithmic improvement that eliminates 5 redundant passes over 50K+ entries. The fast-path for no-offer ledgers is well-targeted since the dominant workload (SAC transfers) has no offers. The +13.4% gain is well above noise and reflects real savings from reduced iteration and allocation.

#### Similar Opportunities
The same single-pass pattern could apply to any code that iterates the delta multiple times with different filters.

#### Recommendations
1. Add a unit test for `categorize_for_bucket_update()` verifying it produces identical results to the six separate calls.
2. Consider restoring the single-lock pattern for commit_close if offer-heavy ledgers become a concern.

### 24. `0bfec57` — Eliminate meta clones + cache TX hash

#### Commit Summary
- **Hash**: `0bfec57`
- **Message**: Eliminate clones in meta building and cache TX hash across execution phases
- **Files changed**: `crates/ledger/src/execution/mod.rs` (+9/−0), `crates/ledger/src/execution/result_mapping.rs` (+8/−3), `crates/ledger/src/manager.rs` (+57/−23), `crates/ledger/tests/transaction_execution/preconditions.rs` (+1/−0)
- **Optimization category**: Clone elimination (move semantics) + redundant computation caching

#### Correctness Review
- **Hot path**: Three sub-phases of `LedgerCloseContext::commit()`: (1) TX result hash computation (hashing 50K `TransactionResultPair`), (2) ledger close meta construction (cloning entire TX set + SCP history + result metas), (3) per-TX hash recomputation during `build_tx_result_pair`.
- **Problem**: (1) Built `TransactionResultSet { results: self.tx_results.clone()... }` — cloning 50K results just to hash them. (2) `build_ledger_close_meta` took references, forcing `.clone()` and `.to_vec()` of ~50K envelopes, SCP entries, and result metas. (3) `build_tx_result_pair` called `frame.hash(network_id)` (XDR serialize + SHA-256) per TX, despite the hash already being computed during `pre_apply`.
- **Strategy**: (1) Streaming XDR hash: manually writes the XDR variable-length array encoding (4-byte length prefix + elements) directly to `Sha256Writer`, eliminating the Vec clone. (2) Move semantics: uses `std::mem::replace`/`std::mem::take` to move `tx_set`, `scp_history`, `tx_result_metas` by value into `build_ledger_close_meta`. (3) TX hash caching: stores hash in `PreApplyResult` → `TransactionExecutionResult` → `build_tx_result_pair`, falling back to recomputation when `None`.
- **Semantic preservation**: (1) Streaming hash writes identical XDR bytes to `TransactionResultSet::write_xdr` (both: 4-byte u32 length + each element). (2) `commit(mut self)` consumes `self` by value — fields extracted via `mem::replace` are only accessed before extraction. (3) TX hash is a deterministic pure function of the same inputs.
- **Edge cases**: (1) `tx_hash: None` fallback for early validation failures — correctly falls back to recomputation. (2) `len as u32` truncation for >4B TXs — impossible in practice. (3) Hollow `close_data` after extraction — no code reads drained fields before `self` is dropped.
- **Parity**: Internal optimization. XDR encoding is byte-identical, `LedgerCloseMeta` contains the same values (moved not cloned), TX hash is the same hash stellar-core computes.
- **Test coverage**: Existing tests updated (`test_ledger_close_meta_includes_scp_history`, `test_fee_bump_result_encoding`) to match new signatures. No dedicated streaming hash equivalence test.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 12564 TPS (recheck runs: 13047, 12533, 12564)
- **Without fix**: 11367 TPS (runs: 11421, 11349, 11367)
- **Delta**: +1197 TPS (+10.5%)
- **Measurement notes**: Using the recheck baseline (12564) for apples-to-apples comparison with serial "without" measurements. The clone elimination saves 50K clones of `TransactionResultPair` and the entire TX set during meta construction. The streaming XDR hash avoids allocating a full `TransactionResultSet` just to hash it. The TX hash caching saves one SHA-256 per TX across execution phases.

#### Necessity Judgment
- **TPS gain**: +10.5% (above noise)
- **Complexity**: +75/−26 lines, 4 files — moderate
- **Risk**: Low (SOUND correctness)
- **Verdict**: **WORTHWHILE**
- **Rationale**: The move semantics for meta building are clean and eliminate unnecessary allocations. The streaming XDR hash is a principled improvement. The TX hash caching is a small but correct optimization. All three changes are low-risk. The +10.5% gain reflects real savings from avoiding massive clones in the meta construction path.

#### Similar Opportunities
The streaming XDR hash pattern could be applied to any code that serializes a large collection solely to hash it.

#### Recommendations
1. Add a unit test comparing `Hash256::hash_xdr(&TransactionResultSet { results })` against the streaming approach for a non-trivial input.

### 25. `1952c77` — Skip redundant dedup in add_batch

#### Commit Summary
- **Hash**: `1952c77`
- **Message**: Optimize add_batch: skip redundant dedup and cache sort keys
- **Files changed**: `crates/bucket/src/bucket_list.rs` (+70/−18), `crates/ledger/src/manager.rs` (+1/−1)
- **Optimization category**: Allocation reduction / algorithmic optimization

#### Correctness Review
- **Hot path**: `BucketList::add_batch`, called once per ledger close. At 50K TXs, processes ~100K entries. Dominated by deduplication (sort+dedup) and final sort.
- **Problem**: (1) The `LedgerDelta` already coalesces entries into a `HashMap<LedgerKey, EntryChange>`, so output is guaranteed unique per key. The `deduplicate_entries_by_sort()` / `deduplicate_keys_by_sort()` calls were redundant O(n log n) passes. (2) `sort_by(compare_entries)` called `BucketEntry::key()` on every comparison, allocating a new `LedgerKey` each time (~3.4M heap allocations during sort for 100K entries).
- **Strategy**: (1) New `add_batch_unique()` sets `skip_dedup = true`, bypassing the three dedup calls. Original `add_batch()` preserved as safe fallback. (2) `sort_by_cached_key(|entry| entry.key())` computes `Option<LedgerKey>` once per entry (O(n) allocations), then sorts by cached keys.
- **Semantic preservation**: The sort ordering is identical. Original `compare_entries` returns `Less` for `(None, Some)`, `Greater` for `(Some, None)`, delegates to `a.cmp(b)` for `(Some, Some)`. `sort_by_cached_key` with `Option<LedgerKey>` derives the same ordering (`None < Some`, then `Ord`). Both are stable sorts.
- **Edge cases**: (1) Evicted keys appended after categorization could theoretically duplicate delta dead entries (if a TX deletes a ContractData entry without modifying its TTL). In practice: the original dedup logged a *warning* when it removed duplicates, calling it "a bug in the entry-generation path" — confirming dedup was a safety net, not a relied-upon mechanism. (2) Duplicate dead entries are harmless (delete is idempotent). Duplicate live entries shadow to the same value.
- **Parity**: stellar-core does not deduplicate in `addBatch`; it trusts `LedgerDelta` produces unique entries. `add_batch_unique` is actually *closer* to stellar-core behavior.
- **Test coverage**: No new tests added. Existing `add_batch` tests use the original method (with dedup). `add_batch_unique` only tested via integration tests.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 12564 TPS (recheck runs: 13047, 12533, 12564)
- **Without fix**: 9636 TPS (runs: 9636, 9654, 9595)
- **Delta**: +2928 TPS (+30.4%)
- **Measurement notes**: Massive delta — the largest individual optimization by TPS gain. Very consistent across 3 runs (tight 9595-9654 range). Using the recheck baseline for apples-to-apples comparison. The dedup removal saves O(n log n) sorting + dedup of 100K entries that were already unique. The `sort_by_cached_key` eliminates ~3.4M heap allocations from key construction during sort. Both savings compound on large ledgers.

#### Necessity Judgment
- **TPS gain**: +30.4% (well above noise, the largest single-commit gain)
- **Complexity**: +70/−18 lines, 2 files — small
- **Risk**: Low (SOUND correctness; uniqueness invariant maintained by delta construction; dedup was already documented as a "bug-catcher" not a correctness requirement; stellar-core also trusts delta uniqueness)
- **Verdict**: **ESSENTIAL**
- **Rationale**: This is the most impactful single optimization in the entire set. The `sort_by_cached_key` alone eliminates millions of allocations, and skipping redundant dedup removes an entire O(n log n) pass. The uniqueness contract is well-justified (delta enforces it via HashMap, stellar-core behaves identically). At +30.4%, this optimization single-handedly accounts for more TPS gain than all the MARGINAL commits combined.

#### Similar Opportunities
Consider adding a `debug_assertions`-only check in `add_batch_unique` that validates no duplicate keys exist, to catch upstream bugs during testing.

#### Recommendations
1. Add debug assertion for duplicate key detection in `add_batch_unique`.
2. Document the uniqueness contract on the `add_batch_unique` API.

### 26. `3bc76a2` — Drop delta on background thread

#### Commit Summary
- **Hash**: `3bc76a2`
- **Message**: Optimize commit_close: drop delta on background thread
- **Files changed**: `crates/ledger/src/manager.rs` (+4/−0)
- **Optimization category**: Deferred deallocation

#### Correctness Review
- **Hot path**: `commit_close` in `LedgerManager`. Every ledger close calls this exactly once, and its latency directly adds to close-to-close time.
- **Problem**: `LedgerDelta` contains a `HashMap` with 150K+ entries after a large ledger close. When `commit_close` returned, the delta was dropped synchronously on the calling thread. Destructors must deallocate every key, every `EntryChange` value (containing `LedgerEntry` objects with nested allocations), and the `change_order: Vec`. Cost: ~89ms.
- **Strategy**: `std::thread::spawn(move || drop(delta))` — moves ownership into a new OS thread whose sole purpose is running the destructor. The calling thread returns immediately.
- **Semantic preservation**: At the spawn point: (1) offer store and pool share index already updated, (2) ledger state (header + hash) already written, (3) bucket list already updated. `delta` is owned by `commit_close` (passed by value), so no other code references it. The delta is genuinely dead — only destruction remains, which has no observable side effects.
- **Edge cases**: (1) Thread spawn failure: `std::thread::spawn` panics if OS refuses — extremely unlikely and correct behavior (system is resource-starved). (2) Thread accumulation: 89ms deallocation is much smaller than ~5s ledger close interval, so threads don't accumulate. (3) Deferred memory pressure: ~tens of MB persists until background thread finishes — marginal relative to process memory. (4) Process exit during background drop: OS reclaims all memory.
- **Parity**: No parity implications — only affects *when* memory is freed, not *what* is computed.
- **Test coverage**: No new tests needed. Existing integration tests exercise `commit_close`. Rust's borrow checker enforces correctness — if `delta` were used after the `spawn`, it wouldn't compile.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 12564 TPS (recheck runs: 13047, 12533, 12564)
- **Without fix**: 10391 TPS (runs: 10374, 10391, 10467)
- **Delta**: +2173 TPS (+20.9%)
- **Measurement notes**: Surprisingly large delta for a 4-line change. Using the recheck baseline for apples-to-apples comparison. The ~89ms saved per ledger close is significant at high TPS because ledger close time is the bottleneck. The delta may be amplified by interaction with commit #27 (HashMap delta is larger to deallocate than the old Vec-keyed map). The benchmark consistently shows 10374-10467 TPS without this optimization across 3 serial runs.

#### Necessity Judgment
- **TPS gain**: +20.9% (well above noise)
- **Complexity**: +4/−0 lines, 1 file — trivial
- **Risk**: None (SOUND correctness, Rust borrow checker enforces safety)
- **Verdict**: **ESSENTIAL**
- **Rationale**: A 4-line change yielding +20.9% TPS is the highest ROI optimization in the entire set. Moving expensive deallocation to a background thread is a well-known Rust idiom. Zero complexity cost, zero correctness risk.

#### Similar Opportunities
Any large data structure dropped on the critical path could benefit from background-thread deallocation. The same pattern was subsequently applied to `offer_pool_changes` in commit #27.

#### Recommendations
1. No changes needed. This is an exemplary micro-optimization.

### 27. `011a745` — LedgerKey HashMap, async persist, drain delta, presorted prepare

#### Commit Summary
- **Hash**: `011a745`
- **Message**: Optimize ledger close: LedgerKey HashMap, async persist, drain delta, presorted prepare
- **Files changed**: 12 files (+462/−380)
- **Optimization category**: Multi-technique ledger close hot-path optimization (serialization, allocation, I/O overlap, move semantics)

Key file changes:
- `crates/ledger/src/delta.rs` (+130/−67) — LedgerKey HashMap, drain categorization
- `crates/ledger/src/close.rs` (+101/−2) — `prepare_presorted()`, presorted flag
- `crates/ledger/src/snapshot.rs` (+30/−77) — LedgerKey HashMap, remove `key_to_bytes`
- `crates/bucket/src/bucket_list.rs` (+70/−8) — Async bucket persist, manual Clone/Drop
- `crates/herder/src/parallel_tx_set_builder.rs` (+30/−2) — Skip sorting in TX set builder
- `crates/ledger/src/manager.rs` (+28/−14) — Wire drain + offer_pool_changes

#### Correctness Review

Five sub-optimizations:

**R4-1: LedgerKey as HashMap key** (replaces `HashMap<Vec<u8>, _>` with `HashMap<LedgerKey, _>`):
- Eliminates `key_to_bytes` XDR serialization (~1µs per lookup) on every `get_change`, `get_entry`, `record_*` call. `LedgerKey` derives `Hash`/`Eq` from `rs-stellar-xdr` (verified: already used as HashMap key in 30+ crate locations). Removes `Result` from several return types since XDR serialization can no longer fail. **SOUND**.

**R4-2: Skip double-hashing in TX set builder**:
- New `stages_to_xdr_phase_unsorted()` skips sort in the builder since `prepare_with_hash` re-sorts anyway. Only active in simulation path (presorted). Production uses unchanged `prepare_with_hash`. **SOUND**.

**R4-3: Async bucket persistence**:
- Spawns background `std::thread` for bucket file persistence. Bounded to 1 outstanding via `join()` at start of next `add_batch_internal`. `Drop` impl ensures thread completes before `BucketList` is dropped. `Clone` impl sets `pending_persist: None` on clones. Fire-and-forget (errors logged, not fatal) — matches pre-optimization behavior. **SOUND**.

**R4-4: Drain categorization**:
- New `drain_categorization_for_bucket_update()` uses `HashMap::drain()` (arbitrary order) vs. original's insertion-order iteration. **Safe** because `add_batch_impl` sorts all entries by key before creating the bucket — input order is irrelevant. `offer_pool_changes` also in arbitrary order but commit_close operations are idempotent per entry and order-independent. **SOUND**.

**R4-5: Consuming prepare_presorted**:
- `prepare_presorted(self)` consumes TX set by value, wraps in Arc without hashing/sorting. Only triggered when `presorted == true`, which is only set in `applyload.rs` (simulation harness). Production/replay always uses `prepare_with_hash(&self)`. For Classic TXs, still calls `sorted_for_apply_sequential`. **SOUND**.

- **Edge cases**: (1) BucketList Drop during pending persist: `handle.join().ok()` waits, swallows panics — acceptable since persistence was already non-fatal. (2) Non-simulation callers accidentally setting `presorted`: field is pub but defaults to false, only explicitly set in applyload.rs. (3) `key_to_bytes` removal: old non-draining `categorize_for_bucket_update` retained — should be removed if unused.
- **Parity**: No parity implications. LedgerKey HashMap is internal. Presorted is simulation-only. Async persist is for restart recovery, not consensus. Drain produces same entries (sorted before use). stellar-core also persists bucket files asynchronously.
- **Test coverage**: 3 test files updated for new `add_entry` signature (no longer `Result`). 3 delta unit tests updated. No new tests for `drain_categorization`, `prepare_presorted`, `stages_to_xdr_phase_unsorted`, or async persist.
- **Correctness verdict**: **SOUND**

#### Performance Measurement
- **Baseline (HEAD)**: 12564 TPS (recheck runs: 13047, 12533, 12564)
- **Without fix**: 10106 TPS (runs: 10106, 10107, 10072)
- **Delta**: +2458 TPS (+24.3%)
- **Measurement notes**: Very consistent across 3 runs (tight 10072-10107 range). Using the recheck baseline for apples-to-apples comparison. The multi-part optimization targets 5 distinct bottlenecks. The LedgerKey HashMap eliminates ~1µs XDR serialization per key lookup. The drain categorization avoids cloning 50K entries. The async bucket persistence moves disk I/O off the critical path. The presorted prepare skips redundant hashing+sorting of 50K TX envelopes.

#### Necessity Judgment
- **TPS gain**: +24.3% (well above noise)
- **Complexity**: +462/−380 lines, 12 files — high (largest commit by line count)
- **Risk**: Low (all 5 sub-optimizations are SOUND; presorted path is simulation-only; drain order is irrelevant due to sort; async persist is bounded)
- **Verdict**: **ESSENTIAL**
- **Rationale**: The combined +24.3% gain across 5 distinct optimizations justifies the high line count. The LedgerKey HashMap and drain categorization are clean architectural improvements that simplify the API (removing `Result` from key operations). The async persist and presorted prepare demonstrate understanding of where the bottleneck has shifted after earlier optimizations. This is the capstone commit that ties together the preceding optimization work.

#### Similar Opportunities
1. The `key_to_bytes` removal pattern could apply to any other XDR-serialization-as-key usage.
2. The async persistence pattern could apply to any I/O that doesn't need to complete before the next ledger operation.
3. The drain pattern could apply to any data structure consumed after its last read.

#### Recommendations
1. Remove the old non-draining `categorize_for_bucket_update` if no callers remain.
2. Add a unit test for `drain_categorization_for_bucket_update` verifying identical counts/entries as the non-draining version.
3. Add a unit test for `prepare_presorted` verifying structural equivalence with `prepare_with_hash` for a given input.
4. Document the `presorted` field with a clear warning that it's simulation-only.

---

## Vendored Typed API vs Standard XDR API Benchmark

**Date**: Mar 17, 2026
**Session**: `7212e6cb` — artifacts at `~/data/7212e6cb/`
**Branch**: `bench/standard-xdr-api` (commit `53f31fe`)

### Background

The soroban-env-host crates are vendored at `vendor/soroban-env-p25/` with a
custom "typed API" backported from `tomerweller/rs-soroban-env` commit
`74d051cf`. The typed API adds `invoke_host_function_typed()` which accepts
and returns native Rust types (`Rc<LedgerKey>`, `Rc<LedgerEntry>`, `ScVal`)
instead of `&[u8]` XDR byte vectors, eliminating serialization round-trips at
the embedder-host boundary.

Both APIs share the same `invoke_host_function_core()` — actual contract
execution is identical. The savings come purely from avoiding XDR
encode/decode of inputs and outputs.

### Methodology

- **Benchmark**: `apply-load --mode single-shot --tx-count 50000 --clusters 4 --iterations 10`
- **Workload**: SAC (Stellar Asset Contract) transfer transactions
- **Protocol**: 3 runs per binary, alternating (baseline, standard, baseline, standard, ...) to minimize environmental drift
- **Baseline binary**: `~/data/7212e6cb/baseline-fresh` (built from `main`, uses typed API)
- **Standard binary**: `~/data/7212e6cb/standard-api` (built from `bench/standard-xdr-api`, uses XDR API)

### Results

| Run | Baseline (Typed API) | Standard (XDR API) | Delta |
|-----|---------------------:|-------------------:|------:|
| 1   | 14,721 TPS           | 14,355 TPS         | -2.5% |
| 2   | 14,804 TPS           | 14,301 TPS         | -3.4% |
| 3   | 14,698 TPS           | 14,185 TPS         | -3.5% |

- **Baseline median**: **14,721 TPS** (sorted: 14698, 14721, 14804)
- **Standard median**: **14,301 TPS** (sorted: 14185, 14301, 14355)
- **Delta**: **-420 TPS / -2.9%**

No overlap between ranges (baseline worst: 14,698 > standard best: 14,355).

### Where the Time Goes

The difference appears almost entirely in the `soroban_exec` phase:

| Metric (avg ms/ledger) | Typed API | Standard API | Gap |
|------------------------|----------:|-------------:|----:|
| soroban_exec           | 2,389     | 2,501–2,537  | ~120–148 ms |
| Per-transaction overhead | —       | —            | ~2–3 μs |

All other phases (prepare, commit, bucket, etc.) are statistically identical.

### Conclusion

The vendored typed API provides a **consistent, measurable ~2.9% throughput
improvement** by eliminating XDR serialization at the embedder boundary. The
gain is real (zero overlap across 3 alternating runs) and justifies the
vendoring approach. The per-transaction overhead of ~2–3 μs will compound
with heavier Soroban workloads that involve more/larger ledger entries.
