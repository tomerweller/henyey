# Soroban Execution Optimization Plan

## Problem Statement

Henyey's ledger close time is 1.88x slower than stellar-core v25.2.0 on the same
hardware, same ledger range. The gap is **149ms** per ledger (317.5ms vs 168.5ms).

**Current status**: Steps 1–5a done, plus Step 5b (raw-key decompression bypass).
Combined sig cache + raw-key: 273.5ms mean (−30.7ms vs 304.2ms baseline, −10.1%).
Next targets: reducing check_operation_signatures bookkeeping overhead (~15-20ms) and
profiling the unprofiled ~217ms region.

## Root Cause

Linear regression on 136 mainnet ledgers (61349505–61349640) decomposes the gap:

| Component | stellar-core | henyey | Gap at mean workload |
|-----------|-------------|--------|---------------------|
| Per classic-op | 0.023ms | 0.054ms | +16ms (2.4x) |
| Per soroban-op | 0.241ms | 0.830ms | +152ms (3.5x) |
| Fixed overhead | 95.4ms | 77.0ms | −18ms |
| **Total** | **168.5ms** | **317.5ms** | **+149ms** |

**Soroban per-op cost is 3.5x slower, accounting for 152ms of the 149ms gap.**

Mean workload per ledger: ~500 classic ops, ~257 soroban ops (~130 soroban TXs).

## Profiling Breakdown

Granular profiling (Step 1 commit `a1db12f`, `RUST_LOG=debug` on release build)
reveals where per-Soroban-TX time goes:

### Per Soroban TX (~1100μs total, ~130 TXs/ledger = ~143ms)

| Component | Avg (μs) | % | Per ledger | Optimizable? |
|-----------|---------|---|------------|--------------|
| e2e_invoke (WASM host) | 360 | 33% | 47ms | No (upstream soroban-env-host) |
| Per-op bookkeeping | 480 | 44% | 62ms | Partially — see lessons learned |
| fee_seq (fees, seq bump, signers) | 112 | 10% | 15ms | Partially |
| apply_storage_changes | 69 | 6% | 9ms | Partially |
| validation | 71 | 6% | 9ms | Partially |
| footprint loading | 45 | 4% | 6ms | Minor |
| XDR encode + extract | 45 | 4% | 6ms | Not worth it |

**Per-op bookkeeping** is the per-operation overhead in `execute_single_transaction`:
2× `delta_snapshot()`, `delta_changes_between()`, `flush_modified_entries()`,
`begin_op_snapshot()` / `end_op_snapshot()`, savepoint management, entry change
building with state overrides. For Soroban TXs with exactly 1 operation, much of
this bookkeeping is redundant — the "operation changes" ARE the "transaction changes".

### Per-ledger setup/teardown (~36ms)

| Component | Time | Optimizable? |
|-----------|------|-------------|
| executor_setup (HashMap retain for offers) | 10.5ms | ✅ Fixed (Step 3 — offer/non-offer map split) |
| post_exec (fee event generation) | 7.9ms | ✅ Fixed (Step 4 — reuses prepared TX data) |
| tx_parse (XDR deserialization) | 7.4ms | ✅ Fixed (Step 4 — single prepare() call) |
| fee_deduct + preload | 5.0ms | Minor |
| phase_parse (soroban phase structure) | 4.4ms | ✅ Fixed (Step 4 — single prepare() call) |

### What's NOT the bottleneck

- **XDR entry serialization** (encode + extract): Only 45μs/TX total (6ms/ledger).
  For P25, `disk_read_bytes_exceeded` skips Soroban entries entirely — no duplicate
  serialization. The original plan's Steps 2–3 targeted this, but they would yield <6ms.
- **e2e_invoke host execution**: 360μs/TX (47ms/ledger). This is the upstream
  soroban-env-host crate — same Rust code as stellar-core. Cannot be optimized here.
- **`build_entry_changes_with_hot_archive` micro-optimizations**: Debug logging removal,
  `Vec<u8>` → `LedgerKey` keys, lazy HashMap, O(1) dedup — yielded 0ms measurable
  gain (see Step 2b). The function's cost is dominated by entry cloning and state
  lookups, not by key hashing or linear scans.

---

## Benchmark Protocol

All measurements use:
- **Binary**: release build (`cargo build --release --bin henyey -p henyey`)
- **Range**: `verify-execution --from 61349000 --to 61350000` (1000 closes, protocol 25)
- **Cache**: `--cache-dir ~/data/<session>/cache` (pre-warmed from prior run)
- **Logging**: `RUST_LOG=info` for timing, `RUST_LOG=debug` for phase breakdown
- **Machine**: same host for all runs (no cross-machine comparisons)
- **A/B method**: Build baseline and optimized binaries, run back-to-back on same
  1000-ledger range in a single session to minimize system load variance

### Baseline

| Metric | Value |
|--------|-------|
| Mean | 317.5ms |
| p50 | 385ms |
| p95 | 507ms |
| stellar-core reference | 168.5ms mean |

### Acceptance Criteria

The optimization is considered successful when:

1. **Performance**: Mean ledger close ≤ 220ms on the benchmark range (1.3x stellar-core)
2. **Correctness**: Hash parity on ≥1000 consecutive mainnet ledgers with `verify-execution`
3. **No RSS regression**: Peak RSS increase ≤ 200MB over baseline
4. **All tests pass**: `cargo test --all` + `cargo clippy --all` clean

Stretch goal: ≤ 190ms mean (1.13x stellar-core).

---

## Optimization Steps

### Step 1: TTL Key Hash Caching ✅ DONE

**Commit**: `a1db12f` | **Result**: −10.4ms (307.1ms)

Built `TtlKeyCache` (`HashMap<LedgerKey, Hash>`) during `load_soroban_footprint`,
threaded it through all Soroban validation/execution functions. Eliminates ~15K
redundant `key.to_xdr() + SHA256` computations per ledger.

Original estimate was −60 to −80ms. Actual: −10.4ms. SHA-256 of small keys
(~100-200 bytes) takes <1μs each — the hash computation was never the real
bottleneck. The profiling done after this step revealed the true cost structure
(see Profiling Breakdown above).

---

### Step 2: Incremental Mutation Tracking ✅ DONE (below expectations)

**Commit**: `b74e111` | **Result**: −3.5ms (303.6ms)

Two sub-optimizations targeting per-op bookkeeping:

**A) Zero-copy DeltaSlice**: Replaced `DeltaChanges` (5 owned `Vec`s cloned per
call via `.to_vec()`) with `DeltaSlice<'a>` holding range indices into the parent
`LedgerDelta`, returning `&[T]` slices on demand. Eliminates allocations at the
2 hot-path call sites (fee charging, per-op loop).

**B) Skip savepoint for single-op TXs**: For TXs with exactly 1 operation (all
Soroban, many classic), skip `create_savepoint()` since TX-level rollback handles
failures. Guarded `rollback_to_savepoint()` with `Option`.

**Why it underperformed** (original estimate: −30 to −50ms):

Targeted profiling with per-call instrumentation revealed the original sampled
profiling grossly overestimated costs:

| Operation | Estimated per-call | Actual per-call (Soroban) | Actual per-call (classic) |
|-----------|-------------------|--------------------------|--------------------------|
| `create_savepoint()` | 100-150μs | **~2μs** | 30-120μs |
| `delta_changes_between()` | 30-50μs | **<1μs** | varies |

Root cause: Soroban TXs have tiny state (few modified entries) → savepoint clones
near-empty maps, `.to_vec()` copies 1-3 element vectors. The 480μs/TX estimate from
sampling profiler was primarily attributable to `build_entry_changes_with_hot_archive`
(60-100μs/TX, 15-25ms/ledger), not to delta cloning or savepoints.

Per-ledger phase breakdown (busy ledger, ~250 TXs, ~200 Soroban):

| Phase | Per-ledger cost |
|-------|----------------|
| `create_savepoint` (Soroban, skippable) | 0.3-1.0ms |
| `create_savepoint` (classic, required) | 2-5ms |
| `flush_modified_entries` | 0.3-0.8ms |
| `change_order` alloc | ~0ms |
| `build_entry_changes_with_hot_archive` | **15-25ms** |

The changes are correct and harmless but deliver only ~3.5ms of the estimated
30-50ms. The real per-op bookkeeping bottleneck is meta construction
(`build_entry_changes_with_hot_archive`).

---

### Step 2b: Meta Construction Micro-Optimizations ✅ DONE (no measurable gain)

**Commit**: `3b48532` | **Result**: ~0ms (303.6ms → 312ms, within noise)

Five targeted optimizations to `build_entry_changes_with_hot_archive`:

1. **Removed debug logging** — 7 debug loops, inline TTL traces, `entry_type_name`
   helper, `build_transaction_meta` debug log (-227 lines)
2. **Lazy `final_updated` HashMap** — moved into fallback branch (Soroban/classic
   change_order paths never used it)
3. **`Vec<u8>` → `LedgerKey` keys** — eliminated `entry_key_bytes()` (XDR serialize
   per key). `created_keys`, `seen_keys`, `final_updated` now use `LedgerKey` directly
4. **O(1) `already_processed` check** — replaced O(n×m) `changes.iter().any()` with
   `HashSet<LedgerKey>` for live_bucket_list_entries/hot_archive_entries loops
5. **Pre-computed key passing** — `push_created_or_restored` accepts `&LedgerKey`

Benchmark (3 runs, median): 312.15ms. No improvement over 303.6ms baseline.

**Why it didn't help**: The function's cost is dominated by `LedgerEntry` cloning
(each change pushes `.clone()`) and snapshot state lookups, not by key hashing or
linear scans. The O(n×m) `already_processed` check only fires for restore operations
(rare). Debug logging with `tracing::debug!` at `RUST_LOG=info` short-circuits
after a single bool check — the loop iteration overhead was negligible.

**Lesson learned**: Micro-optimizing data structures within a function rarely helps
when the dominant cost is entry cloning and I/O. The 15-25ms/ledger attributed to
this function likely reflects the cost of building `Vec<LedgerEntryChange>` with
cloned entries — fundamentally required for correctness. Further optimization would
require structural changes (e.g., avoiding entry clones via `Arc<LedgerEntry>` or
building meta lazily/on-demand).

---

### Step 3: Executor Setup — Offer/Non-Offer Map Split ✅ DONE

**Commit**: `0edb0d4` | **Result**: −8.83ms (A/B on 1000 ledgers)

Split `entry_sponsorships`, `entry_sponsorship_ext`, and `entry_last_modified` into
offer-specific and non-offer maps. On `clear_cached_entries_preserving_offers()`,
non-offer maps call `.clear()` (O(1)) instead of `.retain()` (O(n) scan).

Added `is_offer_key()` routing and helper methods (`get_entry_sponsorship`,
`insert_entry_sponsorship`, etc.) to abstract the split. Updated all access points
in `entries.rs`, `sponsorship.rs`, and rollback/savepoint logic in `mod.rs`.

**A/B benchmark** (1000 ledgers, 61349000–61350000):

| | Step 4 only | Step 4 + Step 3 | Delta |
|--|-------------|-----------------|-------|
| Average per ledger | 337.05ms | 328.22ms | −8.83ms (−2.6%) |
| tx_exec | 302.08ms | 294.70ms | −7.38ms |

**Files modified**:
- `crates/tx/src/state/mod.rs` — split maps, helpers, updated clear/rollback/savepoint
- `crates/tx/src/state/entries.rs` — routed via helpers
- `crates/tx/src/state/sponsorship.rs` — routed via helpers

---

### Step 4: Unified TX Set Parsing ✅ DONE

**Result**: Structural improvement (eliminates 5 redundant TX set parses).

**Problem**: Five separate passes parse the `GeneralizedTransactionSet`:
1. `transactions_with_base_fee()` — hash + sort + clone all TXs
2. `soroban_phase_structure()` — hash + sort stages/clusters
3. `classic_phase_transactions()` — hash + sort classic TXs
4. Post-exec fee events — `transactions_with_base_fee()` again + `TransactionFrame` per TX
5. Post-exec perf data — `transactions_with_base_fee()` again + `TransactionFrame` per TX

Each call recomputes the TX set hash (full XDR serialize + SHA-256) and re-sorts.

**Solution**: Added `PreparedTxSet` struct in `close.rs` with single-pass `prepare()`:
- `hash`: computed once via `self.hash()`
- `classic_txs`: sorted classic phase TXs
- `soroban_phase`: pre-parsed `SorobanPhaseStructure` (if present)
- `all_txs`: flat ordered list (classic + soroban flattened)
- `tx_meta`: per-TX `fee_source` and `is_soroban` (avoids `TransactionFrame` construction)

All 5 call sites in `apply_transactions()` replaced with reads from `prepared`.

**Files modified**:
- `crates/ledger/src/close.rs` — added `PreparedTxSet`, `TxMeta`, `envelope_is_soroban()`, `prepare()`
- `crates/ledger/src/manager.rs` — replaced 5 parsing calls with single `prepared`
- `crates/ledger/src/execution/mod.rs` — made `fee_source_account_id()` `pub(crate)`

**Benchmark** (A/B, 1000 ledgers 61349000–61350000, same session back-to-back):

| | Baseline (`6ecd777`) | Optimized (`3f8a47f`) | Delta |
|--|----------------------|----------------------|-------|
| Average per ledger | 586.91ms | 346.07ms | −240.84ms (−41%) |
| close_ledger | 446.89ms | 322.00ms | −124.89ms |
| tx_exec | 430.07ms | 311.53ms | −118.54ms |
| commit | 8.74ms | 5.48ms | −3.26ms |
| Mismatches | — | 0 | — |

The −41% delta is larger than expected from parsing elimination alone. The baseline
binary (`6ecd777`) may have been running under different system memory pressure, or
the parsing elimination reduced GC/allocator pressure with cascading benefits.

---

### Step 5a: Global Ed25519 Signature Verification Cache ✅ DONE

**Commit**: `87e7c2e` | **Result**: −33ms (A/B on 1000 ledgers)

Added a global thread-safe `SigVerifyCache` (250K-entry FIFO) inside `verify_hash()`
in `crates/crypto/src/signature.rs`, matching stellar-core's `gVerifySigCache` in
`SecretKey.cpp`. Cache key: `SHA-256(pubkey || signature || message_hash)`.

All 10 ed25519 verification call sites flow through `verify_hash()` and automatically
benefit — zero call-site changes required. Within a TX, the same signature is verified
2+N times (N = num ops); the cache eliminates all redundant ed25519 verifies.

**A/B benchmark** (1000 ledgers, 61349000–61350000, back-to-back same session):

| | Baseline | With sig cache | Delta |
|--|----------|---------------|-------|
| close_ledger (run 1) | 307.1ms | 277.7ms | −29.4ms (−9.6%) |
| close_ledger (run 2) | 310.2ms | 282.0ms | −28.2ms (−9.1%) |
| tx_exec (run 1) | 295.2ms | 263.9ms | −31.3ms |
| Mismatches | 0 | 0 | — |
| Peak RSS | ~12.6GB | ~12.6GB | negligible |

**Why it outperformed estimates**: Original estimate was −5 to −15ms based on the
profiled validation cost (27.8ms). But the cache captures savings across ALL phases —
validation, fee_seq (signer verification), per-op signature checks, and
`check_operation_signatures`. With ~297 TXs/ledger and ~297 ops/ledger, each signature
is verified multiple times across these phases, and all redundant verifies become
HashMap lookups (~50ns vs ~50μs for ed25519 verify).

**Post-5a fee_seq re-profiling** (100 ledgers, RUST_LOG=debug, sig_check sub-phases):

| Sub-phase | No cache | With cache | Delta |
|-----------|----------|-----------|-------|
| sig_verify (check_operation_signatures) | 58.6ms | 20.9ms | −37.7ms |
| fee_deduct | 0.5ms | 0.5ms | 0ms |
| fee_bump_hash | 0.9ms | 0.9ms | 0ms |
| signer_remove | 1.4ms | 1.4ms | 0ms |
| seq_bump | 1.8ms | 1.8ms | 0ms |
| **fee_seq total** | **63.8ms** | **26.1ms** | **−37.7ms** |

The 20.9ms residual in `check_operation_signatures` is:
- Soroban: 11.2ms (50μs/TX × 224 TXs) — signer list building, type splitting, iteration
- Classic: 9.6ms (41μs/TX × 236 TXs) — same overhead, often more ops per TX

This overhead is from allocations (4 Vec splits, HashSet per type) and signer list
construction on each call. The cache eliminates the ed25519 verify cost but not the
surrounding bookkeeping. Potential optimization: cache the full `check_signature` result
per (account, tx_hash) pair, or restructure to avoid per-call allocation.

**Files modified**:
- `crates/crypto/src/signature.rs` — `SigVerifyCache`, global static, cached `verify_hash()`
- `crates/crypto/Cargo.toml` — added `once_cell` dependency

---

### Step 5b: Avoid Ed25519 Point Decompression on Cache Hits ✅ DONE

**Commit**: `d95e7e2` | **Result**: Combined with 5a: −30.7ms (A/B, 1001 ledgers)

**Problem**: Even with the sig cache (Step 5a), `check_operation_signatures` still took
20.9ms/ledger. Investigation revealed hidden cost: `PublicKey::from_bytes()` calls
`ed25519_dalek::VerifyingKey::from_bytes()` which performs ed25519 curve point
decompression (~35μs per call). This ran on every signer check — even when the
subsequent `verify_hash()` would hit the cache and skip verification entirely.

stellar-core's `PubKeyUtils::verifySig` checks the signature cache using raw bytes
**before** any decompression. On cache hits, no crypto work occurs at all.

**Solution**: Added `verify_hash_from_raw_key(pubkey_bytes: &[u8; 32], ...)` which
checks the cache with raw bytes first, and only decompresses on cache miss. Updated
all 6 ed25519 verification call sites across 5 files to pass raw `&[u8; 32]` bytes
instead of decompressing to `PublicKey` first.

**A/B benchmark** (1001 ledgers, 61349000–61350000):

| | Baseline (no cache) | Cache + raw-key | Delta |
|--|---------------------|----------------|-------|
| close_ledger | 304.15ms | 273.46ms | −30.7ms (−10.1%) |
| tx_exec | 293.65ms | 261.15ms | −32.5ms |
| Mismatches | 0 | 0 | — |
| Peak RSS | 12813MB | 12946MB | +133MB (cache overhead) |

**Files modified**:
- `crates/crypto/src/signature.rs` — added `verify_hash_from_raw_key()`
- `crates/tx/src/validation.rs` — added `verify_signature_with_raw_key()`
- `crates/tx/src/lib.rs` — exported new function
- `crates/tx/src/signature_checker.rs` — use raw key in `verify_ed25519()`
- `crates/ledger/src/execution/mod.rs` — use raw key in `check_signature_from_signers`
- `crates/ledger/src/execution/signatures.rs` — `has_ed25519_signature_raw()` with raw key
- `crates/herder/src/tx_queue/mod.rs` — use raw key in tx queue signature check

---

### Step 5c: Reduce check_operation_signatures Bookkeeping (Expected: −5 to −10ms)

**Status**: Not started

**Problem**: With ed25519 verify cached and decompression bypassed on hits, the
residual `check_operation_signatures` cost (~15-20ms/ledger) is per-call bookkeeping:
- Build signer list from AccountEntry signers (Vec alloc + SignerKey clone)
- Split into 4 type-specific Vecs (alloc × 4)
- HashSet<usize> creation per type for consumed tracking
- Called 2× per Soroban TX (TX-level + 1 op), 1+N per classic TX

**Solution options**:
- (A) Skip per-op check for single-op same-source TXs (covers ~90% of Soroban)
- (B) Cache check_signature result per (account_id, tx_hash) pair
- (C) Pre-split signers by type once per account load

**Files to modify**:
- `crates/ledger/src/execution/signatures.rs` — optimize `check_operation_signatures`
- `crates/ledger/src/execution/mod.rs` — `check_signature_from_signers`

**Benchmark gate**: Expected: mean ≤ 265ms. If improvement < 3ms, investigate.

---

## Execution Protocol

For each step:

1. **Implement** the optimization
2. **Verify correctness**: `cargo test --all` + `cargo clippy --all` clean
3. **Verify parity**: `verify-execution` on ≥1000 consecutive mainnet ledgers
4. **Run benchmark**: benchmark protocol (3 runs, median of means)
5. **Evaluate**:
   - If improvement meets or exceeds the step's expected range → document results
     in the table below, commit, push, and proceed to next step
   - If improvement is below the step's minimum threshold → investigate root cause,
     attempt to fix. If fixed, re-benchmark and proceed
   - If not fixable → stop, document findings, alert human and wait for instructions

---

## Results

| Step | Commit | Mean | Δ from prev | Δ from baseline | Notes |
|------|--------|------|-------------|-----------------|-------|
| Baseline | `bd8f3f7` | 317.5ms | — | — | |
| 1: TTL key hash caching | `a1db12f` | 307.1ms | −10.4ms | −10.4ms | SHA-256 was <1μs/call |
| 2: Incremental mutation tracking | `b74e111` | 303.6ms | −3.5ms | −13.9ms | Savepoint ~2μs for Soroban (not 100-150μs) |
| 2b: Meta construction cleanup | `3b48532` | ~303.6ms | ~0ms | −13.9ms | Code cleanup only, no perf gain |
| 3: Offer/non-offer maps | `0edb0d4` | 328.2ms* | −8.83ms* | — | A/B on 1000 ledgers |
| 4: Unified TX set parsing | `3f8a47f` | 346.1ms* | −240.8ms* | — | A/B on 1000 ledgers; *delta inflated by system conditions |
| 5a: Sig verify cache | `87e7c2e` | ~280ms | −29ms | — | A/B on 1000 ledgers; 2 runs consistent |
| **5b: Raw-key decompression bypass** | **`d95e7e2`** | **273.5ms** | **−30.7ms combined** | — | **A/B on 1001 ledgers; bypasses point decompression on cache hits** |
| 5c: check_op_sigs bookkeeping | | | | | |

---

## Projected Results

| Step | Expected Gain | Cumulative | Ratio vs stellar-core |
|------|--------------|------------|----------------------|
| Baseline | — | 317.5ms | 1.88x |
| 1: TTL key hash caching | −10ms | 307ms | 1.82x |
| 2: Incremental mutation tracking | −3.5ms | 303.6ms | 1.80x |
| 2b: Meta construction cleanup | 0ms | 303.6ms | 1.80x |
| 3: Offer/non-offer maps | −8.83ms | ~295ms | ~1.75x |
| 4: Unified TX set parsing | ~−10ms (est.) | ~285ms | ~1.69x |
| 5a: Sig verify cache | −29ms | ~280ms | ~1.66x |
| **5b: Raw-key decompression bypass** | **−30.7ms combined** | **273.5ms** | **1.62x** |
| 5c: check_op_sigs bookkeeping | −5 to −10ms | 263–268ms | 1.56–1.59x |
| 6: Profile unprofiled ~217ms | TBD | TBD | TBD |

**Current: 273.5ms (1.62x stellar-core)**

The 220ms acceptance target requires ~53ms more savings. Post-5b, the remaining profiled
optimization targets are check_operation_signatures bookkeeping (~15-20ms), validation
residual (~10-15ms), and prepare/hash (~5-9ms). To reach 220ms, we must find ~25-35ms
in the unprofiled ~217ms region (op execution, commit, bucket list).

---

## Lessons Learned

1. **Sampled profiling overestimates**: The sampling profiler attributed 480μs/TX to
   "per-op bookkeeping," but targeted instrumentation showed the actual costs were
   10–100x smaller for individual operations (savepoint ~2μs, delta diff <1μs).
   The sampled cost likely included overhead from the profiler itself or unresolvable
   call-stack attribution.

2. **Entry cloning dominates meta construction**: `build_entry_changes_with_hot_archive`
   spends most of its time cloning `LedgerEntry` values into the output
   `Vec<LedgerEntryChange>`. Replacing `Vec<u8>` keys with `LedgerKey`, removing debug
   logging, and adding O(1) lookups yielded 0ms because the cloning cost dwarfs
   everything else. Fixing this requires either `Arc<LedgerEntry>` shared ownership or
   lazy/streaming meta construction.

3. **Cross-cutting caches outperform phase-specific optimizations**: The signature
   verification cache (Step 5a) delivered −29ms despite being estimated at −5 to −15ms —
   because signatures are verified across multiple phases (validation, fee_seq signer
   checks, per-op checks). Re-profiling confirmed: `sig_verify` in fee_seq alone dropped
   from 58.6ms → 20.9ms (−37.7ms internal saving). Optimizations at a low-level leaf
   function have outsized impact when called from many hot paths.

4. **Hidden costs in type conversions**: `PublicKey::from_bytes()` performs ed25519
   curve point decompression (~35μs), not just a copy. This ran on every signer check
   even when the signature cache would hit. stellar-core avoids this by checking the
   cache with raw bytes first. The fix (Step 5b) passes raw `&[u8; 32]` through the
   entire pipeline, deferring decompression to cache misses only.

5. **Setup/teardown is the reliable optimization target**: Per-ledger costs like
   executor_setup (10.5ms), tx_parse (7.4ms), and post_exec (7.9ms) are large, fixed,
   and have clear solutions. These are more predictable wins than per-TX micro-opts.

---

## Fresh Profiling Results (Post Steps 1-4)

Instrumented profiling on 1008 ledgers (61349000–61350000), mean close 303.2ms:

| Phase | ms/ledger | % of close | Notes |
|-------|-----------|-----------|-------|
| **fee_seq** | **40.8** | **13.5%** | Fee deduction + seq bump + signer removal |
| **validation** | **27.8** | **9.2%** | TX validation (signatures, preconditions) |
| prepare | 8.8 | 2.9% | TX set parse/hash (was ~15ms before Step 4) |
| footprint | 6.1 | 2.0% | Soroban footprint loading from state/buckets |
| meta_constr | 1.6 | 0.5% | `build_entry_changes_with_hot_archive` |
| flush | 0.7 | 0.2% | `flush_modified_entries` |
| executor_setup | 0.2 | 0.1% | Context creation (was ~10ms before Step 3) |
| fee_events | 0.0 | 0.0% | Already optimized in Step 4 |
| **Subtotal profiled** | **85.9** | **28.3%** | |
| **Unprofiled** | **217.3** | **71.7%** | Op execution + commit + bucket list |

**Key insight**: Meta construction (1.6ms) is far smaller than the 15-25ms estimated
from sampled profiling. The Arc<LedgerEntry> refactor is no longer the highest
priority. fee_seq (40.8ms) and validation (27.8ms) are the dominant profiled costs.

The unprofiled 217ms includes actual operation execution (WASM host, classic ops),
ledger commit, and bucket list updates — these require separate profiling.

---

## Remaining Optimization Targets

Ranked by expected impact. Steps 1–5b done. Current mean: 273.5ms.

### 1. Profile the Unprofiled 217ms (HIGHEST PRIORITY)

**Measured cost**: ~217ms/ledger (71.7% of close time) | **Complexity**: Low (instrumentation)

The majority of ledger close time is unmeasured. Before optimizing smaller profiled
phases, we need to decompose this region:
- **Operation execution**: WASM host invocation, classic op dispatch, state reads/writes
- **Commit phase**: SQLite writes, bucket list adds, entry serialization
- **Bucket list maintenance**: merge scheduling, eviction scans

**Action**: Add `Instant`-based timing to `execute_single_transaction` (per-op dispatch),
`commit_ledger` sub-phases, and bucket list operations. Run on the benchmark range with
`RUST_LOG=debug` to get a breakdown. This will likely reveal the largest remaining
optimization opportunity.

### 2. Reduce `check_operation_signatures` Overhead (Step 5c)

**Measured cost**: 20.9ms/ledger (post-5a) | **Expected gain**: −5 to −10ms | **Complexity**: Medium

Re-profiling shows that even with cached ed25519 verify, `check_operation_signatures`
still takes 20.9ms/ledger. The cost is now dominated by per-call bookkeeping in
`check_signature_from_signers`:
- Building `Vec<(SignerKey, u32)>` from account signers (allocation + clone)
- Splitting into 4 type-specific Vecs (pre_auth, hash_x, ed25519, signed_payload)
- Creating `HashSet<usize>` for consumed-signer tracking per type
- Called 1 + N_ops times per TX (Soroban: 2×, classic: 1 + num_ops)

**Solution options**:
- (A) **Cache check_signature result per (account_id, tx_hash)**: If the same account
  is checked multiple times with the same tx_hash (TX-level + per-op with same source),
  return cached result. Covers ~90% of Soroban TXs (single op, same source).
- (B) **Avoid per-call allocation**: Pre-split signers once when loading the account,
  store type-split lists on the account or in the SignatureTracker.
- (C) **Skip per-op check for single-op same-source TXs**: If the TX has 1 op and
  no per-op source override, the per-op check is identical to the TX-level check.

**Breakdown by TX type** (post-5a):
- Soroban: 50μs/TX × 224/ledger = 11.2ms (signer build + 2 calls, mostly cache-hit verify)
- Classic: 41μs/TX × 236/ledger = 9.6ms (same overhead, but typically 1 op)

### 3. Validation Optimization (partially done by 5a)

**Measured cost**: 27.8ms/ledger (pre-5a), ~10-15ms estimated post-5a | **Expected gain**: −3 to −8ms | **Complexity**: Medium

Step 5a eliminated the ed25519 verification component. Remaining validation cost is
likely precondition checks, account loading, and XDR decoding. Needs re-profiling to
confirm residual cost.

### 4. Prepare Optimization (TX set hash)

**Measured cost**: 8.8ms/ledger | **Expected gain**: −3 to −5ms | **Complexity**: Low

Pass the TX set hash from consensus into `prepare()` to skip recomputation (full XDR
serialize + SHA-256 of the entire transaction set).

### 5. Meta Construction — Arc<LedgerEntry> (deprioritized)

**Measured cost**: 1.6ms/ledger | **Expected gain**: ~1ms | **Complexity**: High

Not cost-effective given high complexity and small actual gain.

---

**Recommendation**: The path to 220ms requires ~53ms more savings. Post-5b:
- `check_operation_signatures` bookkeeping: ~15-20ms — optimizable via skipping
  redundant per-op checks for same-source TXs (Step 5c, expected −5 to −10ms)
- Unprofiled region: ~217ms — must instrument to find the next big target

Concrete next steps:
1. **Step 5c**: Reduce `check_operation_signatures` overhead (~15ms → ~5-10ms)
2. **Instrument** the unprofiled ~217ms (op execution, commit, bucket list)
3. Based on (2), prioritize the next optimization

---

## Methodology Notes

### How the baseline was established

1. Built henyey release binary from commit `bd8f3f7` (pre-optimization main branch)
2. Ran `verify-execution --from 61349540 --to 61349640` with pre-warmed cache
3. Parsed `RUST_LOG=debug` output for per-ledger `apply_transactions` timing
4. Excluded first ledger (cold start: loads ~911K offers)
5. Computed mean/p50/p95 over remaining 136 ledgers

### How stellar-core reference was established

1. Ran stellar-core v25.2.0 (Docker `stellar/stellar-core:latest`) catchup on same
   ledger range: `catchup 61349640/101`
2. Parsed "applying ledger" → "Ledger close complete" timestamp pairs
3. Excluded first ledger, computed stats over 136 ledgers

### Linear regression methodology

Fit `time = a * classic_ops + b * soroban_ops + c` for both stellar-core and henyey.
Op counts from stellar-core's "applying ledger" log lines. Regression coefficients
decompose the gap into per-classic-op, per-soroban-op, and fixed overhead components.

### Profiling methodology (post-Step 1)

Added `std::time::Instant` instrumentation inside `execute_host_function_p25`
(encode/invoke/extract phases) and `execute_contract_invocation` (pre_checks/host/
apply/hash phases). Aggregated across ~5400 Soroban TXs on the benchmark range.
Instrumentation was temporary (reverted after data collection).
