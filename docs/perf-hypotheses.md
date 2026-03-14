# Performance Hypotheses

## Round 4: Target 15,000 TPS at 4 clusters (50K TXs)

Baseline: 9,106 TPS | Target: 15,000 TPS | Date: 2026-03-14
Config: 4 clusters, 50K SAC transfer TXs/ledger, single-shot mode (10 iterations)
Need: 3,333ms/ledger (currently 5,099ms, need to cut 1,766ms = 35%)

### Baseline Breakdown (avg ms/ledger)

| Phase | ms | % | Notes |
|-------|-----|---|-------|
| soroban_exec | 3,271 | 64% | 1 stage, 4 clusters of 12,500 TXs each |
| — cluster wall | 2,814 | 55% | max of 4 parallel clusters (~225µs/TX) |
| — delta_merge | 221 | 4.3% | serial, clones all LedgerEntry values |
| — result_merge | 172 | 3.4% | serial, clones all TX results/meta |
| — prior_stage + prefetch + refund | 64 | 1.3% | |
| add_batch | 620 | 12% | bucket list merge, single-threaded |
| prepare | 279 | 5.5% | TX hash computation dominates (~5.6µs/TX) |
| fee_pre_deduct | 168 | 3.3% | sequential fee deductions |
| meta | 162 | 3.2% | TX meta building |
| commit soroban_state | 100 | 2.0% | in-memory state updates |
| commit setup | 14 | 0.3% | |
| post_exec | 14 | 0.3% | |
| **total** | **5,099** | **100%** | |

### Hypotheses

| # | Hypothesis | Status | Expected Gain | Measured Gain | TPS After |
|---|-----------|--------|---------------|---------------|-----------|
| 20 | Move cluster results by value instead of cloning (delta_merge + result_merge) | pending | ~350ms (7%) | | |
| 21 | Parallelize prepare phase (TX hash computation) | pending | ~200ms (4%) | | |
| 22 | Parallelize meta building (per-TX independent) | pending | ~120ms (2.5%) | | |
| 23 | Reduce per-TX cost in cluster execution (225µs→150µs) | pending | ~500ms (10%) | | |
| 24 | Overlap add_batch with next iteration setup | pending | ~400ms (8%) | | |
| 25 | Batch fee deduction (parallel for unique accounts) | pending | ~120ms (2.5%) | | |

### Hypothesis Details

**H20: Move cluster results by value (delta_merge + result_merge = 393ms)**
- `delta.merge(cluster_delta)` clones every LedgerEntry in each cluster's delta
- `all_results.extend(cr.results.iter().cloned())` clones all 50K TX results
- Fix: consume the cluster delta by moving entries, extend results with `into_iter()` instead of `.iter().cloned()`
- Expected: 393ms → ~50ms (most entries become zero-cost moves)

**H21: Parallelize prepare phase (279ms)**
- TX hash computation (XDR serialize + SHA-256) at ~5.6µs/TX is embarrassingly parallel
- Use rayon par_iter to compute all 50K hashes across available cores
- Expected: 279ms → ~70ms (4x speedup on 4+ cores)

**H22: Parallelize meta building (162ms)**
- Each TX's meta (TransactionResultMetaV1) is independent
- Currently built sequentially within each cluster
- Move to parallel construction or batch the XDR encoding
- Expected: 162ms → ~40ms

**H23: Reduce per-TX soroban cost (225µs/TX, 2,814ms wall)**
- At 16 clusters previous round measured 115µs/TX; at 4 clusters it's 225µs
- The 2x slowdown is likely due to larger per-cluster delta/state maps
- Profile to find the per-TX hotspot at 12,500 TX scale
- Target: validate_preconditions, load_soroban_footprint, host invocation

**H24: Overlap add_batch (620ms)**
- Bucket list add_batch runs after execution completes
- Could run in background while next iteration starts setup
- Requires snapshot isolation (next iteration reads from bucket list)
- Complex but high-value

**H25: Batch fee deduction (168ms)**
- SAC loadgen uses unique source accounts, no balance dependencies
- Could parallelize with rayon if accounts are guaranteed unique within a batch

---

## Round 3: Target 30,000 TPS (gap remaining)

Baseline: 25,764 TPS (perf) | Target: 30,000 TPS | Date: 2026-03-14

### Current Best: ~29,400 TPS perf-equivalent (perf total: ~849ms)

| Phase | ms (baseline) | ms (current) | Savings |
|-------|---------------|-------------|---------|
| soroban_exec | 462 | 408 | **-54ms** |
| add_batch | 192 | 168 | **-24ms** |
| prepare | 95 | 94 | -1ms |
| fee_pre_deduct | 42 | 39 | -3ms |
| meta | 40 | 32 | -8ms |
| soroban_state | 24 | ~24 | ~0 |
| commit_setup | 5 | ~5 | ~0 |
| header_hash | 0.02 | 0.02 | ~0 |
| **total (perf)** | **~970** | **~849** | **-121ms (-12.5%)** |

Perf-equivalent TPS: 24992/0.849 = **29,437 TPS** (target: 30,000)
Overall TPS (incl. bucket ops): ~26,500 (avg), ~26,600 (best run)

Note: "perf total" measures only TX processing time (soroban exec + add_batch +
prepare + fees + meta). Overall TPS also includes bucket list maintenance (spill,
merge, eviction) which adds ~200-350ms of variable overhead per ledger. Closing
the remaining gap to 30K overall TPS requires either reducing bucket overhead or
further shaving ~16ms from the perf total.

### Hypotheses

| # | Hypothesis | Status | Expected Gain | Measured Gain | TPS After |
|---|-----------|--------|---------------|---------------|-----------|
| 7 | Zero-alloc ValDeser charging in Soroban host | accepted | ~2% | minor (part of H8) | - |
| 8 | Reuse TTL key SHA-256 cache across TXs | accepted | ~3-5% | +3.6% | 25,723 |
| 11 | Arc-wrap TransactionEnvelope in TransactionFrame | accepted | ~2% | -14ms (prep+fee) | 25,764 |
| 16 | Incremental hash in bucket merge (avoid 2nd XDR pass) | accepted | ~1-2% | -13ms add_batch | ~26,500 |
| 17 | Reuse TransactionFrame in pre_apply (1 clone → 0) | accepted | ~3-4% | -34ms soroban_exec | ~26,500 |
| 18 | Thread Arc through execute_transaction hot path | accepted | ~1-2% | -10ms soroban_exec | ~27,000 |
| 19 | Zero-alloc XDR size via CountingWriter (7 sites) | accepted | ~5-8% | -77ms total | ~29,400 |
| 13 | Lazy bucket key index (skip HashMap build on fresh) | superseded | ~3-5% | — | — |
| 14 | Reduce entry cloning in bucket merge (move semantics) | superseded | ~3-5% | — | — |
| 12 | Cache Soroban cost params per ledger (avoid clone/TX) | pending | ~1-2% | | |
| 9 | Skip per-TX footprint XDR ser via pre-computed key hash | pending | ~2-3% | | |
| 10 | Reduce prior_load overhead via Arc sharing | pending | ~1-2% | | |

H13 and H14 were superseded by H16 (incremental merge hash), which addresses the
same bucket merge overhead from a different angle: instead of skipping the key
index or avoiding clones, H16 computes hash + index during the merge loop itself,
eliminating the separate `from_sorted_entries` serialization pass. The fresh bucket
already used an empty key index (`fresh_in_memory_only`), so H13 was already
partially in place. H14's clone reduction is partially achieved by H16's buffer
reuse (single `xdr_buf` instead of per-entry `Vec<u8>` + `entry.clone()`).

H15 (eliminate redundant XDR ser for size) was implemented as H19 with a broader
scope: 7 sites across host.rs and invoke_host_function.rs replaced with a zero-
allocation CountingWriter.

### Per-TX Timing Analysis (updated after H19)

Soroban host execution: ~27µs per TX (very fast — this is the Soroban VM itself)
Henyey per-TX wrapper overhead: ~152µs → ~115µs per TX (24% reduction)
- validate_preconditions: ~36µs (down from ~50µs; frame no longer cloned per TX)
- load_soroban_footprint: ~40µs (key XDR ser + SHA-256 + bucket list lookup)
- host invocation setup: ~20µs (typed entry building, budget creation; no XDR alloc for size checks)
- result building: ~12µs (no XDR alloc for return value/event size computation)
- frame creation: ~1µs (was ~12µs; now Arc::clone instead of deep copy)

### Profiling Findings

Key discoveries from code analysis and profiling (samply):

**soroban_exec (408ms = 48% of perf total)**
- Per-TX: ~16.3µs wrapper + ~27µs host = ~43µs total × 24992 TXs ≈ 408ms given 16-cluster parallelism
- Biggest per-TX costs: footprint key SHA-256 hashing (~4-6µs), state snapshot/restore (~3µs),
  budget creation with cost param clone (~1µs), auth entry cloning (~0.5µs)
- 7 XDR-for-size serialization sites were the single largest optimization target (H19: -49ms)
- Remaining: cost param clone (ContractCostParams ~30 entries × 2 per TX) is ~1µs/TX = ~25ms total

**add_batch (168ms = 20% of perf total)**
- Dominated by XDR serialization during `from_sorted_entries()`: each of ~25K bucket entries
  serialized to compute the bucket hash and build the key index
- H16 (incremental merge) reduced this by computing hash during merge instead of a separate pass
- Remaining: deduplication sorts (~15-30ms), structural key comparisons during merge (~20ms),
  entry cloning in merge loop (~30ms), final bucket serialization (~80ms)

**prepare (94ms = 11% of perf total)**
- Dominated by per-TX hash computation: XDR serialize full TransactionEnvelope + SHA-256
  (~2µs/TX × 25K = ~50ms) plus HashMap grouping by account + sort (~40ms)
- Already well-optimized: hashes pre-computed before sort (Round 1, H1)

**fee_pre_deduct (39ms = 5% of perf total)**
- Per-TX: create TransactionFrame, compute fee, deduct from account on delta
- Reduced by H11 (Arc envelope) from ~48ms

---

## Round 2: Target 40,000 TPS (gap remaining)

| # | Hypothesis | Status | Measured Gain | TPS After |
|---|-----------|--------|---------------|-----------|
| 2 | Structural ScAddress comparison | accepted | -23% add_batch | 22,968 |
| 3 | Streaming XDR hash + TX set hash caching | accepted | header_hash 50ms->0ms | ~23,500 |
| 4 | Structural dedup in add_batch | accepted | -10% add_batch | ~24,500 |
| 6 | Index-based sort to avoid TX cloning | rejected | no improvement | - |

## Round 1: Target 15,000 TPS (completed)

| # | Hypothesis | Status | Measured Gain | TPS After |
|---|-----------|--------|---------------|-----------|
| 1 | Cache TX hashes in sort + eliminate TX clones | accepted | +77% | 20,097 |

---

## Cumulative Performance Summary

Original baseline: 11,329 TPS
Current best:      ~29,400 TPS (perf-equiv), ~26,500 TPS (overall incl. bucket ops)
Improvement:       +160% from original (perf-equivalent), +134% overall

### Round 3 optimizations applied (this session):
- H11: Arc-wrap TransactionEnvelope in TransactionFrame (-14ms prep+fee)
  Changed `envelope: TransactionEnvelope` → `Arc<TransactionEnvelope>` in
  TransactionFrame, propagated Arc through TxWithFee and all 27 files.
- H16: Incremental hash in bucket merge (-13ms add_batch)
  IncrementalMergeOutput computes SHA-256 hash + key index during the merge
  loop, reusing a single XDR buffer. Replaces separate from_sorted_entries pass.
- H17: Reuse TransactionFrame in pre_apply (-34ms soroban_exec)
  Create frame once in pre_apply, pass to validate_preconditions_with_frame.
  Eliminates 1 envelope deep-copy per TX (was 2 copies: one for soroban fee
  check, one for validation).
- H18: Thread Arc<TransactionEnvelope> through hot execution path (-10ms soroban_exec)
  Added execute_transaction_with_arc() + pre_apply_arc() that accept
  Arc<TransactionEnvelope> directly. Cluster and sequential execution callers
  pass Arc::clone() (~1ns) instead of deep-copying the ~500-byte envelope (~3µs).
- H19: Zero-alloc XDR size via CountingWriter (-77ms total, biggest win)
  7 sites in soroban host invocation serialized XDR to Vec<u8> just to call
  .len(). Replaced with CountingWriter that discards bytes, eliminating all
  per-TX heap allocations for size checks (return values, events, footprint
  entries, write bytes, read bytes metering).
- Combined: ~970ms → ~849ms total perf (-12.5%)

### Commits:
1. `0c66a74d` — Wrap TransactionFrame envelope in Arc for cheap cloning (H11)
2. `1e915d72` — Optimize merge hash computation and reduce per-TX envelope clones (H16, H17)
3. `3beef9f3` — Thread Arc<TransactionEnvelope> through hot execution path (H18)
4. `066299fd` — Replace allocating XDR serialization with counting writer (H19)
