# Performance Hypotheses

Baseline: 11,329 TPS | Target: 15,000 TPS | Date: 2026-03-14

## Benchmark Configuration

- Mode: single-shot, 24,992 TXs/ledger (SAC payments), 16 clusters, 10 iterations
- Config: configs/testnet.toml
- Hardware: macOS (Darwin 25.3.0)
- Build: release (RUSTFLAGS="-A deprecated")

## Baseline Perf Breakdown (avg ms/ledger)

Wall clock: ~2200ms = txset_build (~1096ms) + lm_close (~1100ms)

Inside lm_close:
- soroban_exec: 429ms
- add_batch (bucket list): 253ms
- prepare (tx apply): 125ms
- fee_pre_deduct: 49ms
- header_hash: 49ms
- meta: 31ms
- soroban_state: 26ms
- commit_setup: 6ms
- other: ~28ms gap

## Hypotheses

| # | Hypothesis | Status | Expected Gain | Measured Gain | TPS After |
|---|-----------|--------|---------------|---------------|-----------|
| 1 | Cache TX hashes in sort + eliminate TX clones in txset build | accepted | ~40-50% | +77% | 20,097 |
| 2 | Optimize soroban_exec: batch host function invocation or reduce per-TX overhead | pending | ~5-10% | | |
| 3 | Optimize add_batch: reduce bucket list merge overhead | pending | ~5% | | |
| 4 | Reduce prepare phase overhead (tx validation, footprint setup) | pending | ~3% | | |
| 5 | Reduce fee_pre_deduct overhead | pending | ~2% | | |
| 6 | Optimize header_hash computation | pending | ~2% | | |

## Performance Optimization Summary

Baseline:  11,329 TPS
Final:     20,097 TPS
Target:    15,000 TPS
Improvement: +77%
Status:    target reached

Accepted optimizations:
- H1: Cache TX hashes in sort + eliminate TX clones: +77% (11,329 -> 20,097 TPS)
  - `stages_to_xdr_phase`: replaced `sort_by` (re-hashing per comparison) with `sort_by_cached_key` (hash once per TX)
  - `build_two_phase_tx_set`: changed to take owned `Vec<TransactionEnvelope>` instead of `&[TransactionEnvelope]`
  - `build_tx_set_from_envelopes`: partition via `into_iter()` instead of `iter().cloned()`
  - Root cause: for 25K TXs, the sort did ~275K XDR-serialize+SHA256 operations; now does ~25K
