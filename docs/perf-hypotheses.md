# Performance Hypotheses

## Round 3: Target 30,000 TPS (target reached!)

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
| 12 | Cache Soroban cost params per ledger (avoid clone/TX) | pending | ~1-2% | | |
| 9 | Skip per-TX footprint XDR ser via pre-computed key hash | pending | ~2-3% | | |
| 10 | Reduce prior_load overhead via Arc sharing | pending | ~1-2% | | |

### Per-TX Timing Analysis (updated after H19)

Soroban host execution: ~27µs per TX (very fast)
Henyey per-TX wrapper overhead: ~152µs → ~115µs per TX
- validate_preconditions: ~36µs (frame no longer cloned)
- load_soroban_footprint: ~40µs (key XDR ser + SHA-256 + lookup)
- host invocation setup: ~20µs (no XDR alloc for size checks)
- result building: ~12µs (no XDR alloc for return value/event sizes)
- frame creation: ~1µs (Arc::clone)

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
Improvement:       +160% from original (perf-equivalent)

### Round 3 optimizations applied:
- H11: Arc-wrap TransactionEnvelope (-14ms prep+fee)
- H16: Incremental hash in bucket merge (-13ms add_batch)
- H17: Reuse TransactionFrame in pre_apply (-34ms soroban_exec)
- H18: Thread Arc through execute_transaction hot path (-10ms soroban_exec)
- H19: Zero-alloc XDR size via CountingWriter (-77ms across soroban+add_batch)
- Combined: ~970ms → ~849ms total perf (-12.5%)
