# Performance Hypotheses (uftrace)

Baseline: 14,233 TPS | Target: 20,000 TPS | Date: 2026-03-19

## Performance Optimization Summary

```
Baseline:    14,233 TPS (4 clusters)
Final:       20,372 TPS (8 clusters) / 23,131 TPS (16 clusters)
Target:      20,000 TPS
Improvement: +43.1% (8 clusters) / +62.5% (16 clusters)
Status:      TARGET REACHED

Accepted optimizations:
- H1 (HotArchive key serialization): +2.6% combined with H2 (14,233 -> 14,610 TPS @ 4 clusters)
- H2 (TransactionFrame hash/XDR caching): +2.6% combined with H1 (14,233 -> 14,610 TPS @ 4 clusters)
- H5+H7 (CountingWriter / XDR size): ~0% measurable gain (14,610 -> 14,571 TPS @ 4 clusters)
- Cluster parallelism increase (4 -> 8): +39.7% (14,571 -> 20,372 TPS)

Key finding: With 32 CPU cores available, the original 4-cluster configuration
only utilized ~12.5% of available parallelism during the soroban execution
phase. Increasing to 8 clusters cut soroban_exec from 2,463ms to 1,533ms
without any code changes.

Remaining bottlenecks (serial phases, 8 clusters):
- add_batch: 347ms (bucket list updates)
- fee_pre_deduct: 130ms (sequential fee deduction)
- soroban_state: 100ms (HashMap updates)
- prepare: 84ms (TX deserialization)
- Total serial: ~700ms (fixed regardless of cluster count)
```

## uftrace Profile Summary

| Category | Self-time | % of active | Per-TX avg |
|----------|-----------|-------------|------------|
| Storage operations | 3.127s | 23.7% | 250us |
| Host function setup/dispatch | 2.908s | 22.0% | 233us |
| SAC contract logic | 2.126s | 16.1% | 170us |
| Signature verification (crypto) | 1.362s | 10.3% | 109us |
| Bucket/snapshot lookup | 1.121s | 8.5% | 90us |
| XDR serialization | 0.817s | 6.2% | 65us |
| Metered XDR (soroban) | 0.440s | 3.3% | 35us |
| HashMap/allocation/cleanup | 0.326s | 2.5% | 26us |
| Wasmi linker clone | 0.321s | 2.4% | 26us |
| Events/diagnostics | 0.276s | 2.1% | 22us |
| Other soroban host overhead | 0.115s | 0.9% | 9us |
| **Total active self-time** | **13.200s** | **100%** | **1056us** |

## Hypotheses

| # | Hypothesis | Target function(s) | Self-time before | Status | Expected gain | Measured gain | TPS after |
|---|-----------|-------------------|------------------|--------|---------------|---------------|-----------|
| 1 | Serialize HotArchive lookup key once before level loop (22x redundant serialization) | HotArchiveBucketList::get | 760ms | accepted | +5% | +2.6% (combined w/ H2) | 14,610 |
| 2 | Cache TX hash and XDR bytes on TransactionFrame (25K+ redundant serializations) | TransactionFrame::hash, to_xdr | 713ms | accepted | +3% | +2.6% (combined w/ H1) | 14,610 |
| 3 | Skip wasmi Linker/ModuleCache clone for SAC builtin contracts | Linker::clone, module_cache.clone() | 184ms | not tested | +1.5% | | |
| 4 | Pre-size HashMaps in apply_soroban_storage_changes | apply_soroban_storage_changes | 655ms | not tested | +1.5% | | |
| 5 | Use counting writer in invoke_host_function_typed charge_val_deser | invoke_host_function_typed | 632ms | accepted | +1% | ~0% | 14,571 |
| 6 | Reduce redundant frame construction in pre_apply_arc | pre_apply_arc | 568ms | not tested | +1% | | |
| 7 | Cache XDR sizes for get_ledger_changes_typed | get_ledger_changes_typed | 486ms | accepted | +1.5% | ~0% | 14,571 |
| 8 | Reduce key cloning in load_soroban_footprint via entry API | load_soroban_footprint | 442ms | not tested | +0.5% | | |
| 9 | Pre-size collections in build_entry_changes_with_hot_archive | build_entry_changes_with_hot_archive | 292ms | not tested | +0.5% | | |
| 10 | Increase cluster parallelism (4 -> 8 clusters) | execute_stage_clusters | N/A | accepted | +38% | +39.7% | 20,372 |

## Measurement Log

### Baseline (original code, 4 clusters)
- Run 1: 14,233 TPS
- Run 2: 14,261 TPS
- Run 3: 14,168 TPS
- **Median: 14,233 TPS**

### After H1+H2 (4 clusters)
- Run 1: 14,610 TPS
- Run 2: 14,619 TPS
- Run 3: 14,531 TPS
- **Median: 14,610 TPS** (+2.6%)

### After H1+H2+H5+H7 (4 clusters)
- Run 1: 14,571 TPS
- Run 2: 14,579 TPS
- Run 3: 14,556 TPS
- **Median: 14,571 TPS** (+0.3% from H5+H7, negligible)

### After H1+H2+H5+H7 (8 clusters)
- Run 1: 20,183 TPS
- Run 2: 20,372 TPS
- Run 3: 20,463 TPS
- **Median: 20,372 TPS** (+43.1% from baseline)

### After H1+H2+H5+H7 (16 clusters)
- Run 1: 23,131 TPS (single run, not full median)

## Phase Timing Breakdown (8 clusters, median run)

| Phase | Time (ms) | % of Total |
|-------|-----------|------------|
| soroban_exec | 1,533 | 64.7% |
| add_batch | 347 | 14.6% |
| fee_pre_deduct | 130 | 5.5% |
| soroban_state | 100 | 4.2% |
| prepare | 84 | 3.5% |
| commit_setup | 58 | 2.5% |
| post_exec | 13 | 0.5% |
| hot_archive | 3 | 0.1% |
| gap (unaccounted) | 97 | 4.1% |
| **Total** | **2,367** | **100%** |

## Future Optimization Opportunities

### Serial Phase Optimizations (for beyond 20K TPS)
1. **add_batch (347ms)**: Check if SHA-256 uses hardware acceleration; parallelize independent level merges
2. **fee_pre_deduct (130ms)**: Parallelize per-cluster if fee source accounts don't overlap
3. **soroban_state (100ms)**: Use parallel iterators for HashMap updates
4. **prepare (84ms)**: Parallelize TX deserialization

### Per-TX Optimizations (diminishing returns at current scale)
- H3, H4, H6, H8, H9 remain untested but expected gains are small (0.5-1.5% each)
