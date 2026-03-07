# Structural Performance Gap: Henyey vs stellar-core

## Summary

Henyey currently runs at ~330ms/ledger (mean) vs an estimated ~200ms for stellar-core on
identical traffic. The remaining gap breaks into three categories:

| Source | Est. gap | Status |
|--------|----------|--------|
| Cross-ledger cache miss on dynamic keys | ~10–20ms | P1: actionable |
| Top-N DEX offer seller prefetch | ~5–15ms | P2: actionable (functions exist) |
| Ed25519 per-op re-verification (C1) | ~5–10ms | P3: low-risk win |
| Deferred XDR serialization | ~10–15ms | NOT viable — O7 proved +43ms regression |
| stellar-core LedgerTxnRoot in-memory account index | ~20–30ms | Architectural; no short-term fix |

This doc describes actionable plans for P1–P3 and explains why the architectural gap
cannot be closed without a major structural change.

---

## Background: Why the Cache Hit Rate Is Low

### Per-ledger `prefetch_cache` lifecycle

`SnapshotHandle::prefetch_cache` is an `Arc<parking_lot::RwLock<HashMap<Vec<u8>, LedgerEntry>>>`.
It is constructed fresh for every ledger (all three `SnapshotHandle::new`/`with_lookup`/
`with_lookups_and_entries` constructors call `Arc::new(parking_lot::RwLock::new(HashMap::new()))`).

`run_transactions_on_executor` populates it in two ways:
1. **Static prefetch** (lines 109–127 of `tx_set.rs`): upfront bulk load of all
   statically-determinable keys (`keys_for_fee_processing` + `keys_for_apply` for every TX).
2. **Cache-through** (commit 8104131): every `get_entry` / `load_entries` miss writes the
   loaded entry back into `prefetch_cache`, so the second load within the same ledger is free.

After ledger N closes, the snapshot and its `prefetch_cache` are discarded. Ledger N+1 gets a
fresh snapshot with an empty cache. All dynamic keys (DEX offer sellers loaded during path
payment crossing, sponsor accounts, etc.) require bucket list scans again.

### What "dynamic" means

Static keys are those recoverable from the TX envelope at parse time (source accounts,
destinations, declared offer IDs, etc.). Dynamic keys are those discovered only during
execution: which DEX offer seller happens to be at the top of the book when a path payment
crosses, which sponsor account exists for a created account, etc.

Measured on ledger range 61348953–61349952:
- ~1021 bucket list misses/ledger (dynamic, cold)
- ~148 prefetch cache hits/ledger (12.6% hit rate)

The 87% miss rate is almost entirely dynamic keys not covered by static prefetch.

### What stellar-core does instead

stellar-core's `LedgerTxnRoot` maintains an in-RAM index of all ledger entries loaded since
node startup. Account X loaded in ledger 100 is a zero-cost hit in ledger 110. There is no
per-ledger reset. Henyey's snapshot model makes this impossible without an explicit cross-ledger
hot-key cache.

---

## P1: Cross-Ledger Hot-Key Prefetch (HIGH PRIORITY, ~10–20ms)

### Idea

After ledger N's `run_transactions_on_executor` returns, extract all keys from the snapshot's
`prefetch_cache` that were loaded dynamically (i.e., via cache-through from the bucket list).
Store them in the persistent `TransactionExecutor`. At the start of ledger N+1's
`run_transactions_on_executor`, include them in the static prefetch call to pre-warm the new
ledger's `prefetch_cache` before any TX runs.

This mirrors stellar-core's cross-ledger caching without requiring an architectural overhaul.

### Why it works

- DEX offer sellers change slowly. The same 10–50 sellers are at the top of a given order
  book for many consecutive ledgers.
- The same fee-bump inner source accounts, sponsor accounts, and multi-hop payment
  intermediaries appear repeatedly across ledgers.
- By seeding the new ledger's prefetch with last ledger's hot keys, the static prefetch pass
  converts ~400–700 dynamic misses to static hits.

### Size estimate

The prefetch_cache after a typical ledger contains:
- Static prefetch entries: ~112 TXs × ~4 keys/TX = ~450 entries
- Dynamic cache-through entries: ~300–600 entries (offer sellers, sponsors, etc.)
- Total: ~750–1050 entries → `Vec<LedgerKey>` of ~750–1050 elements

This is small enough to keep in memory indefinitely and pass to the next `prefetch()` call.

### Implementation

#### Step 1: Add `take_prefetch_keys()` to `SnapshotHandle`

**File: `crates/ledger/src/snapshot.rs`**

```rust
/// Extract all keys currently in the prefetch cache.
///
/// Used at end-of-ledger to capture dynamically-loaded keys for cross-ledger warm-up.
/// Returns raw XDR-serialized key bytes (not decoded LedgerKey) to avoid
/// re-serialization cost on the next call to `prefetch()`.
pub fn prefetch_cache_keys(&self) -> Vec<LedgerKey> {
    let cache = self.prefetch_cache.read();
    cache
        .values()
        .filter_map(|entry| crate::delta::entry_to_key(entry).ok())
        .collect()
}
```

#### Step 2: Add `hot_keys` field to `TransactionExecutor`

**File: `crates/ledger/src/execution/mod.rs`**

```rust
pub struct TransactionExecutor {
    // ... existing fields ...
    /// Keys loaded dynamically in the previous ledger's execution.
    /// Used to pre-warm the next ledger's prefetch cache before TX execution.
    hot_keys: Vec<LedgerKey>,
}
```

Initialize as `Vec::new()` in `TransactionExecutor::new()`. Both `advance_to_ledger` and
`advance_to_ledger_preserving_offers` leave it unchanged (it will be overwritten by
`run_transactions_on_executor`).

#### Step 3: Include hot_keys in static prefetch pass

**File: `crates/ledger/src/execution/tx_set.rs` — `run_transactions_on_executor()`**

In the static prefetch block (after building `all_keys` from frame keys), add:

```rust
// Seed from previous ledger's dynamically-loaded keys (cross-ledger hot-key cache).
// These are keys not statically determinable from TX envelopes (DEX offer sellers,
// sponsor accounts, etc.) that are likely to be accessed again this ledger.
all_keys.extend(executor.hot_keys.iter().cloned());
```

This extends `all_keys` before the single `snapshot.prefetch(&keys_vec)` call. The `prefetch()`
implementation already deduplicates (skips keys already in cache), so adding stale or
overlapping keys is safe.

#### Step 4: Update `hot_keys` after execution

**File: `crates/ledger/src/execution/tx_set.rs` — end of `run_transactions_on_executor()`**

Before returning `tx_set_result`:

```rust
// Capture dynamically-loaded keys for the next ledger's hot-key prefetch.
executor.hot_keys = snapshot.prefetch_cache_keys();
tracing::debug!(
    hot_keys = executor.hot_keys.len(),
    "Captured hot keys for next ledger"
);
```

### Expected impact

- ~400–700 of the ~1021 dynamic misses/ledger converted to static prefetch hits
- Each converted miss saves ~150μs (bucket list scan time)
- Estimated savings: 400–700 × 150μs = **60–105ms of bucket list scan time**

However, the prefetch batch itself takes time (bulk bucket list scan). The P1 benefit comes
from converting per-TX scattered misses into a single upfront scan. The net improvement
depends on how many of the hot keys actually appear in the next ledger.

Conservative estimate: **~10–20ms net improvement** (accounting for prefetch overhead and
hot-key miss rate across ledger boundaries).

### Risks

- **Stale entries**: keys that existed in ledger N but are deleted in ledger N+1 will be
  prefetched but not found — this is fine, `prefetch()` only stores entries that exist.
- **Key set growth**: if hot_keys accumulates stale entries across many ledgers, it grows
  unboundedly. Mitigation: replace hot_keys entirely each ledger (overwrite, not append).
- **First ledger**: hot_keys is empty; behavior identical to current.

---

## P2: Top-N DEX Offer Seller Prefetch (MEDIUM PRIORITY, ~5–15ms)

### Current state

The infrastructure for this already exists (from commit 8104131, partially retained after
e570d28):

- `OfferIndex::top_n_offer_keys()` — returns top-N offer keys by price for an asset pair
  (in `crates/tx/src/state/offer_index.rs`)
- `TransactionExecutor::collect_seller_keys_for_pairs()` — given a set of (buying, selling)
  pairs, loads the top-N offers per pair and returns their seller account + trustline keys
  (in `crates/ledger/src/execution/mod.rs:1098`)
- `collect_dex_asset_pairs()` — extracts DEX asset pairs from a TX set
  (in `crates/ledger/src/execution/tx_set.rs:1118`, currently `#[cfg(test)]` only)

What was reverted in e570d28 was the wiring of these into `apply_transactions`
(`crates/ledger/src/manager.rs`). The revert message: "Revert offer seller bulk prefetch from
apply_transactions". Calling it from `apply_transactions` was wrong because:
- `apply_transactions` holds the mutex on the persistent executor; the prefetch adds
  latency to the critical path before the snapshot is even used.
- The prefetch was using the executor's stale offer state (from the previous ledger) to
  generate keys, but against the new ledger's snapshot.

### The correct approach

Wire `collect_dex_asset_pairs` + `collect_seller_keys_for_pairs` into
`run_transactions_on_executor` in `tx_set.rs`, **after** the existing static prefetch but
before fee processing. This is the demand-driven approach: only prefetch sellers for pairs
actually referenced by this ledger's TXs.

```rust
// Prefetch seller deps for top-N best offers in DEX pairs from this TX set.
{
    const TOP_N_OFFERS_PER_PAIR: usize = 10;
    let dex_pairs = collect_dex_asset_pairs(transactions);
    if !dex_pairs.is_empty() {
        let seller_keys = executor.collect_seller_keys_for_pairs(&dex_pairs, TOP_N_OFFERS_PER_PAIR);
        if !seller_keys.is_empty() {
            let stats = snapshot.prefetch(&seller_keys)?;
            tracing::debug!(
                pairs = dex_pairs.len(),
                requested = stats.requested,
                loaded = stats.loaded,
                "Prefetched DEX offer seller deps"
            );
        }
    }
}
```

Also remove `#[cfg(test)]` from `collect_dex_asset_pairs`.

### Interaction with P1

If P1 (cross-ledger hot-key prefetch) is implemented first, P2 may have diminishing returns:
the offer sellers from last ledger will already be in `hot_keys` and prefetched at the start
of the static pass. P2 adds coverage for new sellers who weren't present last ledger but are
at the top of the book this ledger (e.g., new offers posted in this ledger's TX set). The
marginal benefit of P2 on top of P1 is probably ~3–8ms.

### Regression risk

The previous regression (which led to e570d28) came from calling this from `apply_transactions`
rather than `run_transactions_on_executor`. Wiring into `run_transactions_on_executor` avoids
that issue. However, if TOP_N_OFFERS_PER_PAIR × number_of_pairs is large, the prefetch call
itself adds latency. Start with N=5 and benchmark; increase if the net is positive.

---

## P3: Skip Already-Verified Ed25519 Signatures (LOW PRIORITY, ~5–10ms)

### Problem

From `perf-analysis-classic-tx-execution.md` Finding 2: `check_operation_signatures` iterates
all TX signatures and calls `ed25519_dalek::verify` for each signature, for every operation in
the TX. For a 100-op TX with 1 signature, this means 100 Ed25519 verifications. Each takes
~40μs → ~4ms of crypto overhead per TX, ~80ms across 20 such TXs/ledger.

stellar-core has the same pattern, so this is not a henyey-specific regression.

### Fix

In `check_signature_from_signers` (`crates/ledger/src/execution/signatures.rs`), extend
`SignatureTracker` to cache the verified weight per signature on first verification:

```rust
for (sig_idx, sig) in tracker.signatures.iter().enumerate() {
    if tracker.used[sig_idx] {
        // Already verified and matched this signer; reuse cached weight.
        if let Some(weight) = tracker.verified_weights[sig_idx] {
            accumulated_weight += weight;
        }
        continue;
    }
    if let Ok(weight) = verify_signature_with_key(sig, &tracker.tx_hash, signer_key) {
        tracker.verified_weights[sig_idx] = Some(weight);
        tracker.used[sig_idx] = true;
        accumulated_weight += weight;
    }
}
```

This diverges from stellar-core in which verification calls fire, but the result (accumulated
weight, success/failure) must be identical. Requires careful testing on the multi-signer,
multi-threshold edge cases.

**Estimated savings**: 30–50% reduction in `fee_seq_us` for multi-op TXs
= ~5–10ms/ledger for the 20 high-op TXs.

---

## What Cannot Be Fixed (Structural Constraints)

### Deferred XDR serialization (O7, INVESTIGATED AND REJECTED)

O7 attempted to defer `build_entry_changes_with_state_overrides` from `pre_apply` to
`apply_body` to avoid XDR serialization of AccountEntry during the fee/seq hot path.
Result: +43ms regression. Root cause: the AccountEntry data is hot in CPU cache immediately
after `flush_modified_entries`; deferring to after op execution makes it cold (Soroban
WASM + contract data loads evict it). The lesson: eager is faster than lazy when the data
is cache-warm. See `perf-analysis-classic-tx-execution.md` § O7.

### stellar-core's LedgerTxnRoot global account index

stellar-core maintains a RAM-resident index of all loaded ledger entries since startup. Any
account loaded in ledger 100 is a zero-cost pointer dereference in ledger 110. Replicating
this in henyey would require abandoning the snapshot model and maintaining a mutable
in-memory ledger state across all ledger closes. This is a fundamental architectural
difference — P1 approximates it via explicit hot-key tracking without the full redesign.

---

## Implementation Priority

1. **P1 first**: cross-ledger hot-key prefetch is the most impactful, lowest-risk change.
   It requires only ~60 lines across 2 files and has no correctness risk (prefetch is
   read-only and idempotent).

2. **Measure P1**: benchmark against the 1000-ledger range before proceeding.

3. **P2 if P1 ≥ 5ms**: wire `collect_dex_asset_pairs` + `collect_seller_keys_for_pairs`
   into `run_transactions_on_executor`. The infrastructure already exists.

4. **P3 last**: requires careful correctness testing; only worth doing if P1+P2 leave
   a measurable gap.

---

## Benchmark Reference

Baseline (post-O7-revert, post-8104131 cache-through):
- Mean: ~330ms/ledger
- Median: ~396ms/ledger
- Range: 61348953–61349952 (1000 ledgers, protocol 25)

```bash
RUST_LOG=info ~/data/<session>/cargo-target/release/henyey --mainnet verify-execution \
  --from 61348953 --to 61349952 --cache-dir ~/data/mainnet/
```
