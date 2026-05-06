# H-042: ItemFetcher Tracker Unbounded waiting_envelopes Growth

**Date**: 2025-07-27
**Crate**: overlay
**Status**: SELF-REJECTED (NOT_VIABLE)

## Hypothesis

Each `Tracker` in `ItemFetcher` accumulates SCP envelopes in `waiting_envelopes`
without a per-tracker cap. Since SCP messages are exempt from `PeerRateLimiter`
(TrafficClass::classify returns None for SCP), a malicious peer could send many
SCP envelopes referencing the same unknown TxSet/QuorumSet hash, causing unbounded
memory growth within a single tracker.

## Analysis

### Bounds that prevent exploitation:

1. **Flow control grants (decisive)**: SCP messages ARE flow-controlled
   (`is_flow_controlled_message` returns true for SCP). Each peer can only send
   messages up to their granted capacity. With default `flood_capacity = 200`
   messages, a peer can accumulate at most ~200 envelopes per tracker before
   capacity is exhausted and the node stops granting more.

2. **Tracker count cap (MAX_TRACKERS = 512)**: Limits total tracker count, so
   even if each has 200 envelopes, worst case is 512 × 200 = 102,400 envelopes.
   Each envelope is ~500 bytes = ~50MB maximum across all trackers from all peers.
   This is bounded and manageable.

3. **Slot range pruning**: `stop_fetching_outside_range()` prunes trackers for
   old ledger slots, preventing accumulation across consensus rounds.

4. **Deduplication in listen()**: Envelopes are deduplicated by hash
   (`compute_envelope_hash`), so the same envelope cannot be added twice.

5. **Per-peer rate**: Even without PeerRateLimiter, a single peer's capacity
   grants provide a hard upper bound on how many messages arrive per unit time.

## Verdict

NOT_VIABLE — Multiple stacked bounds (flow control grants, tracker cap, slot
pruning, dedup) prevent unbounded growth. Worst-case memory is ~50MB, which
is well within operational limits for a validator node.

## Key Lesson

Flow control grants are the decisive bound on per-peer message volume, even
for traffic classes exempt from the per-peer rate limiter.
