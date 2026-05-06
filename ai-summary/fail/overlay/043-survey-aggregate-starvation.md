# H-043: Survey Traffic Starves Flood Traffic via Aggregate Budget Exhaustion

**Date**: 2025-07-27
**Crate**: overlay
**Status**: SELF-REJECTED (NOT_VIABLE)

## Hypothesis

In `PeerRateLimiter`, Survey messages have no sub-budget (TrafficClass::Survey
goes to the aggregate counter directly). A peer sending many Survey messages
(up to aggregate_limit=200/sec) could exhaust the aggregate budget, starving
TxAndDemand and Advert traffic. Only ControlFetch (with 20 reserved slots above
aggregate) would survive.

## Analysis

### Why this is not exploitable:

1. **Survey messages are rare in practice**: Survey request/response pairs are
   protocol-level diagnostic tools. A peer sending 200 surveys/sec would be
   immediately suspicious and the messages themselves are bounded by the overlay
   manager's survey state machine (one active survey at a time per direction).

2. **Flow control is the true bound**: Survey messages are NOT flow-controlled
   (`is_flow_controlled_message` returns false for Survey), BUT the TCP connection
   throughput and the overlay manager's survey dispatch logic bound how many can
   arrive. The overlay manager processes surveys sequentially and has its own
   rate limiting (survey-limiter crate).

3. **PeerRateLimiter is defense-in-depth**: Even without it, per-peer processing
   is sequential (one message at a time per peer_loop). The aggregate limit is
   additional hardening on top of flow control, not the primary bound.

4. **Henyey-specific hardening, not parity issue**: stellar-core does not have
   PeerRateLimiter. This is extra protection in henyey. A weakness in extra
   hardening does not constitute a vulnerability in the base protocol.

5. **Impact is transient**: Even if aggregate is briefly exhausted by surveys,
   the window resets each second. Flood traffic resumes immediately. SCP (exempt
   from rate limiter entirely) is unaffected.

## Verdict

NOT_VIABLE — Survey traffic cannot realistically exhaust the aggregate budget due
to upstream dispatch bounds, and even if it did, the impact is transient (1-second
window) with no lasting state corruption.

## Key Lesson

Per-peer rate limiting in henyey is defense-in-depth; the upstream dispatch logic
and flow control are the primary bounds. Weaknesses in defense-in-depth layers
alone do not constitute vulnerabilities unless the primary bounds can also be
bypassed.
