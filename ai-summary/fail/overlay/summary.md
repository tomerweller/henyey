# Failed Investigations: overlay

Condensed failure summaries. Last updated 2025-07-26.

## Summary Table

| File | Hypothesis | Why Failed | Stage | Key Lesson |
|------|-----------|------------|-------|------------|
| 001 | Survey limiter unbounded surveyors | Validation at different layer (app-layer limiter exists) | reviewer | Application layers can provide decisive bounds |
| 002 | Unbounded dedicated overlay channels | Non-novel / duplicate of audit #608 | reviewer | SCP/fetch channel issues already filed |
| 003 | Stale preferred peer snapshot after DNS | Non-novel / duplicate of AUDIT-055 | reviewer | DNS snapshot issues already tracked |
| 004 | Incomplete handshakes resource hold | Bounded by pending slots + 2s auth timeout | hypothesis | Sequential timeouts prevent unbounded retention |
| 005 | MAC counter desync via auth bit | State-based verification, not bit-based | hypothesis | Security decision based on local state |
| 007 | Full outbound channel defeats peer drop | Non-novel / duplicate of audit #611 | reviewer | send_error_and_drop lossy-shutdown already filed |
| 009 | Banned outbound peer-ID leak | Bounded by 30s sweep, not exploitable | hypothesis | Temporary bounds are sufficient for cleanup |
| 010 | Item fetcher lacks upper-slot pruning | Future slots pre-filtered, bounded by herder | reviewer | Higher-layer pre-filtering provides bounds |
| 011 | Zero-message SEND_MORE throttle reset | Upstream parity (stellar-core same behavior) | hypothesis | Protocol design limitation applies to both |
| 012 | Duplicate auth peer-ID after full handshake | Non-novel / bounded by pending slots | reviewer | Similar issues in #1189 and #617 |
| 013 | Load-rejected peers get startup messages | Low impact, not security-relevant | hypothesis | Extra work is minimal and bounded |
| 017 | PEERS inflates peer table + refresh cost | Non-novel / duplicate of audit #615 | reviewer | Unbounded peer persistence already filed |
| 019 | FloodGate record_seen TOCTOU race | Herder has downstream dedup, harmless duplicates | hypothesis | Downstream layers provide actual safety |
| 020 | Missing read throttle backpressure | Dead code, sequential processing prevents exhaust | reviewer | Async architecture provides implicit bounds |
| 021 | Outbound TX queue oversized acceptance | Validation at herder layer + 3MB queue cap | reviewer | Layer-wise validation + implicit bounds |
| 024 | Unauthenticated ErrorMsg peer drop | Upstream parity, MITM attack model | hypothesis | Exact protocol design match with stellar-core |
| 025 | SCP flood bypasses rate limits | Intentional priority design, herder validates | hypothesis | Consensus messages exempt by design |
| 026 | Zero-message SEND_MORE outbound starvation | Upstream parity (stellar-core same) | hypothesis | Protocol-level limitation applies to both |
| 027 | Total capacity unthrottle never fires | Dead code, sequential processing + duplicate of H-020 | reviewer | Architectural model makes throttle unnecessary |
| 029 | Total reading capacity exhaustion | Sequential per-peer model prevents exhaust | hypothesis | Tokio model processes one message at a time |
| 030 | Flood capacity granted for duplicates | Per-peer rate limiter provides binding constraint | hypothesis | Rate limiting is the actual security boundary |
| 031a | process_auth missing state precondition | Call site enforces correct handshake ordering | hypothesis | Handshake ordering prevents unreachable state |
| 031b | SEND_MORE_EXTENDED rate limit bypass | Outbound queue bounded at 3MB, non-novel hardening | reviewer | Bounded queue prevents memory exhaustion |
| 032a | FloodAdvert unbounded queue growth | Bounded by rate limit + queue cap + flow control | hypothesis | Multiple independent bounds stack |
| 032b | FloodGate TOCTOU allows duplicate relay | Herder dedup prevents impact, bounded ledger window | hypothesis | Downstream dedup is the actual gate |
| 032c | Missing forgetRecord pollution | Bounded by ledger close interval (~5s) | hypothesis | Temporary state, not persistent pollution |
| 032d | Global rate limit bypass SCP exemption | Matches upstream design, signature verification cost | hypothesis | SCP exemption necessary for liveness |
| 033 | Concurrent frame buffer memory amplification | Bounded by connection pool (57 max) + 30s timeout | hypothesis | Multiple independent bounds prevent DoS |
| 034 | Eclipse attack peer management | Comprehensive review: all 8 vectors NOT_VIABLE | reviewer | Peer management faithfully mirrors stellar-core |
| 035 | Auth cert expiry off-by-one | Fresh certs + rotation prevent reachability | hypothesis | Cert lifecycle prevents exploitation |
| 036 | Responder no HELLO before version reject | Stricter validation order is more secure | hypothesis | Intentional ordering improves security posture |
| 037 | HELLO frame missing XDR continuation bit | Both sides ignore the bit, no behavioral impact | hypothesis | Cosmetic wire-level difference only |
| 038 | SendMoreExtended per-peer rate limit bypass | O(1) cost + total_capacity bound + sequential processing | hypothesis | Rate limiter bypass is moot with O(1) processing cost |
| 039 | SCP outbound queue growth under backpressure | Parity with stellar-core, bounded by capacity + timeout | hypothesis | being_sent exclusion from trim is upstream design |
| 040 | Overlay-layer SurveyMessageLimiter missing unique-surveyor cap | App-layer survey limiter + peer rate limiter provide bounds | hypothesis | Overlay is not the right layer for this cap |
| 041 | PeerRateLimiter telemetry double-counts dropped_aggregate for Survey | Cosmetic metric bug, no security impact | hypothesis | Telemetry inaccuracy ≠ vulnerability |
| 042 | ItemFetcher Tracker unbounded waiting_envelopes growth | Flow control grants + tracker cap + slot pruning bound memory | hypothesis | Flow control grants are decisive per-peer bound |
| 043 | Survey traffic starves flood traffic via aggregate budget exhaustion | Upstream dispatch limits surveys; impact is transient (1s window) | hypothesis | Defense-in-depth weakness alone ≠ vulnerability |

## Meta-Patterns

1. **Layer Separation Provides Bounds**: Many hypotheses assume overlay handles all constraints, but app/herder layers provide decisive validation (Items 001, 010, 021).

2. **Upstream Parity Suppression**: Several issues match stellar-core's behavior exactly; these are protocol design limitations, not vulnerabilities (Items 011, 024, 026, 032d).

3. **Sequential Processing Model**: Henyey's per-peer async task architecture processes one message at a time, eliminating race windows and capacity exhaustion that stellar-core guards against with timeouts (Items 020, 027, 029).

4. **Dead Code from Incomplete Ports**: Throttle mechanism (`maybe_throttle_read`, `stop_throttling`) was ported but never called; architecture makes it unnecessary (Items 020, 027).

5. **Downstream Dedup is Effective**: FloodGate's TOCTOU and missing forgetRecord are mitigated by herder-level dedup and ledger-close cleanup (Items 019, 032b, 032c).

6. **Bounded Amplification via Independent Limits**: Connection pool limits + auth requirement + idle timeout + per-peer rate limiter create stacked bounds (Items 004, 033).

7. **Intentional Design Gaps**: Some differences from stellar-core are deliberate hardening (non-parity, preferred auth ordering) rather than bugs (Items 036, and henyey-specific rate limiter in 031b).

8. **Non-Novelty Clustering**: Multiple findings already exist as filed audit issues (#608, #611, #615, AUDIT-055); audit workflow suppresses duplicate publications (Items 002, 003, 007, 012, 017, 031b).

## Coverage Notes

- **Thoroughly analyzed**: overlay handshake flow (HELLO, AUTH, state machine); flow control and SEND_MORE capacity management; flood gating and message dedup; per-peer rate limiting; connection pool and preferred peer handling; ban management; peer discovery and PEERS validation.

- **Unexplored**: interaction with consensus layer during SCP envelope storms (beyond rate limiting); Byzantine quorum-set manipulation during discovery; timing-side-channel attacks on cryptographic operations; detailed DOS amplification with Sybil peer counts on mainnet.

- **Design verification**: All examined peer-management, auth, and flow-control code was confirmed to match or intentionally improve upon stellar-core's implementations, with suppression documented where parity applies.
