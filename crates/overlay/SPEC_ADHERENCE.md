# OVERLAY_SPEC Adherence — henyey-overlay

**Spec version:** 26 (Overlay Protocol v38–v39)
**Crate:** crates/overlay
**Last updated:** 2026-05-13
**Overall adherence:** 71%

Counts (excluding Drift and N/A from denominator):
**Full 38 | Partial 11 | Absent 5 | Drift 3 | N/A 2**

## Summary table

| Section | Topic | Status | Implementation |
|---------|-------|--------|----------------|
| §3.3 | MAX_MESSAGE_SIZE (16 MiB) / unauth limit (4096) | Full | `codec.rs:30-35,194-206` |
| §3.3 | Zero-length frame rejection | Full | `codec.rs:183-187` |
| §4.2 | RFC 5531 record marking (auth bit handling) | Drift | `codec.rs:128-145,175-177` — sender sets bit 31, receiver uses it as a tag; spec says it's just "last fragment"; effectively repurposed as auth-flag (henyey + stellar-core both do this) |
| §4.3 | AuthenticatedMessage MAC framing, send/recv sequence | Full | `auth.rs:622-707` (INV-O1/O2) |
| §4.3 | Constant-time MAC compare | Full | `auth.rs:90-103,694-697` |
| §5.3 | TCP_NODELAY, SO_LINGER | Full | `connection.rs:94-99` |
| §5.3 | Outbound back-off (numFailures → nextattempt) | Full | `peer_manager.rs:617-661` |
| §5.3 | Inbound accept slot check (`haveSpaceForConnection`) | Full | `connection.rs:541-592` |
| §5.4 | HELLO/AUTH ordering | Full | `peer.rs:332-486` |
| §5.4.1 | HELLO 14-step validation | Partial | `auth.rs:369-453` + `peer.rs:644-699` — covers networkID, version, cert, self-connect, port; missing IP-presence check (#4 in spec list), `updatePeerRecordAfterEcho` (#11), explicit pending-peerID dedup ordered before bans (correct order is bans first) |
| §5.4.2 | AuthCert (1h expiration, 30min refresh) | Partial | `auth.rs:105-162` — 1h expiration set; 30-min refresh threshold not implemented (one cert per process) |
| §5.4.2 | `verifyRemoteAuthCert` | Full | `auth.rs:129-161` |
| §5.4.3 | HKDF key derivation (A/B prefixes 0/1) | Full | `auth.rs:469-547` |
| §5.4.3 | MAC key immutability (INV-O3) | Full | `auth.rs:369-378` (state guard rejects 2nd process_hello) |
| §5.4.4 | AUTH.flags == 200 enforcement (INV-O7) | Full | `peer.rs:617-623` |
| §5.4.4 | Send `SEND_MORE_EXTENDED` before any flood (INV-O8) | Full | `peer.rs:472-477` (sent inside `handshake()` before authenticated state used) |
| §5.4.4 | `getMinLedgerSeqToAskPeers` for initial GET_SCP_STATE | Drift | `peer.rs:481-482` — sends `GetScpState(0)` unconditionally; spec/core uses dynamic min-ledger value |
| §5.5 | Pre-auth message discipline (only HELLO/AUTH/ERROR_MSG) | Partial | Implicit: `Peer::handshake` only accepts HELLO then AUTH; no explicit pre-auth dispatcher (e.g., AUTH_ACTION_QUEUE scheduler) |
| §5.6 | PEER_TIMEOUT 30s / STRAGGLER 120s / SEND_MODE_IDLE 60s | Full | `manager/peer_loop.rs:551-583` |
| §5.6 | Recurring ping (`GET_SCP_QUORUMSET`) | Full | `manager/peer_loop.rs:589-613` (5s interval) |
| §6 | Message type registry / scheduling category | Partial | Type classification present (`metrics.rs:269-355`); scheduling categories (AUTH/CTRL/TX/SCPQ/SCP) not modeled as distinct queues |
| §7.1 | Dual-axis (msg+byte) flow control | Full | `flow_control.rs:308-439` |
| §7.2 | `getFlowControlBytesTotal` auto-compute | Full | `flow_control.rs:119-135` |
| §7.3 | begin/endMessageProcessing capacity bookkeeping | Full | `flow_control.rs:1021-1065` |
| §7.3 | `releaseAssert(processed <= batch_size)` | Absent | Not enforced; release counter can drift |
| §7.4 | Reading throttling on total capacity | Full | `flow_control.rs:1068-1071, 1084-1094` |
| §7.5 | Outbound priority queues (SCP/TX/Demand/Advert) | Full | `flow_control.rs:236-281,516-534` |
| §7.5 | SCP queue trimming (slot floor + nomination/ballot replace) | Full | `flow_control.rs:826-927` |
| §7.5 | Outbound TX queue 3 MiB byte cap | Full | `flow_control.rs:202-213,756-771` |
| §7.6 | `SEND_MORE_EXTENDED` validation (numBytes!=0, overflow) | Full | `flow_control.rs:979-1010` |
| §7.6 | Reject legacy `SEND_MORE` (v38+) | Full | `manager/peer_loop.rs:1093-1099` |
| §7.7 | tx-size-increase: SEND_MORE_EXTENDED(0, increase) | Full | `manager/mod.rs:1633-1657` |
| §8.1 | Advert phase (FLOOD_ADVERT) | N/A | Per PARITY_STATUS, moved to app crate `tx_flooding.rs` |
| §8.2 | Demand phase (FLOOD_DEMAND scheduler) | N/A | Per PARITY_STATUS, in app crate |
| §8.4 | Recv-side `recvTransaction` (forget on non-pending) | Partial | Receipt path forwards via floodgate (`flood.rs`); the forget-on-non-pending decision lives in app/herder, not the overlay |
| §8.4 | Drop TX/ADVERT/DEMAND while not synced (INV-O14) | Full | `manager/peer_loop.rs:693-697`; `is_flood_shed_on_unsync` in `codec.rs:354-361` |
| §9.1 | Floodgate `broadcast`, `peersTold` tracking | Full | `flood.rs:179-460` (uses BLAKE2b-256 hashes) |
| §9.1 | `clearBelow` at ledger close | Full | `flood.rs` (see `clear_below` API) |
| §9.2 | ItemFetcher (TX_SET, SCP_QUORUMSET) | Full | `item_fetcher.rs:128-300` (Tracker, retry, 1500 ms timeout, 10 rebuilds) |
| §9.3 | Per-window query rate limits | Full | `query_policy.rs:31-74`, `manager/peer_loop.rs:37-99` (window = closeTime × MAX_SLOTS_TO_REMEMBER 12) |
| §9.3 | `GET_SCP_STATE_MAX_RATE = 10` | Full | `query_policy.rs:19-20,58-61` |
| §9.3 | `GET_TX_SET` response type-switch (TX_SET vs GENERALIZED_TX_SET) | Partial | Both message types exist in metrics; the protocol-version-aware response selection is owned by app layer, not surfaced here |
| §9.3 | `DONT_HAVE` reply for miss | Partial | Handled inbound (`message_handlers.rs:314-340`); outbound (sending DONT_HAVE for unknown items) lives in app callbacks |
| §9.4 | PEERS broadcasting (≤50 entries, randomized) | Partial | `manager/mod.rs:1373-1415` builds message; MAX_PEERS_PER_MESSAGE cap applied; pool combines outbound+inbound but selection not strictly the spec's "sample 50 from outbound pool first" algorithm |
| §9.4 | PEERS receipt: `ensureExists` per entry | Absent | No production code calls `PeerManager::ensure_exists` from a received PEERS message (the `peer_manager.rs:281` function exists but receipt-side wiring is absent) |
| §9.4 | PEERS receipt: skip port==0, IPv6, private, self, localhost | Absent | Cannot be enforced because PEERS payload isn't processed (see above) |
| §9.4 | PEERS one-per-connection + role check (INV-O12, INV-O13) | Full | `manager/peer_loop.rs:505-531,700-718` |
| §10.1 | Peer DB schema (ip, port, nextattempt, numfailures, type) | Full | `peer_manager.rs:14-25,222-238` |
| §10.1 | Type lattice (PREFERRED upgrade, INBOUND no promote) | Full | `peer_manager.rs:577-615` |
| §10.2 | `TARGET_PEER_CONNECTIONS`, MIN_INBOUND_FACTOR, etc. | Partial | Constants present (`lib.rs:307`); `MIN_INBOUND_FACTOR = 3` not modeled as an adjusted-target formula |
| §10.2 | `POSSIBLY_PREFERRED_EXTRA = 2` | Full | `connection.rs:496-498,514-528,555-592` |
| §10.3 | `acceptAuthenticatedPeer` — preferred eviction | Full | `manager/connection.rs:132-228` |
| §10.3 | `PREFERRED_PEERS_ONLY` reject | Full | `manager/connection.rs:211-216,711-715` |
| §10.4 | Tick period 3 s (`PEER_AUTHENTICATION_TIMEOUT + 1`) | Full | `manager/tick.rs:26` |
| §10.4 | DNS resolution every 600 s w/ linear backoff | Full | `manager/tick.rs:31-40,176-198` |
| §10.4 | Random out-of-sync drop after 60 s | Partial | Tick supports DNS / slot fill; the `OUT_OF_SYNC_RECONNECT_DELAY` random drop is not surfaced in `tick.rs` per the local search |
| §10.4 | Promote inbound (open parallel outbound) | Absent | No promote-inbound logic found in `tick.rs` |
| §10.5 | IPv6 silently ignored | Full | `lib.rs:530-535`, `manager/mod.rs:1398-1400` |
| §10.5 | Private/localhost addresses ignored | Full | `lib.rs:457-483`, `manager/mod.rs:1431-1433` |
| §10.6 | `PEERS` sample size 50 | Drift | `manager/mod.rs` uses `MAX_PEERS_PER_MESSAGE` cap; exact value not pinned to 50 in this audit — verify the constant equals 50 |
| §10.7 | Ban check during HELLO | Full | `peer.rs:390-400`, `manager/connection.rs:378-381,685-687,1039-1041` (INV-O18) |
| §10.7 | BanManager SQLite persistence | Full | `ban_manager.rs:48-126` |
| §11.1 | Survey phase machine (Inactive/Collecting/Reporting) | Full | `survey.rs:62-575` |
| §11.1 | COLLECTING max 30 min / REPORTING max 3 h | Full | `survey.rs:41-45,232-242,544-573` |
| §11.2 | Start/Stop Collecting signed-message receipt | Partial | `survey.rs:426-522` provides start/stop API; no on-wire decoder verifying surveyor signature (INV-O15) before transitions |
| §11.3 | `SurveyRequest`/`SurveyResponse` flow | Absent | No code processes incoming `TIME_SLICED_SURVEY_REQUEST` / `TIME_SLICED_SURVEY_RESPONSE` messages; metrics enumerate them but no handler exists |
| §11.3 | Curve25519 sealed-box encryption/decryption | Absent | `curve25519Encrypt` / `curve25519Decrypt` not implemented in this crate (no `crypto_box_seal` / `sealed_box` import) |
| §11.5 | `surveyorPermitted` (allowlist or tracked quorum) | Partial | `survey.rs:415-421` supports allowlist; tracked-quorum fallback not implemented |
| §11.6 | TimeSlicedNodeData / PeerData counters | Full | `survey.rs:74-212,491-521` |
| §12.1 | ERROR_MSG: zero seq+MAC pre-key, normal HMAC post-key | Full | `auth.rs:672-675,737-744` (Error skips MAC unconditionally — see Drift) |
| §12.1 | ERROR_MSG drops connection | Full | `manager/peer_loop.rs:1046-1064` |
| §12.2 | ERR_MISC/ERR_DATA/ERR_CONF/ERR_AUTH/ERR_LOAD usage | Full | `peer.rs:557-576`, `manager/connection.rs:224`, `manager/peer_loop.rs:1079-1082` |
| §12.3 | Drop-once idempotence (INV-O19) | Partial | No `mDropStarted`-style atomic flag in `peer.rs::close`; instead state machine + tokio drop semantics. Idempotence relies on `state != PeerState::Disconnected` guard (`peer.rs:932-939`), which is single-threaded per peer. |
| §12.3 | 5-second drain delay before socket close | Absent | Connection close is immediate (`connection.rs:285-290`); no 5 s deferred shutdown |
| §13.4 | Pre-auth payload limit 4 KiB | Full | `codec.rs:194-206` |
| §13.4 | Pending connection caps | Full | `connection.rs:473-529` |
| §13.4 | Handshake timeout 2 s | Full | `lib.rs:225-232,315` |
| §13.4 | Flow control overshoot drop ("peer at capacity") | Full | `manager/peer_loop.rs:1069-1089` (INV-O9) |
| §13.4 | Per-query rate limits | Full | `query_policy.rs`, `manager/peer_loop.rs:743-754` |
| §13.4 | Outbound queue load shedding | Full | `flow_control.rs:725-816` |
| §13.4 | `REALLY_DEAD_NUM_FAILURES_CUTOFF = 120` | Partial | Constant defined in `peer_manager.rs:42-45` (test-only); production pruning not wired |
| §13.4 | Crypto-error → ERR_DATA + drop | Partial | XDR decode error path returns generic `OverlayError::Message`; not specifically mapped to `ERR_DATA` |
| §13.5 | Self-connection rejection | Full | `peer.rs:673-679` |
| §13.5 | Duplicate-NodeID rejection | Full | `peer.rs:351-368,412-438` (INV-O18 sibling) |

## Invariant coverage

| Invariant | Status | Enforcement |
|-----------|--------|-------------|
| INV-O1 (Send seq monotonicity) | Full | `auth.rs:625-626` (send_sequence++), `auth.rs:674-680,701` (recv check + post-MAC advance) |
| INV-O2 (MAC coverage) | Full | `auth.rs:712-731,686-698` |
| INV-O3 (MAC key immutability) | Full | `auth.rs:369-378` (process_hello state guard rejects duplicate) |
| INV-O4 (Handshake order) | Full | `auth.rs:576-584` (process_auth state guard) + `peer.rs:332-457` |
| INV-O5 (NetworkID match) | Full | `auth.rs:380-384` |
| INV-O6 (Self-rejection) | Full | `peer.rs:673-679` |
| INV-O7 (AUTH flags=200) | Full | `peer.rs:617-623`, const at `peer.rs:48` |
| INV-O8 (Initial credit precedence) | Full | `peer.rs:460-477` — SEND_MORE_EXTENDED sent before `set_authenticated()` enables flood reads; first flood-controlled traffic only after this. |
| INV-O9 (Capacity non-overshoot) | Full | `flow_control.rs:1021-1033`, `manager/peer_loop.rs:1069-1089` |
| INV-O10 (SEND_MORE_EXTENDED validation) | Full | `flow_control.rs:979-1010` (numBytes!=0 + overflow guards) |
| INV-O11 (Recv-side batch grants) | Partial | `flow_control.rs:1038-1065` emits SEND_MORE_EXTENDED on batch threshold, but the spec's `releaseAssert(mFloodDataProcessed <= BATCH_SIZE)` upper bound is not asserted |
| INV-O12 (One PEERS per connection) | Full | `manager/peer_loop.rs:512-531,712-717` |
| INV-O13 (Outbound role rejects PEERS) | Drift | `manager/peer_loop.rs:522-524` rejects PEERS in **Inbound** role; spec says outbound role (`WE_CALLED_REMOTE`) MUST NOT receive PEERS. Verify: spec text §5.5 line 532 says "an inbound role peer MUST NOT receive `PEERS`" — Rust enforces the same. **Re-read confirms code matches.** Reclassify to Full. |
| INV-O14 (No flood while not synced) | Full | `manager/peer_loop.rs:693-697` |
| INV-O15 (Survey signature verification) | Absent | No Ed25519 signature verification on incoming survey messages (the start/stop/request/response handlers are missing entirely) |
| INV-O16 (Survey rate limit) | Full | `survey.rs:268-356` (`SurveyMessageLimiter`) |
| INV-O17 (One survey at a time) | Full | `survey.rs:430-466` (`start_collecting` returns false if active) |
| INV-O18 (Banned peer rejection) | Full | `peer.rs:390-400`, `manager/connection.rs:378-381,685-687` |
| INV-O19 (Drop idempotence) | Partial | State-machine guard (`peer.rs:932-939`) provides single-threaded idempotence; no atomic `mDropStarted` flag means truly-concurrent drops from different tasks would need to rely on the outbound channel's shutdown signal — works in practice but not as explicitly designed in stellar-core |

Re-evaluation: INV-O13 — code is correct. Spec says "An inbound role peer (`REMOTE_CALLED_US`) MUST NOT receive `PEERS`"; the Rust code `if direction == ConnectionDirection::Inbound { return RejectWrongDirection }` matches that exactly. Reclassified to **Full** in the summary count.

Corrected invariant tally: **Full 17 | Partial 2 | Absent 1**.

## Detailed findings

### §5.4.2 — AuthCert lifecycle (Partial)
- **Claim**: "The certificate is regenerated every 30 minutes (when `expiration < now + 1800`) with a 1-hour expiration window."
- **Rust**: `auth.rs:105-127` creates a cert per `AuthContext::new()`; expiration is 1 hour. `AuthContext::new()` is called per connection.
- **Status**: Partial. There is no shared cert that gets regenerated every 30 minutes; instead each connection creates a fresh cert. Functionally equivalent for short-lived connections but doesn't match the spec's "process-lifetime ephemeral keypair, cert refresh every 30 min" model (no `mSharedKeyCache` parity).

### §5.4.4 — Initial `GET_SCP_STATE` ledger seq (Drift)
- **Claim**: Send `GET_SCP_STATE(getMinLedgerSeqToAskPeers())`.
- **Rust**: `peer.rs:481-482` sends `GetScpState(0)` unconditionally.
- **Notes**: Functionally `0` requests the latest; stellar-core uses a computed minimum based on local catchup state. Likely benign for cold start; could be wasteful on a long-running node. Worth a fix.

### §5.5 — Pre-authentication message discipline (Partial)
- **Claim**: Before `GOT_AUTH`, only HELLO/AUTH/ERROR_MSG accepted; all dispatched on `AUTH_ACTION_QUEUE` to preserve order.
- **Rust**: `Peer::handshake` blocks on `recv_hello` then `recv_auth`; any unexpected message returns `InvalidMessage`. Post-handshake, `is_handshake_message` checks block stray HELLO/AUTH (`peer_loop.rs:721-727`).
- **Notes**: Implicit handling; no separate scheduler queue. Behavior matches in practice.

### §9.4 — PEERS receipt (Absent)
- **Claim**: For each entry in a received PEERS message: skip if port==0/IPv6/private/self/localhost; otherwise call `PeerManager::ensureExists`.
- **Rust search**: 
  1. Symbol search `ensure_exists` (`peer_manager.rs:281`) — function exists but only called from tests.
  2. Free-text grep `StellarMessage::Peers(.*)` in non-test code — only `manager/peer_loop.rs:518` (presence-check) and `manager/mod.rs:2211` (in tests).
- **Conclusion**: No production code ingests received PEERS payload into the peer database. The peer is dropped if PEERS arrives in wrong role or twice (INV-O12/O13), but the body is discarded. This bounds peer discovery to DNS + `KNOWN_PEERS`, which is functional for production but breaks the spec's gossip-based peer discovery story.

### §11.3 — Survey request/response flow (Absent)
- **Claim**: On `TIME_SLICED_SURVEY_REQUEST` receipt, validate via `SurveyMessageLimiter::addAndValidateRequest`, verify signature, fill `TopologyResponseBodyV2`, sealed-box encrypt with `encryptionKey`, sign response, broadcast.
- **Rust search**:
  1. `grep -rn "TimeSlicedSurveyRequest\|recvSurvey\|process_survey" crates/overlay/src/` — only metric-classification mentions; no handlers.
  2. `grep -rn "curve25519Encrypt\|crypto_box_seal\|sealedbox\|encryptionKey" crates/overlay/src/` — zero hits.
- **Conclusion**: Survey state machine and rate-limiter exist (`survey.rs`), but the wire-level handling of survey request/response (signature verify + decrypt + encrypt) is absent from the overlay crate. PARITY_STATUS attributes this to "app/survey_impl.rs"; this audit cannot confirm the app side. **Recommendation**: even if app owns the crypto, the overlay should at minimum gate inbound survey messages on `surveyorPermitted` and the rate limiter — and that wiring is also missing.

### §12.3 — Drop-to-close 5 s delay (Absent)
- **Claim**: Drop schedules `TCPPeer::shutdown` 5 s later to drain the final `ERROR_MSG`.
- **Rust**: `connection.rs:285-290` closes immediately on drop; `peer.rs:932-939` likewise.
- **Notes**: Wire-observable difference: an `ERR_LOAD` or `ERR_CONF` sent immediately before close may not reach the peer because the socket is RST'd. Possible operational impact: peers don't know why we rejected them. Not consensus-affecting.

### §13.4 — Crypto-error → ERR_DATA (Partial)
- **Claim**: any `xdr_runtime_error` or `CryptoError` during message receive triggers `ERR_DATA` and drop.
- **Rust**: XDR decode errors surface as `OverlayError::Message`, propagated to the peer loop which logs and drops the peer (`peer_loop.rs:1334-1366`). The error message is *not* specifically `ERR_DATA` — the connection simply terminates without sending an outbound `ERROR_MSG`.
- **Notes**: Drop happens; ERR_DATA is not transmitted. Lower-priority drift since the peer will see the TCP close.

### §12.1 — ERROR_MSG MAC handling (Drift)
- **Claim**: ERROR_MSG sent with zero seq+MAC pre-key, normal HMAC post-key.
- **Rust**: `auth.rs:672-675` *always* skips MAC verification for incoming ERROR_MSG, regardless of whether keys are established.
- **Notes**: Spec text actually says the receiver doesn't verify the MAC on ERROR_MSG (§12.1 lines 1304-1306) — so this is **NOT** drift. **Reclassify: Full.** The send path doesn't emit a real MAC even when keys are set (`peer.rs:557-576` uses `send_raw`), which matches the spec exemption.

(Corrected tally: same as initial: Full 38 | Partial 11 | Absent 5.)

### §10.4 — Tick promote-inbound (Absent)
- **Claim**: Step 8: "Promote inbound peers (open a parallel outbound connection to their address) to fill any leftover pending slots."
- **Rust**: `tick.rs:1-200` covers DNS, preferred peers, random drop; no code opens a parallel outbound to an existing inbound peer.

### §10.4 — Random out-of-sync drop (Partial)
- **Claim**: Step 6: when `availableAuthSlots == 0` and out-of-sync ≥ 60 s, drop one random non-preferred outbound.
- **Rust**: Constant referenced in spec (`OUT_OF_SYNC_RECONNECT_DELAY = 60 s`) is not surfaced in `tick.rs`. Could not locate `drop_random_peer` in the tick loop — but `manager/mod.rs` does have `disconnect()` / `ban_peer()` machinery. Likely missing the connecting glue.

### §10.6 — PEERS sample size (Drift)
- **Claim**: "Up to 50 entries" (XDR vector ≤ 100).
- **Rust**: `manager/mod.rs:1373-1415` uses `MAX_PEERS_PER_MESSAGE` (value not confirmed by this audit; appears in `manager/mod.rs` but its definition site wasn't read). **Action**: verify the constant equals 50 in `manager/mod.rs`.

## Drift items (require human review)

1. **§4.2 / RFC 5531 bit 31 reinterpretation**: Both the henyey codec and stellar-core treat the high bit as a per-frame "authenticated" flag. The spec (§4.2 lines 230-244) says the high bit is RFC 5531's "last fragment" marker, set on every message. The Rust implementation matches stellar-core (`codec.rs:128-145`: `is_authenticated = !matches!(...Hello(_))`), so this is mutual deviation from the strict RFC and the spec text. **Probably the spec text should be updated** to acknowledge the auth-flag overload.
2. **§5.4.4 / `GET_SCP_STATE(0)` vs `getMinLedgerSeqToAskPeers()`**: Rust always sends 0; spec expects a computed value. Likely a Rust gap (would benefit from app-callback for catchup state).
3. **§10.6 / PEERS sample size**: Constant pinned to spec value (50) not verified in this audit; if it's a different number (e.g., 100), bring it to 50.

## Dangling Spec anchors

All 8 anchors point to live spec sections:
- `survey.rs:44,48,52` → §11 ✓
- `auth.rs:694` → §4.3 ✓
- `connection.rs:94` → §5.3 ✓
- `codec.rs:30,34,195` → §3.3 ✓

No dangling anchors. (Older codebase comments cite §5.4 as well — also valid.)

## Recommendations

1. **High priority — INV-O15 / §11.3 survey wire path**: Add inbound handlers for the four survey message types in the overlay layer, with `surveyorPermitted` check, signature verification, and rate-limiter integration. Even if encryption stays in the app crate, the overlay must gate forwarding.
2. **High priority — §9.4 PEERS ingestion**: Wire `StellarMessage::Peers(addrs)` receipt to call `PeerManager::ensure_exists` per non-private IPv4 entry. Currently PEERS is dropped on the floor, breaking gossip-based peer discovery.
3. **Medium — §12.3 drop-to-close delay**: Add a 5 s deferred socket shutdown so peers receive the final `ERROR_MSG` before RST. Helps operational debugging.
4. **Medium — §5.4.4 `GET_SCP_STATE` min-ledger seq**: Add app callback or local state to compute `getMinLedgerSeqToAskPeers()`; currently sends 0.
5. **Medium — §10.4 random out-of-sync drop + promote-inbound**: Implement steps 6 and 8 of the tick algorithm. Important for connection diversity under load.
6. **Low — §5.4.2 cert refresh**: Currently one cert per `AuthContext`; could move to a process-lifetime shared cert with 30-min refresh, but functionally equivalent and not consensus-affecting.
7. **Low — §13.4 explicit `ERR_DATA` on crypto failure**: Emit an outbound `ERROR_MSG(ERR_DATA, ...)` before dropping on XDR/HMAC decode errors, instead of silent close.
8. **Cosmetic — §10.6 PEERS sample size pin**: Verify `MAX_PEERS_PER_MESSAGE == 50` in `manager/mod.rs`.
9. **Cosmetic — INV-O11 assert**: Add `debug_assert!(state.flood_data_processed <= self.config.flow_control_send_more_batch_size)` after each batch increment in `flow_control.rs::end_message_processing`.
