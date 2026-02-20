# Henyey Overlay Crate — Specification Adherence Evaluation

**Evaluated against:** `docs/OVERLAY_SPEC.md` (Stellar Overlay Protocol Specification v25)
**Crate:** `crates/overlay/` (henyey-overlay)
**Date:** 2026-02-20

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Evaluation Methodology](#2-evaluation-methodology)
3. [Section-by-Section Evaluation](#3-section-by-section-evaluation)
   - [§3 Data Encoding](#33-data-encoding-spec-3)
   - [§4 Connection Lifecycle](#34-connection-lifecycle-spec-4)
   - [§5 Message Framing and Authentication](#35-message-framing-and-authentication-spec-5)
   - [§6 Message Type Registry](#36-message-type-registry-spec-6)
   - [§7 Message Definitions](#37-message-definitions-spec-7)
   - [§8 Flow Control Protocol](#38-flow-control-protocol-spec-8)
   - [§9 Transaction Flooding Protocol](#39-transaction-flooding-protocol-spec-9)
   - [§10 Peer Management](#310-peer-management-spec-10)
   - [§11 Survey Protocol](#311-survey-protocol-spec-11)
   - [§12 Error Handling](#312-error-handling-spec-12)
   - [§13 Security Considerations](#313-security-considerations-spec-13)
   - [§14 Protocol Constants](#314-protocol-constants-spec-14)
4. [Gap Summary](#4-gap-summary)
5. [Risk Assessment](#5-risk-assessment)
6. [Recommendations](#6-recommendations)

---

## 1. Executive Summary

The henyey overlay crate implements a substantial portion of the Stellar overlay protocol as specified in `OVERLAY_SPEC.md`. The core protocol machinery — TCP connection management, HELLO/AUTH handshake, Curve25519 key exchange, HMAC-SHA256 message authentication, dual-axis flow control, pull-mode transaction flooding, and SQLite-backed peer persistence — is present and structurally correct.

### Overall Adherence Rating

| Category | Rating | Notes |
|----------|--------|-------|
| **Connection Lifecycle** | **High** | Full handshake, self-connection rejection, version validation |
| **Message Framing & Auth** | **High** | RFC 5531 framing, ECDH, HKDF, HMAC-SHA256 all correct |
| **Flow Control** | **High** | Dual-axis capacity, 4-priority queuing, SEND_MORE_EXTENDED |
| **Transaction Flooding** | **High** | Pull-mode with advert batching, demand scheduling, retry backoff |
| **Peer Management** | **Medium** | SQLite persistence present; missing tick-loop functions |
| **Survey Protocol** | **Medium** | Time-sliced lifecycle present; message signing/verification missing |
| **Error Handling** | **Medium** | Error types defined; some spec'd behaviors not triggered |
| **Protocol Constants** | **High** | All critical constants match stellar-core values |

**Estimated specification coverage: ~82%** of MUST/SHALL requirements are implemented or have a reasonable equivalent. The remaining gaps are concentrated in periodic maintenance (tick loop), survey message cryptography, and several peer management edge cases.

---

## 2. Evaluation Methodology

This evaluation compares the henyey overlay implementation file-by-file against the formal specification. Each spec section is assessed on three dimensions:

1. **Structural completeness**: Are the required data structures, messages, and state machines present?
2. **Behavioral correctness**: Do the implementations follow the specified algorithms and state transitions?
3. **Constant fidelity**: Do hardcoded values, thresholds, and timeouts match the spec?

Ratings per requirement:

| Symbol | Meaning |
|--------|---------|
| ✅ | Fully implemented and matches spec |
| ⚠️ | Partially implemented or minor deviation |
| ❌ | Not implemented |
| ➖ | Not applicable to henyey's architecture |

Source file references use the format `file.rs:line`.

---

## 3. Section-by-Section Evaluation

### 3.3 Data Encoding (Spec §3)

**Source files:** `codec.rs`, `auth.rs`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| XDR encoding per RFC 4506 | ✅ | Uses `stellar_xdr` crate for all serialization (`codec.rs:1`) |
| Big-endian byte ordering | ✅ | Handled by the XDR crate |
| `StellarMessage` as top-level union | ✅ | All messages encoded/decoded as `StellarMessage` variants |
| `AuthenticatedMessage` wrapping | ✅ | `AuthenticatedMessageV0` with sequence + HMAC (`codec.rs:180-220`) |
| 32-byte HMAC-SHA256 MACs | ✅ | `HmacSha256Mac` correctly sized (`auth.rs:400+`) |
| Ed25519 signatures 64 bytes | ✅ | Standard Ed25519 via `ed25519-dalek` |
| Curve25519 public keys 32 bytes | ✅ | X25519 via `x25519-dalek` (`auth.rs:80+`) |
| SHA-256 hashes 32 bytes | ✅ | Via `sha2` crate |

**Assessment: Full adherence.** The XDR encoding layer is delegated to the well-tested `stellar_xdr` crate, which correctly implements RFC 4506.

---

### 3.4 Connection Lifecycle (Spec §4)

**Source files:** `peer.rs`, `connection.rs`, `manager.rs`, `lib.rs`

#### 4.1 TCP Transport

| Requirement | Status | Evidence |
|-------------|--------|----------|
| TCP as transport | ✅ | `TcpStream` used throughout (`connection.rs:30+`) |
| Default port 11625 (pubnet) / 11626 (testnet) | ✅ | Configurable via `OverlayConfig` (`lib.rs:50+`) |
| `TCP_NODELAY` set | ✅ | `stream.set_nodelay(true)` (`connection.rs:85`) |
| Connection timeout for pending peers | ⚠️ | 10s connect timeout present (`connection.rs:75`), but no separate handshake-phase timeout for pending peers (spec says 2s for `PEER_AUTHENTICATION_TIMEOUT`) |

#### 4.2 Connection Limits

| Requirement | Status | Evidence |
|-------------|--------|----------|
| `MAX_ADDITIONAL_PEER_CONNECTIONS` (64) default | ✅ | `max_inbound_connections: 64` (`lib.rs:65`) |
| `TARGET_PEER_CONNECTIONS` (8) default | ✅ | `target_outbound_connections: 8` (`lib.rs:60`) |
| Preferred peers get extra slots | ✅ | `max_preferred_connections` separate from main limit (`manager.rs:250+`) |
| Reject inbound when at capacity | ✅ | Checked in `handle_inbound_connection` (`manager.rs:400+`) |
| Pending peer tracking | ⚠️ | Peers move directly from connecting to authenticated; no explicit "pending" state tracking with separate limits |

#### 4.3 Handshake State Machine

| Requirement | Status | Evidence |
|-------------|--------|----------|
| 4-step: HELLO→HELLO→AUTH→AUTH | ✅ | `perform_handshake` in `peer.rs:150-300` |
| Initiator sends HELLO first | ✅ | `send_hello` called first for `WE_CALLED_REMOTE` (`peer.rs:160`) |
| Responder sends HELLO after receiving | ✅ | `recv_hello` then `send_hello` for `REMOTE_CALLED_US` (`peer.rs:170`) |
| Initiator sends AUTH after receiving HELLO | ✅ | Sequence enforced in handshake flow |
| Responder sends AUTH after receiving AUTH | ✅ | Sequence enforced in handshake flow |
| `PEER_AUTHENTICATION_TIMEOUT` (2s) | ❌ | No 2-second handshake timeout; uses general connect timeout |

#### 4.4 Hello Message Validation

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Reject if `overlayVersion < MIN_OVERLAY_VERSION` | ✅ | Version check in `validate_hello` (`peer.rs:320+`) |
| Reject if `networkID` mismatch | ✅ | Network ID compared (`peer.rs:330`) |
| Reject self-connections via nonce | ✅ | `is_self_connection` check (`peer.rs:340`) |
| Reject if peer already connected (by NodeID) | ✅ | Duplicate detection in `manager.rs:450+` |
| Validate `listeningPort` > 0 | ⚠️ | Not explicitly validated; zero port would cause issues in peer persistence but not rejected during handshake |
| Validate AuthCert expiration | ✅ | Expiry checked against current time (`auth.rs:300+`) |
| Validate AuthCert signature | ✅ | Ed25519 signature verification (`auth.rs:310+`) |
| Update peer address from Hello | ✅ | Remote address recorded from Hello message (`peer.rs:350`) |

#### 4.5 Ping/Pong Keepalive

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Periodic GET_PEERS as keepalive | ❌ | No periodic keepalive mechanism implemented |
| Ping/pong RTT measurement | ❌ | Not implemented; uses synthetic `GetScpQuorumset` every 5s as a workaround (`manager.rs:800+`) |
| Latency-based peer quality | ❌ | No latency tracking |
| Idle timeout disconnect | ⚠️ | No explicit idle timeout; relies on TCP keepalive |

**Assessment: High adherence on handshake, gaps in keepalive and pending peer management.** The 4-step handshake is correctly sequenced. The main gaps are: (1) no `PEER_AUTHENTICATION_TIMEOUT` distinct from the connect timeout, (2) no ping/pong latency tracking, and (3) no explicit pending peer state. The synthetic `GetScpQuorumset` keepalive is a functional workaround but diverges from spec.

---

### 3.5 Message Framing and Authentication (Spec §5)

**Source files:** `codec.rs`, `auth.rs`

#### 5.1 Record Marking (RFC 5531)

| Requirement | Status | Evidence |
|-------------|--------|----------|
| 4-byte big-endian length prefix | ✅ | `codec.rs:100-130`, length read as `u32::from_be_bytes` |
| Bit 31 = 1 for last fragment (always set) | ✅ | Auth flag in bit 31 (`codec.rs:115`) |
| No multi-fragment support needed | ✅ | Single-fragment messages only |
| `MAX_MESSAGE_SIZE` = 0x2000000 (32 MB) | ✅ | `MAX_MESSAGE_SIZE: u32 = 0x200_0000` (`codec.rs:20`) |
| `MIN_MESSAGE_SIZE` = 12 bytes | ✅ | Minimum size enforced (`codec.rs:22`) |
| Reject oversized messages | ✅ | Size check before allocation (`codec.rs:135`) |

#### 5.2 Authentication Bit Semantics

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Bit 31 clear → unauthenticated (Hello only) | ✅ | Hello sent without auth bit (`codec.rs:180`) |
| Bit 31 set → authenticated message | ✅ | Auth bit set for post-handshake messages (`codec.rs:190`) |
| Reject auth messages before handshake complete | ✅ | State-checked in codec decode path |
| Auth flags field = 200 for authenticated | ⚠️ | Rigid check for exactly 200 (`codec.rs:200`); stellar-core treats any non-zero as auth'd — this is stricter than spec |

#### 5.3 Key Derivation

| Requirement | Status | Evidence |
|-------------|--------|----------|
| X25519 ECDH shared secret | ✅ | `x25519_dalek::diffie_hellman` (`auth.rs:200+`) |
| HKDF-Extract with `SHA-256(empty)` as salt | ✅ | `hkdf::Hkdf::<Sha256>::new(None, ...)` (`auth.rs:220`) |
| HKDF-Expand with direction-differentiated info | ✅ | `"sending"` vs `"receiving"` labels based on role (`auth.rs:230-240`) |
| Separate send/receive keys | ✅ | `sending_mac_key` and `receiving_mac_key` (`auth.rs:250`) |
| Direction swapped for initiator vs responder | ✅ | Role-based key assignment (`auth.rs:260`) |

#### 5.4 HMAC-SHA256 Message Authentication

| Requirement | Status | Evidence |
|-------------|--------|----------|
| HMAC-SHA256 over `(sequence ∥ message_xdr)` | ✅ | MAC computed over sequence number concatenated with message bytes (`auth.rs:400+`) |
| Monotonically increasing sequence numbers | ✅ | `send_sequence` incremented per message (`auth.rs:420`) |
| Reject out-of-sequence messages | ✅ | Sequence validation in `verify_mac` (`auth.rs:430`) |
| Zero MAC for unauthenticated messages | ✅ | Hello messages have zeroed MAC field (`auth.rs:440`) |

**Assessment: Full adherence on framing and cryptography.** The auth flags = 200 rigidity is stricter than stellar-core's behavior but not a protocol violation — it's a conservative choice. The ECDH + HKDF + HMAC pipeline is correctly implemented with proper direction differentiation.

---

### 3.6 Message Type Registry (Spec §6)

**Source files:** Uses `stellar_xdr::MessageType` enum (external crate)

| Message Type | Handled | Evidence |
|-------------|---------|----------|
| `ERROR_MSG` (0) | ✅ | Sent on disconnect (`manager.rs`), received and logged |
| `AUTH` (2) | ✅ | Handshake (`peer.rs`) |
| `DONT_HAVE` (3) | ✅ | Handled in message dispatch (`message_handlers.rs:100+`) |
| `GET_PEERS` (4) | ✅ | Response with peer list (`manager.rs:600+`) |
| `PEERS` (5) | ✅ | Peer list received and stored (`manager.rs:620+`) |
| `GET_TX_SET` (6) | ✅ | Dispatched to handler (`message_handlers.rs:120+`) |
| `TX_SET` (7) | ✅ | Received, forwarded to ledger subsystem |
| `GENERALIZED_TX_SET` (8) | ✅ | Handled alongside TX_SET |
| `TRANSACTION` (9) | ✅ | Core flooding path (`flood.rs`, `manager.rs`) |
| `GET_SCP_QUORUM` (11) | ✅ | Used as synthetic keepalive |
| `SCP_QUORUM` (12) | ✅ | Handled in dispatch |
| `SCP_MESSAGE` (13) | ✅ | Core SCP path (`manager.rs:700+`) |
| `GET_SCP_STATE` (14) | ✅ | Dispatched |
| `HELLO` (15) | ✅ | Handshake (`peer.rs`) |
| `SURVEY_REQUEST` (16) | ✅ | Survey subsystem (`survey.rs`) |
| `SURVEY_RESPONSE` (17) | ✅ | Survey subsystem (`survey.rs`) |
| `SEND_MORE` (18) | ✅ | Flow control (`flow_control.rs`) |
| `SEND_MORE_EXTENDED` (19) | ✅ | Flow control with byte capacity (`flow_control.rs`) |
| `FLOOD_ADVERT` (20) | ✅ | Pull-mode flooding (`tx_adverts.rs`) |
| `FLOOD_DEMAND` (21) | ✅ | Pull-mode flooding (`tx_demands.rs`) |
| `TIME_SLICED_SURVEY_REQUEST` (22) | ✅ | Survey subsystem (`survey.rs`) |
| `TIME_SLICED_SURVEY_RESPONSE` (23) | ✅ | Survey subsystem (`survey.rs`) |
| `TIME_SLICED_SURVEY_START_COLLECTING` (24) | ✅ | Survey subsystem (`survey.rs`) |
| `TIME_SLICED_SURVEY_STOP_COLLECTING` (25) | ✅ | Survey subsystem (`survey.rs`) |

**Assessment: Full coverage.** All 25 message types in the spec are recognized and dispatched. The XDR crate provides the type definitions; henyey provides the handling logic.

---

### 3.7 Message Definitions (Spec §7)

**Source files:** `peer.rs`, `auth.rs`, `manager.rs`, `message_handlers.rs`

#### 7.1 Hello Message

| Field/Requirement | Status | Evidence |
|-------------------|--------|----------|
| `ledgerVersion` populated | ✅ | From current ledger state (`peer.rs:200`) |
| `overlayVersion` populated | ✅ | From config (`peer.rs:202`) |
| `overlayMinVersion` populated | ✅ | Set to minimum supported (`peer.rs:204`) |
| `networkID` = SHA-256(passphrase) | ✅ | Network ID from config (`peer.rs:206`) |
| `versionStr` ≤ 100 bytes | ✅ | Truncated if needed (`peer.rs:208`) |
| `listeningPort` from config | ✅ | From `OverlayConfig` (`peer.rs:210`) |
| `peerID` = node's Ed25519 public key | ✅ | From `LocalNode` (`peer.rs:212`) |
| `cert` = valid AuthCert | ✅ | Generated or cached AuthCert (`auth.rs:100+`) |
| `nonce` = 32 random bytes | ✅ | `rand::random()` nonce (`peer.rs:214`) |

#### 7.2 Auth Message

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Auth message is empty (flags = 0) | ✅ | `Auth { flags: 0 }` sent (`peer.rs:250`) |
| Unused field, value ignored | ✅ | Field not inspected on receipt |

#### 7.3 Error Message

| Requirement | Status | Evidence |
|-------------|--------|----------|
| `ErrorCode` enum used | ✅ | XDR `ErrorCode` variants (`error.rs`) |
| `msg` string ≤ 100 chars | ⚠️ | Error messages constructed but length not explicitly capped |
| Sent before disconnect | ✅ | `send_error_and_disconnect` pattern (`manager.rs:500+`) |

#### 7.4 AuthCert

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Curve25519 ephemeral key | ✅ | X25519 keypair generated (`auth.rs:80-100`) |
| Expiry = current time rounded to 1-hour boundary + 1 hour | ✅ | `expiration` calculation matches spec (`auth.rs:120`) |
| Ed25519 signature over `(ENVELOPE_TYPE_AUTH ∥ expiry ∥ pubkey)` | ✅ | Signature computed over correct preimage (`auth.rs:130-150`) |
| Cached for reuse within validity window | ✅ | `AuthCert` cached and reused (`auth.rs:160`) |

**Assessment: High adherence.** All critical message fields are correctly populated. Minor gap: error message length not explicitly capped at 100 characters.

---

### 3.8 Flow Control Protocol (Spec §8)

**Source files:** `flow_control.rs`, `manager.rs`

#### 8.1 Dual-Axis Capacity

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Message-count capacity axis | ✅ | `flood_capacity` field (`flow_control.rs:100`) |
| Byte-count capacity axis | ✅ | `flood_capacity_bytes` field (`flow_control.rs:102`) |
| Initial flood capacity = 200 messages | ✅ | `INITIAL_FLOOD_CAPACITY: u32 = 200` (`flow_control.rs:20`) |
| Initial byte capacity = 300,000 bytes | ✅ | `INITIAL_FLOOD_CAPACITY_BYTES: u32 = 300_000` (`flow_control.rs:22`) |
| `SEND_MORE` increments message capacity | ✅ | Handled in `receive_send_more` (`flow_control.rs:200+`) |
| `SEND_MORE_EXTENDED` increments both | ✅ | Both capacities updated (`flow_control.rs:210+`) |
| Capacity checked before sending flood message | ✅ | `can_send_flood` check (`flow_control.rs:250`) |
| Both axes must have capacity | ✅ | `msg_capacity > 0 && byte_capacity > 0` (`flow_control.rs:255`) |

#### 8.2 SEND_MORE / SEND_MORE_EXTENDED

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Send SEND_MORE_EXTENDED after processing flood msg | ✅ | `send_send_more` called after message processing (`flow_control.rs:300+`) |
| Include message count and byte count replenished | ✅ | Both values included in `SendMoreExtended` (`flow_control.rs:310`) |
| Batch SEND_MORE messages (not per-message) | ✅ | Batched based on threshold (`flow_control.rs:320`) |

#### 8.3 Outbound Priority Queuing

| Requirement | Status | Evidence |
|-------------|--------|----------|
| 4 priority levels | ✅ | `Priority::Scp > Priority::Transaction > Priority::Demand > Priority::Advert` (`flow_control.rs:50-60`) |
| SCP messages highest priority | ✅ | `Priority::Scp` is highest (`flow_control.rs:50`) |
| Per-peer outbound queues | ✅ | `OutboundQueue` per peer (`flow_control.rs:400+`) |
| SCP queue trimming by slot age | ✅ | Old SCP slots evicted (`flow_control.rs:500+`) |
| Transaction queue FIFO | ✅ | `VecDeque` ordering (`flow_control.rs:410`) |
| Advert queue FIFO | ✅ | `VecDeque` ordering |
| Demand queue FIFO | ✅ | `VecDeque` ordering |
| Drop lowest-priority first on capacity | ✅ | Priority-ordered dequeue (`flow_control.rs:450+`) |

#### 8.4 Read Throttling

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Throttle reading when outbound queue full | ✅ | Read throttling flag (`flow_control.rs:600+`) |
| Resume reading when capacity available | ✅ | Unthrottle check (`flow_control.rs:620`) |

#### 8.5 CapacityTrackedMessage

| Requirement | Status | Evidence |
|-------------|--------|----------|
| RAII wrapper tracking message size | ❌ | Not implemented; size tracking is manual |
| Automatic capacity release on drop | ❌ | Manual release instead |

**Assessment: High adherence.** The dual-axis flow control system is well-implemented with correct initial values and priority ordering. The only gap is the `CapacityTrackedMessage` RAII pattern, which is a code-quality concern rather than a behavioral difference — capacity is still tracked, just manually.

---

### 3.9 Transaction Flooding Protocol (Spec §9)

**Source files:** `flood.rs`, `tx_adverts.rs`, `tx_demands.rs`, `manager.rs`

#### 9.1 Pull Mode (FloodAdvert → FloodDemand → Transaction)

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Pull mode as default flooding mechanism | ✅ | Pull mode used for all transaction flooding (`tx_adverts.rs:1`) |
| FloodAdvert contains transaction hash(es) | ✅ | `FloodAdvert` with hash vector (`tx_adverts.rs:50+`) |
| FloodDemand contains requested hash(es) | ✅ | `FloodDemand` with hash vector (`tx_demands.rs:50+`) |
| Transaction sent in response to demand | ✅ | Demand-response path in `manager.rs` |
| Advert batching interval = 100ms | ✅ | `ADVERT_BATCH_INTERVAL_MS: u64 = 100` (`tx_adverts.rs:20`) |
| Maximum adverts per batch | ✅ | Batch size limited (`tx_adverts.rs:25`) |

#### 9.2 Demand Scheduling

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Demand scheduling interval = 500ms | ✅ | `DEMAND_SCHEDULE_INTERVAL_MS: u64 = 500` (`tx_demands.rs:20`) |
| Round-robin across peers for demands | ✅ | Peer rotation in demand scheduling (`tx_demands.rs:200+`) |
| Track which peer advertised which hash | ✅ | Per-hash peer tracking (`tx_demands.rs:100+`) |
| Retry demands from alternate peers | ✅ | Retry logic with peer fallback (`tx_demands.rs:300+`) |
| Maximum 15 retries | ✅ | `MAX_RETRIES: u32 = 15` (`tx_demands.rs:22`) |
| Exponential backoff on retry | ✅ | Backoff calculation (`tx_demands.rs:310`) |
| Demand timeout before retry | ✅ | Timeout tracked per outstanding demand (`tx_demands.rs:250`) |

#### 9.3 Flood Deduplication

| Requirement | Status | Evidence |
|-------------|--------|----------|
| BLAKE2b-256 message hashing | ✅ | `blake2b_simd` 256-bit hash (`flood.rs:30+`) |
| Dedup by message hash | ✅ | Hash-based dedup set (`flood.rs:100+`) |
| TTL-based cleanup of dedup entries | ✅ | Periodic purge of old entries (`flood.rs:200+`) |
| Do not re-flood to originator | ✅ | Sender excluded from flood targets (`flood.rs:150`) |

#### 9.4 Push Mode (Legacy)

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Push mode for older protocol versions | ➖ | Not needed; henyey targets protocol 25+ only (pull mode is mandatory) |

#### 9.5 Custom Additions (Not in Spec)

| Feature | Notes |
|---------|-------|
| Rate limiting (1000 msg/s) | Custom addition in `flood.rs:250+`; not in stellar-core. Conservative choice — could cause issues with high-throughput peers |

**Assessment: High adherence.** Pull-mode flooding is comprehensively implemented with correct batching intervals, demand scheduling, retry limits, and deduplication. The custom rate limiter is a deviation but errs on the side of caution.

---

### 3.10 Peer Management (Spec §10)

**Source files:** `peer_manager.rs`, `ban_manager.rs`, `manager.rs`, `lib.rs`

#### 10.1 Peer Database

| Requirement | Status | Evidence |
|-------------|--------|----------|
| SQLite-backed peer persistence | ✅ | SQLite via `rusqlite` (`peer_manager.rs:1+`) |
| Store peer address + port | ✅ | `PeerAddress` stored (`peer_manager.rs:50+`) |
| Store peer type (inbound/outbound/preferred) | ✅ | `PeerType` enum (`peer_manager.rs:30`) |
| Store next attempt time | ✅ | `next_attempt` field (`peer_manager.rs:55`) |
| Store number of failures | ✅ | `num_failures` field (`peer_manager.rs:57`) |
| `storeConfigPeers` on startup | ❌ | Config peers not pre-loaded into SQLite; connected directly |
| `purgeDeadPeers` periodic cleanup | ❌ | No periodic purge of long-dead peers |
| Peer rank/quality scoring | ❌ | No quality scoring system |

#### 10.2 Connection Backoff

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Exponential backoff on failure | ✅ | `2^n * 10s` formula (`peer_manager.rs:200+`) |
| Maximum backoff exponent = 10 | ✅ | `max(n, 10)` cap (`peer_manager.rs:210`) |
| Reset backoff on successful connect | ✅ | Failure count reset (`peer_manager.rs:220`) |

#### 10.3 Peer Selection

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Preferred peers prioritized | ✅ | Preferred peers attempted first (`manager.rs:300+`) |
| Random selection among non-preferred | ✅ | Random peer selection (`manager.rs:320`) |
| DNS re-resolution of seed peers | ❌ | No DNS re-resolution; addresses resolved once |
| Random peer drop for rotation | ❌ | No periodic random peer drop (part of tick loop) |
| `getRandomPeer` from database | ⚠️ | Random selection exists but not via the exact `getRandomPeer` SQL query pattern |

#### 10.4 Ban Management

| Requirement | Status | Evidence |
|-------------|--------|----------|
| SQLite-backed ban list | ✅ | `ban_manager.rs:1+` |
| Ban by NodeID | ✅ | `ban_peer` by public key (`ban_manager.rs:50+`) |
| Ban expiry | ✅ | Time-based ban expiration (`ban_manager.rs:60`) |
| Check ban before accepting connection | ✅ | Ban check in connection acceptance (`manager.rs:380`) |
| `unban` functionality | ✅ | `unban_peer` method (`ban_manager.rs:80`) |

#### 10.5 Tick Loop

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Periodic `tick()` function | ❌ | No unified tick loop for peer maintenance |
| `checkForDeadPeers` — disconnect timed-out peers | ❌ | Not implemented |
| `updateSizeRemaining` — adjust capacities | ❌ | Not implemented |
| `maybeDropRandomPeer` — rotation | ❌ | Not implemented |
| `resolvePreferredPeers` — DNS refresh | ❌ | Not implemented |

#### 10.6 Peer Reporting

| Requirement | Status | Evidence |
|-------------|--------|----------|
| GET_PEERS response with up to 50 peers | ✅ | Peer list response (`manager.rs:600+`) |
| Include only authenticated peers | ⚠️ | Returns known peers; may include not-yet-authenticated addresses from DB |
| Separate inbound/outbound peer queries | ❌ | No distinct inbound vs outbound query API |

**Assessment: Medium adherence.** The core persistence, backoff, and ban management are solid. The significant gap is the absence of a `tick()` loop that drives periodic maintenance (dead peer cleanup, peer rotation, DNS refresh). This means peer lists can become stale and connections won't be proactively rotated.

---

### 3.11 Survey Protocol (Spec §11)

**Source files:** `survey.rs`

#### 11.1 Survey Lifecycle

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Time-sliced survey model | ✅ | `SurveyPhase::Collecting` / `Reporting` (`survey.rs:50+`) |
| `START_COLLECTING` initiates survey | ✅ | Handled (`survey.rs:200+`) |
| `STOP_COLLECTING` transitions to reporting | ✅ | Handled (`survey.rs:250+`) |
| Survey requests forwarded during collecting | ✅ | Request relay logic (`survey.rs:300+`) |
| Survey responses routed back during reporting | ✅ | Response routing (`survey.rs:350+`) |
| Survey expiry timeout | ✅ | Expiry-based cleanup (`survey.rs:400+`) |

#### 11.2 Rate Limiting

| Requirement | Status | Evidence |
|-------------|--------|----------|
| One survey request per ledger per surveyor | ✅ | Rate limiting tracked (`survey.rs:150+`) |
| Surveyor allowlist | ✅ | Allowlist check (`survey.rs:160`) |
| Reject surveys from non-allowed nodes | ✅ | Rejected if not in allowlist (`survey.rs:165`) |

#### 11.3 Survey Message Construction

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Curve25519 encryption of survey data | ❌ | Not implemented; survey data sent unencrypted |
| Ed25519 signing of survey messages | ❌ | Not implemented; no signature verification |
| Survey nonce for replay prevention | ⚠️ | Survey ID tracked but no cryptographic nonce |

#### 11.4 Survey Data Collection

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Collect peer topology information | ✅ | Topology data gathered (`survey.rs:500+`) |
| Collect per-peer metrics (bytes in/out, latency) | ⚠️ | Some metrics available; latency not tracked |
| Report flow control state | ⚠️ | Partial; not all flow control fields reported |

**Assessment: Medium adherence.** The survey lifecycle (time-slicing, phases, rate limiting) is well-structured. The critical gap is the absence of Curve25519 encryption and Ed25519 signing for survey messages, which are security requirements in the spec. Survey data is transmitted in cleartext, which could expose network topology information.

---

### 3.12 Error Handling (Spec §12)

**Source files:** `error.rs`, `manager.rs`, `peer.rs`

#### 12.1 Error Codes

| Requirement | Status | Evidence |
|-------------|--------|----------|
| `ERR_MISC` for general errors | ✅ | Used in error messages (`error.rs:20`) |
| `ERR_DATA` for invalid data | ✅ | Used for malformed messages |
| `ERR_CONF` for configuration mismatch | ✅ | Used for network ID mismatch |
| `ERR_AUTH` for authentication failure | ✅ | Used for HMAC/handshake failures |
| `ERR_LOAD` for load shedding | ⚠️ | Error code defined but load shedding not implemented |
| Send ERROR_MSG before closing | ✅ | `send_error_and_disconnect` pattern (`manager.rs:500+`) |

#### 12.2 Connection Failure Handling

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Increment failure count on disconnect | ✅ | `record_failure` called (`peer_manager.rs:200`) |
| Ban on repeated failures | ⚠️ | Manual ban available; no automatic ban on failure threshold |
| Graceful shutdown on error | ✅ | Error logged, connection closed cleanly |
| Remove from active peer list | ✅ | Peer removed on disconnect (`manager.rs:550+`) |

**Assessment: Medium adherence.** Error types and the disconnect-on-error pattern are correct. Gaps: no automatic ban escalation on repeated failures, and no `ERR_LOAD` load-shedding behavior.

---

### 3.13 Security Considerations (Spec §13)

**Source files:** `auth.rs`, `codec.rs`, `manager.rs`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Authenticated encryption for all post-handshake messages | ✅ | HMAC-SHA256 on all authenticated messages (`auth.rs`) |
| Ephemeral key exchange (forward secrecy) | ✅ | X25519 ephemeral keys per connection (`auth.rs:80+`) |
| AuthCert expiry prevents stale keys | ✅ | 1-hour expiry enforced (`auth.rs:120`) |
| Nonce uniqueness per connection | ✅ | 32 random bytes per connection (`peer.rs:214`) |
| Sequence number replay prevention | ✅ | Monotonic sequence numbers (`auth.rs:420`) |
| Network ID binding prevents cross-network | ✅ | Network ID validated in Hello (`peer.rs:330`) |
| Self-connection prevention | ✅ | Nonce-based self-detection (`peer.rs:340`) |
| Duplicate connection prevention | ✅ | NodeID-based dedup (`manager.rs:450+`) |
| Resource exhaustion protection | ⚠️ | Message size limits present; no per-IP connection rate limiting |
| DoS via pending connection slots | ⚠️ | No explicit pending peer limit; could exhaust connection slots |
| Survey data encryption | ❌ | Survey data unencrypted (see §11) |

**Assessment: High adherence on core security.** The cryptographic pipeline is sound. Gaps are in resource-exhaustion mitigation (no connection rate limiting per IP) and survey encryption.

---

### 3.14 Protocol Constants (Spec §14)

**Source files:** Various (constants spread across files)

| Constant | Spec Value | Henyey Value | Status |
|----------|-----------|--------------|--------|
| `MAX_MESSAGE_SIZE` | 0x2000000 (32 MB) | 0x200_0000 | ✅ |
| `MIN_MESSAGE_SIZE` | 12 bytes | 12 | ✅ |
| `PEER_AUTHENTICATION_TIMEOUT` | 2 seconds | Not set (uses connect timeout) | ❌ |
| `TARGET_PEER_CONNECTIONS` | 8 | 8 | ✅ |
| `MAX_ADDITIONAL_PEER_CONNECTIONS` | 64 | 64 | ✅ |
| `INITIAL_FLOOD_CAPACITY` | 200 messages | 200 | ✅ |
| `INITIAL_FLOOD_CAPACITY_BYTES` | 300,000 bytes | 300,000 | ✅ |
| `AUTH_CERT_EXPIRY` | 3600 seconds (1 hour) | 3600 | ✅ |
| `ADVERT_BATCH_INTERVAL` | 100 ms | 100 | ✅ |
| `DEMAND_SCHEDULE_INTERVAL` | 500 ms | 500 | ✅ |
| `MAX_DEMAND_RETRIES` | 15 | 15 | ✅ |
| `BACKOFF_BASE` | 10 seconds | 10 | ✅ |
| `MAX_BACKOFF_EXPONENT` | 10 | 10 | ✅ |
| `OVERLAY_VERSION` | 35-38 range | Configurable, supports 35+ | ✅ |
| `MAX_PEERS_IN_RESPONSE` | 50 | 50 | ✅ |

**Assessment: High adherence.** All critical protocol constants match. The only missing constant is `PEER_AUTHENTICATION_TIMEOUT`.

---

## 4. Gap Summary

### Critical Gaps (Behavioral Divergence)

| # | Gap | Spec Section | Impact |
|---|-----|-------------|--------|
| G1 | No `tick()` loop for periodic maintenance | §10.5 | Stale peer lists, no dead-peer cleanup, no rotation |
| G2 | No `PEER_AUTHENTICATION_TIMEOUT` (2s) | §4.3 | Slow handshakes could consume connection slots |
| G3 | Survey messages not encrypted/signed | §11.3 | Topology data exposed in cleartext |
| G4 | No ping/pong latency tracking | §4.5 | No peer quality assessment |

### Moderate Gaps (Missing Functionality)

| # | Gap | Spec Section | Impact |
|---|-----|-------------|--------|
| G5 | No `storeConfigPeers` at startup | §10.1 | Config peers not persisted for reconnection |
| G6 | No `purgeDeadPeers` cleanup | §10.1 | Peer DB grows unbounded |
| G7 | No DNS re-resolution of seed peers | §10.3 | Cannot track IP changes of seed nodes |
| G8 | No random peer drop for rotation | §10.3 | Network topology may ossify |
| G9 | No `CapacityTrackedMessage` RAII pattern | §8.5 | Risk of capacity leak on error paths |
| G10 | No automatic ban escalation on repeated failures | §12.2 | Must manually ban misbehaving peers |
| G11 | No `ERR_LOAD` load-shedding behavior | §12.1 | Cannot shed load under pressure |
| G12 | No pending peer state tracking | §4.2 | Cannot limit pending connection slots |
| G13 | No separate inbound/outbound peer list queries | §10.6 | Cannot query peer lists by direction |

### Minor Gaps (Conservative Deviations)

| # | Gap | Spec Section | Notes |
|---|-----|-------------|-------|
| G14 | Auth flags = 200 strict check | §5.2 | Stricter than stellar-core; not a violation |
| G15 | Error message length not capped at 100 chars | §7.3 | Could send oversized error messages |
| G16 | Custom rate limiter (1000 msg/s) | §9 | Not in stellar-core; conservative but may cause issues |
| G17 | Synthetic GetScpQuorumset as keepalive | §4.5 | Functional workaround but non-standard |

---

## 5. Risk Assessment

### High Risk

| Gap | Risk Description | Mitigation |
|-----|-----------------|------------|
| G1 (No tick loop) | Without periodic maintenance, the node will accumulate stale peers, not detect dead connections proactively, and not rotate its peer set. Over time, the node's view of the network could degrade. | Implement a unified `tick()` function that runs every ~10 seconds, performing: dead peer check, peer rotation, DNS refresh, and DB cleanup. |
| G3 (Survey encryption) | Survey data reveals network topology. Without encryption, any peer on the path can observe topology information. On testnet this is low risk; on mainnet it would be a security concern. | Implement Curve25519 survey encryption and Ed25519 signing before mainnet deployment. |

### Medium Risk

| Gap | Risk Description |
|-----|-----------------|
| G2 (No auth timeout) | A malicious peer could hold a connection slot indefinitely by never completing the handshake. |
| G12 (No pending tracking) | Combined with G2, many pending connections could exhaust inbound slots. |
| G4 (No latency tracking) | Cannot prefer low-latency peers, which could impact consensus performance. |
| G6 (No purge) | Peer database grows without bound, eventually degrading query performance. |

### Low Risk

| Gap | Risk Description |
|-----|-----------------|
| G5, G7, G8 | Quality-of-life features; network functions without them but suboptimally. |
| G9, G14-G17 | Code-quality or conservative deviations; no behavioral impact on happy path. |

---

## 6. Recommendations

### Priority 1 — Required Before Mainnet

1. **Implement `tick()` loop** (G1): Add a periodic maintenance function (~10s interval) that:
   - Checks for dead/timed-out peers and disconnects them
   - Drops a random non-preferred peer occasionally to encourage rotation
   - Re-resolves DNS names for seed/preferred peers
   - Calls `purgeDeadPeers` to clean the peer database

2. **Add `PEER_AUTHENTICATION_TIMEOUT`** (G2, G12): Track pending peers with a 2-second timeout. Disconnect peers that don't complete the handshake in time. Add pending peer count limits.

3. **Implement survey message encryption** (G3): Add Curve25519-based encryption and Ed25519 signing for survey request/response messages per the spec.

### Priority 2 — Recommended

4. **Add ping/pong latency tracking** (G4): Implement proper latency measurement using GET_PEERS/PEERS round-trip or a dedicated ping mechanism. Use latency for peer quality scoring.

5. **Add `CapacityTrackedMessage`** (G9): Implement an RAII wrapper that automatically releases flow-control capacity when a message is dropped or consumed, preventing leaks on error paths.

6. **Add automatic ban escalation** (G10): After N consecutive failures (e.g., 5), automatically ban a peer for an escalating duration.

7. **Implement load shedding** (G11): Support `ERR_LOAD` to gracefully reject new connections when the node is under heavy load.

### Priority 3 — Nice to Have

8. **Store config peers in DB** (G5): Persist configured peers to SQLite for resilient reconnection.
9. **DNS re-resolution** (G7): Periodically re-resolve seed peer hostnames.
10. **Random peer rotation** (G8): Periodically drop a random outbound peer to encourage topology diversity.
11. **Separate inbound/outbound queries** (G13): Add API to query peers by connection direction.

---

*This evaluation was conducted against commit `1c1fd4a` of the henyey repository and the formal overlay protocol specification at `docs/OVERLAY_SPEC.md`.*
