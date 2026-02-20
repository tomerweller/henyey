# Overlay Protocol Gap Closure Plan

This plan closes all 17 gaps (G1–G17) identified in
`docs/OVERLAY_SPEC_HENYEY_EVAL.md`, achieving 100% adherence to the overlay
protocol specification. Gaps are grouped into 6 implementation phases ordered
by dependency — each phase builds on the prior one.

**Estimated scope**: ~2,500–3,000 lines of new/modified code + ~1,500 lines of
tests.

---

## Phase 1: Tick Loop & Core Lifecycle (G1, G5, G6, G12)

These four gaps form the foundation. The tick loop (G1) is the scheduling
backbone for G5, G6, G7, G8. Pending peer tracking (G12) is needed by G2 and
G8.

### G1 — Central `tick()` Loop

**Problem**: No periodic maintenance loop. Connector and advertiser run on
ad-hoc intervals.

**Implementation**:
1. Add a `start_tick()` method to `OverlayManager` in `manager.rs`.
2. Timer fires every **3 seconds** (`PEER_AUTHENTICATION_TIMEOUT + 1`).
3. Each tick executes, in order:
   - Clean up dropped/disconnected peers.
   - Check DNS resolution results (see G7).
   - Update survey phase (`survey_manager.maybe_advance_phase()`).
   - Connect to preferred peers if not connected.
   - Maybe drop random peer if out of sync (see G8).
   - Fill outbound peer slots (subsume current `start_connector` logic).
   - Attempt inbound→outbound promotion for preferred peers.
4. Spawn `start_tick()` from `start()`, replacing `start_connector()`.
5. Keep `start_listener()` and `start_peer_advertiser()` as separate tasks.

**Startup sequence** (in `start()`, before spawning tick):
- `store_config_peers()` (G5)
- `purge_dead_peers()` (G6)
- `trigger_peer_resolution()` (G7)
- Then spawn tick timer.

**Files**: `manager.rs`, `lib.rs`.

### G5 — `store_config_peers` at Startup

**Problem**: `known_peers` and `preferred_peers` from config are not persisted
to the peer database at startup.

**Implementation**:
1. Add `store_config_peers(&self)` method to `OverlayManager`.
2. For each peer in `config.known_peers` and `config.preferred_peers`:
   - Call `peer_manager.store_peer()` with appropriate type.
3. Store the resolved preferred peer addresses for fast lookup.
4. Call this from `start()` before the first tick.

**Files**: `manager.rs`, `peer_manager.rs`.

### G6 — `purge_dead_peers` Cleanup

**Problem**: Peers with excessive failures are never cleaned from the database.

**Implementation**:
1. Add `purge_dead_peers(&self)` method to `OverlayManager`.
2. Call `peer_manager.remove_peers_with_many_failures(120)`.
3. Call this from `start()` after `store_config_peers()`.

**Files**: `manager.rs`, `lib.rs` (constant `REALLY_DEAD_NUM_FAILURES_CUTOFF = 120`).

### G12 — Pending Peer State Tracking

**Problem**: No distinction between pending (handshaking) and authenticated
peers in connection accounting.

**Implementation**:
1. Add `pending_inbound` and `pending_outbound` atomic counters to
   `ConnectionPool`.
2. Transition counters on handshake start / auth success / disconnect.
3. Add query methods: `pending_peers_count()`, `inbound_pending_peers()`,
   `outbound_pending_peers()`.

**Files**: `connection.rs`, `manager.rs`, `peer.rs`.

---

## Phase 2: Timeouts & Keepalive (G2, G4, G17)

### G2 — `PEER_AUTHENTICATION_TIMEOUT` (2 seconds)

**Problem**: `auth_timeout_secs` is 30s — should be 2s for unauthenticated
peers.

**Implementation**:
1. Change `auth_timeout_secs` default from 30 to 2.
2. Ensure authenticated peer idle timeout remains 30s via separate config.
3. Audit all uses of `auth_timeout_secs` to confirm pre-auth only.

**Files**: `lib.rs`, `manager.rs`, `peer.rs`.

### G4 — Ping/Pong Latency Tracking

**Problem**: No ping/pong mechanism for RTT measurement.

**Implementation** (match stellar-core's `GET_SCP_QUORUMSET` abuse):
1. Add ping state to `Peer`: `ping_sent_time`, `last_pong_rtt`,
   `ping_nonce_hash`.
2. `ping_peer()`: send `GET_SCP_QUORUMSET(nonce_hash)`, record time.
3. `maybe_process_ping_response()`: match `DONT_HAVE` response, compute RTT.
4. Call from existing recurrent timer (every 5s).
5. Intercept `DONT_HAVE` in message dispatch.

**Files**: `peer.rs`, `manager.rs`, `metrics.rs`.

### G17 — Synthetic `GET_SCP_QUORUMSET` as Keepalive

Fully subsumed by G4. The ping mechanism doubles as keepalive.

---

## Phase 3: Peer Rotation & DNS (G7, G8)

### G7 — DNS Re-Resolution of Seed Peers

**Problem**: Seed peer hostnames are resolved once. No periodic re-resolution.

**Implementation**:
1. Add DNS state: `dns_pending`, `last_dns_resolution`, retry count.
2. `trigger_peer_resolution()`: spawn async DNS resolution task.
3. In tick: check results, update peer DB, re-trigger every 600s.
4. Retry with exponential backoff (10s × retry_count) on failure.

**Files**: `manager.rs`, `lib.rs`.

### G8 — Random Peer Drop for Rotation

**Problem**: Out-of-sync nodes never rotate outbound peers.

**Implementation**:
1. `maybe_drop_random_peer()` in tick.
2. Guards: out of sync + full outbound slots + 60s cooldown.
3. Drop random non-preferred outbound peer with ERR_LOAD.

**Files**: `manager.rs`, `peer.rs`, `lib.rs`.

---

## Phase 4: Error Handling & Load Shedding (G10, G11, G14, G15)

### G11 — `ERR_LOAD` Load-Shedding

**Problem**: No ERR_LOAD error code sent in overload scenarios.

**Implementation**:
1. Add `send_error_and_drop()` to `Peer`.
2. Send ERR_LOAD in 3 scenarios: connection limit, preferred eviction,
   out-of-sync drop.
3. On receiving ERR_LOAD: don't increment failure count.

**Files**: `peer.rs`, `manager.rs`, `connection.rs`.

### G10 — Automatic Ban Escalation

**Problem**: No automatic banning based on failure history.

**Implementation**:
1. `maybe_auto_ban()` on peer disconnect with failure.
2. Time-limited bans (5 min) after threshold (10 failures).
3. `banned_until` column in SQLite.
4. Cleanup expired bans in tick.

**Files**: `ban_manager.rs`, `peer_manager.rs`, `manager.rs`.

### G14 — Auth Flags Check

**Resolution**: Already correct. Code uses bit 31 (`0x80000000`), matching
stellar-core. Add clarifying comment only.

### G15 — Error Message Length Cap

**Problem**: Error messages not truncated to 100 characters.

**Implementation**: Truncate to 100 bytes at valid UTF-8 boundary in
`send_error_and_drop()`.

**Files**: `peer.rs`.

---

## Phase 5: Survey Crypto (G3)

### G3 — Survey Messages Signed and Encrypted

**Problem**: No signing or encryption of survey messages.

**Implementation**:
1. **Signing**: Ed25519 sign all outgoing survey messages; verify on receive.
2. **Encryption**: Curve25519 sealed-box encrypt survey responses using
   surveyor's ephemeral public key.
3. **Ephemeral keys**: Generate on `start_survey()`, zero on `stop_survey()`.
4. Use existing `crates/crypto/src/sealed_box.rs`.

**Files**: `survey.rs`, `crates/crypto`.

---

## Phase 6: Flow Control & Rate Limiting (G9, G16, G13)

### G9 — `CapacityTrackedMessage` RAII Pattern

**Problem**: Manual acquire/release pair is error-prone.

**Implementation**: `CapacityGuard` struct with `Drop` impl that releases
capacity. Replace all manual call sites.

**Files**: `flow_control.rs`, `manager.rs`.

### G16 — Per-Peer Rate Limiting

**Problem**: Rate limiter is global, not per-peer.

**Implementation**: Move rate limiting to per-peer level. Exceed → ERR_LOAD +
disconnect.

**Files**: `flood.rs`, `manager.rs`, `peer.rs`.

### G13 — Separate Inbound/Outbound Peer Queries

**Problem**: `load_random_peers()` doesn't distinguish direction.

**Implementation**: Add `PeerDirection` filter to peer queries.

**Files**: `peer_manager.rs`, `manager.rs`.

---

## Implementation Order & Dependencies

```
Phase 1 (Foundation)     Phase 2 (Timeouts)     Phase 3 (Rotation)
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ G1  Tick Loop    │────>│ G2  Auth Timeout │     │ G7  DNS Re-Res  │
│ G5  StoreConfig  │     │ G4  Ping/Pong    │     │ G8  Random Drop │
│ G6  PurgeDead    │     │ G17 Keepalive    │     │                 │
│ G12 PendingPeers │     └─────────────────┘     └─────────────────┘
└─────────────────┘              |                        |
         |                       |                        |
         v                       v                        v
Phase 4 (Errors)         Phase 5 (Survey)    Phase 6 (Flow/Rate)
┌─────────────────┐     ┌─────────────────┐  ┌─────────────────┐
│ G11 ERR_LOAD     │     │ G3  Survey Crypto│  │ G9  RAII Guards  │
│ G10 Auto-Ban     │     │                 │  │ G16 Rate Limiter │
│ G14 Auth Flags   │     │                 │  │ G13 In/Out Query │
│ G15 Msg Length   │     │                 │  │                 │
└─────────────────┘     └─────────────────┘  └─────────────────┘
```

Phases 4, 5, and 6 are independent and can be parallelized.

---

## Test Strategy

| Phase | New Unit Tests | New Integration Tests | Total |
|-------|---------------|----------------------|-------|
| 1     | 10            | 1                    | 11    |
| 2     | 8             | 1                    | 9     |
| 3     | 8             | 0                    | 8     |
| 4     | 8             | 0                    | 8     |
| 5     | 8             | 1                    | 9     |
| 6     | 7             | 0                    | 7     |
| **Total** | **49**    | **3**                | **52**|

---

## Gap Closure Verification Checklist

- [ ] G1  — Tick fires every 3s, executes all sub-actions
- [ ] G2  — Unauthenticated peers timeout at 2s
- [ ] G3  — All survey messages signed; responses encrypted
- [ ] G4  — Ping/pong RTT tracked per peer
- [ ] G5  — Config peers in DB after startup
- [ ] G6  — Peers with >=120 failures removed at startup
- [ ] G7  — DNS re-resolved every 10 min with retry backoff
- [ ] G8  — Random non-preferred peer dropped when out of sync
- [ ] G9  — Capacity released on drop (incl. panic)
- [ ] G10 — Peers auto-banned after threshold failures
- [ ] G11 — ERR_LOAD sent in all 3 scenarios
- [ ] G12 — Pending peer counts accurate through state transitions
- [ ] G13 — Peer queries filterable by inbound/outbound
- [ ] G14 — Auth flag uses bit 31 (already correct)
- [ ] G15 — Error messages truncated to 100 bytes
- [ ] G16 — Per-peer rate limiting with ERR_LOAD on exceed
- [ ] G17 — Keepalive via ping mechanism (subsumed by G4)
