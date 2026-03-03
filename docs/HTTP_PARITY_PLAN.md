# HTTP Parity Plan: Henyey ↔ stellar-core

## Goal

Two-pronged approach to HTTP API maturity:

**(A) Improve henyey's native HTTP server** — richer response data, missing fields,
modular code organization, and the query server. Follows Rust/REST best practices
(snake_case, proper HTTP methods, typed responses). This is the primary interface
for henyey-native tooling.

**(B) Optional stellar-core compatibility HTTP server** — a thin translation layer
that wraps henyey's native responses into stellar-core's exact wire format. This
enables henyey as a drop-in replacement for stellar-core when used by stellar-rpc
(with zero changes to stellar-rpc).

Both servers run concurrently on separate configurable ports. The compat server is
opt-in via config (`[compat_http]`).

See also: `docs/RPC_COMP_PLAN.md` for the broader RPC compatibility plan (config,
CLI, meta pipe, diagnostics) — this document focuses specifically on the HTTP layer.

---

## Current State

### What exists (`crates/app/src/run_cmd.rs`, 2120 lines)

- Axum-based HTTP server with 27 endpoints on a single `Router`
- All response structs, request structs, and handlers in one monolithic file
- Clean snake_case JSON responses (intentionally not stellar-core format)
- `ServerState` holds `Arc<App>`, `Instant` start time, optional `LogLevelHandle`

### Endpoints registered (lines 595-627)

| Endpoint | Method | Henyey-only? |
|----------|--------|-------------|
| `/` | GET | Yes |
| `/info` | GET | |
| `/status` | GET | Yes |
| `/metrics` | GET | |
| `/peers` | GET | |
| `/connect` | POST | |
| `/droppeer` | POST | |
| `/bans` | GET | |
| `/unban` | POST | |
| `/ledger` | GET | Yes |
| `/upgrades` | GET | |
| `/self-check` | POST | |
| `/quorum` | GET | |
| `/survey` | GET | |
| `/scp` | GET | |
| `/survey/start` | POST | |
| `/survey/stop` | POST | |
| `/survey/topology` | POST | |
| `/survey/reporting/stop` | POST | |
| `/tx` | POST | |
| `/shutdown` | POST | Yes |
| `/health` | GET | Yes |
| `/ll` | GET/POST | |
| `/manualclose` | POST | |
| `/sorobaninfo` | GET | |
| `/clearmetrics` | POST | |
| `/logrotate` | POST | |
| `/maintenance` | POST | |
| `/dumpproposedsettings` | GET | |

### Missing endpoints (stellar-core has, henyey doesn't)

| Endpoint | Priority | Notes |
|----------|----------|-------|
| `/getledgerentryraw` | **Critical** | Query server, separate port. Required by stellar-rpc |
| `/getledgerentry` | **Critical** | Query server, separate port. Required by stellar-rpc |
| `generateload`, `testacc`, `testtx` | Skip | Test-only, not needed |

---

## Part A: Native Henyey HTTP Server

### A1. Code Organization — Extract Module Structure

**Problem**: 2120 lines in a single file mixing run logic, server setup, 27
handlers, 30+ request/response structs, and helper functions.

**Solution**: Extract into a module tree under `crates/app/src/http/`:

```
crates/app/src/http/
├── mod.rs              # Re-exports, ServerState, router construction
├── handlers/
│   ├── mod.rs
│   ├── info.rs         # /info, /status, /health, /ledger
│   ├── tx.rs           # /tx
│   ├── peers.rs        # /peers, /connect, /droppeer, /bans, /unban
│   ├── scp.rs          # /scp, /quorum
│   ├── survey.rs       # /survey, /survey/start, /survey/stop, etc.
│   ├── soroban.rs      # /sorobaninfo, /dumpproposedsettings
│   ├── admin.rs        # /shutdown, /maintenance, /clearmetrics, /logrotate, /ll
│   └── metrics.rs      # /metrics
├── types/
│   ├── mod.rs
│   ├── info.rs         # InfoResponse, HealthResponse, LedgerResponse, NodeStatus
│   ├── tx.rs           # SubmitTxRequest, SubmitTxResponse, TxStatus enum
│   ├── peers.rs        # PeersResponse, PeerInfo
│   ├── scp.rs          # ScpInfoResponse, ScpSlotInfo, QuorumResponse
│   ├── survey.rs       # SurveyCommandResponse, survey params
│   ├── soroban.rs      # SorobanInfoResponse and sub-structs
│   └── admin.rs        # LlResponse, MaintenanceResponse, etc.
└── helpers.rs          # parse_connect_params, parse_peer_id, etc.
```

`run_cmd.rs` retains `RunCmd`, `RunOptions`, `RunMode`, and the `run()` method but
delegates HTTP setup to `http::build_router()`.

**Effort**: ~1 day

### A2. Enrich `/info` Response

**Current** (line 658):
```rust
struct InfoResponse {
    version, node_name, public_key, network_passphrase, is_validator, state, uptime_secs
}
```

**Target** — add fields from stellar-core's `getJsonInfo()` (`ApplicationImpl.cpp:460-554`):
```rust
struct InfoResponse {
    build: String,              // "henyey-v0.1.0"
    protocol_version: u32,
    state: String,
    started_on: String,         // ISO 8601 timestamp
    uptime_secs: u64,
    node_name: String,
    public_key: String,
    network_passphrase: String,
    is_validator: bool,
    ledger: LedgerSummary {
        num: u32,
        hash: String,
        close_time: u64,
        version: u32,
        base_fee: u32,
        base_reserve: u32,
        max_tx_set_size: u32,
        max_soroban_tx_set_size: Option<u32>,
        flags: u32,
        age: u64,               // seconds since last close
    },
    peers: PeerSummary {
        pending_count: usize,
        authenticated_count: usize,
    },
    status: Vec<String>,        // last N status messages
}
```

Data sources: `App::ledger_info()` already returns `(seq, hash, close_time,
protocol_version)`. Need to expose `base_fee`, `base_reserve`, `max_tx_set_size`,
`flags` from `LedgerHeader`. Peer counts from `App::peer_snapshots()`.

**Effort**: ~0.5 day

### A3. Enrich `/peers` Response

**Current** (line 681): Flat `{count, peers: [{id, address, direction}]}`.

**Target** — add per-peer metrics from `Peer::getJsonInfo()` (`Peer.cpp:478-529`):
```rust
struct PeerInfo {
    id: String,
    address: String,
    direction: String,
    // New fields:
    version: String,            // remote overlay version
    protocol_version: u32,
    latency_ms: u64,
    message_read_count: u64,
    message_write_count: u64,
    bytes_read: u64,
    bytes_written: u64,
    connected_duration_secs: u64,
}
```

Also categorize by state: `{authenticated: {inbound: [...], outbound: [...]},
pending: {inbound: [...], outbound: [...]}}` is the native henyey format too (it's
just good practice), but keep a flat `peers` list for backward compat.

Requires `PeerSnapshot` in `henyey-overlay` to expose these metrics (some may
already be tracked internally).

**Effort**: ~1 day (depends on overlay crate exposure)

### A4. Enrich `/scp` Response

**Current** (line 732): Simplified `{node, slots: [{slot_index, is_externalized,
is_nominating, ballot_phase, nomination_round, ballot_round, envelope_count}]}`.

**Target** — add full SCP internal state from `Slot::getJsonInfo()` (`Slot.cpp:339-372`):
- Nomination: `round_number`, `heard_from` (nodes), candidate values
- Ballot protocol: `phase`, `current_ballot`, `committed_ballot`, `high_ballot`,
  `low_ballot`, prepared/preparedPrime values
- Quorum set hash for this slot
- Envelope details (optional, with `?fullkeys=true` parameter)

Requires SCP crate to expose richer slot state. Currently `ScpSlotSnapshot` only
has summary fields.

**Effort**: ~1-2 days

### A5. Enrich `/quorum` Response

**Current** (line 726): Only local quorum set: `{local: {hash, threshold, validators, inner_sets}}`.

**Target** — add transitive quorum info from `HerderImpl::getJsonQuorumInfo()`:
- Per-node in transitive closure: `{node_id, status, latest_slot, value_hash}`
- `maybe_dead_nodes` — nodes not recently heard from
- `transitive_closure` with agreement percentages

Requires herder crate to expose transitive quorum analysis.

**Effort**: ~2 days

### A6. Fix `/tx` Semantics

**Current** (line 766):
```rust
struct SubmitTxResponse {
    success: bool,
    hash: Option<String>,
    error: Option<String>,  // human-readable
}
```

**Target**:
```rust
enum TxStatus { Pending, Duplicate, Error, TryAgainLater, Filtered }

struct SubmitTxResponse {
    status: TxStatus,
    hash: String,
    // On Error:
    error: Option<String>,               // base64-encoded XDR TransactionResult
    // On Soroban Error with diagnostics enabled:
    diagnostic_events: Option<Vec<String>>,  // base64-encoded XDR DiagnosticEvent
}
```

Mapping from `TxQueueResult` (lines 1648-1676):
- `Added` → `Pending`
- `Duplicate` → `Duplicate`
- `Invalid(code)` → `Error` + XDR result
- `TryAgainLater` → `TryAgainLater`
- `Filtered` → `Filtered`
- `QueueFull` → `TryAgainLater` (stellar-core behavior)
- `FeeTooLow` → `Error` + XDR result with `txINSUFFICIENT_FEE`
- `Banned` → `Error`

Requires `TxQueueResult::Invalid` to carry the full `TransactionResult` XDR, not
just an optional result code string.

**Effort**: ~1 day

### A7. Enrich `/sorobaninfo`

**Current** (line 834): Basic format only. `detailed` and `upgrade_xdr` return stubs.

**Target** — add missing fields for p23+ from stellar-core's `LedgerManagerImpl`:
- `max_footprint_size`
- `max_dependent_tx_clusters`
- SCP timing settings
- `average_bucket_list_size`
- `bucket_list_size_snapshot_period`
- Implement `detailed` format (full ConfigSettingEntry JSON)
- Implement `upgrade_xdr` format (base64-encoded ConfigUpgradeSet)

**Effort**: ~1 day

### A8. Enrich `/metrics`

**Current**: Basic Prometheus text with 5 metrics (ledger_seq, peer_count,
pending_transactions, uptime, is_validator, meta_stream stats).

**Target**: Expose all internal metrics as Prometheus counters/gauges:
- SCP metrics (envelope send/receive, nomination rounds, externalize time)
- Herder metrics (tx queue size, tx applied, ledger close time)
- Overlay metrics (messages by type, bytes, connection counts)
- Ledger metrics (close duration, tx set size, tx apply time)
- Bucket metrics (merge count, eviction count)

Keep Prometheus text format as the native format (best practice for monitoring).
stellar-core's medida JSON format is handled by the compat layer (Part B).

**Effort**: ~2 days (depends on what metrics each crate exposes)

### A9. Implement Query Server

See `docs/RPC_COMP_PLAN.md` Phase 3 for the full specification. Summary:

- New `crates/app/src/query_server.rs` with separate axum server on `query.port`
- `/getledgerentryraw` — raw bucket list point lookups
- `/getledgerentry` — enriched lookups with TTL resolution and Hot Archive queries
- Uses `BucketSnapshotManager` for thread-safe snapshot access
- URL-encoded form body parsing (not JSON)

Infrastructure ready:
- `SearchableBucketListSnapshot::load_keys()` and `load_keys_from_ledger()` exist
- `BucketSnapshotManager::copy_live_and_hot_archive_snapshots()` provides atomic access
- `SearchableHotArchiveBucketListSnapshot` needs `load_keys()` methods added

**Effort**: ~2 weeks

### A10. Add Missing Config Fields

New config struct and fields in `crates/app/src/config.rs`:

```rust
#[derive(Deserialize)]
struct QueryConfig {
    port: Option<u16>,              // HTTP_QUERY_PORT (default: none = disabled)
    snapshot_ledgers: u32,          // QUERY_SNAPSHOT_LEDGERS (default: 5)
    thread_pool_size: usize,        // QUERY_THREAD_POOL_SIZE (default: 4)
}

#[derive(Deserialize)]
struct DiagnosticsConfig {
    soroban_diagnostic_events: bool,     // ENABLE_SOROBAN_DIAGNOSTIC_EVENTS
    tx_submission_diagnostics: bool,     // ENABLE_DIAGNOSTICS_FOR_TX_SUBMISSION
}
```

Also add to `MetadataConfig`:
```rust
emit_soroban_tx_meta_ext_v1: bool,
emit_ledger_close_meta_ext_v1: bool,
```

**Effort**: ~0.5 day

---

## Part B: stellar-core Compatibility HTTP Server

### B1. Architecture

A separate optional axum `Router` that:
1. Listens on a configurable port (`[compat_http] port = 11626`)
2. Shares the same `Arc<App>` (same underlying state)
3. Routes to **compat handler** functions that:
   a. Call the same `App` methods as the native handlers
   b. Transform responses into stellar-core's exact JSON format
4. Wraps all handlers in a `safe_router` middleware that catches panics and returns
   `{"exception": "message"}` (matching stellar-core's `safeRouter` at
   `CommandHandler.cpp:154-167`)

```
crates/app/src/compat_http/
├── mod.rs              # Router construction, safe_router middleware
├── handlers/
│   ├── info.rs         # /info → nested {"info": {...}} format
│   ├── tx.rs           # GET /tx?blob=... → {"status": "PENDING", ...}
│   ├── peers.rs        # /peers → categorized {authenticated_peers, pending_peers}
│   ├── scp.rs          # /scp → full SCP state dump
│   ├── metrics.rs      # /metrics → medida JSON format
│   ├── survey.rs       # stellar-core URL paths (/getsurveyresult, etc.)
│   ├── quorum.rs       # /quorum → transitive quorum format
│   ├── plaintext.rs    # /connect, /droppeer, /maintenance, etc. → plain text
│   └── query.rs        # /getledgerentryraw, /getledgerentry (if on same port)
└── transforms.rs       # Response format conversion helpers
```

Config:
```toml
[compat_http]
enabled = true
port = 11626         # stellar-core default port

[http]
port = 11725         # native henyey port (different)
```

When `compat_http.enabled = false` (default), only the native server runs.

**Effort**: ~0.5 day for scaffolding

### B2. `/tx` Compat Handler — CRITICAL

stellar-rpc's Go client (`stellarcore.Client.SubmitTransaction`) sends:
```
GET /tx?blob=<base64-url-encoded-tx-envelope>
```

And expects:
```json
{
  "status": "PENDING",
  "error": "<base64 XDR TransactionResult>"
}
```

The compat handler:
1. Accepts `GET /tx?blob=...` (not POST with JSON body)
2. URL-decodes the blob, base64-decodes it, parses as `TransactionEnvelope`
3. Calls `App::submit_transaction()`
4. Maps result to stellar-core status strings
5. On `ERROR`: serializes `TransactionResult` as base64 XDR in `"error"` field
6. On Soroban error with diagnostics: includes `"diagnostic_events"` array

**Effort**: ~0.5 day

### B3. `/info` Compat Handler — CRITICAL

stellar-rpc's `Client.Info()` method parses a specific JSON structure.

The compat handler wraps the response under `"info"` key and uses stellar-core
field names:

| Native henyey field | Compat output field |
|---------------------|---------------------|
| `build` | `info.build` |
| `protocol_version` | `info.protocol_version` |
| `state` | `info.state` (stellar-core state strings) |
| `started_on` | `info.startedOn` (camelCase!) |
| `ledger.num` | `info.ledger.num` |
| `ledger.hash` | `info.ledger.hash` |
| `ledger.close_time` | `info.ledger.closeTime` (camelCase!) |
| `ledger.version` | `info.ledger.version` |
| `ledger.base_fee` | `info.ledger.baseFee` (camelCase!) |
| `ledger.base_reserve` | `info.ledger.baseReserve` (camelCase!) |
| `ledger.max_tx_set_size` | `info.ledger.maxTxSetSize` (camelCase!) |
| `ledger.age` | `info.ledger.age` |
| `peers.pending_count` | `info.peers.pending_count` |
| `peers.authenticated_count` | `info.peers.authenticated_count` |
| `network_passphrase` | `info.network` |

State string mapping (henyey → stellar-core):
- `Booting` → `"Booting"`
- `Joining` → `"Joining SCP"`
- `Connected` → `"Connected"`
- `CatchingUp` → `"Catching up"`
- `Synced` → `"Synced!"`
- `Validating` → `"Synced!"` (stellar-core uses same string for both)
- `Stopping` → `"Stopping"`

**Effort**: ~0.5 day

### B4. `/peers` Compat Handler

Transform from native henyey categorized format to stellar-core's:
```json
{
  "authenticated_peers": {
    "inbound": [{"address": "...", "elapsed": 123, "id": "...", "olver": 35, "ver": "v25.0.0"}],
    "outbound": [...]
  },
  "pending_peers": {
    "inbound": [...],
    "outbound": [...]
  }
}
```

Per-peer fields in stellar-core format: `address`, `elapsed`, `id`,
`message_read`, `message_write`, `olver` (overlay version), `ver` (app version),
`latency`.

**Effort**: ~0.5 day

### B5. `/metrics` Compat Handler

Transform Prometheus metrics to stellar-core's medida JSON format:
```json
{
  "metrics": {
    "scp.envelope.emit": {"count": 42, "sum": 0},
    "ledger.ledger.close": {"count": 100, "mean": 5.2}
  }
}
```

This is a lossy transformation — Prometheus counters/gauges map to medida
counters/timers with some fields approximated.

**Effort**: ~1 day

### B6. `/scp` Compat Handler

Transform henyey's SCP slot info to stellar-core's verbose format:
```json
{
  "scp": [
    {
      "slotIndex": 12345,
      "nomination": {"round_number": 1, "votes": [], "accepted": []},
      "ballotProtocol": {"phase": "PREPARE", "ballot": {}},
      "quorumSetHash": "abc...",
      "envelopes": []
    }
  ]
}
```

**Effort**: ~1 day (depends on A4 SCP enrichment)

### B7. Plain-Text Endpoints

stellar-core returns plain text (not JSON) for these endpoints:
- `/connect` → `"done\n"` or `"Already connected to ...\n"`
- `/droppeer` → `"done\n"` or error text
- `/unban` → `"done\n"` or error text
- `/maintenance` → `"Done\n"` or `"No work performed\n"`
- `/clearmetrics` → `"Cleared ... metrics!\n"`
- `/logrotate` → `"Log rotate...\n"`
- `/manualclose` → ledger number or error text

Compat handlers return `(StatusCode, String)` instead of JSON.

**Effort**: ~0.5 day

### B8. Survey URL Path Mapping

| stellar-core path | Henyey native path |
|-------------------|--------------------|
| `/getsurveyresult` | `/survey` |
| `/startsurveycollecting?nonce=N` | `/survey/start?nonce=N` |
| `/stopsurveycollecting` | `/survey/stop` |
| `/surveytopography?node=...&...` | `/survey/topology?node=...&...` |
| `/stopreporting` | `/survey/reporting/stop` |

Compat router registers the stellar-core paths and delegates to the same `App`
methods.

**Effort**: ~0.5 day

### B9. Error Wrapping Middleware

stellar-core wraps all handler exceptions in:
```json
{"exception": "error message"}
```

Implement as axum middleware/layer that catches handler errors and panics:
```rust
async fn safe_router<F, R>(handler: F) -> Response
where F: Future<Output = R>
{
    match catch_unwind(AssertUnwindSafe(handler)).await {
        Ok(response) => response,
        Err(panic) => Json(json!({"exception": panic_message(panic)})).into_response(),
    }
}
```

**Effort**: ~0.5 day

---

## Phasing & Dependencies

```
Phase 1: Code organization (A1)                    [1 day]
    └─> unlocks all other Part A work

Phase 2: Core enrichment (A2, A3, A6, A10)          [3 days]
    ├── A2: /info enrichment
    ├── A3: /peers enrichment
    ├── A6: /tx semantics fix
    └── A10: config fields
    └─> unlocks Part B compat handlers

Phase 3: Advanced enrichment (A4, A5, A7, A8)       [4 days]
    ├── A4: /scp enrichment
    ├── A5: /quorum enrichment
    ├── A7: /sorobaninfo enrichment
    └── A8: /metrics enrichment

Phase 4: Query server (A9)                           [2 weeks]
    └── depends on A10 for config

Phase 5: Compat layer (B1-B9)                        [4 days]
    └── depends on Phase 2 for enriched data
    ├── B1: scaffolding + middleware (B9)
    ├── B2: /tx compat (CRITICAL)
    ├── B3: /info compat (CRITICAL)
    ├── B4-B8: remaining compat handlers
    └── B7: plain-text endpoints

Phase 6: Integration testing                          [3 days]
    └── depends on all phases
```

**Critical path for stellar-rpc**: Phases 1 → 2 → 4 → 5 (B2, B3) → 6
(~3 weeks to minimal RPC compatibility, ~4 weeks for full HTTP parity)

---

## Testing Strategy

### Unit tests (per handler)
- Each native handler: test response structure and field values
- Each compat handler: test exact JSON output matches stellar-core
- `/tx`: test all `TxQueueResult` variants map correctly in both native and compat
- Query server: port tests from `stellar-core/src/main/test/QueryServerTests.cpp`

### Schema validation
- Deserialize compat server responses through Go `stellarcore.Client` JSON structs
- Automated: generate golden JSON files from stellar-core, assert compat matches

### Integration
- Run stellar-rpc → henyey (compat port) on testnet
- Verify: `/info` parsing, `/tx` submission, `/getledgerentryraw` queries,
  `/getledgerentry` with TTL resolution, preflight simulation

---

## Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Go client is sensitive to exact JSON field names/types | High | Golden-file testing against real stellar-core responses |
| camelCase vs snake_case in compat layer | High | Use `#[serde(rename)]` exhaustively, test each field |
| Hot Archive query correctness | Medium | Port stellar-core's exact 3-pass algorithm |
| Metrics format mapping is lossy | Low | Compat metrics only need enough for RPC's health checks |
| SCP/quorum enrichment requires deep crate changes | Medium | Prioritize /tx and /info compat first (RPC-critical) |
