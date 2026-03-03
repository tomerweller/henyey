# Plan: Run stellar-rpc with Henyey as a Drop-in Replacement for stellar-core

## Goal

Run stellar-rpc (Soroban RPC) with Henyey instead of stellar-core, with **no changes to stellar-rpc**. Henyey must present the same interfaces that the Go `stellarcore.Client` expects.

## Background

stellar-rpc integrates with stellar-core through 4 interfaces:

| # | Interface | Mechanism | Henyey Status |
|---|-----------|-----------|---------------|
| 1 | **Meta Pipe** | Named pipe / fd streaming `LedgerCloseMeta` XDR | Implemented |
| 2 | **HTTP Command** | `GET /tx`, `GET /info`, etc. on port 11626 | Implemented (schema mismatch) |
| 3 | **HTTP Query** | `POST /getledgerentryraw`, `POST /getledgerentry` on query port | Not implemented |
| 4 | **Preflight FFI** | CGO -> Rust `soroban-simulation` (in-process) | N/A (bypasses core) |

Interface #4 runs entirely within the stellar-rpc Go process and only needs ledger entries from interface #3. No work needed.

### Existing Infrastructure

Henyey already has strong foundations for this work:

- **Meta pipe**: `MetaStreamManager` (`crates/app/src/meta_stream.rs`) supports files, named pipes, and `fd:N` with wire-compatible XDR framing. Fatal on write errors.
- **Bucket snapshots**: `BucketSnapshotManager` (`crates/bucket/src/snapshot.rs:1142`) manages current + historical snapshots with configurable retention.
- **Point lookups**: `SearchableBucketListSnapshot::load_keys_from_ledger()` (`snapshot.rs:772`) supports historical ledger queries.
- **Hot archive**: `SearchableHotArchiveBucketListSnapshot` (`snapshot.rs:1099`) exists but lacks query methods.
- **Atomic dual-snapshot copies**: `BucketSnapshotManager::copy_live_and_hot_archive_snapshots()` (`snapshot.rs:1216`) already provides consistent live + hot archive access.
- **HTTP server**: Axum-based with all production endpoints (`crates/app/src/run_cmd.rs`).

---

## Phase 1: Config Compatibility Layer (~1 week)

### Problem

stellar-rpc generates a flat TOML config with `SCREAMING_CASE` keys at the top level:

```toml
NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"
HTTP_PORT = 11626
HTTP_QUERY_PORT = 11627
METADATA_OUTPUT_STREAM = "fd:3"
NODE_SEED = "S..."
UNSAFE_QUORUM = true
ENABLE_SOROBAN_DIAGNOSTIC_EVENTS = true
ENABLE_DIAGNOSTICS_FOR_TX_SUBMISSION = true
EMIT_SOROBAN_TRANSACTION_META_EXT_V1 = true
EMIT_LEDGER_CLOSE_META_EXT_V1 = true
DATABASE = "sqlite3:///tmp/stellar-core.db"
BUCKET_DIR_PATH = "/tmp/buckets"
```

Henyey uses nested `[section]` tables with `snake_case` keys:

```toml
[network]
passphrase = "Test SDF Network ; September 2015"

[http]
port = 11626

[metadata]
output_stream = "fd:3"
```

### Solution

Add a config compatibility layer in `crates/app/src/compat_config.rs`:

1. **Auto-detection**: If the TOML has top-level uppercase keys (e.g., `NETWORK_PASSPHRASE`), treat it as stellar-core format.
2. **Translation**: Map each stellar-core key to its Henyey `AppConfig` equivalent.
3. **New config fields**: Add fields that don't exist yet in Henyey's config.

### Key Mappings

| stellar-core Key | Henyey Equivalent | Status |
|-------------------|-------------------|--------|
| `METADATA_OUTPUT_STREAM` | `metadata.output_stream` | Exists |
| `HTTP_PORT` | `http.port` | Exists |
| `HTTP_QUERY_PORT` | `query.port` | **New** |
| `QUERY_SNAPSHOT_LEDGERS` | `query.snapshot_ledgers` | **New** |
| `QUERY_THREAD_POOL_SIZE` | `query.thread_pool_size` | **New** |
| `NODE_SEED` | `node.node_seed` | Exists |
| `NODE_IS_VALIDATOR` | `node.is_validator` | Exists |
| `NETWORK_PASSPHRASE` | `network.passphrase` | Exists |
| `PEER_PORT` | `overlay.peer_port` | Exists |
| `KNOWN_PEERS` | `overlay.known_peers` | Exists |
| `PREFERRED_PEERS` | `overlay.preferred_peers` | Exists |
| `DATABASE` | `database.path` | Exists (format differs: `sqlite3://path` vs raw path) |
| `BUCKET_DIR_PATH` | `buckets.directory` | Exists |
| `CATCHUP_COMPLETE` | `catchup.complete` | Exists |
| `CATCHUP_RECENT` | `catchup.recent` | Exists |
| `BUCKETLIST_DB_INDEX_*` | `buckets.bucket_list_db.*` | Exists |
| `ENABLE_SOROBAN_DIAGNOSTIC_EVENTS` | `diagnostics.soroban_diagnostic_events` | **New** (wire to existing `DiagnosticConfig`) |
| `ENABLE_DIAGNOSTICS_FOR_TX_SUBMISSION` | `diagnostics.tx_submission_diagnostics` | **New** |
| `EMIT_SOROBAN_TRANSACTION_META_EXT_V1` | `metadata.emit_soroban_tx_meta_ext_v1` | **New** |
| `EMIT_LEDGER_CLOSE_META_EXT_V1` | `metadata.emit_ledger_close_meta_ext_v1` | **New** |
| `UNSAFE_QUORUM` | `node.unsafe_quorum` | **New** |
| `RUN_STANDALONE` | `node.run_standalone` | **New** |
| `[HISTORY.name] get="..."` | `[[history.archives]]` | Exists (syntax differs) |

### Files to Modify

- `crates/app/src/config.rs` — Add `QueryConfig`, `DiagnosticsConfig` structs; add new fields to `MetadataConfig`
- `crates/app/src/compat_config.rs` — **New**: stellar-core TOML parser/translator
- `crates/app/src/lib.rs` — Wire new module

---

## Phase 2: HTTP Response Schema Alignment (~1 week)

### Problem: `/tx` Endpoint

| Aspect | Henyey (current) | stellar-core (expected) |
|--------|-------------------|-------------------------|
| **HTTP method** | `POST` with JSON body `{"tx": "..."}` | `GET` with query param `?blob=...` |
| **Success field** | `"success": true` | `"status": "PENDING"` |
| **Status values** | boolean | `"PENDING"`, `"DUPLICATE"`, `"ERROR"`, `"TRY_AGAIN_LATER"`, `"FILTERED"` |
| **Error format** | Human-readable string | Base64-encoded XDR `TransactionResult` |
| **Diagnostic events** | Not returned | `"diagnostic_events"` (base64 XDR, Soroban) |

### Solution: `/tx`

- Accept `GET /tx?blob=<base64>` (stellar-core format) in addition to `POST /tx` with JSON body
- Change response to: `{"status": "PENDING"|"DUPLICATE"|"ERROR"|"TRY_AGAIN_LATER"|"FILTERED"}`
- On `ERROR`: include `"error"` as base64-encoded XDR `TransactionResult`
- On Soroban `ERROR` with diagnostics enabled: include `"diagnostic_events"` as base64-encoded XDR
- Map internal `TxQueueResult` variants:
  - `Added` → `"PENDING"`
  - `Duplicate` → `"DUPLICATE"`
  - `Invalid(code)` → `"ERROR"` + XDR result
  - `TryAgainLater` → `"TRY_AGAIN_LATER"`
  - `Filtered` → `"FILTERED"`
  - `QueueFull` / `FeeTooLow` → map to closest stellar-core equivalent

### Problem: `/info` Endpoint

| Aspect | Henyey (current) | stellar-core (expected) |
|--------|-------------------|-------------------------|
| **Wrapper** | Flat JSON | Nested under `"info"` key |
| **Version** | `"version"` | `"build"` |
| **Protocol** | Missing | `"protocol_version"` |
| **Ledger data** | Missing | `"ledger"` object: `num`, `hash`, `closeTime`, `version`, `baseFee`, `baseReserve`, `maxTxSetSize`, `maxSorobanTxSetSize`, `flags`, `age` |
| **Peer data** | Missing | `"peers"`: `pending_count`, `authenticated_count` |
| **Network** | `"network_passphrase"` | `"network"` |
| **State strings** | Henyey-style | stellar-core style (e.g., `"Synced!"`) |

### Solution: `/info`

Restructure `/info` response to match stellar-core exactly:

```json
{
  "info": {
    "build": "henyey-v0.1.0",
    "protocol_version": 25,
    "state": "Synced!",
    "startedOn": "2026-01-01T00:00:00Z",
    "ledger": {
      "num": 123456,
      "hash": "abc...",
      "closeTime": 1700000000,
      "version": 25,
      "baseFee": 100,
      "baseReserve": 5000000,
      "maxTxSetSize": 1000,
      "maxSorobanTxSetSize": 100,
      "flags": 0,
      "age": 5
    },
    "peers": {
      "pending_count": 3,
      "authenticated_count": 10
    },
    "network": "Test SDF Network ; September 2015"
  }
}
```

### Files to Modify

- `crates/app/src/run_cmd.rs` — Response structs and handlers for `/tx` and `/info`
- May need changes in `crates/herder/` to expose XDR `TransactionResult` from `TxQueueResult`

---

## Phase 3: HTTP Query Server (~2-3 weeks)

### Overview

The query server is the largest new feature. It runs on a separate port (`HTTP_QUERY_PORT`) and serves ledger entry lookups from the bucket list.

### `/getledgerentryraw` Endpoint

**Request**: `POST /getledgerentryraw`
- Body: URL-encoded `key=<base64 XDR LedgerKey>&key=...&ledgerSeq=<uint32>` (ledgerSeq optional)

**Response** (200):
```json
{
  "ledgerSeq": 123456,
  "entries": [
    {"entry": "<base64 XDR LedgerEntry>"},
    {"entry": "<base64 XDR LedgerEntry>"}
  ]
}
```

**Behavior**:
- If `ledgerSeq` specified: use `SearchableBucketListSnapshot::load_keys_from_ledger()`; return 404 `"Ledger not found\n"` if unavailable
- If `ledgerSeq` not specified: use `load_keys()` on current snapshot; set `ledgerSeq` from snapshot
- Only include entries that exist (missing keys silently omitted)
- "Raw" interface: no TTL reasoning, no Hot Archive queries

### `/getledgerentry` Endpoint

**Request**: `POST /getledgerentry`
- Body: URL-encoded `key=<base64 XDR LedgerKey>&key=...&ledgerSeq=<uint32>` (ledgerSeq optional)
- Reject TTL keys with error: `"TTL keys are not allowed\n"`
- Reject duplicate keys with error: `"Duplicate keys\n"`

**Response** (200):
```json
{
  "ledgerSeq": 123456,
  "entries": [
    {"entry": "<base64 XDR>", "state": "live"},
    {"entry": "<base64 XDR>", "state": "live", "liveUntilLedgerSeq": 500000},
    {"state": "not-found"},
    {"entry": "<base64 XDR>", "state": "archived", "liveUntilLedgerSeq": 0}
  ]
}
```

**3-pass algorithm** (mirrors `stellar-core/src/main/QueryServer.cpp:219-429`):

1. **Pass 1 — Live BucketList**: Load all keys from live snapshot via `load_keys_from_ledger()`
2. **Pass 2 — Hot Archive**: For Soroban keys not found in live, query Hot Archive snapshot
3. **Pass 3 — TTL resolution**: For live Soroban entries, construct TTL keys and load them

**State classification**:
- Classic entries found in live → `"live"` (no `liveUntilLedgerSeq`)
- Soroban entries found in live with valid TTL → `"live"` + `liveUntilLedgerSeq`
- Soroban entries found in live but expired persistent → `"archived"` + `liveUntilLedgerSeq: 0`
- Soroban entries found in live but expired temporary → `"not-found"`
- Entries found in Hot Archive → `"archived"` + `liveUntilLedgerSeq: 0`
- Not found anywhere → `"not-found"`

**Response order must match request order.**

### Infrastructure Needed

**Bucket crate changes** (`crates/bucket/src/snapshot.rs`):
- Add `load_keys()` and `load_keys_from_ledger()` to `SearchableHotArchiveBucketListSnapshot`
- Wire `QUERY_SNAPSHOT_LEDGERS` config to `BucketSnapshotManager`'s `num_historical_snapshots`

**New query server** (`crates/app/src/query_server.rs`):
- Separate axum HTTP server listening on `HTTP_QUERY_PORT`
- Each handler gets its own `SearchableBucketListSnapshot` copy (thread-local pattern)
- `BucketSnapshotManager::maybe_update_live_snapshot()` to refresh stale snapshots
- URL-encoded form body parsing (not JSON)

**TTL helpers**:
- Port `getTTLKey()` and `isLive()` functions (may already exist in tx crate)
- Port `isSorobanEntry()` classification (check if Soroban data/code/instance)

### Files to Create/Modify

- `crates/app/src/query_server.rs` — **New**: Query server with both endpoints
- `crates/bucket/src/snapshot.rs` — Add query methods to `SearchableHotArchiveBucketListSnapshot`
- `crates/app/src/config.rs` — `QueryConfig` struct (from Phase 1)
- `crates/app/src/run_cmd.rs` — Start query server alongside status server

---

## Phase 4: CLI Compatibility (~2-3 days)

### Problem

stellar-rpc spawns stellar-core with invocations like:

```bash
stellar-core run --conf /tmp/captive-core.toml --metadata-output-stream fd:3
stellar-core catchup 12345/100 --conf /tmp/captive-core.toml --metadata-output-stream fd:3
```

### Solution

- Add `--conf` as alias for `--config` (stellar-core uses `--conf`)
- Add `--wait-for-consensus` flag to `run` (RPC uses this to know when the node is ready to stream)
- Add `--start-at-ledger` and `--start-at-hash` flags to `run` (for bounded replay)
- Verify `catchup LEDGER/COUNT` positional parsing matches stellar-core format
- Ensure SIGTERM/SIGINT handling matches (clean exit, pipe flush)

### Files to Modify

- `crates/henyey/src/main.rs` — CLI argument definitions

---

## Phase 5: Diagnostic Events & Meta Extensions (~1 week)

### Problem

stellar-rpc enables several flags that control what's included in the metadata stream:

- `ENABLE_SOROBAN_DIAGNOSTIC_EVENTS` — Include Soroban diagnostic events in meta
- `ENABLE_DIAGNOSTICS_FOR_TX_SUBMISSION` — Include diagnostic events in `/tx` error responses
- `EMIT_SOROBAN_TRANSACTION_META_EXT_V1` — Extended Soroban transaction meta
- `EMIT_LEDGER_CLOSE_META_EXT_V1` — Extended ledger close meta

### Solution

- Wire `ENABLE_SOROBAN_DIAGNOSTIC_EVENTS` to existing `DiagnosticConfig` in `crates/tx`
- Wire `ENABLE_DIAGNOSTICS_FOR_TX_SUBMISSION` to `/tx` handler
- Implement `EMIT_SOROBAN_TRANSACTION_META_EXT_V1` flag to include `SorobanTransactionMetaExtV1` in `TransactionMeta`
- Implement `EMIT_LEDGER_CLOSE_META_EXT_V1` flag to include `LedgerCloseMetaExtV1` in `LedgerCloseMeta`

### Files to Modify

- `crates/app/src/config.rs` — Wire diagnostic config to AppConfig
- `crates/tx/src/` — Ensure diagnostic events are captured when enabled
- `crates/ledger/src/manager.rs` — Conditional meta extension inclusion
- `crates/app/src/run_cmd.rs` — Wire diagnostic events to `/tx` response

---

## Phase 6: Integration Testing (~1 week)

### Strategy

1. **Unit tests**: Each new endpoint gets unit tests matching stellar-core's `QueryServerTests.cpp`
2. **Schema validation**: Parse test responses through the Go `stellarcore.Client` JSON structures
3. **End-to-end**: Run stellar-rpc pointed at Henyey on testnet:
   - Configure stellar-rpc to use the henyey binary instead of stellar-core
   - Verify ledger ingestion via meta pipe
   - Verify `/tx` submission and response parsing
   - Verify `/getledgerentryraw` and `/getledgerentry` queries
   - Verify preflight simulation (which calls back to query server)
4. **Captive mode lifecycle**: Test subprocess spawn, config generation, pipe streaming, graceful shutdown

---

## Timeline

| Phase | Description | Effort | Dependencies |
|-------|-------------|--------|--------------|
| 1 | Config compatibility layer | ~1 week | None |
| 2 | HTTP response schema alignment | ~1 week | None |
| 3 | HTTP query server | ~2-3 weeks | Phase 1 (for config) |
| 4 | CLI compatibility | ~2-3 days | None |
| 5 | Diagnostic events & meta extensions | ~1 week | Phase 1 (for config) |
| 6 | Integration testing | ~1 week | All phases |
| **Total** | | **~5-7 weeks** | |

Phases 1, 2, and 4 can run in parallel. Phase 3 depends on Phase 1 for config. Phase 5 depends on Phase 1 for config. Phase 6 depends on all others.

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Go client JSON parsing sensitivity | High | Test each response against actual Go `stellarcore.Client` deserialization |
| Hot archive query correctness | Medium | Port stellar-core's exact 3-pass algorithm and state classification logic |
| Process lifecycle edge cases | Medium | Test pipe buffering, shutdown timing, and error reporting against RPC's captive core manager |
| Snapshot memory pressure | Low | `QUERY_SNAPSHOT_LEDGERS` defaults to 5; monitor memory under load |

## What's Not Needed

- No changes to stellar-rpc
- No preflight/simulation work (runs in-process within RPC)
- No validator mode changes (RPC runs core in non-validator mode)
- No history archive publish changes
