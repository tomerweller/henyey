# Plan: Run stellar-rpc with Henyey as a Drop-in Replacement for stellar-core

## Goal

Run stellar-rpc (Soroban RPC) with Henyey instead of stellar-core, with **no changes to stellar-rpc**. Henyey must present the same interfaces that the Go `stellarcore.Client` expects.

## Status Summary

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Config compatibility layer | **Done** |
| 2 | HTTP response schema alignment | **Done** |
| 3 | HTTP query server | **Done** |
| 4 | CLI compatibility | **Done** |
| 5 | Diagnostic events & meta extensions | **Done** |
| 6 | Integration testing | Pending |

## Background

stellar-rpc integrates with stellar-core through 4 interfaces:

| # | Interface | Mechanism | Henyey Status |
|---|-----------|-----------|---------------|
| 1 | **Meta Pipe** | `fd:N` streaming `LedgerCloseMeta` XDR | **Done** — `MetaStreamManager` supports `fd:N`, file, and named pipe with wire-compatible framing. Works for both `run` and `catchup`. |
| 2 | **HTTP Command** | `GET /info`, `GET /tx?blob=...` on port 11626 | **Done** — Compat HTTP server matches stellar-core wire format exactly. |
| 3 | **HTTP Query** | `POST /getledgerentryraw`, `POST /getledgerentry` on query port | **Done** — Full 3-pass algorithm with `BucketSnapshotManager`, form-encoded parsing. |
| 4 | **Preflight FFI** | CGO → Rust `soroban-simulation` (in-process) | N/A (bypasses core entirely) |

### stellar-rpc's HTTP Usage (3 endpoints only)

| Endpoint | Port | Method | Used For |
|----------|------|--------|----------|
| `/info` | 11626 | GET | `WaitForNetworkSync()` — polls until `state == "Synced!"` |
| `/tx?blob=<b64>` | 11626 | GET | Transaction submission |
| `/getledgerentry` | query port | POST (form) | Ledger entry queries for preflight |

### stellar-rpc CLI Invocation Sequence

```bash
# Construction-time (always):
stellar-core version                                                     # protocol version check (x2)

# Online mode (live streaming):
stellar-core --conf <conf> --console offline-info                        # check existing DB
stellar-core --conf <conf> --console new-db                              # conditional: if no valid DB
stellar-core --conf <conf> --console catchup <from-1>/0                  # conditional: minimal catchup
stellar-core --conf <conf> --console run --metadata-output-stream fd:3   # always: long-running

# Offline mode (bounded replay):
stellar-core --conf <conf> --console new-db                              # always
stellar-core --conf <conf> --console catchup <to>/<count> --metadata-output-stream fd:3
```

---

## Phase 1: Config Compatibility Layer — DONE

**Files:**
- `crates/app/src/compat_config.rs` — Auto-detect stellar-core format + translate to `AppConfig`
- `crates/app/src/config.rs` — `QueryConfig`, `DiagnosticsConfig`, `MetadataConfig` extensions, `CompatHttpConfig`

**Key mappings implemented:**

| stellar-core Key | Henyey Equivalent | Status |
|-------------------|-------------------|--------|
| `NETWORK_PASSPHRASE` | `network.passphrase` | Done |
| `HTTP_PORT` | `compat_http.port` | Done (native HTTP disabled when compat enabled) |
| `HTTP_QUERY_PORT` | `query.port` | Done |
| `METADATA_OUTPUT_STREAM` | `metadata.output_stream` | Done |
| `NODE_SEED` | `node.node_seed` | Done |
| `DATABASE` | `database.path` (strips `sqlite3://`) | Done |
| `BUCKET_DIR_PATH` | `buckets.directory` | Done |
| `ENABLE_SOROBAN_DIAGNOSTIC_EVENTS` | `diagnostics.soroban_diagnostic_events` | Done (config parsed, wired to meta builder) |
| `ENABLE_DIAGNOSTICS_FOR_TX_SUBMISSION` | `diagnostics.tx_submission_diagnostics` | Done (config parsed) |
| `EMIT_SOROBAN_TRANSACTION_META_EXT_V1` | `metadata.emit_soroban_tx_meta_ext_v1` | Done (config parsed, wired to tx meta) |
| `EMIT_LEDGER_CLOSE_META_EXT_V1` | `metadata.emit_ledger_close_meta_ext_v1` | Done (config parsed, wired to ledger meta) |
| `[HISTORY.name]` | `[[history.archives]]` | Done |
| `[[VALIDATORS]]` | `node.quorum_set.validators` + inline history | Done |

8 unit tests covering format detection, translation, and edge cases.

---

## Phase 2: HTTP Response Schema Alignment — DONE

**Compat HTTP server** (`crates/app/src/compat_http/`):
- `GET /info` — stellar-core wire format with `"info"` wrapper, `"build"`, `"state": "Synced!"`, ledger object, peer counts
- `GET /tx?blob=<b64>` — Returns `"status": "PENDING"|"DUPLICATE"|"ERROR"|...` with base64 XDR `TransactionResult` on error
- `GET /peers` — stellar-core peer format
- `GET /metrics` — Prometheus format
- Plaintext admin endpoints

**Native HTTP server** (`crates/app/src/http/`):
- Enriched `/info` with `LedgerSummary`, `App::ledger_summary()`, `App::peer_counts()`
- Fixed `/tx` semantics with proper `TxStatus` enum
- Full module tree: `types/`, `handlers/`, `helpers.rs`

---

## Phase 3: HTTP Query Server — DONE

**Files:**
- `crates/app/src/http/handlers/query.rs` — Both endpoints with 3-pass algorithm
- `crates/app/src/http/types/query.rs` — Request/response types
- `crates/bucket/src/snapshot.rs` — `SearchableHotArchiveBucketListSnapshot` query methods

**Endpoints:**
- `POST /getledgerentryraw` — Raw ledger entry lookup from live bucket list
- `POST /getledgerentry` — Full 3-pass algorithm: live → hot archive → TTL resolution

State classification: `live`, `archived`, `not-found` with `liveUntilLedgerSeq` for Soroban entries.

---

## Phase 4: CLI Compatibility — DONE

**File:** `crates/henyey/src/main.rs`

- `--conf` alias for `--config`
- `--console` flag (accepted, no-op)
- `version` subcommand (stellar-core compatible output, runs before logging init)
- `offline-info` subcommand (opens DB read-only, emits JSON)
- `new-db` + `catchup <N>/0` behavior verified
- Meta streaming during catchup (`MetaCallback` in `CatchupManager`)
- Deprecated flags: `--in-memory`, `--start-at-ledger`, `--wait-for-consensus`, `--ll`, `--metric`

---

## Phase 5: Diagnostic Events & Meta Extensions — DONE

### Config flags and their wiring:

| Flag | Config Field | Wiring |
|------|-------------|--------|
| `EMIT_LEDGER_CLOSE_META_EXT_V1` | `metadata.emit_ledger_close_meta_ext_v1` | Wired through `LedgerManagerConfig` → `build_ledger_close_meta()`. When true, emits `LedgerCloseMetaExtV1 { soroban_fee_write_1kb }`. |
| `EMIT_SOROBAN_TRANSACTION_META_EXT_V1` | `metadata.emit_soroban_tx_meta_ext_v1` | Wired through `LedgerManagerConfig` → `build_transaction_meta()`. When true and Soroban fee info is present, emits `SorobanTransactionMetaExtV1`. When false, emits `SorobanTransactionMetaExt::V0`. |
| `ENABLE_SOROBAN_DIAGNOSTIC_EVENTS` | `diagnostics.soroban_diagnostic_events` | Wired through `LedgerManagerConfig` → `build_transaction_meta()`. When true, includes diagnostic events in `TransactionMetaV4.diagnostic_events`. When false, emits empty vec. Soroban host always captures diagnostics (hardcoded `enable_diagnostics: true`); this flag controls whether they appear in the meta stream. |
| `ENABLE_DIAGNOSTICS_FOR_TX_SUBMISSION` | `diagnostics.tx_submission_diagnostics` | Config parsed and stored. Not yet wired to `/tx` handler (low priority — stellar-rpc doesn't use diagnostic events from `/tx` responses). |

### Shutdown behavior:
- `run` command has SIGTERM/SIGINT handling → clean exit 0
- Meta stream uses per-write flush (no buffered data between frames)
- `shutdown_internal()` explicitly flushes and drops the meta stream before returning

---

## Phase 6: Integration Testing — PENDING

### Strategy

1. **Unit tests**: Each endpoint has unit tests matching stellar-core's behavior
2. **Schema validation**: Parse test responses through the Go `stellarcore.Client` JSON structures
3. **End-to-end**: Run stellar-rpc pointed at Henyey on testnet:
   - Configure stellar-rpc to use the henyey binary instead of stellar-core
   - Verify ledger ingestion via meta pipe
   - Verify `/tx` submission and response parsing
   - Verify `/getledgerentryraw` and `/getledgerentry` queries
   - Verify preflight simulation (which calls back to query server)
4. **Captive mode lifecycle**: Test subprocess spawn, config generation, pipe streaming, graceful shutdown

---

## Architecture Notes

### Three HTTP Servers

Henyey can run up to three independent HTTP servers:

1. **Native status server** (`StatusServer`) — Rust-idiomatic API on configurable port (default 11626)
2. **Compat server** (`CompatServer`) — stellar-core wire format on `HTTP_PORT` (11626)
3. **Query server** (`QueryServer`) — Ledger entry queries on `HTTP_QUERY_PORT` (11627)

When stellar-core format config is detected, the native status server is **automatically disabled** (sets `http.enabled = false`) to avoid port conflict, since both would default to port 11626. Port collision validation in `AppConfig::validate()` catches misconfiguration.

### Meta Stream Lifecycle

- `MetaStreamManager` opened at `App::new()` based on `metadata.output_stream`
- Each `LedgerCloseMeta` written as length-prefixed XDR frame with immediate flush
- Main stream write failure → `std::process::abort()` (fatal, matches stellar-core)
- On shutdown: explicit flush + drop in `shutdown_internal()`

### Config Auto-Detection

`compat_config.rs` checks for known uppercase keys (`NETWORK_PASSPHRASE`, `HTTP_PORT`, etc.) to detect stellar-core format. When detected, translates to `AppConfig` with compat HTTP auto-enabled.

## What's Not Needed

- No changes to stellar-rpc
- No preflight/simulation work (runs in-process within RPC)
- No validator mode changes (RPC runs core in non-validator mode)
- No history archive publish changes
- Phase 3 advanced enrichment (A4/A5/A7/A8 from HTTP_PARITY_PLAN): `/scp`, `/quorum`, `/sorobaninfo`, `/metrics` — not used by stellar-rpc
