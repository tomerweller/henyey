# stellar-rpc Parity Status

**Crate**: `henyey-rpc`
**Upstream**: `stellar/stellar-rpc` (Go, GitHub)
**Overall Parity**: 85%
**Last Updated**: 2026-03-13

## Summary

| Area | Status | Notes |
|------|--------|-------|
| JSON-RPC 2.0 envelope | Full | Request/response parsing, error codes |
| Method dispatch | Full | All 12 methods registered |
| getHealth | Partial | No latency check; `oldestLedger` from DB |
| getNetwork | Full | Passphrase, friendbot URL, protocol version |
| getLatestLedger | Full | All fields: `id`, `sequence`, `protocolVersion`, `closeTime`, `headerXdr`, `metadataXdr` |
| getVersionInfo | Partial | `commitHash`, `buildTimestamp`, `captiveCoreVersion` empty |
| getFeeStats | Full | Sliding window, nearest-rank percentiles, classic + soroban fees |
| getLedgerEntries | Partial | Core lookup + TTL works; `xdrFormat` support; no key limit |
| getTransaction | Full | Full lookup, `xdrFormat` support, all fields |
| getTransactions | Partial | Range query, TOID cursor, `xdrFormat` support; missing status filter |
| getLedgers | Full | Range query, cursor pagination, `xdrFormat` support |
| getEvents | Partial | Core query works; `xdrFormat` support; missing filter limits, `**` wildcard |
| sendTransaction | Partial | Submission works; `xdrFormat` support; generic error XDR |
| simulateTransaction | Partial | InvokeHostFunction + ExtendTTL + Restore; `xdrFormat` support; no authMode/stateChanges |
| Infrastructure | Partial | `xdrFormat` JSON output implemented; no body size limit, no batch rejection |

## File Mapping

| stellar-rpc File | Rust Module | Notes |
|-------------------|-------------|-------|
| `cmd/soroban-rpc/internal/methods/health.go` | `methods/health.rs` | |
| `cmd/soroban-rpc/internal/methods/get_network.go` | `methods/network.rs` | |
| `cmd/soroban-rpc/internal/methods/get_latest_ledger.go` | `methods/latest_ledger.rs` | |
| `cmd/soroban-rpc/internal/methods/get_version_info.go` | `methods/version_info.rs` | |
| `cmd/soroban-rpc/internal/methods/get_fee_stats.go` | `methods/fee_stats.rs` | Full sliding window |
| `cmd/soroban-rpc/internal/methods/get_ledger_entries.go` | `methods/get_ledger_entries.rs` | |
| `cmd/soroban-rpc/internal/methods/get_transaction.go` | `methods/get_transaction.rs` | |
| `cmd/soroban-rpc/internal/methods/get_transactions.go` | `methods/get_transactions.rs` | |
| `cmd/soroban-rpc/internal/methods/get_ledgers.go` | `methods/get_ledgers.rs` | |
| `cmd/soroban-rpc/internal/methods/get_events.go` | `methods/get_events.rs` | |
| `cmd/soroban-rpc/internal/methods/send_transaction.go` | `methods/send_transaction.rs` | |
| `cmd/soroban-rpc/internal/methods/simulate_transaction.go` | `methods/simulate_transaction.rs` | Delegates to `simulate/` |
| `cmd/soroban-rpc/internal/preflight/` | `simulate/mod.rs`, `simulate/snapshot.rs` | Soroban host invocation |
| `cmd/soroban-rpc/internal/feewindow/` | `fee_window.rs` | Ring buffer, percentile distribution |
| `cmd/soroban-rpc/internal/ingest/` | — | Handled by henyey-app/henyey-db |

## Component Mapping

### JSON-RPC Envelope (`server.rs`, `types/jsonrpc.rs`, `error.rs`, `dispatch.rs`)

Corresponds to: `cmd/soroban-rpc/internal/jsonrpc.go`, `cmd/soroban-rpc/internal/methods/`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| JSON-RPC 2.0 request parsing | `JsonRpcRequest` | Full |
| JSON-RPC 2.0 response envelope | `JsonRpcResponse` | Full |
| Error codes (-32600, -32601, -32602, -32603) | `JsonRpcError` | Full |
| Method dispatch by name | `dispatch()` | Full |
| HTTP body size limit (512KB) | — | None |
| Batch request rejection | — | None |
| xdrFormat parameter support | `util::parse_format()`, `XdrFormat` enum | Full |

### getHealth (`methods/health.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/health.go`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| Return "healthy" status | `handle()` | Full |
| `latestLedger` field | `handle()` | Full |
| `oldestLedger` from DB retention | `util::oldest_ledger()` | Full |
| `ledgerRetentionWindow` | `DEFAULT_LEDGER_RETENTION_WINDOW` | Full |
| Ledger age check (`maxHealthyLedgerLatency`) | — | None |

### getNetwork (`methods/network.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/get_network.go`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| `passphrase` | `handle()` | Full |
| `friendbotUrl` | `handle()` | Full |
| `protocolVersion` | `handle()` | Full |

### getLatestLedger (`methods/latest_ledger.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/get_latest_ledger.go`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| `id` (ledger hash) | `handle()` | Full |
| `sequence` | `handle()` | Full |
| `protocolVersion` | `handle()` | Full |
| `closeTime` | `handle()` | Full |
| `headerXdr` | `handle()` | Full |
| `metadataXdr` | `handle()` | Full |

### getVersionInfo (`methods/version_info.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/get_version_info.go`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| `version` | `handle()` | Full |
| `protocolVersion` | `handle()` | Full |
| `commitHash` | Empty string | None |
| `buildTimestamp` | Empty string | None |
| `captiveCoreVersion` | Empty string | None |

### getFeeStats (`methods/fee_stats.rs`, `fee_window.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/get_fee_stats.go`, `cmd/soroban-rpc/internal/feewindow/`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| `FeeWindow` sliding window tracking | `FeeWindow`, `LedgerBucketWindow` | Full |
| Nearest-rank percentile computation | `compute_fee_distribution()` | Full |
| `sorobanInclusionFee` distribution | `FeeWindows::soroban_stats()` | Full |
| `inclusionFee` distribution | `FeeWindows::classic_stats()` | Full |
| Background ingestion from DB | `fee_window_poller` task | Full |
| `latestLedger` | `handle()` | Full |

### getLedgerEntries (`methods/get_ledger_entries.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/get_ledger_entries.go`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| Base64 XDR key decoding | `handle()` | Full |
| Bucket list snapshot lookup | `handle()` | Full |
| TTL lookup for contract data/code | `ttl_key_for_entry()` | Full |
| `liveUntilLedgerSeq` in response | `handle()` | Full |
| `lastModifiedLedgerSeq` | `handle()` | Full |
| `extXdr` field | `handle()` | Full |
| Max 200 keys limit | — | None |
| `xdrFormat` JSON output | `handle()` | Full |

### getTransaction (`methods/get_transaction.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/get_transaction.go`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| Hash-based lookup from DB | `handle()` | Full |
| `envelopeXdr` | `handle()` | Full |
| `resultXdr` (extracted from pair) | `extract_result_xdr()` | Full |
| `resultMetaXdr` | `handle()` | Full |
| Status determination (SUCCESS/FAILED) | `determine_tx_status()` | Full |
| NOT_FOUND response | `handle()` | Full |
| `ledger`, `applicationOrder`, `createdAt` | `handle()` | Full |
| `oldestLedger` from DB | `util::oldest_ledger()` | Full |
| `feeBump` field | `handle()` | Full |
| `diagnosticEventsXdr` | `util::extract_diagnostic_events()` | Full |
| `xdrFormat` JSON output | `handle()` | Full |

### getTransactions (`methods/get_transactions.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/get_transactions.go`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| Range query by startLedger | `handle()` | Full |
| TOID-based cursor pagination | `util::validate_pagination()` | Full |
| Transaction envelope/result/meta per entry | `handle()` | Full |
| `feeBump` detection | `is_fee_bump_envelope()` | Full |
| `diagnosticEventsXdr` | `util::extract_diagnostic_events()` | Full |
| `txHash`, `ledger`, `createdAt`, `applicationOrder` | `handle()` | Full |
| `latestLedger`, `oldestLedger`, close times | `handle()` | Full |
| Filter by status | — | None |
| `xdrFormat` support | `handle()` | Full |

### getLedgers (`methods/get_ledgers.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/get_ledgers.go`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| Range query by startLedger | `handle()` | Full |
| Cursor-based pagination (ledger seq) | `validate_ledger_pagination()` | Full |
| Ledger hash, sequence, close time | `handle()` | Full |
| `headerXdr` (LedgerHeaderHistoryEntry) | `handle()` | Full |
| `metadataXdr` (full LedgerCloseMeta) | `handle()` | Full |
| `latestLedger`, `oldestLedger`, close times | `handle()` | Full |
| `xdrFormat` support | `handle()` | Full |

### getEvents (`methods/get_events.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/get_events.go`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| `startLedger` parameter | `handle()` | Full |
| `endLedger` parameter | `handle()` | Full |
| Event type filter (contract/system) | `parse_event_filters()` | Full |
| `contractIds` filter | `parse_event_filters()` | Full |
| Topic filters with OR alternatives | `parse_event_filters()` | Full |
| Pagination with cursor and limit | `handle()` | Full |
| DB query for events | `handle()` | Full |
| Ledger close time lookup | `get_ledger_close_time()` | Full |
| Event value XDR extraction | `extract_event_value()` | Full |
| Max 5 filters enforcement | — | None |
| Max 5 contractIDs per filter | — | None |
| Max 5 topics, 4 segments per topic | — | None |
| `**` wildcard support | — | None |
| `diagnostic` type rejected (Go only allows contract/system) | Accepted (divergence) | Partial |
| `oldestLedger` from DB | `util::oldest_ledger()` | Full |
| `xdrFormat` JSON output | `handle()` | Full |

### sendTransaction (`methods/send_transaction.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/send_transaction.go`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| Base64 envelope decoding | `handle()` | Full |
| Transaction hash computation | `handle()` | Full |
| Herder submission | `handle()` | Full |
| PENDING/DUPLICATE/TRY_AGAIN_LATER/ERROR status | `handle()` | Full |
| `errorResultXdr` with actual error code | Generic `TxFailed` always | Partial |
| `diagnosticEventsXdr` | Empty array for Invalid | Partial |
| `xdrFormat` JSON output | `handle()` | Full |

### simulateTransaction (`simulate/mod.rs`, `simulate/snapshot.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/simulate_transaction.go`, `cmd/soroban-rpc/internal/preflight/`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| InvokeHostFunction simulation | `handle_invoke()` | Full |
| Recording mode invocation | `run_invoke_simulation()` | Full |
| BucketList snapshot source | `BucketListSnapshotSource` | Full |
| TTL-aware entry lookup | `get_entry_ttl()` | Full |
| Resource adjustment (1.04x + 50k) | `adjust_resources()` | Full |
| Refundable fee adjustment (1.15x) | `compute_invoke_resource_fee()` | Full |
| SorobanTransactionData construction | `build_invoke_response()` | Full |
| Auth entries in response | `build_invoke_response()` | Full |
| Return value XDR | `build_invoke_response()` | Full |
| Error response with cost | `build_error_response()` | Full |
| ExtendFootprintTtl simulation | `simulate_extend_ttl_op()` | Full |
| RestoreFootprint simulation | `simulate_restore_op()` | Full |
| Rent fee computation | `compute_resource_fee_with_rent()` | Full |
| `xdrFormat` support | `handle()` | Full |
| `authMode` parameter | — | None |
| `stateChanges` in response | — | None |
| `resourceConfig` parameter | — | None |
| Memo validation | — | None |

## Intentional Omissions

| stellar-rpc Component | Reason |
|------------------------|--------|
| Ingestion pipeline (`internal/ingest/`) | Handled by `henyey-app` and `henyey-db`; not part of the RPC crate |
| Database layer (`internal/db/`) | Handled by `henyey-db` |
| Captive core management | henyey is a full node, not a captive-core wrapper |
| Prometheus metrics endpoint | Out of scope for initial implementation |
| CORS / HTTP middleware | Not required for node-internal RPC |

## Gaps

| stellar-rpc Component | Priority | Notes |
|------------------------|----------|-------|
| `getTransactions` status filter | Low | Missing status-based filtering |
| `getHealth` latency check | Low | Always returns "healthy" regardless of ledger age |
| `getVersionInfo` build metadata | Low | Empty strings for commit/build/captiveCore |
| `getEvents` filter limits | Low | No enforcement of max filters/contractIDs/topics |
| `getEvents` `**` wildcard | Low | Topic wildcard not supported |
| `sendTransaction` actual error codes | Low | Always returns generic TxFailed |
| `simulateTransaction` authMode | Low | No auth mode parameter support |
| `simulateTransaction` stateChanges | Low | Not included in response |
| `simulateTransaction` resourceConfig | Low | No resource config parameter |
| HTTP body size limit (512KB) | Low | No request size enforcement |
| `getLedgerEntries` max 200 keys | Low | No key count limit |
| Batch request rejection | Low | Multiple requests in one HTTP body not rejected |

## Architectural Differences

1. **Language and framework**
   - **stellar-rpc**: Go, `jrpc2` library, HTTP handler middleware
   - **Rust**: Axum web framework, manual JSON-RPC dispatch
   - **Rationale**: Axum is idiomatic Rust; manual dispatch is simpler for 12 methods

2. **Simulation execution**
   - **stellar-rpc**: Calls into `soroban-simulation` (C/Go bridge via CGo)
   - **Rust**: Directly invokes `soroban-env-host-p25` in `spawn_blocking`
   - **Rationale**: No CGo bridge needed; Rust can call soroban-env-host natively

3. **State access**
   - **stellar-rpc**: Maintains its own ledger entry reader backed by a DB
   - **Rust**: Reads directly from `SearchableBucketListSnapshot` (in-memory)
   - **Rationale**: Faster reads; bucket list snapshots are already maintained by henyey-bucket

4. **Integrated vs standalone**
   - **stellar-rpc**: Standalone service that connects to a captive stellar-core instance
   - **Rust**: Embedded module within the henyey node process
   - **Rationale**: Simpler deployment; direct access to `App` state without IPC

5. **Fee window ingestion**
   - **stellar-rpc**: Hooks into ingestion pipeline via `InsertFn` callback
   - **Rust**: Background poller reads new LCMs from DB every second
   - **Rationale**: Avoids cross-crate coupling; DB is the source of truth

## Test Coverage

| Area | stellar-rpc Tests | Rust Tests | Notes |
|------|-------------------|------------|-------|
| JSON-RPC envelope | Extensive integration tests | 6 `#[test]` in `server.rs` | Rust covers parsing and serialization |
| TOID encoding/pagination | N/A (inline in Go) | 10 `#[test]` in `util.rs` | TOID roundtrip, ordering, pagination validation |
| Fee window | Unit + integration tests | 13 `#[test]` in `fee_window.rs` | Distribution, ring buffer, fee extraction, ops counting |
| getHealth | Integration test | 0 | No unit tests |
| getLedgerEntries | Integration tests with TTL | 0 | No unit tests |
| getEvents | Integration tests with filters | 0 | No unit tests |
| sendTransaction | Integration tests | 0 | No unit tests |
| simulateTransaction | Integration + preflight tests | 0 | No unit tests |

### Test Gaps

- `server.rs` has 6 unit tests for request parsing and response serialization
- `util.rs` has 10 unit tests covering TOID encode/decode, cursor parsing, pagination validation, and tx status determination
- `fee_window.rs` has 13 unit tests covering distribution computation, ring buffer, fee window, and ops counting
- No handler-level unit tests for any method
- No integration tests for the RPC server
- stellar-rpc has extensive integration tests that exercise the full request/response cycle

## Parity Calculation

| Category | Count |
|----------|-------|
| Implemented (Full) | 89 |
| Gaps (None + Partial) | 16 |
| Intentional Omissions | 5 |
| **Parity** | **89 / (89 + 16) = 85%** |
