# stellar-rpc Parity Status

**Crate**: `henyey-rpc`
**Upstream**: `stellar/stellar-rpc` (Go, GitHub)
**Overall Parity**: 67%
**Last Updated**: 2026-03-13

## Summary

| Area | Status | Notes |
|------|--------|-------|
| JSON-RPC 2.0 envelope | Full | Request/response parsing, error codes |
| Method dispatch | Full | All 12 methods registered |
| getHealth | Partial | No latency check; `oldestLedger` from DB |
| getNetwork | Full | Passphrase, friendbot URL, protocol version |
| getLatestLedger | Partial | Missing `closeTime`, `headerXdr`, `metadataXdr` |
| getVersionInfo | Partial | `commitHash`, `buildTimestamp`, `captiveCoreVersion` empty |
| getFeeStats | None | Returns hardcoded base fee; no sliding window |
| getLedgerEntries | Partial | Core lookup + TTL works; no key limit, no xdrFormat |
| getTransaction | Partial | Core lookup works; `oldestLedger` from DB, `feeBump`, `diagnosticEventsXdr`; missing `xdrFormat` |
| getTransactions | Partial | Range query, TOID cursor, `feeBump`, `diagnosticEventsXdr`; missing `xdrFormat`, status filter |
| getLedgers | Partial | Range query, cursor pagination, `headerXdr`/`metadataXdr`; missing `xdrFormat` |
| getEvents | Partial | Core query works; `oldestLedger` from DB; missing filter limits, `**` wildcard, `xdrFormat` |
| sendTransaction | Partial | Submission works; generic error XDR, no xdrFormat |
| simulateTransaction | Partial | InvokeHostFunction only; no Extend/Restore, no authMode/stateChanges |
| Infrastructure | Partial | No body size limit, no xdrFormat JSON output, no batch rejection |

## File Mapping

| stellar-rpc File | Rust Module | Notes |
|-------------------|-------------|-------|
| `cmd/soroban-rpc/internal/methods/health.go` | `methods/health.rs` | |
| `cmd/soroban-rpc/internal/methods/get_network.go` | `methods/network.rs` | |
| `cmd/soroban-rpc/internal/methods/get_latest_ledger.go` | `methods/latest_ledger.rs` | |
| `cmd/soroban-rpc/internal/methods/get_version_info.go` | `methods/version_info.rs` | |
| `cmd/soroban-rpc/internal/methods/get_fee_stats.go` | `methods/fee_stats.rs` | Stub only |
| `cmd/soroban-rpc/internal/methods/get_ledger_entries.go` | `methods/get_ledger_entries.rs` | |
| `cmd/soroban-rpc/internal/methods/get_transaction.go` | `methods/get_transaction.rs` | |
| `cmd/soroban-rpc/internal/methods/get_transactions.go` | `methods/get_transactions.rs` | |
| `cmd/soroban-rpc/internal/methods/get_ledgers.go` | `methods/get_ledgers.rs` | |
| `cmd/soroban-rpc/internal/methods/get_events.go` | `methods/get_events.rs` | |
| `cmd/soroban-rpc/internal/methods/send_transaction.go` | `methods/send_transaction.rs` | |
| `cmd/soroban-rpc/internal/methods/simulate_transaction.go` | `methods/simulate_transaction.rs` | Delegates to `simulate/` |
| `cmd/soroban-rpc/internal/preflight/` | `simulate/mod.rs`, `simulate/snapshot.rs` | Soroban host invocation |
| `cmd/soroban-rpc/internal/feewindow/` | — | Not implemented |
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
| xdrFormat parameter support | — | None |

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
| `closeTime` | — | None |
| `headerXdr` | — | None |
| `metadataXdr` | — | None |

### getVersionInfo (`methods/version_info.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/get_version_info.go`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| `version` | `handle()` | Full |
| `protocolVersion` | `handle()` | Full |
| `commitHash` | Empty string | None |
| `buildTimestamp` | Empty string | None |
| `captiveCoreVersion` | Empty string | None |

### getFeeStats (`methods/fee_stats.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/get_fee_stats.go`, `cmd/soroban-rpc/internal/feewindow/`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| `FeeWindow` sliding window tracking | — | None |
| Nearest-rank percentile computation | — | None |
| `sorobanInclusionFee` distribution | Hardcoded base fee | None |
| `inclusionFee` distribution | Hardcoded base fee | None |
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
| `xdrFormat` JSON output | — | None |

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
| `diagnosticEventsXdr` | `util::extract_diagnostic_events_xdr()` | Full |
| `xdrFormat` JSON output | — | None |

### getTransactions (`methods/get_transactions.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/get_transactions.go`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| Range query by startLedger | `handle()` | Full |
| TOID-based cursor pagination | `util::validate_pagination()` | Full |
| Transaction envelope/result/meta per entry | `handle()` | Full |
| `feeBump` detection | `is_fee_bump_envelope()` | Full |
| `diagnosticEventsXdr` | `util::extract_diagnostic_events_xdr()` | Full |
| `txHash`, `ledger`, `createdAt`, `applicationOrder` | `handle()` | Full |
| `latestLedger`, `oldestLedger`, close times | `handle()` | Full |
| Filter by status | — | None |
| `xdrFormat` support | — | None |

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
| `xdrFormat` support | — | None |

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
| `xdrFormat` JSON output | — | None |

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
| `xdrFormat` JSON output | — | None |

### simulateTransaction (`simulate/mod.rs`, `simulate/snapshot.rs`)

Corresponds to: `cmd/soroban-rpc/internal/methods/simulate_transaction.go`, `cmd/soroban-rpc/internal/preflight/`

| stellar-rpc | Rust | Status |
|-------------|------|--------|
| InvokeHostFunction simulation | `run_simulation()` | Full |
| Recording mode invocation | `run_simulation()` | Full |
| BucketList snapshot source | `BucketListSnapshotSource` | Full |
| TTL-aware entry lookup | `get_entry_ttl()` | Full |
| Resource adjustment (1.04x + 50k) | `adjust_resources()` | Full |
| Refundable fee adjustment (1.15x) | `compute_resource_fee()` | Full |
| SorobanTransactionData construction | `build_success_response()` | Full |
| Auth entries in response | `build_success_response()` | Full |
| Return value XDR | `build_success_response()` | Full |
| Error response with cost | `build_error_response()` | Full |
| ExtendFootprintTtl simulation | — | None |
| RestoreFootprint simulation | — | None |
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
| `getFeeStats` sliding window | Medium | Returns hardcoded base fee; inaccurate for fee estimation |
| `simulateTransaction` ExtendTTL/Restore | Medium | Returns error instead of simulating |
| `xdrFormat` JSON output | Medium | Missing across all methods; needed for some SDK modes |
| `getLatestLedger` missing fields | Medium | `closeTime`, `headerXdr`, `metadataXdr` |
| `getTransactions` status filter | Low | Missing status-based filtering |
| `getHealth` latency check | Low | Always returns "healthy" regardless of ledger age |
| `getVersionInfo` build metadata | Low | Empty strings for commit/build/captiveCore |
| `getEvents` filter limits | Low | No enforcement of max filters/contractIDs/topics |
| `getEvents` `**` wildcard | Low | Topic wildcard not supported |
| `sendTransaction` actual error codes | Low | Always returns generic TxFailed |
| `simulateTransaction` authMode | Low | No auth mode parameter support |
| `simulateTransaction` stateChanges | Low | Not included in response |
| HTTP body size limit (512KB) | Low | No request size enforcement |
| `getLedgerEntries` max 200 keys | Low | No key count limit |

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

## Test Coverage

| Area | stellar-rpc Tests | Rust Tests | Notes |
|------|-------------------|------------|-------|
| JSON-RPC envelope | Extensive integration tests | 6 `#[test]` in `server.rs` | Rust covers parsing and serialization |
| TOID encoding/pagination | N/A (inline in Go) | 10 `#[test]` in `util.rs` | TOID roundtrip, ordering, pagination validation |
| getHealth | Integration test | 0 | No unit tests |
| getLedgerEntries | Integration tests with TTL | 0 | No unit tests |
| getEvents | Integration tests with filters | 0 | No unit tests |
| sendTransaction | Integration tests | 0 | No unit tests |
| simulateTransaction | Integration + preflight tests | 0 | No unit tests |
| Fee window | Unit + integration tests | 0 | Not implemented |

### Test Gaps

- `server.rs` has 6 unit tests for request parsing and response serialization
- `util.rs` has 10 unit tests covering TOID encode/decode, cursor parsing, pagination validation, and tx status determination
- No handler-level unit tests for any method
- No integration tests for the RPC server
- stellar-rpc has extensive integration tests that exercise the full request/response cycle

## Parity Calculation

| Category | Count |
|----------|-------|
| Implemented (Full) | 70 |
| Gaps (None + Partial) | 35 |
| Intentional Omissions | 5 |
| **Parity** | **70 / (70 + 35) = 67%** |
