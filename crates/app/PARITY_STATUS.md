# stellar-core Parity Status

**Overall Parity: ~75%**

This document details the parity between this Rust implementation (`henyey-app`) and the stellar-core `src/main/` directory (v25.x).

## stellar-core Mapping

This crate corresponds to the following stellar-core components:

| stellar-core File | Rust Module | Status |
|----------|-------------|--------|
| `Application.h` / `ApplicationImpl.cpp` | `app.rs` | Partial |
| `Config.h` / `Config.cpp` | `config.rs` | Partial |
| `CommandHandler.h` / `CommandHandler.cpp` | `run_cmd.rs` (StatusServer) | Partial |
| `CommandLine.cpp` | `run_cmd.rs`, `catchup_cmd.rs` | Partial |
| `PersistentState.h` / `PersistentState.cpp` | `henyey-db` crate | Partial |
| `Maintainer.h` / `Maintainer.cpp` | `maintainer.rs` | Implemented |
| `ApplicationUtils.h` / `ApplicationUtils.cpp` | Distributed across modules | Partial |
| `QueryServer.h` / `QueryServer.cpp` | Not implemented | Missing |

## Implemented Features

### Core Application (Application.h/ApplicationImpl.cpp)

| Feature | Status | Notes |
|---------|--------|-------|
| Application lifecycle management | Implemented | `App::new()`, `App::run()`, `App::shutdown()` |
| Application state machine | Implemented | `AppState` enum: Initializing, CatchingUp, Synced, Validating, ShuttingDown |
| Configuration loading | Implemented | TOML-based via `AppConfig` |
| Database initialization | Implemented | SQLite via `henyey-db` |
| Bucket manager integration | Implemented | Via `henyey-bucket` |
| Ledger manager integration | Implemented | Via `henyey-ledger` |
| Overlay manager integration | Implemented | Via `henyey-overlay` |
| Herder integration | Implemented | Via `henyey-herder` |
| Network ID computation | Implemented | Hash of network passphrase |
| Graceful shutdown | Implemented | Signal handling, shutdown broadcast |
| Metrics registry | Partial | Prometheus-style metrics via HTTP |
| Worker thread pools | Different | Uses Tokio async runtime instead of ASIO threads |
| VirtualClock | Different | Uses `tokio::time` instead of custom VirtualClock |

### CLI Commands (CommandLine.cpp)

CLI commands are implemented in the `henyey` binary crate. This crate provides the
run/catchup handlers and HTTP server wiring used by those commands.

| stellar-core Command | Rust Status | Notes |
|-------------|-------------|-------|
| `run` | Implemented | `run_node()` in `run_cmd.rs` |
| `catchup` | Implemented | `run_catchup()` in `catchup_cmd.rs` |
| `version` | Implemented | Via `--version` flag |
| `help` | Implemented | Via `--help` flag |
| `verify-checkpoints` | Implemented | Via `offline verify-checkpoints` in henyey |
| `convert-id` | Implemented | `offline convert-key` in henyey |
| `diag-bucket-stats` | Not Implemented | |
| `dump-ledger` | Implemented | `offline dump-ledger` in henyey |
| `dump-xdr` | Not Implemented | |
| `dump-wasm` | Not Implemented | |
| `encode-asset` | Implemented | `offline encode-xdr --type Asset` in henyey |
| `force-scp` | Not Implemented | Deprecated in stellar-core |
| `gen-seed` | Implemented | `new-keypair` command in henyey |
| `http-command` | Implemented | `http-command` in henyey |
| `self-check` (CLI) | Implemented | Via `offline self-check` in henyey |
| `merge-bucketlist` | Not Implemented | |
| `dump-archival-stats` | Not Implemented | |
| `new-db` | Implemented | `new-db` in henyey |
| `new-hist` | Not Implemented | |
| `offline-info` | Partial | `info` shows basic offline info if app init fails |
| `print-xdr` | Partial | `offline decode-xdr` in henyey (base64 input only) |
| `publish` | Implemented | `publish-history` in henyey |
| `report-last-history-checkpoint` | Not Implemented | |
| `sec-to-pub` | Implemented | Via `offline sec-to-pub` in henyey |
| `sign-transaction` | Implemented | Via `offline sign-transaction` in henyey |
| `upgrade-db` | Implemented | `upgrade-db` in henyey |
| `get-settings-upgrade-txs` | Not Implemented | |
| `check-quorum-intersection` | Implemented | `check-quorum-intersection` in henyey |
| `print-publish-queue` | Not Implemented | |
| `replay-debug-meta` | Not Implemented | |

### Test-Only CLI Commands (BUILD_TESTS)

| stellar-core Command | Rust Status | Notes |
|-------------|-------------|-------|
| `load-xdr` | Not Implemented | |
| `rebuild-ledger-from-buckets` | Not Implemented | |
| `fuzz` | Not Implemented | |
| `gen-fuzz` | Not Implemented | |
| `test` | Not Applicable | Uses Rust test framework |
| `apply-load` | Not Implemented | |
| `pregenerate-loadgen-txs` | Not Implemented | |

### HTTP Command Handler (CommandHandler.cpp)

| stellar-core Endpoint | Rust Status | Notes |
|--------------|-------------|-------|
| `/info` | Implemented | Node info and version |
| `/peers` | Implemented | Connected peer list |
| `/connect` | Implemented | Connect to peer |
| `/droppeer` | Implemented | Disconnect peer |
| `/bans` | Implemented | List banned peers |
| `/unban` | Implemented | Remove peer from ban list |
| `/quorum` | Implemented | Quorum set configuration |
| `/scp` | Implemented | SCP slot status summary |
| `/metrics` | Implemented | Prometheus-format metrics |
| `/tx` | Implemented | Submit transaction |
| `/ll` | Implemented | Dynamic log level changes via tracing-subscriber reload layer |
| `/selfCheck` | Implemented | Via `/self-check` |
| `/upgrades` | Implemented | Current and proposed upgrades |
| `/startSurveyCollecting` | Implemented | Via `/survey/start` |
| `/stopSurveyCollecting` | Implemented | Via `/survey/stop` |
| `/surveyTopologyTimeSliced` | Implemented | Via `/survey/topology` |
| `/survey` | Implemented | Survey data report |
| `/shutdown` | Implemented | Graceful shutdown |
| `/health` | Implemented | Health check endpoint |
| `/ledger` | Implemented | Current ledger info (Rust-specific) |
| `/status` | Implemented | Current node status (Rust-specific) |
| `/manualclose` | Implemented | Triggers manual ledger close (requires is_validator and manual_close config) |
| `/sorobaninfo` | Implemented | Basic format, reads actual config from ledger |
| `/logrotate` | Implemented | Logs request; actual rotation depends on logging backend |
| `/maintenance` | Implemented | Manual database maintenance (cleans old SCP/ledger history) |
| `/clearmetrics` | Implemented | Logs request; Prometheus metrics don't support clearing |
| `/dumpproposedsettings` | Implemented | Returns ConfigUpgradeSet from ledger |
| `/surveyTopology` (legacy) | Not Implemented | Non-time-sliced survey |
| `/getSurveyResult` (legacy) | Not Implemented | Legacy survey result |
| `/survey/reporting/stop` | Implemented | Stop survey reporting |

### Test-Only HTTP Endpoints (BUILD_TESTS)

| stellar-core Endpoint | Rust Status | Notes |
|--------------|-------------|-------|
| `/generateLoad` | Not Implemented | |
| `/testAcc` | Not Implemented | |
| `/testTx` | Not Implemented | |
| `/toggleOverlayOnlyMode` | Not Implemented | |

### Configuration (Config.h/Config.cpp)

| Config Category | Status | Notes |
|-----------------|--------|-------|
| Node identity | Implemented | `node.name`, `node.node_seed`, `node.is_validator` |
| Quorum set | Implemented | `node.quorum_set` with threshold and validators |
| Network settings | Implemented | `network.passphrase`, `network.base_fee`, `network.base_reserve` |
| Database | Implemented | `database.path`, `database.pool_size` |
| Bucket storage | Implemented | `buckets.directory`, `buckets.cache_size` |
| History archives | Implemented | `history.archives[]` with get/put commands |
| Overlay | Implemented | Peer ports, limits, flooding rates, surveyor keys |
| HTTP server | Implemented | `http.port`, `http.address`, `http.enabled` |
| Logging | Implemented | `logging.level`, `logging.format`, `logging.colors` |
| Protocol upgrades | Implemented | `upgrades.protocol_version`, etc. |
| Surge pricing | Implemented | `surge_pricing.classic_byte_allowance`, etc. |
| Events | Implemented | `events.emit_classic_events`, `events.backfill_stellar_asset_events` |
| `ARTIFICIALLY_*_FOR_TESTING` | Not Implemented | Testing-only options |
| `LOADGEN_*` | Not Implemented | Load generation options |
| `APPLY_LOAD_*` | Not Implemented | Apply-load benchmarking |
| `MANUAL_CLOSE` | Implemented | `node.manual_close` enables manual close mode |
| `RUN_STANDALONE` | Not Implemented | Standalone mode |
| Parallel ledger application | Not Implemented | `EXPERIMENTAL_PARALLEL_LEDGER_APPLY` |
| Background overlay processing | Different | Always uses async via Tokio |

### Survey System

| Feature | Status | Notes |
|---------|--------|-------|
| Time-sliced survey protocol | Implemented | Full collecting and reporting phases |
| SurveyDataManager | Implemented | Collects peer statistics, latency histograms |
| SurveyMessageLimiter | Implemented | Rate limiting and deduplication |
| Collecting phase (30 min max) | Implemented | |
| Reporting phase (3 hr max) | Implemented | |
| Latency histograms | Implemented | SCP latency tracking |
| Legacy (non-time-sliced) survey | Not Implemented | |

### PersistentState (PersistentState.h/PersistentState.cpp)

| Feature | Status | Notes |
|---------|--------|-------|
| Last closed ledger | Implemented | Via `henyey-db` |
| History archive state | Implemented | Via `henyey-db` |
| Database schema version | Implemented | Via `henyey-db` |
| Network passphrase storage | Implemented | Via `henyey-db` |
| Ledger upgrades | Partial | Via herder |
| SCP state persistence | Partial | Slot state stored, migration not implemented |
| TxSet storage | Partial | Basic storage via `henyey-db` |
| Rebuild ledger flag | Not Implemented | |

### Application Subsystems

| Subsystem | Status | Notes |
|-----------|--------|-------|
| TmpDirManager | Not Implemented | |
| ProcessManager | Not Implemented | External process spawning |
| WorkScheduler | Partial | Uses `henyey-work` with Tokio |
| Maintainer | Implemented | Automatic table cleanup via `maintainer.rs` |
| InvariantManager | Partial | Via `henyey-ledger` |
| BanManager | Implemented | Via `henyey-overlay` |
| StatusManager | Partial | Via HTTP endpoints |
| Protocol23CorruptionDataVerifier | Not Implemented | |
| Protocol23CorruptionEventReconciler | Not Implemented | |

### Consensus Recovery

| Feature | Status | Notes |
|---------|--------|-------|
| Consensus stuck detection | Implemented | 35-second timeout |
| SCP state broadcast | Implemented | Request and broadcast SCP state |
| Out-of-sync recovery | Implemented | Via `SyncRecoveryManager` |
| Automatic catchup on stuck | Implemented | Falls back to catchup |
| Buffered ledger tx_set updates | Implemented | Entry pattern for late-arriving tx_sets |
| Broadcast tx_set requests during catchup | Implemented | Request from all peers, not just sender |

## Bug Fixes and Improvements

### Catchup Gap Recovery (January 2026)

Two related issues were fixed to improve recovery after catchup completes:

1. **Buffered tx_set update fix** (`80bd38d`): When a slot is buffered without its tx_set
   (because the tx_set hasn't arrived yet), and the tx_set arrives later, the buffered
   entry was not being updated. This was caused by using `or_insert()` which doesn't
   update existing entries. Fixed by using the `Entry::Occupied/Vacant` pattern to
   properly update existing entries when tx_sets arrive.

2. **Broadcast tx_set requests to all peers** (`759757b`): During catchup, when
   EXTERNALIZE messages arrive for future slots, the validator now broadcasts GetTxSet
   requests to ALL connected peers instead of just the message sender. This increases
   the probability of receiving tx_sets before they are evicted from peer caches,
   helping bridge the gap between catchup checkpoint and live consensus.

**Root cause**: After catchup completes at a checkpoint boundary (e.g., ledger 690303),
the network may be 20-30 slots ahead. The validator needs tx_sets for these "gap" slots
to close ledgers. Previously, tx_set requests went only to the peer that sent the
EXTERNALIZE message, but that peer might have already evicted the tx_set from cache.
By requesting from all peers and properly updating buffered entries, the validator
can now successfully bridge this gap.

## Architectural Differences

### Async Runtime

| Aspect | stellar-core | Rust |
|--------|-----|------|
| Event loop | ASIO io_context | Tokio async runtime |
| Timer management | VirtualTimer | `tokio::time` |
| Thread pools | Explicit worker threads | Tokio task spawning |
| Signal handling | ASIO signals | `tokio::signal` |
| Clock abstraction | VirtualClock | System time (no virtual clock) |

### Configuration Format

| Aspect | stellar-core | Rust |
|--------|-----|------|
| Parser | cpptoml (custom TOML-like) | `toml` crate with serde |
| Field naming | SCREAMING_SNAKE_CASE | snake_case in TOML |
| Environment overrides | Not standard | `RS_STELLAR_CORE_*` prefix |

### HTTP Server

| Aspect | stellar-core | Rust |
|--------|-----|------|
| Framework | Custom `lib/http/server.hpp` | Axum with tower middleware |
| Response format | JSON | JSON (similar but not byte-identical) |
| URL structure | Query string parameters | Query string parameters |

### Logging

| Aspect | stellar-core | Rust |
|--------|-----|------|
| Framework | Custom logging system | `tracing` ecosystem |
| Log levels | Per partition | Per partition via filter directives |
| Format | Custom | Text or JSON via `tracing-subscriber` |
| Dynamic changes | Fully supported | Fully supported via `/ll` endpoint |
| Partition mapping | Direct stellar-core modules | Maps stellar-core partitions to Rust crate targets |

### Metrics

| Aspect | stellar-core | Rust |
|--------|-----|------|
| Framework | libmedida | Prometheus-style counters |
| Registry | MetricsRegistry | Direct collection in handlers |
| Export format | JSON via /metrics | Prometheus text format |

## Design Decisions

1. **No cpptoml dependency**: Configuration uses native Rust TOML parsing with serde.

2. **No libmedida**: Metrics use Prometheus-compatible format directly instead of the medida library.

3. **Simplified thread model**: Tokio handles all async work distribution; no separate worker thread pools.

4. **Survey implementation**: Full time-sliced survey support; legacy survey protocol not implemented.

5. **Command parity**: Focus on essential operational commands (`run`, `catchup`) first; utility commands are lower priority.

6. **Database locking**: Uses file-based locking (`.lock` file) to prevent multiple instances.

7. **Virtual clock**: Not implemented; uses real system time only. This affects testability but simplifies the implementation.

## Known Behavioral Differences

1. **Log output format**: Log messages have different formatting and structure.

2. **HTTP response formatting**: JSON responses are functionally equivalent but not byte-identical.

3. **Metrics naming**: Metric names follow Prometheus conventions rather than medida conventions.

4. **Error messages**: Error message text differs but conveys equivalent information.

5. **Startup sequence**: Initialization order and startup messages differ slightly.

6. **Thread naming**: No explicit thread naming as Tokio manages task scheduling.

## Testing Notes

- Unit tests use Rust's built-in test framework (`#[test]`)
- No `BUILD_TESTS` equivalent; test code is always available
- No fuzzing infrastructure implemented
- No load generation (`generateLoad`) implemented
