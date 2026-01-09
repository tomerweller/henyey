# C++ Parity Status

This document details the parity between this Rust implementation (`stellar-core-app`) and the upstream C++ stellar-core `src/main/` directory (v25.x).

## Upstream Mapping

This crate corresponds to the following C++ stellar-core components:

| C++ File | Rust Module | Status |
|----------|-------------|--------|
| `Application.h` / `ApplicationImpl.cpp` | `app.rs` | Partial |
| `Config.h` / `Config.cpp` | `config.rs` | Partial |
| `CommandHandler.h` / `CommandHandler.cpp` | `run_cmd.rs` (StatusServer) | Partial |
| `CommandLine.cpp` | `run_cmd.rs`, `catchup_cmd.rs` | Partial |
| `PersistentState.h` / `PersistentState.cpp` | `stellar-core-db` crate | Partial |
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
| Database initialization | Implemented | SQLite via `stellar-core-db` |
| Bucket manager integration | Implemented | Via `stellar-core-bucket` |
| Ledger manager integration | Implemented | Via `stellar-core-ledger` |
| Overlay manager integration | Implemented | Via `stellar-core-overlay` |
| Herder integration | Implemented | Via `stellar-core-herder` |
| Network ID computation | Implemented | Hash of network passphrase |
| Graceful shutdown | Implemented | Signal handling, shutdown broadcast |
| Metrics registry | Partial | Prometheus-style metrics via HTTP |
| Worker thread pools | Different | Uses Tokio async runtime instead of ASIO threads |
| VirtualClock | Different | Uses `tokio::time` instead of custom VirtualClock |

### CLI Commands (CommandLine.cpp)

| C++ Command | Rust Status | Notes |
|-------------|-------------|-------|
| `run` | Implemented | `run_node()` in `run_cmd.rs` |
| `catchup` | Implemented | `run_catchup()` in `catchup_cmd.rs` |
| `version` | Implemented | Via `--version` flag |
| `help` | Implemented | Via `--help` flag |
| `verify-checkpoints` | Not Implemented | |
| `convert-id` | Implemented | `offline convert-key` in rs-stellar-core |
| `diag-bucket-stats` | Not Implemented | |
| `dump-ledger` | Not Implemented | |
| `dump-xdr` | Not Implemented | |
| `dump-wasm` | Not Implemented | |
| `encode-asset` | Not Implemented | |
| `force-scp` | Not Implemented | Deprecated in C++ |
| `gen-seed` | Implemented | `new-keypair` command in rs-stellar-core |
| `http-command` | Not Implemented | |
| `self-check` (CLI) | Not Implemented | HTTP endpoint exists |
| `merge-bucketlist` | Not Implemented | |
| `dump-archival-stats` | Not Implemented | |
| `new-db` | Not Implemented | |
| `new-hist` | Not Implemented | |
| `offline-info` | Not Implemented | |
| `print-xdr` | Not Implemented | |
| `publish` | Not Implemented | |
| `report-last-history-checkpoint` | Not Implemented | |
| `sec-to-pub` | Implemented | Via `offline sec-to-pub` in rs-stellar-core |
| `sign-transaction` | Implemented | Via `offline sign-transaction` in rs-stellar-core |
| `upgrade-db` | Not Implemented | |
| `get-settings-upgrade-txs` | Not Implemented | |
| `check-quorum-intersection` | Not Implemented | |
| `print-publish-queue` | Not Implemented | |
| `replay-debug-meta` | Not Implemented | |

### Test-Only CLI Commands (BUILD_TESTS)

| C++ Command | Rust Status | Notes |
|-------------|-------------|-------|
| `load-xdr` | Not Implemented | |
| `rebuild-ledger-from-buckets` | Not Implemented | |
| `fuzz` | Not Implemented | |
| `gen-fuzz` | Not Implemented | |
| `test` | Not Applicable | Uses Rust test framework |
| `apply-load` | Not Implemented | |
| `pregenerate-loadgen-txs` | Not Implemented | |

### HTTP Command Handler (CommandHandler.cpp)

| C++ Endpoint | Rust Status | Notes |
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
| `/manualclose` | Stub | Requires RUN_STANDALONE mode |
| `/sorobaninfo` | Partial | Basic format only |
| `/logRotate` | Not Implemented | |
| `/maintenance` | Not Implemented | |
| `/clearMetrics` | Not Implemented | |
| `/dumpProposedSettings` | Not Implemented | |
| `/surveyTopology` (legacy) | Not Implemented | Non-time-sliced survey |
| `/getSurveyResult` (legacy) | Not Implemented | Legacy survey result |
| `/survey/reporting/stop` | Implemented | Stop survey reporting |

### Test-Only HTTP Endpoints (BUILD_TESTS)

| C++ Endpoint | Rust Status | Notes |
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
| `MANUAL_CLOSE` | Not Implemented | Manual ledger close mode |
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
| Last closed ledger | Implemented | Via `stellar-core-db` |
| History archive state | Implemented | Via `stellar-core-db` |
| Database schema version | Implemented | Via `stellar-core-db` |
| Network passphrase storage | Implemented | Via `stellar-core-db` |
| Ledger upgrades | Partial | Via herder |
| SCP state persistence | Partial | Slot state stored, migration not implemented |
| TxSet storage | Partial | Basic storage via `stellar-core-db` |
| Rebuild ledger flag | Not Implemented | |

### Application Subsystems

| Subsystem | Status | Notes |
|-----------|--------|-------|
| TmpDirManager | Not Implemented | |
| ProcessManager | Not Implemented | External process spawning |
| WorkScheduler | Partial | Uses `stellar-core-work` with Tokio |
| Maintainer | Implemented | Automatic table cleanup via `maintainer.rs` |
| InvariantManager | Partial | Via `stellar-core-ledger` |
| BanManager | Implemented | Via `stellar-core-overlay` |
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

## Architectural Differences

### Async Runtime

| Aspect | C++ | Rust |
|--------|-----|------|
| Event loop | ASIO io_context | Tokio async runtime |
| Timer management | VirtualTimer | `tokio::time` |
| Thread pools | Explicit worker threads | Tokio task spawning |
| Signal handling | ASIO signals | `tokio::signal` |
| Clock abstraction | VirtualClock | System time (no virtual clock) |

### Configuration Format

| Aspect | C++ | Rust |
|--------|-----|------|
| Parser | cpptoml (custom TOML-like) | `toml` crate with serde |
| Field naming | SCREAMING_SNAKE_CASE | snake_case in TOML |
| Environment overrides | Not standard | `RS_STELLAR_CORE_*` prefix |

### HTTP Server

| Aspect | C++ | Rust |
|--------|-----|------|
| Framework | Custom `lib/http/server.hpp` | Axum with tower middleware |
| Response format | JSON | JSON (similar but not byte-identical) |
| URL structure | Query string parameters | Query string parameters |

### Logging

| Aspect | C++ | Rust |
|--------|-----|------|
| Framework | Custom logging system | `tracing` ecosystem |
| Log levels | Per partition | Per partition via filter directives |
| Format | Custom | Text or JSON via `tracing-subscriber` |
| Dynamic changes | Fully supported | Fully supported via `/ll` endpoint |
| Partition mapping | Direct C++ modules | Maps C++ partitions to Rust crate targets |

### Metrics

| Aspect | C++ | Rust |
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
