## C++ Parity Status

This section documents the parity between this Rust implementation and the upstream C++ stellar-core `src/main/` directory.

### Implemented

#### Core Application Features
- **Application lifecycle management** (`App`, `AppState`): Create, initialize, run, and gracefully shutdown nodes
- **Configuration loading** (`AppConfig`): TOML-based configuration with environment variable overrides
- **Testnet/Mainnet presets**: Pre-configured defaults for public networks

#### CLI Commands
- **`run`**: Run a Stellar Core node (full, validator, or watcher mode)
- **`catchup`**: Synchronize from history archives to a target ledger

#### HTTP Command Handler (StatusServer)
- `/info` - Node information
- `/status` - Current node status
- `/metrics` - Prometheus-format metrics
- `/peers` - Connected peer list
- `/connect` - Connect to peer
- `/droppeer` - Disconnect peer (with optional ban)
- `/bans` - List banned peers
- `/unban` - Remove peer from ban list
- `/ledger` - Current ledger info
- `/upgrades` - Current and proposed protocol upgrades
- `/quorum` - Quorum set configuration
- `/scp` - SCP slot status summary
- `/survey` - Survey data report
- `/survey/start` - Start survey collecting
- `/survey/stop` - Stop survey collecting
- `/survey/topology` - Request topology from peer
- `/survey/reporting/stop` - Stop survey reporting
- `/self-check` - Run self-validation checks
- `/tx` - Submit transaction
- `/shutdown` - Request graceful shutdown
- `/health` - Health check endpoint
- `/ll` - Get/set log levels (query supported, dynamic set partial)
- `/manualclose` - Manual ledger close (stub, requires RUN_STANDALONE)
- `/sorobaninfo` - Soroban network configuration (basic format)

#### Survey System
- **Time-sliced survey protocol**: Full implementation of collecting and reporting phases
- **SurveyDataManager**: Collects peer statistics, latency histograms, node metrics
- **SurveyMessageLimiter**: Rate limiting and deduplication

#### Configuration Options
- Node identity (name, seed, validator mode, quorum set)
- Network settings (passphrase, base fee, base reserve, protocol version)
- Database path and pool size
- Bucket storage directory and cache settings
- History archive configuration (read/write)
- Overlay settings (ports, peer limits, flood rates, surveyor keys)
- Logging (level, format, colors)
- HTTP server (port, address)
- Surge pricing (byte allowances)
- Protocol upgrades

#### Logging and Progress
- Structured logging with tracing
- Text and JSON log formats
- Progress tracking for long-running operations
- Catchup phase progress reporting

### Not Yet Implemented (Gaps)

#### CLI Commands (from C++ CommandLine.cpp)
- **`verify-checkpoints`**: Write verified checkpoint ledger hashes
- **`convert-id`**: Display ID in all known forms
- **`diag-bucket-stats`**: Report statistics on bucket content
- **`dump-ledger`**: Dump current ledger state as JSON
- **`dump-xdr`**: Dump an XDR file for debugging
- **`dump-wasm`**: Dump WASM blobs from ledger
- **`encode-asset`**: Print encoded asset in base64
- **`force-scp`**: Force SCP (deprecated)
- **`gen-seed`**: Generate random node seed
- **`http-command`**: Send command to local stellar-core
- **`self-check`** (CLI): Self-check as CLI command (HTTP endpoint exists)
- **`merge-bucketlist`**: Write diagnostic merged bucket list
- **`dump-archival-stats`**: Print state archival statistics
- **`new-db`**: Create/restore DB to genesis ledger
- **`new-hist`**: Initialize history archives
- **`offline-info`**: Return information for offline instance
- **`print-xdr`**: Pretty-print XDR envelope
- **`publish`**: Execute publish of queued items
- **`report-last-history-checkpoint`**: Report last checkpoint info
- **`sec-to-pub`**: Print public key from secret key
- **`sign-transaction`**: Add signature to transaction envelope
- **`upgrade-db`**: Upgrade database schema
- **`get-settings-upgrade-txs`**: Get settings upgrade transactions
- **`check-quorum-intersection`**: Check quorum intersection from JSON
- **`print-publish-queue`**: Print checkpoints scheduled for publish
- **`replay-debug-meta`**: Apply ledgers from local debug metadata

#### Test-Only CLI Commands (BUILD_TESTS)
- **`load-xdr`**: Load XDR bucket file
- **`rebuild-ledger-from-buckets`**: Rebuild ledger from bucket list
- **`fuzz`**: Run single fuzz input
- **`gen-fuzz`**: Generate random fuzzer input
- **`test`**: Execute test suite
- **`apply-load`**: Run apply time load test
- **`pregenerate-loadgen-txs`**: Generate payment transactions for load testing

#### HTTP Command Handler Gaps
- **`ll` (dynamic set)**: Dynamic log level changes require tracing-subscriber reload support
- **`logRotate`**: Rotate log files
- **`maintenance`**: Trigger maintenance operations
- **`manualClose` (full)**: Full manual close requires RUN_STANDALONE infrastructure
- **`clearMetrics`**: Clear metrics by domain
- **`dumpProposedSettings`**: Dump proposed settings
- **`surveyTopology`** (legacy): Non-time-sliced survey
- **`getSurveyResult`** (legacy): Get legacy survey result
- **`sorobanInfo` (detailed/upgrade_xdr)**: Detailed formats require reading config entries from ledger

#### Test-Only HTTP Endpoints (BUILD_TESTS)
- **`generateLoad`**: Generate synthetic load
- **`testAcc`**: Test account operations
- **`testTx`**: Test transaction operations
- **`toggleOverlayOnlyMode`**: Toggle overlay-only mode

#### Application Subsystems
- **Maintainer**: Automatic maintenance scheduling (table cleanup)
- **ProcessManager**: External process spawning (for history commands)
- **WorkScheduler**: Background work scheduling
- **Protocol23CorruptionDataVerifier**: P23 hot archive bug verification
- **Protocol23CorruptionEventReconciler**: P23 event reconciliation

#### Configuration Options
- Many `ARTIFICIALLY_*_FOR_TESTING` options
- `LOADGEN_*` options for load generation
- `APPLY_LOAD_*` options for apply-load benchmarking
- `CATCHUP_SKIP_KNOWN_RESULTS_FOR_TESTING`
- Manual close mode (`MANUAL_CLOSE`)
- `PUBLISH_TO_ARCHIVE_DELAY`
- Detailed flow control parameters

#### PersistentState
- Full database-backed persistent state (currently minimal implementation)
- SCP state persistence across restarts
- TxSet storage and retrieval
- Slot state migration

### Implementation Notes

#### Architectural Differences

1. **Async Runtime**: The Rust implementation uses Tokio for async I/O, while C++ uses ASIO with a custom VirtualClock. This affects:
   - Timer management (Rust uses `tokio::time` vs C++ `VirtualTimer`)
   - Thread pools (Rust uses Tokio tasks vs C++ explicit worker threads)
   - Signal handling (Rust uses `tokio::signal` vs C++ ASIO signals)

2. **Configuration Format**:
   - C++ uses a custom configuration parser with TOML-like syntax
   - Rust uses standard TOML with serde for deserialization
   - Both support similar configuration options, but field names differ

3. **HTTP Server**:
   - C++ uses a custom HTTP server implementation (`lib/http/server.hpp`)
   - Rust uses Axum with tower middleware
   - Response formats are similar but not byte-identical

4. **Logging**:
   - C++ uses a custom logging system with log levels per partition
   - Rust uses the `tracing` ecosystem with structured logging
   - Log format differs slightly

5. **Build-Time Features**:
   - C++ uses `#ifdef BUILD_TESTS` for test-only code
   - Rust uses Cargo features (not yet implemented for test-only commands)

#### Design Decisions

1. **No cpptoml dependency**: Configuration uses native Rust TOML parsing
2. **No libmedida**: Metrics use Prometheus-compatible format directly
3. **Simplified thread model**: Tokio handles work distribution
4. **Survey implementation**: Full time-sliced survey support; legacy survey not implemented
5. **Command parity**: Focus on essential operational commands first

## Upstream Mapping

This crate corresponds to the following C++ stellar-core components:

- `src/main/Application.h` - Application interface
- `src/main/ApplicationImpl.h` - Application implementation
- `src/main/Config.h` - Configuration handling
- `src/main/CommandHandler.h` - HTTP API
- `src/main/CommandLine.cpp` - CLI commands
- `src/main/ApplicationUtils.h` - Application utilities
- `src/main/PersistentState.h` - Persistent state management
- `src/main/Maintainer.h` - Maintenance scheduling
