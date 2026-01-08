# stellar-core-app

Application orchestration layer for rs-stellar-core.

## Overview

This crate provides the top-level application layer that wires together all subsystems of a Stellar Core node. It is the main entry point for running a node and handles:

- **Configuration management**: Loading and validating TOML configuration files with environment variable overrides
- **Application lifecycle**: Initializing, running, and gracefully shutting down all node components
- **Command execution**: Implementing CLI commands like `run` and `catchup`
- **HTTP API**: Serving status, metrics, and control endpoints
- **Logging**: Structured logging with progress tracking for long-running operations

## Architecture

The `App` struct is the central coordinator that owns handles to all subsystems:

```
                    +-----------------+
                    |      App        |
                    |  (Coordinator)  |
                    +--------+--------+
                             |
        +--------------------+--------------------+
        |                    |                    |
        v                    v                    v
+---------------+   +---------------+   +---------------+
|   Database    |   |    Herder     |   |   Overlay     |
|   (SQLite)    |   |  (Consensus)  |   |   (P2P)       |
+---------------+   +---------------+   +---------------+
        |                    |                    |
        v                    v                    v
+---------------+   +---------------+   +---------------+
|    Bucket     |   |    Ledger     |   |   History     |
|   Manager     |   |   Manager     |   |   Archives    |
+---------------+   +---------------+   +---------------+
```

## Key Types

| Type | Description |
|------|-------------|
| `App` | Main application struct coordinating all subsystems |
| `AppConfig` | Configuration loaded from TOML with defaults for testnet/mainnet |
| `AppState` | Application lifecycle state (Initializing, CatchingUp, Synced, etc.) |
| `RunMode` | Node running mode (Full, Validator, Watcher) |
| `CatchupMode` | History download mode (Minimal, Complete, Recent) |

## Usage

### Running a Node

```rust
use stellar_core_app::{App, AppConfig, run_node, RunOptions};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration from file
    let config = AppConfig::from_file("config.toml")?;

    // Run the node
    run_node(config, RunOptions::default()).await
}
```

### Catching Up from History

```rust
use stellar_core_app::{run_catchup, CatchupOptions, CatchupMode, AppConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = AppConfig::testnet();

    let options = CatchupOptions::to_ledger(1000000)
        .with_mode(CatchupMode::Recent(1000))
        .with_parallelism(16);

    run_catchup(config, options).await?;
    Ok(())
}
```

### Programmatic Configuration

```rust
use stellar_core_app::config::ConfigBuilder;

let config = ConfigBuilder::new()
    .node_name("my-node")
    .database_path("/var/lib/stellar/stellar.db")
    .peer_port(11625)
    .log_level("info")
    .build();
```

## Configuration

Configuration is loaded from TOML files. See the `config` module for all options.

### Example Configuration

```toml
[node]
name = "my-validator"
node_seed = "S..."  # Required for validators
is_validator = true

[network]
passphrase = "Test SDF Network ; September 2015"

[database]
path = "/var/lib/stellar/stellar.db"

[overlay]
peer_port = 11625
known_peers = [
    "core-testnet1.stellar.org:11625",
    "core-testnet2.stellar.org:11625"
]

[[history.archives]]
name = "sdf1"
url = "https://history.stellar.org/prd/core-testnet/core_testnet_001"

[logging]
level = "info"
format = "text"
```

### Environment Overrides

Configuration values can be overridden using environment variables:

| Variable | Description |
|----------|-------------|
| `RS_STELLAR_CORE_NODE_NAME` | Node name |
| `RS_STELLAR_CORE_NODE_SEED` | Node secret seed |
| `RS_STELLAR_CORE_NETWORK_PASSPHRASE` | Network passphrase |
| `RS_STELLAR_CORE_DATABASE_PATH` | Database file path |
| `RS_STELLAR_CORE_LOG_LEVEL` | Log level |

## HTTP API

When enabled, the status server provides REST endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/info` | GET | Node information and version |
| `/status` | GET | Current node status |
| `/metrics` | GET | Prometheus-format metrics |
| `/peers` | GET | Connected peer list |
| `/connect` | POST | Connect to a peer |
| `/droppeer` | POST | Disconnect a peer |
| `/bans` | GET | List banned peers |
| `/unban` | POST | Unban a peer |
| `/ledger` | GET | Current ledger state |
| `/upgrades` | GET | Current/proposed upgrades |
| `/quorum` | GET | Quorum set configuration |
| `/scp` | GET | SCP consensus state |
| `/survey` | GET | Survey report |
| `/survey/start` | POST | Start survey collecting |
| `/survey/stop` | POST | Stop survey collecting |
| `/survey/topology` | POST | Request topology from peer |
| `/survey/reporting/stop` | POST | Stop survey reporting |
| `/self-check` | POST | Run self-check validation |
| `/tx` | POST | Submit a transaction |
| `/shutdown` | POST | Request graceful shutdown |
| `/health` | GET | Health check endpoint |

## Module Structure

```
src/
├── lib.rs          # Crate root with re-exports
├── app.rs          # Core App struct and lifecycle
├── config.rs       # Configuration types and loading
├── run_cmd.rs      # Run command and HTTP server
├── catchup_cmd.rs  # Catchup command implementation
├── logging.rs      # Logging setup and progress tracking
└── survey.rs       # Network topology survey support
```

## Design Notes

### State Machine

The application transitions through well-defined states:

```
Initializing --> CatchingUp --> Synced <--> Validating
                     ^              |
                     |              v
                     +---- ShuttingDown
```

### Consensus Stuck Recovery

When consensus stalls (no ledger close for 35+ seconds with buffered ledgers), the node:

1. Broadcasts its SCP state to peers
2. Requests SCP state from peers
3. Attempts recovery every 10 seconds
4. Falls back to catchup if recovery fails

### Transaction Flooding

Transactions are propagated using an advert/demand protocol:
- Nodes advertise transaction hashes they have
- Peers demand transactions they need
- Rate limiting prevents bandwidth abuse

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
- **`ll`**: Set log level dynamically
- **`logRotate`**: Rotate log files
- **`maintenance`**: Trigger maintenance operations
- **`manualClose`**: Manually close ledger (MANUAL_CLOSE mode)
- **`clearMetrics`**: Clear metrics by domain
- **`dumpProposedSettings`**: Dump proposed settings
- **`surveyTopology`** (legacy): Non-time-sliced survey
- **`getSurveyResult`** (legacy): Get legacy survey result
- **`sorobanInfo`**: Soroban-specific information

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
