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

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed C++ parity analysis.
