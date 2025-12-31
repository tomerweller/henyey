# rs-stellar-core

A pure Rust implementation of Stellar Core, focused on testnet synchronization and Protocol 23+ support.

## Status

**Work in Progress** - Core modules implemented, ready for testing.

| Module | Status | Description |
|--------|--------|-------------|
| `stellar-core-common` | Complete | Common types, config, utilities |
| `stellar-core-crypto` | Complete | Ed25519, SHA256, strkey encoding |
| `stellar-core-db` | Complete | SQLite database layer |
| `stellar-core-bucket` | Complete | BucketList implementation |
| `stellar-core-history` | Complete | History archive access, catchup |
| `stellar-core-overlay` | Complete | P2P networking |
| `stellar-core-scp` | Complete | Stellar Consensus Protocol |
| `stellar-core-herder` | Complete | Transaction queue, SCP coordination |
| `stellar-core-ledger` | Complete | Ledger state management |
| `stellar-core-tx` | Complete | Transaction processing |

## Requirements

- Rust 1.75+
- SQLite 3 (bundled via rusqlite)

## Quick Start

### Build

```bash
cargo build --release
```

### Run Tests

```bash
cargo test --all
```

### Catch Up to Testnet

```bash
# Create a new database
./target/release/rs-stellar-core --testnet new-db

# Catch up to the current ledger
./target/release/rs-stellar-core --testnet catchup current

# Or catch up to a specific ledger
./target/release/rs-stellar-core --testnet catchup 1000000
```

### Run Node

```bash
# Run in sync mode (track testnet after catchup)
./target/release/rs-stellar-core --testnet run

# Run with verbose logging
./target/release/rs-stellar-core --testnet --verbose run
```

## Configuration

### Using Configuration File

```bash
./target/release/rs-stellar-core --config my-config.toml run
```

### Sample Configuration

```bash
./target/release/rs-stellar-core sample-config > my-config.toml
```

### Example Configuration (testnet)

```toml
[node]
name = "my-testnet-node"
is_validator = false

[network]
passphrase = "Test SDF Network ; September 2015"

[database]
path = "testnet.db"

[history]
archives = [
    "https://history.stellar.org/prd/core-testnet/core_testnet_001",
    "https://history.stellar.org/prd/core-testnet/core_testnet_002",
    "https://history.stellar.org/prd/core-testnet/core_testnet_003"
]

[peers]
known = [
    "core-testnet1.stellar.org:11625",
    "core-testnet2.stellar.org:11625",
    "core-testnet3.stellar.org:11625"
]
```

## CLI Commands

```
rs-stellar-core - Pure Rust implementation of Stellar Core

USAGE:
    rs-stellar-core [OPTIONS] <COMMAND>

OPTIONS:
    -c, --config <FILE>    Path to configuration file
    -v, --verbose          Enable verbose logging
        --trace            Enable trace logging
        --log-format       Log format: text or json
        --testnet          Use testnet configuration
        --mainnet          Use mainnet configuration

COMMANDS:
    run                 Run the node
    catchup <TARGET>    Catch up from history archives
    new-db              Create a new database
    upgrade-db          Upgrade database schema
    new-keypair         Generate a new node keypair
    info                Print node information
    verify-history      Verify history archives
    publish-history     Publish history to archives (validators only)
    sample-config       Print sample configuration
    offline             Offline utilities
```

### Catchup Options

```bash
# Minimal catchup (just latest state)
rs-stellar-core catchup current --mode minimal

# Complete history (from genesis)
rs-stellar-core catchup current --mode complete

# Recent N ledgers
rs-stellar-core catchup current --mode recent

# With parallel downloads
rs-stellar-core catchup current --parallelism 16

# Skip verification (faster, less safe)
rs-stellar-core catchup current --no-verify
```

### Offline Utilities

```bash
# Convert key formats
rs-stellar-core offline convert-key GDKXE2OZMJIPOSLNA6N6F2BVCI3O777I2OOC4BV7VOYUEHYX7RTRYA7Y

# Decode XDR from base64
rs-stellar-core offline decode-xdr --type LedgerHeader <base64>

# Encode to XDR
rs-stellar-core offline encode-xdr --type AccountId GDKXE2OZMJIPOSLNA6N6F2BVCI3O777I2OOC4BV7VOYUEHYX7RTRYA7Y
rs-stellar-core offline encode-xdr --type Asset "USD:GDKXE2OZMJIPOSLNA6N6F2BVCI3O777I2OOC4BV7VOYUEHYX7RTRYA7Y"

# Bucket information
rs-stellar-core offline bucket-info /path/to/buckets
```

## HTTP API

When running, the node exposes an HTTP API on the configured port (default: 11626):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API overview and available endpoints |
| `/info` | GET | Node information (version, state, uptime) |
| `/metrics` | GET | Prometheus-style metrics |
| `/peers` | GET | Connected peers list |
| `/ledger` | GET | Current ledger information |
| `/tx` | POST | Submit a transaction (base64 XDR) |
| `/health` | GET | Health check endpoint |

### Example: Submit Transaction

```bash
curl -X POST http://localhost:11626/tx \
  -H "Content-Type: application/json" \
  -d '{"tx": "<base64-encoded-transaction-envelope>"}'
```

## Architecture

```
rs-stellar-core/
├── crates/
│   ├── rs-stellar-core/         # CLI binary and HTTP server
│   ├── stellar-core-common/     # Shared types and utilities
│   ├── stellar-core-crypto/     # Cryptographic primitives
│   ├── stellar-core-db/         # SQLite database layer
│   ├── stellar-core-bucket/     # BucketList state storage
│   ├── stellar-core-history/    # History archive access
│   ├── stellar-core-overlay/    # P2P networking
│   ├── stellar-core-scp/        # Consensus protocol
│   ├── stellar-core-herder/     # Coordination layer
│   ├── stellar-core-ledger/     # Ledger state management
│   └── stellar-core-tx/         # Transaction processing
├── SPEC.md                      # Detailed specification
└── DOCUMENTATION_ISSUES.md      # Feedback for stellar-core docs
```

Each crate has its own README with detailed documentation.

## Dependencies

### Stellar Crates

- `stellar-xdr` v25 - XDR type definitions
- `soroban-env-host` v25 - Soroban smart contract execution

### Key Dependencies

- `tokio` - Async runtime
- `axum` - HTTP server
- `ed25519-dalek` - Ed25519 signatures
- `sha2` - SHA-256 hashing
- `rusqlite` - SQLite database
- `reqwest` - HTTP client for archives
- `clap` - CLI parsing
- `tracing` - Structured logging

## Protocol Support

- **Supported**: Protocol 23+
- **Not Supported**: Pre-Protocol 23 (legacy)

This implementation only supports modern Stellar protocols. It cannot sync from genesis or process historical ledgers from before Protocol 23.

## Comparison with stellar-core

| Feature | stellar-core (C++) | rs-stellar-core (Rust) |
|---------|-------------------|------------------------|
| Full history | Yes | No (Protocol 23+ only) |
| Validator mode | Yes | Planned |
| PostgreSQL | Yes | No (SQLite only) |
| Production ready | Yes | No (research) |
| Pure implementation | No (uses libsodium) | Yes |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `cargo test --all`
4. Run clippy: `cargo clippy --all`
5. Submit a pull request

## License

Apache 2.0

## Acknowledgments

- Stellar Development Foundation for stellar-core and stellar-xdr
- The Rust community for excellent cryptographic crates
