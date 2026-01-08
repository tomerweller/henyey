# rs-stellar-core

A Rust reimplementation of [Stellar Core](https://github.com/stellar/stellar-core) focused on protocol v25 behavior and testnet sync. This is an educational experiment and **not** production-grade software.

## What is Stellar Core?

Stellar Core is the backbone of the [Stellar network](https://stellar.org)—a decentralized payment network. It:

- Validates and processes transactions
- Participates in consensus via the [Stellar Consensus Protocol (SCP)](https://stellar.org/papers/stellar-consensus-protocol)
- Maintains the ledger state (accounts, balances, trustlines, offers, contracts)
- Synchronizes with history archives for catchup and verification

This Rust implementation aims to mirror stellar-core v25.x behavior for educational purposes and to provide an alternative implementation for testing and validation.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              rs-stellar-core                                │
│                           (CLI + entrypoint)                                │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            stellar-core-app                                 │
│                    (orchestration, config, commands)                        │
└─────────────────────────────────────────────────────────────────────────────┘
           │                         │                         │
           ▼                         ▼                         ▼
┌─────────────────┐     ┌─────────────────────┐     ┌─────────────────────────┐
│    overlay      │     │       herder        │     │        history          │
│  (P2P network)  │◄───►│ (consensus coord)   │     │  (archive catchup)      │
└─────────────────┘     └─────────────────────┘     └─────────────────────────┘
                                  │                            │
                                  ▼                            │
                        ┌─────────────────┐                    │
                        │       scp       │                    │
                        │   (consensus)   │                    │
                        └─────────────────┘                    │
                                  │                            │
                                  ▼                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ledger                                         │
│                    (ledger close + state updates)                           │
└─────────────────────────────────────────────────────────────────────────────┘
           │                         │                         │
           ▼                         ▼                         ▼
┌─────────────────┐     ┌─────────────────────┐     ┌─────────────────────────┐
│       tx        │     │       bucket        │     │           db            │
│  (transaction   │     │    (BucketList      │     │       (SQLite           │
│   execution)    │     │     state store)    │     │      persistence)       │
└─────────────────┘     └─────────────────────┘     └─────────────────────────┘
           │
           ▼
┌─────────────────┐
│    invariant    │
│   (validation)  │
└─────────────────┘

Supporting crates: crypto, common, work, historywork, simulation
```

## Status

**Work in progress.** Core functionality is implemented:

- Testnet catchup and sync (observer mode)
- SCP consensus participation (validator mode)
- Transaction execution (classic + Soroban)
- History archive replay and verification
- BucketList state management

See [`PARITY_GAPS.md`](PARITY_GAPS.md) for the detailed, module-by-module gap list.

## C++ Parity Summary

Each crate has been analyzed against its C++ upstream counterpart. The table below summarizes implementation status and key gaps:

| Crate | Status | Key Gaps |
|-------|--------|----------|
| [`stellar-core-bucket`](crates/stellar-core-bucket/README.md) | Core implemented | FutureBucket, HotArchiveBucket, BucketSnapshotManager |
| [`stellar-core-overlay`](crates/stellar-core-overlay/README.md) | Core implemented | FlowControl, ItemFetcher, BanManager persistence |
| [`stellar-core-common`](crates/stellar-core-common/README.md) | Core implemented | VirtualClock, logging system, math utilities |
| [`stellar-core-db`](crates/stellar-core-db/README.md) | Core implemented | PostgreSQL support, query timers, data cleanup |
| [`stellar-core-crypto`](crates/stellar-core-crypto/README.md) | Core implemented | BLAKE2, HMAC-SHA256, signature cache |
| [`stellar-core-herder`](crates/stellar-core-herder/README.md) | Core implemented | Timer management, persistence, upgrades system |
| [`stellar-core-work`](crates/stellar-core-work/README.md) | Core implemented | BatchWork, ConditionalWork, VirtualClock integration |
| [`stellar-core-app`](crates/stellar-core-app/README.md) | Core implemented | Various CLI commands, Maintainer |
| [`stellar-core-scp`](crates/stellar-core-scp/README.md) | Full protocol | State recovery, JSON output |
| [`stellar-core-simulation`](crates/stellar-core-simulation/README.md) | Basic implemented | Multiple topologies, LoadGenerator |
| [`stellar-core-historywork`](crates/stellar-core-historywork/README.md) | Core implemented | BatchDownloadWork, VerifyBucketWork |
| [`stellar-core-invariant`](crates/stellar-core-invariant/README.md) | 16 invariants | BucketListIsConsistentWithDatabase |
| [`stellar-core-history`](crates/stellar-core-history/README.md) | Core implemented | Persistent publish queue, CheckpointBuilder ACID |
| [`stellar-core-tx`](crates/stellar-core-tx/README.md) | All 27 operations | SignatureChecker, TransactionMetaBuilder |
| [`stellar-core-ledger`](crates/stellar-core-ledger/README.md) | Core implemented | Nested LedgerTxn, parallel apply, module cache |
| [`rs-stellar-core`](crates/rs-stellar-core/README.md) | Core commands | Various diagnostic commands |

**Architectural Note**: The main pattern difference across crates is async Rust (Tokio) vs C++'s ASIO/VirtualClock. This affects timer management and asynchronous operation handling throughout.

See each crate's README for detailed parity documentation including implemented features, gaps with priority ratings, and implementation notes.

## Requirements

- **Rust**: 1.75+ (2021 edition)
- **SQLite**: System library (usually pre-installed)
- **Platform**: Linux, macOS (Windows untested)

## Build

```bash
cargo build --release
```

The binary is at `./target/release/rs-stellar-core`.

## Test

```bash
# Run all tests
cargo test --all

# Run tests for a specific crate
cargo test -p stellar-core-scp

# Run with output
cargo test --all -- --nocapture
```

## Run

### Observer Mode (Testnet)

An observer syncs the ledger without participating in consensus:

```bash
# Catch up to current ledger
./target/release/rs-stellar-core --config configs/testnet.toml catchup current

# Run and follow the network
./target/release/rs-stellar-core --config configs/testnet.toml run
```

### Validator Mode (Testnet)

A validator participates in consensus. Requires a secret key and quorum configuration:

```bash
# Use the validator config
./target/release/rs-stellar-core --config configs/validator-testnet.toml catchup current
./target/release/rs-stellar-core --config configs/validator-testnet.toml run
```

### Mainnet

```bash
./target/release/rs-stellar-core --config configs/mainnet.toml catchup current
./target/release/rs-stellar-core --config configs/mainnet.toml run
```

## Configuration

Generate a sample config to customize:

```bash
./target/release/rs-stellar-core sample-config > my-config.toml
```

### Key Configuration Options

```toml
[network]
network_passphrase = "Test SDF Network ; September 2015"

[database]
path = "stellar.db"

[overlay]
listen_port = 11625
max_inbound_peers = 64
max_outbound_peers = 8

[history]
# Archive URLs for catchup
archives = [
    "https://history.stellar.org/prd/core-testnet/core_testnet_001",
    "https://history.stellar.org/prd/core-testnet/core_testnet_002",
]

[validator]
# Required for validator mode
node_seed = "S..."  # Your secret key
node_is_validator = true

[events]
# Classic event emission (off by default)
emit_classic_events = true
backfill_stellar_asset_events = false
```

## Repository Layout

```
rs-stellar-core/
├── crates/
│   ├── rs-stellar-core/          # CLI binary
│   ├── stellar-core-app/         # App orchestration
│   ├── stellar-core-overlay/     # P2P networking
│   ├── stellar-core-scp/         # Consensus protocol
│   ├── stellar-core-herder/      # Consensus coordination
│   ├── stellar-core-ledger/      # Ledger close pipeline
│   ├── stellar-core-tx/          # Transaction execution
│   ├── stellar-core-bucket/      # BucketList state
│   ├── stellar-core-history/     # History archives
│   ├── stellar-core-historywork/ # History work scheduling
│   ├── stellar-core-db/          # SQLite persistence
│   ├── stellar-core-crypto/      # Cryptographic primitives
│   ├── stellar-core-common/      # Shared types
│   ├── stellar-core-invariant/   # Ledger invariants
│   ├── stellar-core-work/        # Work scheduler
│   └── stellar-core-simulation/  # Test harness
├── configs/                      # Example configurations
└── PARITY_GAPS.md               # Parity tracking
```

## Crate Overview

### Core Infrastructure

| Crate | Purpose |
|-------|---------|
| [`rs-stellar-core`](crates/rs-stellar-core/README.md) | CLI entrypoint, argument parsing, command dispatch |
| [`stellar-core-app`](crates/stellar-core-app/README.md) | Application wiring, lifecycle management, run/catchup orchestration |
| [`stellar-core-common`](crates/stellar-core-common/README.md) | Shared types, config helpers, time utilities |
| [`stellar-core-crypto`](crates/stellar-core-crypto/README.md) | Ed25519 signing, SHA-256 hashing, strkey encoding |
| [`stellar-core-db`](crates/stellar-core-db/README.md) | SQLite schema, migrations, query layer |

### Consensus Layer

| Crate | Purpose |
|-------|---------|
| [`stellar-core-scp`](crates/stellar-core-scp/README.md) | Stellar Consensus Protocol: nomination, balloting, quorum logic |
| [`stellar-core-herder`](crates/stellar-core-herder/README.md) | Consensus coordination, transaction queue, ledger close triggers |
| [`stellar-core-overlay`](crates/stellar-core-overlay/README.md) | P2P overlay network, peer management, message flooding |

### Execution Layer

| Crate | Purpose |
|-------|---------|
| [`stellar-core-ledger`](crates/stellar-core-ledger/README.md) | Ledger close pipeline, state snapshots, delta tracking |
| [`stellar-core-tx`](crates/stellar-core-tx/README.md) | Transaction validation and execution (classic + Soroban) |
| [`stellar-core-bucket`](crates/stellar-core-bucket/README.md) | BucketList implementation, merges, on-disk state |
| [`stellar-core-invariant`](crates/stellar-core-invariant/README.md) | Ledger transition validation, consistency checks |

### History & Sync

| Crate | Purpose |
|-------|---------|
| [`stellar-core-history`](crates/stellar-core-history/README.md) | History archive I/O, catchup, replay, verification |
| [`stellar-core-historywork`](crates/stellar-core-historywork/README.md) | History work scheduling, publish/catchup task management |

### Utilities

| Crate | Purpose |
|-------|---------|
| [`stellar-core-work`](crates/stellar-core-work/README.md) | Generic DAG-based work scheduler |
| [`stellar-core-simulation`](crates/stellar-core-simulation/README.md) | Deterministic test harness for overlay/SCP testing |

## Design Constraints

This implementation intentionally limits scope:

| Constraint | Rationale |
|------------|-----------|
| **Protocol 23+ only** | Focus on current protocol behavior |
| **SQLite-only** | Simplicity over PostgreSQL support |
| **No metrics** | Prometheus integration out of scope |
| **No admin API** | HTTP admin interface not implemented |
| **Deterministic** | Observable behavior must match upstream |

## Development

### Running Integration Tests

```bash
# History replay tests (requires network)
cargo test -p stellar-core-history --test replay_integration

# Catchup integration tests
cargo test -p stellar-core-history --test catchup_integration
```

### Debugging

```bash
# Enable trace logging
RUST_LOG=trace ./target/release/rs-stellar-core --config configs/testnet.toml run

# Log specific modules
RUST_LOG=stellar_core_scp=debug,stellar_core_herder=debug ./target/release/rs-stellar-core ...
```

### Adding a New Crate

1. Create `crates/stellar-core-<name>/`
2. Add to workspace in root `Cargo.toml`
3. Add README.md documenting purpose and usage
4. Update this file's crate overview

## Related Resources

- [stellar-core (C++)](https://github.com/stellar/stellar-core) — Upstream implementation
- [Stellar Docs](https://developers.stellar.org/) — Protocol documentation
- [SCP Whitepaper](https://stellar.org/papers/stellar-consensus-protocol) — Consensus protocol specification
- [stellar-xdr](https://github.com/stellar/stellar-xdr-next) — XDR type definitions

## Contributing

- Keep behavior deterministic and aligned with stellar-core v25.x
- Add or update tests when behavior changes
- Update crate READMEs when modifying subsystem behavior
- Run `cargo fmt` and `cargo clippy` before committing

## License

Apache 2.0
