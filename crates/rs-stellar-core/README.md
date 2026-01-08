# rs-stellar-core

Main binary for rs-stellar-core - a pure Rust implementation of Stellar Core.

## Overview

This crate provides:

- Command-line interface (CLI) for all node operations
- Thin wrapper around `stellar-core-app` for runtime orchestration
- Offline tools for XDR manipulation and replay testing

## Quick Start

```bash
# Run a node on testnet (default)
rs-stellar-core --testnet run

# Catch up to the current ledger
rs-stellar-core --testnet catchup current

# Generate a new keypair
rs-stellar-core new-keypair

# Print sample configuration
rs-stellar-core sample-config > config.toml
```

## Architecture

- CLI parsing builds a `Config` and dispatches to `stellar-core-app` commands
- Run modes (watcher/validator) initialize overlay, herder, ledger, and history subsystems
- Catchup and offline tooling reuse historywork/history pipelines for deterministic replay
- HTTP endpoints expose app state and control hooks (status, peers, surveys)

## Key Concepts

- **Run modes**: watcher vs validator, derived from config and CLI flags
- **Catchup modes**: minimal vs complete, controlled by checkpoint selection
- **Offline tools**: deterministic replay and XDR utilities for parity debugging

## CLI Usage

```bash
rs-stellar-core [OPTIONS] <COMMAND>
```

### Global Options

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Path to configuration file |
| `-v, --verbose` | Enable verbose logging (debug level) |
| `--trace` | Enable trace logging (most verbose) |
| `--log-format <FORMAT>` | Log format: `text` or `json` |
| `--testnet` | Use testnet configuration |
| `--mainnet` | Use mainnet configuration |

### Commands

#### run

Start the node:

```bash
# Run with testnet defaults
rs-stellar-core --testnet run

# Run as validator (participate in consensus)
rs-stellar-core --testnet run --validator

# Run as watcher (observe only, no catchup)
rs-stellar-core --testnet run --watcher

# Force catchup even if state exists
rs-stellar-core --testnet run --force-catchup
```

#### catchup

Catch up from history archives:

```bash
# Catch up to current ledger
rs-stellar-core --testnet catchup current

# Catch up to specific ledger
rs-stellar-core --testnet catchup 1000000

# Minimal mode (fastest, only latest state)
rs-stellar-core --testnet catchup current --mode minimal

# Complete mode (full history from genesis)
rs-stellar-core --testnet catchup current --mode complete

# With parallel downloads
rs-stellar-core --testnet catchup current --parallelism 16
```

The catchup command uses the historywork pipeline for checkpoint downloads
when available, falling back to direct archive fetches on failure.

#### new-db

Create a new database:

```bash
rs-stellar-core --testnet new-db
rs-stellar-core --testnet new-db --force  # Overwrite existing
rs-stellar-core --testnet new-db /path/to/db.sqlite
```

#### upgrade-db

Upgrade database schema:

```bash
rs-stellar-core --config config.toml upgrade-db
```

#### new-keypair

Generate a new node keypair:

```bash
rs-stellar-core new-keypair
```

Output:
```
Generated new keypair:

Public Key:  GDKXE2OZM...
Secret Seed: SB7BVQG...

IMPORTANT: Store the secret seed securely! It cannot be recovered.
```

#### info

Print node information:

```bash
rs-stellar-core --config config.toml info
```

#### verify-history

Verify history archives:

```bash
rs-stellar-core --testnet verify-history
rs-stellar-core --testnet verify-history --from 1000 --to 2000
```

Checks:
- HAS (History Archive State) structure validity
- Checkpoint ledger hash chains
- Transaction set hashes
- Transaction result hashes
- SCP history entries

#### publish-history

Publish history to archives (validators only):

```bash
rs-stellar-core --config config.toml publish-history
rs-stellar-core --config config.toml publish-history --force
```

Supports both local file archives and remote archives via shell commands.

#### check-quorum-intersection

Check quorum intersection from a JSON file:

```bash
rs-stellar-core check-quorum-intersection network.json
```

Verifies that a network enjoys quorum intersection (all quorums share at least
one node). This is a critical safety property for SCP.

#### sample-config

Print sample configuration:

```bash
rs-stellar-core sample-config
rs-stellar-core sample-config > config.toml
```

#### offline

Offline utilities that don't require network access:

##### convert-key

Convert key formats:

```bash
# StrKey to hex
rs-stellar-core offline convert-key GDKXE2OZM...

# Hex to strkey
rs-stellar-core offline convert-key a1b2c3d4...
```

##### decode-xdr

Decode XDR from base64:

```bash
rs-stellar-core offline decode-xdr --type LedgerHeader <base64>
rs-stellar-core offline decode-xdr --type TransactionEnvelope <base64>
rs-stellar-core offline decode-xdr --type TransactionResult <base64>
```

##### encode-xdr

Encode values to XDR:

```bash
rs-stellar-core offline encode-xdr --type AccountId GDKXE2OZM...
rs-stellar-core offline encode-xdr --type Asset "USD:GDKXE2OZM..."
rs-stellar-core offline encode-xdr --type Asset native
rs-stellar-core offline encode-xdr --type Hash <64-char-hex>
```

##### bucket-info

Print bucket file/directory information:

```bash
rs-stellar-core offline bucket-info /path/to/buckets
rs-stellar-core offline bucket-info /path/to/bucket.xdr
```

##### replay-bucket-list

Test bucket list implementation by replaying ledger changes from CDP:

```bash
# Test recent ledgers
rs-stellar-core --testnet offline replay-bucket-list

# Test a specific ledger range
rs-stellar-core --testnet offline replay-bucket-list --from 310000 --to 311000

# Stop on first mismatch
rs-stellar-core --testnet offline replay-bucket-list --stop-on-error

# Test only live bucket list (ignore hot archive)
rs-stellar-core --testnet offline replay-bucket-list --live-only
```

This validates bucket list implementation (spills, merges, hash computation)
using exact ledger changes from CDP metadata.

##### verify-execution

Test transaction execution by comparing results against CDP:

```bash
# Test recent ledgers
rs-stellar-core --testnet offline verify-execution

# Test a specific range
rs-stellar-core --testnet offline verify-execution --from 310000 --to 311000

# Stop on first mismatch with detailed diff
rs-stellar-core --testnet offline verify-execution --stop-on-error --show-diff
```

This re-executes transactions and compares the resulting ledger entry changes
against what C++ stellar-core produced (from CDP).

##### debug-bucket-entry

Inspect a specific account in the bucket list:

```bash
rs-stellar-core --testnet offline debug-bucket-entry \
  --checkpoint 310000 \
  --account a1b2c3d4e5f6...  # 64-char hex
```

## HTTP API

When running, the node exposes an HTTP API (default port 11626):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API overview |
| `/info` | GET | Node information |
| `/status` | GET | Node status summary |
| `/metrics` | GET | Prometheus metrics |
| `/peers` | GET | Connected peers |
| `/connect` | POST | Connect to peer (query: `addr` or `peer`+`port`) |
| `/droppeer` | POST | Disconnect peer (query: `peer_id` or `node`, optional `ban=1`) |
| `/bans` | GET | List banned peers |
| `/unban` | POST | Remove peer from ban list (query: `peer_id` or `node`) |
| `/ledger` | GET | Current ledger |
| `/upgrades` | GET | Current + proposed upgrade settings |
| `/self-check` | POST | Run ledger self-check |
| `/quorum` | GET | Local quorum set summary |
| `/survey` | GET | Survey report |
| `/scp` | GET | SCP slot summary (query: `limit`) |
| `/survey/start` | POST | Start survey collecting (query: `nonce`) |
| `/survey/stop` | POST | Stop survey collecting |
| `/survey/topology` | POST | Queue survey topology request |
| `/survey/reporting/stop` | POST | Stop survey reporting |
| `/tx` | POST | Submit transaction |
| `/shutdown` | POST | Request graceful shutdown |
| `/health` | GET | Health check |

### Example Usage

Submit a transaction:
```bash
curl -X POST http://localhost:11626/tx \
  -H "Content-Type: application/json" \
  -d '{"tx": "<base64-xdr>"}'
```

Check health:
```bash
curl http://localhost:11626/health
```

Get node info:
```bash
curl http://localhost:11626/info
```

## Configuration

Configuration can be provided via:
- TOML file (`--config <FILE>`)
- Built-in network defaults (`--testnet` or `--mainnet`)
- Environment variables (prefixed with `STELLAR_`)

### Example Configuration

```toml
[node]
name = "my-node"
is_validator = false

[network]
passphrase = "Test SDF Network ; September 2015"

[database]
path = "stellar.db"

[http]
port = 11626
enabled = true

[buckets]
directory = "buckets"
cache_size = 100  # Number of buckets to cache in memory

[history]
[[history.archives]]
name = "sdf-testnet"
url = "https://history.stellar.org/prd/core-testnet/core_testnet_001"
get = true
put = false

[peers]
known = [
    "core-testnet1.stellar.org:11625",
    "core-testnet2.stellar.org:11625",
]

[quorum]
threshold = 2
validators = [
    "GDKXE2OZM...",
    "GCEZWKCA5...",
    "GBLJNN7HG...",
]
```

### Environment Variables

Override configuration values with environment variables:

| Variable | Description |
|----------|-------------|
| `STELLAR_DATABASE_PATH` | Database file path |
| `STELLAR_HTTP_PORT` | HTTP server port |
| `STELLAR_NODE_NAME` | Node name |
| `STELLAR_NETWORK_PASSPHRASE` | Network passphrase |

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Database error |
| 4 | Network error |

## Logging

Logs use the `tracing` framework with configurable levels and formats:

```bash
# Verbose output (debug level)
rs-stellar-core --verbose run

# Trace output (most verbose)
rs-stellar-core --trace run

# JSON format (for log aggregation)
rs-stellar-core --log-format json run

# Filter by module with RUST_LOG
RUST_LOG=stellar_core_overlay=debug rs-stellar-core run
RUST_LOG=stellar_core_ledger=trace,stellar_core_tx=debug rs-stellar-core run
```

## Debugging Tips

### Hash Mismatch Investigation

When ledger hashes don't match the network:

1. Use `offline verify-execution` to compare transaction execution
2. Use `offline replay-bucket-list` to isolate bucket list vs execution issues
3. Use `offline debug-bucket-entry` to inspect specific accounts
4. Use the header_compare binary for detailed header field comparison

### CDP Data Lake

The verification tools use CDP (Crypto Data Platform) for ground truth:
- Contains exact transaction metadata from C++ stellar-core
- Partitioned by date for historical access
- Default URL points to AWS public testnet data

If you see "epoch mismatch" errors, the network may have been reset since the
CDP date. Try a more recent CDP date or switch to mainnet.

## Source Files

- `src/main.rs` - CLI entry point and command handlers
- `src/quorum_intersection.rs` - Quorum intersection analysis
- `src/bin/header_compare.rs` - Header comparison debugging tool

## Dependencies

- `clap` - CLI argument parsing
- `axum` - HTTP server
- `tokio` - Async runtime
- `tracing` - Structured logging
- `serde` - Configuration serialization
- All `stellar-core-*` library crates

## License

Apache 2.0
