# henyey

Main binary for henyey - a pure Rust implementation of Stellar Core.

## Overview

This crate provides:

- Command-line interface (CLI) for all node operations
- Thin wrapper around `henyey-app` for runtime orchestration
- Offline tools for XDR manipulation and replay testing

## Quick Start

```bash
# Run a node on testnet (default)
henyey --testnet run

# Catch up to the current ledger
henyey --testnet catchup current

# Generate a new keypair
henyey new-keypair

# Print sample configuration
henyey sample-config > config.toml
```

## Architecture

- CLI parsing builds a `Config` and dispatches to `henyey-app` commands
- Run modes (watcher/validator) initialize overlay, herder, ledger, and history subsystems
- Catchup and offline tooling reuse historywork/history pipelines for deterministic replay
- HTTP endpoints expose app state and control hooks (status, peers, surveys)

## Key Concepts

- **Run modes**: watcher vs validator, derived from config and CLI flags
- **Catchup modes**: minimal vs complete, controlled by checkpoint selection
- **Offline tools**: deterministic replay and XDR utilities for parity debugging

## CLI Usage

```bash
henyey [OPTIONS] <COMMAND>
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
henyey --testnet run

# Run as validator (participate in consensus)
henyey --testnet run --validator

# Run as watcher (observe only, no catchup)
henyey --testnet run --watcher

# Force catchup even if state exists
henyey --testnet run --force-catchup
```

#### catchup

Catch up from history archives:

```bash
# Catch up to current ledger
henyey --testnet catchup current

# Catch up to specific ledger
henyey --testnet catchup 1000000

# Minimal mode (fastest, only latest state)
henyey --testnet catchup current --mode minimal

# Complete mode (full history from genesis)
henyey --testnet catchup current --mode complete

# With parallel downloads
henyey --testnet catchup current --parallelism 16
```

The catchup command uses the historywork pipeline for checkpoint downloads
when available, falling back to direct archive fetches on failure.

#### new-db

Create a new database:

```bash
henyey --testnet new-db
henyey --testnet new-db --force  # Overwrite existing
henyey --testnet new-db /path/to/db.sqlite
```

#### upgrade-db

Upgrade database schema:

```bash
henyey --config config.toml upgrade-db
```

#### new-keypair

Generate a new node keypair:

```bash
henyey new-keypair
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
henyey --config config.toml info
```

#### verify-history

Verify history archives:

```bash
henyey --testnet verify-history
henyey --testnet verify-history --from 1000 --to 2000
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
henyey --config config.toml publish-history
henyey --config config.toml publish-history --force
```

Supports both local file archives and remote archives via shell commands.

#### check-quorum-intersection

Check quorum intersection from a JSON file:

```bash
henyey check-quorum-intersection network.json
```

Verifies that a network enjoys quorum intersection (all quorums share at least
one node). This is a critical safety property for SCP.

#### http-command

Send a command to a running stellar-core node's HTTP interface:

```bash
henyey http-command info
henyey http-command "peers?fullkeys=true"
henyey http-command "ll?level=DEBUG"
henyey http-command --port 11627 info
```

#### sample-config

Print sample configuration:

```bash
henyey sample-config
henyey sample-config > config.toml
```

#### offline

Offline utilities that don't require network access:

##### convert-key

Convert Stellar keys between formats. Supports public keys (`G...`), secret
seeds (`S...`), pre-auth transaction hashes (`T...`), SHA256 hashes (`X...`),
muxed accounts (`M...`), contract addresses (`C...`), signed payloads (`P...`),
and 64-character hex strings:

```bash
# Public key (G...) - shows strKey and hex
henyey offline convert-key GDKXE2OZM...

# Secret seed (S...) - shows seed and derived public key
henyey offline convert-key SB7BVQG...

# Contract address (C...)
henyey offline convert-key CAAAA...

# 64-char hex - shows all possible interpretations
henyey offline convert-key a1b2c3d4...
```

##### decode-xdr

Decode XDR from base64:

```bash
henyey offline decode-xdr --type LedgerHeader <base64>
henyey offline decode-xdr --type TransactionEnvelope <base64>
henyey offline decode-xdr --type TransactionResult <base64>
```

##### encode-xdr

Encode values to XDR (output as base64). Supported types: `AccountId`,
`MuxedAccount`, `Asset`, `Hash`, `Uint256`, `LedgerHeader`,
`TransactionEnvelope`, `TransactionResult`. Simple types accept string values;
complex types accept JSON:

```bash
henyey offline encode-xdr --type AccountId GDKXE2OZM...
henyey offline encode-xdr --type Asset "USD:GDKXE2OZM..."
henyey offline encode-xdr --type Asset native
henyey offline encode-xdr --type Hash <64-char-hex>
henyey offline encode-xdr --type LedgerHeader '<json>'
```

##### bucket-info

Print bucket file/directory information:

```bash
henyey offline bucket-info /path/to/buckets
henyey offline bucket-info /path/to/bucket.xdr
```

##### replay-bucket-list

Test bucket list implementation by replaying ledger changes from CDP:

```bash
# Test recent ledgers
henyey --testnet offline replay-bucket-list

# Test a specific ledger range
henyey --testnet offline replay-bucket-list --from 310000 --to 311000

# Stop on first mismatch
henyey --testnet offline replay-bucket-list --stop-on-error

# Test only live bucket list (ignore hot archive)
henyey --testnet offline replay-bucket-list --live-only
```

This validates bucket list implementation (spills, merges, hash computation)
using exact ledger changes from CDP metadata.

##### verify-execution

Test transaction execution by comparing results against CDP:

```bash
# Test recent ledgers
henyey --testnet offline verify-execution

# Test a specific range
henyey --testnet offline verify-execution --from 310000 --to 311000

# Stop on first mismatch with detailed diff
henyey --testnet offline verify-execution --stop-on-error --show-diff
```

This re-executes transactions and compares the resulting ledger entry changes
against what stellar-core produced (from CDP).

##### debug-bucket-entry

Inspect a specific account in the bucket list:

```bash
henyey --testnet offline debug-bucket-entry \
  --checkpoint 310000 \
  --account a1b2c3d4e5f6...  # 64-char hex
```

##### sign-transaction

Add a signature to a transaction envelope (equivalent to stellar-core `sign-transaction`):

```bash
# Sign from base64 string (prompts for secret key on stdin)
henyey offline sign-transaction \
  --netid "Test SDF Network ; September 2015" \
  <base64-envelope>

# Read envelope from stdin
echo "<base64>" | henyey offline sign-transaction \
  --netid "Test SDF Network ; September 2015" -
```

##### sec-to-pub

Print the public key corresponding to a secret key (reads from stdin):

```bash
echo "SB7BVQG..." | henyey offline sec-to-pub
```

##### dump-ledger

Dump ledger entries from the bucket list to a JSON file:

```bash
# Dump all entries
henyey --testnet offline dump-ledger --output entries.json

# Filter by entry type
henyey --testnet offline dump-ledger --output accounts.json --entry-type account

# Limit output count
henyey --testnet offline dump-ledger --output entries.json --limit 1000

# Only entries modified in the last N ledgers
henyey --testnet offline dump-ledger --output entries.json --last-modified-ledger-count 100
```

Supported entry types: `account`, `trustline`, `offer`, `data`,
`claimable_balance`, `liquidity_pool`, `contract_data`, `contract_code`,
`config_setting`, `ttl`.

##### self-check

Perform diagnostic self-checks on the local database and buckets:

```bash
henyey --testnet offline self-check
```

Checks performed:
- Header chain verification (hash linkage across ledgers)
- Bucket hash verification (all bucket files have correct hashes)
- Crypto benchmarking (Ed25519 sign/verify performance)

##### verify-checkpoints

Download and verify checkpoint headers from history archives, then write
verified hashes to a JSON file:

```bash
henyey --testnet offline verify-checkpoints --output checkpoints.json
henyey --testnet offline verify-checkpoints --output checkpoints.json --from 63 --to 10000
```

The output file can be used with `--trusted-checkpoint-hashes` during catchup
to verify against known-good hashes.

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
| `/ll` | GET/POST | Dynamic log level changes (query: `level`) |
| `/sorobaninfo` | GET | Soroban network configuration |
| `/manualclose` | POST | Manual ledger close (requires validator + manual_close config) |
| `/clearmetrics` | POST | Request metrics clearing |
| `/logrotate` | POST | Request log rotation |
| `/maintenance` | POST | Manual database maintenance (cleans old SCP/ledger history) |
| `/dumpproposedsettings` | GET | Returns ConfigUpgradeSet from ledger |

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
henyey --verbose run

# Trace output (most verbose)
henyey --trace run

# JSON format (for log aggregation)
henyey --log-format json run

# Filter by module with RUST_LOG
RUST_LOG=henyey_overlay=debug henyey run
RUST_LOG=henyey_ledger=trace,henyey_tx=debug henyey run
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
- Contains exact transaction metadata from stellar-core
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

## stellar-core Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed stellar-core parity analysis.

## License

Apache 2.0
