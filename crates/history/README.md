# henyey-history

History archive access, catchup, replay, and publish support for Stellar Core.

## Overview

This crate provides infrastructure for interacting with Stellar history archives, enabling nodes to synchronize with the network by downloading and verifying historical ledger data.

### Key Capabilities

- **Archive Access**: Download ledger headers, transactions, results, and bucket files from HTTP-accessible history archives
- **Catchup**: Synchronize a node from genesis or a recent checkpoint to any target ledger
- **Replay**: Re-execute transactions to verify state transitions match expected hashes
- **Publishing**: Write checkpoint data to archives (for validators)
- **CDP Integration**: Fetch detailed `LedgerCloseMeta` from Composable Data Platform (SEP-0054)

## History Archive Structure

Stellar history archives organize data around **checkpoints** - snapshots taken every 64 ledgers (at sequences 63, 127, 191, ...).

```text
archive/
  .well-known/
    stellar-history.json          # Root HAS (latest checkpoint)
  history/
    00/00/00/
      history-0000003f.json       # HAS for checkpoint 63
      history-0000007f.json       # HAS for checkpoint 127
  ledger/
    00/00/00/
      ledger-0000003f.xdr.gz      # Ledger headers for checkpoint
  transactions/
    00/00/00/
      transactions-0000003f.xdr.gz
  results/
    00/00/00/
      results-0000003f.xdr.gz
  bucket/
    e1/13/f8/
      bucket-e113f8cc...fd.xdr.gz # Bucket file (by content hash)
```

## Key Types

| Type | Description |
|------|-------------|
| `HistoryArchive` | Client for accessing a single history archive |
| `HistoryManager` | Manages multiple archives with automatic failover |
| `HistoryArchiveManager` | Full archive manager with read/write capability tracking and config validation |
| `ArchiveEntry` | Single archive entry combining HTTP read and shell-command write capabilities |
| `HistoryArchiveState` | Parsed History Archive State (HAS) file |
| `CatchupManager` | Orchestrates the complete catchup process |
| `CatchupMode` | Catchup strategy: Minimal, Complete, or Recent(N) |
| `CatchupOutput` | Full catchup result including bucket list state and ledger header |
| `ReplayConfig` | Configuration for ledger replay and verification |
| `CheckpointBuilder` | Crash-safe checkpoint file builder using dirty-file-then-rename pattern |
| `PublishManager` | Publishes checkpoint data to archives |
| `PublishQueue` | SQLite-backed persistent queue for pending checkpoint publications |
| `RemoteArchive` | Shell-command-based archive upload client (put, mkdir) |
| `CdpDataLake` | Fetches LedgerCloseMeta from CDP (SEP-0054) |

## Quick Start

### Reading from an Archive

```rust
use henyey_history::archive::HistoryArchive;

async fn example() -> Result<(), henyey_history::HistoryError> {
    // Connect to a testnet archive
    let archive = HistoryArchive::new(
        "https://history.stellar.org/prd/core-testnet/core_testnet_001"
    )?;

    // Get current archive state
    let has = archive.get_root_has().await?;
    println!("Current ledger: {}", has.current_ledger());

    // Download ledger headers for a checkpoint
    let headers = archive.get_ledger_headers(63).await?;
    println!("Got {} ledger headers", headers.len());

    Ok(())
}
```

### Catching Up

```rust
use henyey_history::{CatchupManager, archive::HistoryArchive};
use henyey_bucket::BucketManager;
use henyey_db::Database;

async fn catchup_example() -> Result<(), henyey_history::HistoryError> {
    let archive = HistoryArchive::new(
        "https://history.stellar.org/prd/core-testnet/core_testnet_001"
    )?;
    let bucket_manager = BucketManager::new("/tmp/buckets".into());
    let db = Database::open_or_create("/tmp/stellar.db")?;

    let mut manager = CatchupManager::new(vec![archive], bucket_manager, db);
    let output = manager.catchup_to_ledger(1000000).await?;

    println!("Caught up to ledger {}", output.result.ledger_seq);
    println!("Downloaded {} buckets", output.result.buckets_downloaded);

    Ok(())
}
```

## Catchup Process

The catchup process follows these steps:

1. **Find checkpoint**: Locate the latest checkpoint <= target ledger
2. **Download HAS**: Fetch the History Archive State for that checkpoint
3. **Download buckets**: Fetch all bucket files referenced in the HAS
4. **Apply buckets**: Build initial ledger state from bucket entries
5. **Download ledger data**: Fetch headers, transactions, and results
6. **Verify chain**: Validate the cryptographic hash chain
7. **Replay ledgers**: Re-execute transactions from checkpoint to target

### Re-execution vs Metadata Replay

During catchup, we **re-execute** transactions against the bucket list rather than applying `TransactionMeta` directly. This approach:

- Works with traditional archives that don't include TransactionMeta
- Validates transaction set and result hashes against headers
- May produce slightly different internal results than original execution

For exact verification with TransactionMeta, use the CDP data source.

## Protocol 23+ State Archival

Starting with protocol 23, Stellar introduced state archival:

- **Live bucket list**: Active entries accessible by transactions
- **Hot archive bucket list**: Recently evicted entries that can be restored
- **Eviction scan**: Runs each ledger to move expired entries to hot archive
- **Combined hash**: `SHA256(live_hash || hot_archive_hash)`

The catchup and replay code handles both bucket lists automatically.

## Verification

All downloaded data is cryptographically verified:

1. **Bucket hashes**: `SHA256(content) == expected_hash`
2. **Header chain**: Each header's `previous_ledger_hash` matches previous header
3. **Transaction sets**: Hash matches `scp_value.tx_set_hash`
4. **Transaction results**: Hash matches `tx_set_result_hash`
5. **Bucket list**: Final hash matches `header.bucket_list_hash`

## Module Organization

```
src/
  lib.rs                # Crate root, HistoryManager, HistoryArchiveManager, CatchupMode/Output
  archive.rs            # HistoryArchive HTTP client
  archive_state.rs      # HAS JSON parsing/serialization
  catchup.rs            # CatchupManager orchestration
  cdp.rs                # CDP data lake client (SEP-0054)
  checkpoint.rs         # Checkpoint frequency, boundary, and range utilities
  checkpoint_builder.rs # Crash-safe checkpoint file construction
  download.rs           # HTTP download with retry, gzip decompression, XDR stream parsing
  error.rs              # HistoryError type
  paths.rs              # Archive URL path generation
  publish.rs            # PublishManager for validators
  publish_queue.rs      # SQLite-backed persistent publish queue
  remote_archive.rs     # Shell-command-based archive upload (put/mkdir)
  replay.rs             # Ledger replay and transaction re-execution
  verify.rs             # Cryptographic verification (hashes, header chains)
```

## stellar-core Mapping

This crate corresponds to these components in stellar-core:

- `src/history/` - History archive access and catchup
- `src/catchup/` - Catchup state machine
- `src/historywork/` - Download and verification workers

## Tests

Integration tests that require network access are in `tests/`. Unit tests are inline in each module.

```bash
# Run unit tests
cargo test -p henyey-history

# Run integration tests (requires network)
cargo test -p henyey-history --test '*'
```

## stellar-core Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed stellar-core parity analysis.
