# stellar-core-history

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
| `HistoryArchiveState` | Parsed History Archive State (HAS) file |
| `CatchupManager` | Orchestrates the complete catchup process |
| `ReplayConfig` | Configuration for ledger replay and verification |
| `PublishManager` | Publishes checkpoint data to archives |
| `CdpDataLake` | Fetches LedgerCloseMeta from CDP (SEP-0054) |

## Quick Start

### Reading from an Archive

```rust
use stellar_core_history::archive::HistoryArchive;

async fn example() -> Result<(), stellar_core_history::HistoryError> {
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
use stellar_core_history::{CatchupManager, archive::HistoryArchive};
use stellar_core_bucket::BucketManager;
use stellar_core_db::Database;

async fn catchup_example() -> Result<(), stellar_core_history::HistoryError> {
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
  lib.rs           # Crate root with main type re-exports
  archive.rs       # HistoryArchive client
  archive_state.rs # HAS parsing
  catchup.rs       # CatchupManager
  cdp.rs           # CDP data lake client (SEP-0054)
  checkpoint.rs    # Checkpoint utilities
  download.rs      # HTTP download with retry logic
  error.rs         # Error types
  paths.rs         # Archive URL path generation
  publish.rs       # PublishManager for validators
  replay.rs        # Ledger replay functions
  verify.rs        # Cryptographic verification
```

## Upstream Mapping

This crate corresponds to these components in C++ stellar-core:

- `src/history/` - History archive access and catchup
- `src/catchup/` - Catchup state machine
- `src/historywork/` - Download and verification workers

## Tests

Integration tests that require network access are in `tests/`. Unit tests are inline in each module.

```bash
# Run unit tests
cargo test -p stellar-core-history

# Run integration tests (requires network)
cargo test -p stellar-core-history --test '*'
```

## C++ Parity Status

This section documents the parity between this Rust crate and its C++ upstream counterpart in `stellar-core/src/history/`.

### Implemented

#### Core Archive Access
- [x] `HistoryArchive` - HTTP client for fetching archive data (corresponds to parts of C++ `HistoryArchive`)
- [x] `HistoryManager` - Multi-archive access with failover (similar to C++ `HistoryArchiveManager::selectRandomReadableHistoryArchive`)
- [x] `HistoryArchiveState` - HAS file parsing/serialization with full JSON support
- [x] Hot archive bucket support (protocol 23+ `hotArchiveBuckets`)
- [x] Network passphrase field in HAS (version 2 format)

#### Path Generation
- [x] Checkpoint path computation (`checkpoint_path`, `bucket_path`)
- [x] Checkpoint frequency (64 ledgers)
- [x] Checkpoint ledger calculations (`checkpoint_ledger`, `is_checkpoint_ledger`, `checkpoint_containing`)
- [x] HAS path generation (`.well-known/stellar-history.json` and per-checkpoint paths)

#### Download Infrastructure
- [x] HTTP download with configurable retries and timeouts
- [x] Gzip decompression for archive files
- [x] XDR stream parsing (record-marked format per RFC 5531)
- [x] Bucket file download by hash

#### Catchup
- [x] `CatchupManager` - Full catchup orchestration
- [x] Bucket download and application to BucketList
- [x] Ledger header/transaction/result download
- [x] Header chain verification
- [x] Transaction set hash verification
- [x] Transaction result set hash verification
- [x] Bucket list hash verification at checkpoints
- [x] Pre-downloaded checkpoint data support (`catchup_to_ledger_with_checkpoint_data`)
- [x] Progress tracking with status callbacks (`CatchupProgress`, `CatchupStatus`)
- [x] Disk-backed bucket storage for memory efficiency

#### Replay
- [x] Transaction re-execution replay (`replay_ledger_with_execution`)
- [x] TransactionMeta-based replay (`replay_ledger`)
- [x] Eviction iterator tracking (protocol 23+)
- [x] Hot archive bucket list updates during eviction
- [x] Invariant verification during replay
- [x] Combined bucket list hash computation (live + hot archive)

#### Publishing
- [x] `PublishManager` - Checkpoint publishing to local directory
- [x] Ledger header, transaction, and result file writing
- [x] Bucket file publishing
- [x] HAS file generation
- [x] Directory structure creation following archive layout

#### Verification
- [x] Header chain verification
- [x] Bucket hash verification
- [x] Transaction set hash verification (classic and generalized)
- [x] Transaction result set hash verification
- [x] HAS structure validation
- [x] SCP history entry verification

#### CDP Integration
- [x] `CdpDataLake` - SEP-0054 compliant data lake client
- [x] LedgerCloseMeta fetching and parsing
- [x] Transaction metadata extraction
- [x] Evicted keys extraction (V2 format)
- [x] Upgrade metadata extraction

### Not Yet Implemented (Gaps)

#### HistoryManager / Publishing Queue
- [ ] **Persistent publish queue** - C++ uses SQL database to persist checkpoints queued for publication (`publishQueueLength`, `getMinLedgerQueuedToPublish`, `getMaxLedgerQueuedToPublish`). Rust only supports immediate local directory publishing.
- [ ] **Publish queue migration** - `dropSQLBasedPublish()` for migrating old SQL-based queue format
- [ ] **Missing bucket recovery** - `getMissingBucketsReferencedByPublishQueue()` to identify buckets needed from archives before publishing can resume
- [ ] **Publication success/failure tracking** - Metrics for `getPublishSuccessCount()`, `getPublishFailureCount()`
- [ ] **Publication callback** - `historyPublished()` callback mechanism for successful/failed publication

#### CheckpointBuilder
- [ ] **ACID transactional checkpoint building** - C++ `CheckpointBuilder` provides crash-safe checkpoint construction with dirty files and atomic rename. Rust writes directly without crash recovery.
- [ ] **Incremental transaction appending** - C++ appends transactions/results ledger-by-ledger during close. Rust requires all data upfront.
- [ ] **Checkpoint restoration** - `restoreCheckpoint(lcl)` to recover publish state after crash based on LCL
- [ ] **Dirty file cleanup** - `cleanup(lcl)` to remove uncommitted publish data

#### HistoryArchive Operations
- [ ] **Archive initialization** - `initializeHistoryArchive()` to create `.well-known/stellar-history.json` in new archive
- [ ] **Remote put/mkdir commands** - C++ supports configurable shell commands for remote upload (`putFileCmd`, `mkdirCmd`). Rust only writes to local filesystem.
- [ ] **Get/put/mkdir command templating** - Config-based command templates with `{0}` and `{1}` placeholders for files

#### Archive Manager
- [ ] **Writable archive detection** - `publishEnabled()`, `getWritableHistoryArchives()` based on configured get/put commands
- [ ] **Archive configuration validation** - `checkSensibleConfig()` for validating archive setup
- [ ] **History archive reporting work** - `getHistoryArchiveReportWork()` to check last-published checkpoint on each archive
- [ ] **Ledger header verification work** - `getCheckLedgerHeaderWork()` to verify header against archives

#### StateSnapshot
- [ ] **SCP message writing** - `writeSCPMessages()` for including SCP history in snapshots
- [ ] **Differing HAS file computation** - `differingHASFiles()` to compute what files need uploading vs existing archive state

#### FutureBucket Support
- [ ] **In-progress merge tracking** - HAS `next` field with `state` and `output` for async bucket merges. Rust parses but ignores merge state.
- [ ] **Future resolution** - `resolveAllFutures()`, `resolveAnyReadyFutures()` for completing pending bucket merges

#### Ledger/Transaction History Utilities
- [ ] **Gap handling in history streams** - `getHistoryEntryForLedger()` template for iterating history entries with gaps

#### Testing Support
- [ ] **Publication enable/disable** - `setPublicationEnabled(bool)` for testing
- [ ] **Throw-on-append testing** - `mThrowOnAppend` for crash testing

### Implementation Notes

#### Architectural Differences

1. **Async Model**: The Rust implementation uses `async/await` with Tokio, while C++ uses a Work-based state machine pattern. The Rust approach is more idiomatic for async Rust code but doesn't map 1:1 to C++ Work classes.

2. **Database Integration**: C++ integrates deeply with its SQL database for persistent state (publish queue, archive state). The Rust implementation is more standalone, using the `stellar-core-db` crate only for ledger history storage.

3. **Remote Publishing**: C++ supports configurable shell commands for remote archive access (S3, GCS, etc.). Rust currently only writes to local filesystem; remote upload would need to be handled externally or via a separate upload utility.

4. **Crash Safety**: C++ `CheckpointBuilder` implements careful ACID-like semantics with dirty files and atomic renames. Rust's `PublishManager` writes files directly without explicit crash recovery logic.

5. **Metrics**: C++ uses the Medida library for publish success/failure metrics. Rust doesn't yet have equivalent instrumentation.

#### Design Decisions

1. **CDP Integration**: The Rust crate includes first-class CDP/SEP-0054 support, which is not part of the C++ history module. This provides access to `LedgerCloseMeta` for detailed transaction metadata.

2. **Disk-Backed Buckets**: During catchup, the Rust implementation saves buckets to disk and uses memory-mapped access, avoiding loading all bucket entries into memory. This is similar to C++ but implemented differently.

3. **Re-execution Focus**: The Rust crate emphasizes transaction re-execution during replay rather than TransactionMeta application. This works with traditional archives but may produce different intermediate results than C++ stellar-core.

4. **Invariant Integration**: The Rust crate integrates with `stellar-core-invariant` for runtime verification during replay, providing checks like conservation of lumens and valid ledger entry structure.
