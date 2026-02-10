# henyey-historywork

Work items for Stellar history archive download and publish workflows.

## Overview

This crate provides the building blocks for downloading and publishing Stellar
history archive data. It implements a work-item based architecture that integrates
with the `henyey-work` scheduler to orchestrate complex multi-step operations
with proper dependency management and retry logic.

History archives store snapshots of the Stellar ledger at regular checkpoint
intervals (every 64 ledgers). This crate provides work items to:

- **Download** history data: HAS, buckets, headers, transactions, results, and SCP
- **Verify** downloaded data: hash verification and header chain validation
- **Publish** history data: write checkpoint data back to archives

## Architecture

Work items are organized as a directed acyclic graph (DAG) of dependencies:

```
                   +-------------+
                   |  Fetch HAS  |
                   +------+------+
                          |
              +-----------+-----------+
              |                       |
              v                       v
       +------------+         +------------+
       |  Download  |         |  Download  |
       |  Buckets   |         |  Headers   |
       +------------+         +------+-----+
                                     |
                          +----------+----------+
                          |          |          |
                          v          v          v
                   +----------+ +----------+ +-------+
                   | Download | | Download | |Download|
                   |   Txs    | | Results  | |  SCP   |
                   +----------+ +----+-----+ +-------+
                                     |
                            (depends on Txs too)
```

All work items share state through `SharedHistoryState`, a thread-safe container
that accumulates downloaded data as work progresses.

## Key Types

| Type | Description |
|------|-------------|
| `HistoryWorkState` | Shared container for downloaded history data |
| `SharedHistoryState` | Thread-safe handle (`Arc<Mutex<...>>`) to work state |
| `HistoryWorkBuilder` | Factory for registering single-checkpoint work items with dependencies |
| `HistoryWorkIds` | IDs returned by `HistoryWorkBuilder::register` for dependency tracking |
| `PublishWorkIds` | IDs returned by `HistoryWorkBuilder::register_publish` |
| `HistoryWorkStage` | Enum identifying the current work stage for progress |
| `ArchiveWriter` | Trait for publishing data to history archives |
| `LocalArchiveWriter` | Filesystem implementation of `ArchiveWriter` |
| `CheckpointRange` | Range of checkpoints for batch operations |
| `HistoryFileType` | Enum for archive file types (Ledger, Transactions, Results, Scp) |
| `BatchDownloadWork` | Work item for downloading files across a checkpoint range |
| `BatchDownloadWorkBuilder` | Factory for registering batch download work items |
| `BatchDownloadState` | Shared container for multi-checkpoint download data |
| `SharedBatchDownloadState` | Thread-safe handle to `BatchDownloadState` |
| `CheckSingleLedgerHeaderWork` | Self-contained work item to verify a ledger header against the archive |

### Download Work Items

| Work Item | Description | Dependencies |
|-----------|-------------|--------------|
| `GetHistoryArchiveStateWork` | Fetches the HAS JSON file | None |
| `DownloadBucketsWork` | Downloads and verifies bucket files | HAS |
| `DownloadLedgerHeadersWork` | Downloads and verifies headers | HAS |
| `DownloadTransactionsWork` | Downloads and verifies transactions | Headers |
| `DownloadTxResultsWork` | Downloads and verifies results | Headers, Transactions |
| `DownloadScpHistoryWork` | Downloads SCP consensus history | Headers |
| `CheckSingleLedgerHeaderWork` | Verifies a single ledger header against archive | None (self-contained) |
| `BatchDownloadWork` | Downloads a file type across a checkpoint range | Varies by file type |

### Publish Work Items

| Work Item | Description |
|-----------|-------------|
| `PublishHistoryArchiveStateWork` | Publishes HAS JSON |
| `PublishBucketsWork` | Publishes compressed bucket files |
| `PublishLedgerHeadersWork` | Publishes compressed header XDR |
| `PublishTransactionsWork` | Publishes compressed transaction XDR |
| `PublishResultsWork` | Publishes compressed result XDR |
| `PublishScpHistoryWork` | Publishes compressed SCP history XDR |

## Usage

### Downloading Checkpoint Data

```rust
use henyey_historywork::{
    HistoryWorkBuilder, SharedHistoryState, build_checkpoint_data
};
use henyey_work::{WorkScheduler, WorkSchedulerConfig};
use std::sync::Arc;

// Create shared state for work items
let state: SharedHistoryState = Default::default();

// Build and register work items
let builder = HistoryWorkBuilder::new(archive, checkpoint, state.clone());
let mut scheduler = WorkScheduler::new(WorkSchedulerConfig::default());
let work_ids = builder.register(&mut scheduler);

// Run the scheduler to completion
scheduler.run_until_done().await;

// Extract downloaded data for catchup
let checkpoint_data = build_checkpoint_data(&state).await?;
```

### Publishing Checkpoint Data

```rust
use henyey_historywork::{
    HistoryWorkBuilder, LocalArchiveWriter, SharedHistoryState
};
use std::sync::Arc;
use std::path::PathBuf;

// Create a writer for the target archive
let writer = Arc::new(LocalArchiveWriter::new(PathBuf::from("/var/stellar/history")));

// Register publish work after download work
let download_ids = builder.register(&mut scheduler);
let publish_ids = builder.register_publish(&mut scheduler, writer, download_ids);

// Run all work to completion
scheduler.run_until_done().await;
```

### Monitoring Progress

```rust
use henyey_historywork::get_progress;

let progress = get_progress(&state).await;
if let Some(stage) = progress.stage {
    println!("Stage: {:?}, Status: {}", stage, progress.message);
}
```

### Custom Archive Writers

Implement `ArchiveWriter` for custom storage backends:

```rust
use henyey_historywork::ArchiveWriter;
use async_trait::async_trait;

struct S3ArchiveWriter {
    bucket: String,
    client: S3Client,
}

#[async_trait]
impl ArchiveWriter for S3ArchiveWriter {
    async fn put_bytes(&self, path: &str, data: &[u8]) -> Result<()> {
        self.client.put_object(&self.bucket, path, data).await
    }
}
```

### Batch Downloads (Multi-Checkpoint)

For catching up across multiple checkpoints, use the batch download API:

```rust
use henyey_historywork::{BatchDownloadWorkBuilder, CheckpointRange};
use henyey_work::{WorkScheduler, WorkSchedulerConfig};

// Download headers, transactions, results, and SCP for checkpoints 64-512
let range = CheckpointRange::new(64, 512);
let builder = BatchDownloadWorkBuilder::new(archive, range);

let state = builder.state();
let mut scheduler = WorkScheduler::new(WorkSchedulerConfig::default());
let ids = builder.register(&mut scheduler);

scheduler.run_until_done().await;

// Access downloaded data from state
let guard = state.lock().await;
let headers_for_checkpoint_128 = &guard.headers[&128];
```

## Design Notes

- **Parallel Downloads**: Bucket downloads use up to 16 concurrent requests,
  matching the stellar-core `MAX_CONCURRENT_SUBPROCESSES` limit.

- **Retry Logic**: Download work items are configured with 3 retries; publish
  work items use 2 retries.

- **Verification**: All downloaded data is verified against known hashes before
  being stored in shared state.

- **Memory Usage**: Downloaded data is held in memory. For large catchup ranges,
  consider processing checkpoints incrementally.

---

## stellar-core Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed stellar-core parity analysis.

---

## See Also

- `henyey-history` - History archive access and data structures
- `henyey-work` - Work scheduler for async task orchestration
- `henyey-bucket` - Bucket list implementation
