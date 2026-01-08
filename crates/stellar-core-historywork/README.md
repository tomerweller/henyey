# stellar-core-historywork

Work items for Stellar history archive download and publish workflows.

## Overview

This crate provides the building blocks for downloading and publishing Stellar
history archive data. It implements a work-item based architecture that integrates
with the `stellar-core-work` scheduler to orchestrate complex multi-step operations
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
          +---------------+---------------+
          |               |               |
          v               v               v
   +------------+  +------------+  +------------+
   |  Download  |  |  Download  |  |  Download  |
   |  Buckets   |  |  Headers   |  |    SCP     |
   +------------+  +------+-----+  +------------+
                          |
                   +------+------+
                   v             v
            +------------+ +------------+
            |  Download  | |  Download  |
            |Transactions| |  Results   |
            +------------+ +------------+
```

All work items share state through `SharedHistoryState`, a thread-safe container
that accumulates downloaded data as work progresses.

## Key Types

| Type | Description |
|------|-------------|
| `HistoryWorkState` | Shared container for downloaded history data |
| `SharedHistoryState` | Thread-safe handle (`Arc<Mutex<...>>`) to work state |
| `HistoryWorkBuilder` | Factory for registering work items with dependencies |
| `HistoryWorkStage` | Enum identifying the current work stage for progress |
| `ArchiveWriter` | Trait for publishing data to history archives |
| `LocalArchiveWriter` | Filesystem implementation of `ArchiveWriter` |

### Download Work Items

| Work Item | Description | Dependencies |
|-----------|-------------|--------------|
| `GetHistoryArchiveStateWork` | Fetches the HAS JSON file | None |
| `DownloadBucketsWork` | Downloads and verifies bucket files | HAS |
| `DownloadLedgerHeadersWork` | Downloads and verifies headers | HAS |
| `DownloadTransactionsWork` | Downloads and verifies transactions | Headers |
| `DownloadTxResultsWork` | Downloads and verifies results | Headers, Transactions |
| `DownloadScpHistoryWork` | Downloads SCP consensus history | Headers |

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
use stellar_core_historywork::{
    HistoryWorkBuilder, SharedHistoryState, build_checkpoint_data
};
use stellar_core_work::WorkScheduler;
use std::sync::Arc;

// Create shared state for work items
let state: SharedHistoryState = Default::default();

// Build and register work items
let builder = HistoryWorkBuilder::new(archive, checkpoint, state.clone());
let mut scheduler = WorkScheduler::new();
let work_ids = builder.register(&mut scheduler);

// Run the scheduler to completion
scheduler.run_to_completion().await?;

// Extract downloaded data for catchup
let checkpoint_data = build_checkpoint_data(&state).await?;
```

### Publishing Checkpoint Data

```rust
use stellar_core_historywork::{
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
scheduler.run_to_completion().await?;
```

### Monitoring Progress

```rust
use stellar_core_historywork::get_progress;

let progress = get_progress(&state).await;
if let Some(stage) = progress.stage {
    println!("Stage: {:?}, Status: {}", stage, progress.message);
}
```

### Custom Archive Writers

Implement `ArchiveWriter` for custom storage backends:

```rust
use stellar_core_historywork::ArchiveWriter;
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

## Design Notes

- **Parallel Downloads**: Bucket downloads use up to 16 concurrent requests,
  matching the C++ stellar-core `MAX_CONCURRENT_SUBPROCESSES` limit.

- **Retry Logic**: Download work items are configured with 3 retries; publish
  work items use 2 retries.

- **Verification**: All downloaded data is verified against known hashes before
  being stored in shared state.

- **Memory Usage**: Downloaded data is held in memory. For large catchup ranges,
  consider processing checkpoints incrementally.

---

## C++ Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed C++ parity analysis.

---

## See Also

- `stellar-core-history` - History archive access and data structures
- `stellar-core-work` - Work scheduler for async task orchestration
- `stellar-core-bucket` - Bucket list implementation
