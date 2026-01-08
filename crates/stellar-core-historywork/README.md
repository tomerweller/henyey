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

This section documents the parity between this Rust crate and the upstream C++
stellar-core `src/historywork/` directory.

### Implemented

The following C++ work items have Rust equivalents:

| C++ Class | Rust Equivalent | Notes |
|-----------|-----------------|-------|
| `GetHistoryArchiveStateWork` | `GetHistoryArchiveStateWork` | Full parity |
| `DownloadBucketsWork` | `DownloadBucketsWork` | Simplified - downloads to memory instead of files |
| `Progress` (fmtProgress) | `HistoryWorkProgress` | Simpler stage-based progress instead of checkpoint-range formatting |

**Publish Work Items:**

| C++ Class | Rust Equivalent | Notes |
|-----------|-----------------|-------|
| `PutHistoryArchiveStateWork` | `PublishHistoryArchiveStateWork` | Uses `ArchiveWriter` trait instead of commands |
| (bucket publishing in PutSnapshotFilesWork) | `PublishBucketsWork` | Dedicated work item |
| (header publishing in PutSnapshotFilesWork) | `PublishLedgerHeadersWork` | Dedicated work item |
| (tx publishing in PutSnapshotFilesWork) | `PublishTransactionsWork` | Dedicated work item |
| (results publishing in PutSnapshotFilesWork) | `PublishResultsWork` | Dedicated work item |
| (SCP publishing in PutSnapshotFilesWork) | `PublishScpHistoryWork` | Dedicated work item |

**Download Work Items (Rust-specific, no direct C++ equivalent):**

| Rust Work Item | Description |
|----------------|-------------|
| `DownloadLedgerHeadersWork` | Downloads and verifies ledger headers |
| `DownloadTransactionsWork` | Downloads and verifies transaction sets |
| `DownloadTxResultsWork` | Downloads and verifies transaction results |
| `DownloadScpHistoryWork` | Downloads SCP consensus history |

Note: In C++, these download operations are handled through `BatchDownloadWork`
and `GetAndUnzipRemoteFileWork` with file-based workflows. The Rust implementation
uses a simpler in-memory approach via `stellar-core-history` archive methods.

### Not Yet Implemented (Gaps)

The following C++ work items do not have Rust equivalents:

#### Low-Level File Operations

| C++ Class | Purpose | Priority |
|-----------|---------|----------|
| `RunCommandWork` | Base class for spawning shell commands (curl, gzip, etc.) | Low - Rust uses native libraries |
| `GetRemoteFileWork` | Downloads files via shell commands | Low - Rust uses async HTTP |
| `GetAndUnzipRemoteFileWork` | Downloads and gunzips files | Low - Rust uses flate2 in-memory |
| `GunzipFileWork` | Decompresses .gz files via shell | Low - Rust uses flate2 |
| `GzipFileWork` | Compresses files to .gz via shell | Low - Rust uses flate2 |
| `PutRemoteFileWork` | Uploads files via shell commands | Low - `ArchiveWriter` trait handles this |
| `MakeRemoteDirWork` | Creates remote directories via shell | Low - handled by `ArchiveWriter` |

#### Batch and Range Operations

| C++ Class | Purpose | Priority |
|-----------|---------|----------|
| `BatchDownloadWork` | Downloads multiple checkpoint files in a range | Medium - needed for multi-checkpoint catchup |
| `DownloadVerifyTxResultsWork` | Batch downloads and verifies tx results for a checkpoint range | Medium |

#### Verification Work Items

| C++ Class | Purpose | Priority |
|-----------|---------|----------|
| `VerifyBucketWork` | Verifies bucket hash and builds index in background thread | Medium - Rust verifies inline |
| `VerifyTxResultsWork` | Verifies transaction results against ledger headers | Medium - Rust verifies inline |
| `CheckSingleLedgerHeaderWork` | Offline self-check: verifies LCL against archive | Low |

#### Snapshot and Publishing Pipeline

| C++ Class | Purpose | Priority |
|-----------|---------|----------|
| `WriteSnapshotWork` | Writes ledger snapshot to local files | Medium |
| `ResolveSnapshotWork` | Resolves bucket references in a snapshot | Medium |
| `PutFilesWork` | Orchestrates uploading multiple files to an archive | Medium |
| `PutSnapshotFilesWork` | Full snapshot publish pipeline (gzip + upload) | Medium |
| `PublishWork` | Top-level publish sequence orchestration | Medium |

#### Advanced Features

| C++ Class | Purpose | Priority |
|-----------|---------|----------|
| `WriteVerifiedCheckpointHashesWork` | Batch verifies ledger chain and writes checkpoint hashes to JSON | Low - used for offline verification |
| `FetchRecentQsetsWork` | Fetches recent quorum sets from archives for bootstrap | Low |

#### Hot Archive Buckets

| C++ Feature | Purpose | Priority |
|-------------|---------|----------|
| `HotArchiveBucket` support in `DownloadBucketsWork` | Downloads both live and hot archive buckets | Medium - needed for full Protocol 25 support |

### Implementation Differences

| Aspect | C++ Approach | Rust Approach |
|--------|--------------|---------------|
| **File Downloads** | Shell commands (`curl`, `wget`) via `RunCommandWork` | Native async HTTP via `reqwest` in `stellar-core-history` |
| **Compression** | Shell commands (`gzip`, `gunzip`) | In-memory via `flate2` crate |
| **Bucket Storage** | Files on disk with indexing | In-memory `HashMap<Hash256, Vec<u8>>` |
| **Work Orchestration** | `BasicWork`/`Work`/`BatchWork` hierarchy with state machine | `Work` trait with `WorkScheduler` DAG |
| **Progress Reporting** | `fmtProgress` with checkpoint range math | `HistoryWorkStage` enum with message |
| **Metrics** | `medida` metrics (meters, counters) | Not yet implemented |
| **Error Handling** | Exception-based with `onFailureRaise` callbacks | `Result`-based with `WorkOutcome::Failed` |
| **Archive Selection** | Random archive selection on retry | Single archive per work builder |
| **Publish Target** | Shell-command based (`put` commands) | `ArchiveWriter` trait for abstraction |

### Metrics Not Yet Implemented

The C++ implementation includes extensive metrics via `medida`:

- `history.download.success` / `history.download.failure`
- `history.verify.success` / `history.verify.failure`
- `history.publish.success` / `history.publish.failure`
- Bytes/second meters for downloads
- Per-archive failure tracking

### Testing Gaps

| C++ Test | Status |
|----------|--------|
| `HistoryWorkTests.cpp` | Rust has integration tests but not unit tests for individual work items |

---

## See Also

- `stellar-core-history` - History archive access and data structures
- `stellar-core-work` - Work scheduler for async task orchestration
- `stellar-core-bucket` - Bucket list implementation
