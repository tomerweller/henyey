# Parity Status: stellar-core-historywork

This document tracks the parity between this Rust crate and the upstream C++
stellar-core `src/historywork/` directory (v25.x).

## Summary

| Category | Status |
|----------|--------|
| Core Download Workflow | Implemented (simplified) |
| Core Publish Workflow | Implemented (simplified) |
| Verification | Implemented inline (no background threads) |
| Batch Operations | Complete |
| Hot Archive Buckets | Implemented |
| Metrics | Not implemented |

## Implemented Work Items

### Download Work Items

| C++ Class | Rust Equivalent | Parity Notes |
|-----------|-----------------|--------------|
| `GetHistoryArchiveStateWork` | `GetHistoryArchiveStateWork` | Full parity. Fetches HAS JSON from archive. |
| `DownloadBucketsWork` | `DownloadBucketsWork` | Simplified. Downloads to memory instead of disk. No bucket indexing. Uses parallel async downloads (16 concurrent) matching C++ `MAX_CONCURRENT_SUBPROCESSES`. |
| (via BatchDownloadWork) | `DownloadLedgerHeadersWork` | Rust-specific. Downloads and verifies header chain in one step. |
| (via BatchDownloadWork) | `DownloadTransactionsWork` | Rust-specific. Downloads and verifies tx sets against headers. |
| (via BatchDownloadWork) | `DownloadTxResultsWork` | Rust-specific. Downloads and verifies tx results. |
| (via BatchDownloadWork) | `DownloadScpHistoryWork` | Rust-specific. Downloads SCP consensus messages. |

In C++, ledger headers, transactions, results, and SCP are downloaded via the generic
`BatchDownloadWork` + `GetAndUnzipRemoteFileWork` pipeline. In Rust, each category has
a dedicated work item that uses async HTTP via `stellar-core-history`.

### Publish Work Items

| C++ Class | Rust Equivalent | Parity Notes |
|-----------|-----------------|--------------|
| `PutHistoryArchiveStateWork` | `PublishHistoryArchiveStateWork` | Full parity. Publishes to both checkpoint path and `.well-known/stellar-history.json` (RFC 5785). |
| (part of PutSnapshotFilesWork) | `PublishBucketsWork` | Dedicated work item. Gzips and writes each bucket. |
| (part of PutSnapshotFilesWork) | `PublishLedgerHeadersWork` | Dedicated work item. Serializes headers to XDR, gzips, writes. |
| (part of PutSnapshotFilesWork) | `PublishTransactionsWork` | Dedicated work item. Serializes tx entries, gzips, writes. |
| (part of PutSnapshotFilesWork) | `PublishResultsWork` | Dedicated work item. Serializes result entries, gzips, writes. |
| (part of PutSnapshotFilesWork) | `PublishScpHistoryWork` | Dedicated work item. Serializes SCP entries, gzips, writes. |

### Builder and State

| C++ Concept | Rust Equivalent | Notes |
|-------------|-----------------|-------|
| Implicit work dependencies | `HistoryWorkBuilder` | Explicit builder pattern with `register()` and `register_publish()` |
| Per-work state | `SharedHistoryState` | Single shared state container (`Arc<Mutex<...>>`) |
| Progress formatting | `HistoryWorkProgress` | Simpler stage enum + message instead of `fmtProgress()` |

### Verification

| C++ Class | Rust Approach | Notes |
|-----------|---------------|-------|
| `VerifyBucketWork` | Inline in `DownloadBucketsWork` | C++ verifies and indexes in background thread. Rust verifies hash inline after download. |
| `VerifyTxResultsWork` | Inline in `DownloadTxResultsWork` | C++ runs in background thread. Rust verifies against headers inline. |
| Header chain verification | Inline in `DownloadLedgerHeadersWork` | Uses `stellar_core_history::verify::verify_header_chain()` |

## Not Implemented

### Low-Level File/Shell Operations

These are not needed as Rust uses native libraries instead of shell commands.

| C++ Class | Purpose | Rust Alternative |
|-----------|---------|------------------|
| `RunCommandWork` | Base class for shell commands | Not needed |
| `GetRemoteFileWork` | HTTP downloads via curl/wget | `reqwest` in `stellar-core-history` |
| `GetAndUnzipRemoteFileWork` | Download + gunzip via shell | Async HTTP + `flate2` |
| `GunzipFileWork` | Decompress via shell | `flate2` crate |
| `GzipFileWork` | Compress via shell | `flate2` crate |
| `PutRemoteFileWork` | Upload via shell commands | `ArchiveWriter` trait |
| `MakeRemoteDirWork` | Create remote dirs via shell | `ArchiveWriter` handles this |

### Batch and Range Operations

| C++ Class | Rust Equivalent | Parity Notes |
|-----------|-----------------|--------------|
| `BatchDownloadWork` | `BatchDownloadWork` | Full parity. Downloads files for a `CheckpointRange` with 16 concurrent downloads. |
| `CheckpointRange` | `CheckpointRange` | Full parity. Supports iteration, count, and ledger range calculation. |
| `FileType` | `HistoryFileType` | Full parity. Ledger, Transactions, Results, Scp variants. |
| `BatchDownloadWorkBuilder` | `BatchDownloadWorkBuilder` | Rust-specific. Creates all four batch download work items with proper dependencies. |
| `BatchDownloadState` | `BatchDownloadState` | Rust-specific. Shared state for multi-checkpoint downloads keyed by checkpoint sequence. |
| `DownloadVerifyTxResultsWork` | Inline in `DownloadTxResultsWork` | Verification integrated into download work. |

The Rust implementation supports full multi-checkpoint range operations for catchup.
Downloads are parallelized with up to 16 concurrent requests per batch.

### Advanced Verification and Tools

| C++ Class | Purpose | Priority |
|-----------|---------|----------|
| `WriteVerifiedCheckpointHashesWork` | Offline verification: downloads full chain and writes verified hashes to JSON | Low |
| `CheckSingleLedgerHeaderWork` | Self-check: verifies local LCL against archive | Low |

### Snapshot and Publishing Pipeline

| C++ Class | Purpose | Priority |
|-----------|---------|----------|
| `WriteSnapshotWork` | Write current state snapshot to disk | Medium |
| `ResolveSnapshotWork` | Resolve bucket references in snapshot | Medium |
| `PutFilesWork` | Upload multiple files to archive | Medium - `ArchiveWriter` is simpler |
| `PutSnapshotFilesWork` | Full snapshot publish (gzip + upload) | Medium |
| `PublishWork` | Top-level orchestration of publish | Medium |

The Rust publish workflow is simpler: individual work items handle gzip and write.
C++ has a more complex pipeline with differential uploads (only new files).

### Bootstrap and QSet Operations

| C++ Class | Purpose | Priority |
|-----------|---------|----------|
| `FetchRecentQsetsWork` | Download recent SCP history to extract quorum sets for bootstrap | Low |

### Hot Archive Buckets (Protocol 25)

| C++ Feature | Rust Status | Notes |
|-------------|------------|-------|
| `HotArchiveBucket` download | Implemented | `unique_bucket_hashes()` includes hot archive hashes |
| `HotArchiveBucketList` reconstruction | Implemented | Catchup code builds hot archive bucket list from HAS |

The Rust `DownloadBucketsWork` downloads all bucket hashes from the HAS, including hot archive buckets. The `unique_bucket_hashes()` method collects hashes from both `current_buckets` and `hot_archive_buckets` fields. During catchup, the hot archive bucket list is reconstructed from the downloaded buckets.

## Architecture Differences

| Aspect | C++ Implementation | Rust Implementation |
|--------|-------------------|---------------------|
| **File Downloads** | Shell commands (`curl`, `wget`) via `RunCommandWork` | Native async HTTP via `reqwest` |
| **Compression** | Shell commands (`gzip`, `gunzip`) | In-memory via `flate2` |
| **Bucket Storage** | Files on disk with indexing (`BucketManager.adoptFileAsBucket()`) | In-memory `HashMap<Hash256, Vec<u8>>` |
| **Work Orchestration** | `BasicWork`/`Work`/`BatchWork` hierarchy with state machine | `Work` trait with `WorkScheduler` DAG |
| **Background Work** | `postOnBackgroundThread` for CPU-intensive tasks | All async, no dedicated background threads |
| **Progress Reporting** | `fmtProgress()` with checkpoint-range math | `HistoryWorkStage` enum + message |
| **Error Handling** | Exception-based with `onFailureRaise` callbacks | `Result`-based with `WorkOutcome::Failed` |
| **Archive Selection** | Random archive selection on retry | Single archive per work builder |
| **Retry Logic** | Built into `BasicWork` base class | Configured per-work via `WorkScheduler` |

## Metrics Not Implemented

The C++ implementation includes extensive metrics via `medida`:

- `history.download.success` / `history.download.failure`
- `history.verify.success` / `history.verify.failure`
- `history.publish.success` / `history.publish.failure`
- `history.check.success` / `history.check.failure`
- `history.ledger-check.success` / `history.ledger-check.failure`
- Bytes/second meters for downloads
- Per-archive failure tracking

## Testing Status

| Test Category | C++ | Rust | Notes |
|---------------|-----|------|-------|
| Integration tests | `HistoryWorkTests.cpp` | `tests/history_work.rs` | Rust has end-to-end test with mock HTTP server |
| Unit tests | Various in `test/` | `tests/checkpoint_data.rs` | Basic state tests |
| Acceptance tests | `[acceptance]` tagged | None | C++ has tagged slow tests |
| Catchup simulation | `CatchupSimulation` | None | C++ has elaborate simulation framework |

## Known Behavioral Differences

1. **Bucket Indexing**: C++ builds a bucket index during verification for fast
   lookups. Rust keeps raw bucket data in memory without indexing.

2. **Disk Usage**: C++ downloads to temp files and cleans up. Rust keeps everything
   in memory, which may limit catchup size on memory-constrained systems.

3. **Archive Failover**: C++ randomly selects archives and fails over on error.
   Rust uses a single archive per builder with retry at the work level.

4. **Empty Result Handling**: Rust publish work items fail if data is empty.
   C++ may handle this differently depending on the work type.

## Recommendations for Future Work

1. **Low Priority**: Add metrics collection for monitoring and debugging.

2. **Low Priority**: Consider disk-based bucket storage for large catchup operations.
