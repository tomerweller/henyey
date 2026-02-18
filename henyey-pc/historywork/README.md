# historywork

History work items for Stellar catchup and publish workflows. Provides the building blocks for downloading and publishing history archive data, integrating with the work scheduler for dependency management and retry logic.

## Key Files

- [lib.pc.md](lib.pc.md) -- Work items for downloading HAS, ledger data, buckets, and publishing checkpoints

## Architecture

The historywork crate defines discrete work units that compose into DAGs for catchup and publish operations. Each work item (e.g., `GetHistoryArchiveStateWork`, `GetLedgerDataWork`, `DownloadBucketsWork`, `PublishCheckpointWork`) handles a single stage of the pipeline, reporting progress and delegating to the history archive client for downloads and uploads. Work items are designed for the work scheduler to manage concurrency, retries, and dependency ordering.

## All Files

| File | Description |
|------|-------------|
| [lib.pc.md](lib.pc.md) | Work items for downloading HAS, ledger data, buckets, and publishing |
