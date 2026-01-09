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

#### Publish Queue (`publish_queue.rs`)
- [x] `PublishQueue` - Persistent queue backed by SQLite database
- [x] `enqueue()` / `dequeue()` - Queue management with HAS state persistence
- [x] `len()` / `is_empty()` - Queue size tracking
- [x] `min_ledger()` / `max_ledger()` - Ledger range queries
- [x] `get_state()` - Retrieve queued HistoryArchiveState
- [x] `get_all()` - Load all queued checkpoints
- [x] `get_referenced_bucket_hashes()` - Bucket retention tracking
- [x] `stats()` / `log_status()` - Queue statistics and logging

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
- [ ] **Publish queue migration** - `dropSQLBasedPublish()` for migrating old SQL-based queue format
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
