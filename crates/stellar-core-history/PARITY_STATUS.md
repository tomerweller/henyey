## C++ Parity Status

This document tracks the parity between this Rust crate (`stellar-core-history`) and the C++ `stellar-core/src/history/` module. The upstream reference is `.upstream-v25/src/history/`.

### Module Mapping

| Rust Module | C++ File(s) | Status |
|-------------|-------------|--------|
| `lib.rs` | `HistoryManager.h` | Partial |
| `archive.rs` | `HistoryArchive.h/cpp` | Partial |
| `remote_archive.rs` | `HistoryArchive.h` (putFileCmd, mkdirCmd) | Complete |
| `archive_state.rs` | `HistoryArchive.h` (HistoryArchiveState) | Complete |
| `catchup.rs` | `historywork/*.cpp` (CatchupWork, etc.) | Partial |
| `checkpoint.rs` | `HistoryManager.h` (static methods) | Complete |
| `download.rs` | `historywork/GetRemoteFileWork.cpp` | Complete |
| `paths.rs` | `HistoryArchive.h` (path helpers) | Complete |
| `publish.rs` | `historywork/PublishWork.cpp`, `StateSnapshot.cpp` | Partial |
| `publish_queue.rs` | `HistoryManagerImpl.cpp` (publish queue) | Partial |
| `replay.rs` | `ledger/LedgerManagerImpl.cpp` (closeLedger) | Complete |
| `verify.rs` | Various verification in catchup works | Complete |
| `cdp.rs` | N/A (Rust-only, SEP-0054) | N/A |
| `error.rs` | C++ exceptions | Complete |

---

### Implemented Features

#### Core Archive Access (`archive.rs`, `lib.rs`)

- [x] **HistoryArchive** - HTTP client for fetching archive data
  - `get_root_has()` - Fetch `.well-known/stellar-history.json`
  - `get_checkpoint_has()` - Fetch checkpoint-specific HAS files
  - `get_ledger_headers()` - Download ledger header XDR files
  - `get_transactions()` - Download transaction history XDR files
  - `get_results()` - Download transaction result XDR files
  - `get_scp_history()` - Download SCP history entries
  - `get_bucket()` - Download bucket files by hash
- [x] **HistoryManager** - Multi-archive access with failover
  - Sequential archive iteration until one succeeds
  - Similar to C++ `HistoryArchiveManager::selectRandomReadableHistoryArchive`
- [x] **CatchupMode** enum - Minimal, Complete, Recent modes

#### History Archive State (`archive_state.rs`)

- [x] **HistoryArchiveState** - Full JSON parsing/serialization
  - Version 1 and 2 format support
  - Network passphrase field (version 2)
  - `currentBuckets` array with curr/snap/next structure
  - `hotArchiveBuckets` for protocol 23+ state archival
- [x] **HASBucketLevel** - Per-level bucket hash tracking
  - `curr` and `snap` bucket hashes
  - `next` merge state tracking (parsed but not resolved)
- [x] `all_bucket_hashes()` / `unique_bucket_hashes()` - Bucket enumeration
- [x] `bucket_hashes_at_level()` / `hot_archive_bucket_hashes_at_level()`

#### Path Generation (`paths.rs`, `checkpoint.rs`)

- [x] **Checkpoint frequency** - 64 ledgers (matches `ARTIFICIALLY_ACCELERATE_TIME_FOR_TESTING=false`)
- [x] `checkpoint_ledger()` / `checkpoint_containing()` - Checkpoint calculation
- [x] `is_checkpoint_ledger()` - Checkpoint boundary detection
- [x] `latest_checkpoint_before_or_at()` - Find catchup starting point
- [x] `checkpoint_path()` - Generate `{category}/AA/BB/CC/{category}-AABBCCDD.xdr.gz` paths
- [x] `bucket_path()` - Generate `bucket/AA/BB/CC/bucket-{hash}.xdr.gz` paths
- [x] `root_has_path()` - `.well-known/stellar-history.json`
- [x] `has_path()` - Per-checkpoint HAS file paths

#### Download Infrastructure (`download.rs`)

- [x] HTTP download with configurable retries and timeouts
- [x] Gzip decompression for archive files
- [x] XDR stream parsing (record-marked format per RFC 5531)
- [x] `DownloadConfig` - Timeout, retry, and chunk size configuration

#### Catchup (`catchup.rs`)

- [x] **CatchupManager** - Full catchup orchestration
  - 7-step process: HAS download, bucket download, bucket apply, ledger download, verify, replay, complete
  - Progress tracking with `CatchupProgress` and `CatchupStatus`
- [x] **Bucket download and application**
  - Parallel bucket downloads (16 concurrent, matches C++ `MAX_CONCURRENT_SUBPROCESSES`)
  - Disk-backed bucket storage for memory efficiency
  - Bucket hash verification before use
- [x] **Ledger data download**
  - Headers, transactions, and results per checkpoint
  - SCP history entry download and persistence
- [x] **Pre-downloaded checkpoint data support**
  - `catchup_to_ledger_with_checkpoint_data()` for testing/alternative sources
- [x] **Verification during catchup**
  - Header chain verification
  - Transaction set hash verification (classic and generalized)
  - Transaction result set hash verification
  - Bucket list hash verification at checkpoints

#### Replay (`replay.rs`)

- [x] **Transaction re-execution replay** (`replay_ledger_with_execution`)
  - Re-executes transactions against bucket list state
  - Produces init/live/dead entry batches for bucket list updates
  - Works with traditional archives (no TransactionMeta needed)
- [x] **TransactionMeta-based replay** (`replay_ledger`)
  - Applies exact entry changes from archives
  - Requires CDP or LedgerCloseMeta sources
- [x] **Eviction iterator tracking** (protocol 23+)
  - Loads `EvictionIterator` ConfigSettingEntry from checkpoint
  - Incremental eviction scan during replay
  - Updates iterator position per-ledger
- [x] **Hot archive bucket list updates**
  - Archived persistent entries moved to hot archive during eviction
  - Combined bucket list hash: `SHA256(live_hash || hot_archive_hash)`
- [x] **Invariant verification during replay**
  - Conservation of lumens, valid entry structure, sequence progression
- [x] **ReplayConfig** - Verification and event emission options

#### Publishing (`publish.rs`)

- [x] **PublishManager** - Checkpoint publishing to local directory
  - `publish_checkpoint()` - Write all checkpoint files
  - `is_published()` / `latest_published_checkpoint()` - Publication tracking
- [x] **File writing**
  - Ledger headers, transactions, results (gzipped XDR)
  - Bucket files from bucket list entries
  - HAS file generation (JSON)
- [x] **Directory structure creation** following archive layout
- [x] **Verification before publishing**
  - Header chain verification
  - Transaction set and result hash verification

#### Publish Queue (`publish_queue.rs`)

- [x] **PublishQueue** - Persistent queue backed by SQLite
  - `enqueue()` / `dequeue()` - Queue management with HAS state persistence
  - `len()` / `is_empty()` - Queue size tracking
  - `min_ledger()` / `max_ledger()` - Ledger range queries
  - `get_state()` - Retrieve queued HistoryArchiveState
  - `get_all()` - Load all queued checkpoints
  - `get_referenced_bucket_hashes()` - Bucket retention tracking
  - `stats()` / `log_status()` - Queue statistics and logging
- [x] **Database schema** - `publishqueue` table matching C++ format

#### Verification (`verify.rs`)

- [x] **Header chain verification** (`verify_header_chain`)
- [x] **Bucket hash verification** (`verify_bucket_hash`)
- [x] **Transaction set hash verification** (`verify_tx_set`, `compute_tx_set_hash`)
  - Classic format: `SHA256(previous_ledger_hash || tx1_xdr || tx2_xdr || ...)`
  - Generalized format: `SHA256(full_tx_set_xdr)`
- [x] **Transaction result set verification** (`verify_tx_result_set`)
- [x] **Ledger hash verification** (`verify_ledger_hash`)
- [x] **HAS structure validation** (`verify_has_structure`, `verify_has_checkpoint`)
- [x] **SCP history entry verification** (`verify_scp_history_entries`)

#### CDP Integration (`cdp.rs`) - Rust Extension

- [x] **CdpDataLake** - SEP-0054 compliant data lake client
  - Partition and batch file path calculation
  - Zstd decompression for LedgerCloseMetaBatch files
- [x] `extract_ledger_header()` - Header extraction from LedgerCloseMeta
- [x] `extract_transaction_envelopes()` - Transaction envelope extraction
- [x] `extract_transaction_metas()` - TransactionMeta extraction
- [x] `extract_transaction_results()` - Transaction result extraction
- [x] `extract_evicted_keys()` - V2 evicted keys extraction
- [x] `extract_upgrade_metas()` - Protocol upgrade metadata extraction
- [x] `extract_transaction_processing()` - Combined envelope/result/meta extraction

---

### Not Yet Implemented (Gaps)

#### CheckpointBuilder (`CheckpointBuilder.h/cpp`)

- [ ] **ACID transactional checkpoint building**
  - C++ writes to temporary `.dirty` files first, then atomically renames on commit
  - Provides crash-safe checkpoint construction with automatic recovery
  - Rust writes directly without crash recovery logic
- [ ] **Incremental transaction appending**
  - C++ `appendTransactionSet()` appends transactions ledger-by-ledger during close
  - Rust requires all checkpoint data upfront for `publish_checkpoint()`
- [ ] **Checkpoint restoration** (`restoreCheckpoint(lcl)`)
  - Recovery of publish state after crash based on last committed ledger
- [ ] **Dirty file cleanup** (`cleanup(lcl)`)
  - Remove uncommitted publish data on startup

#### HistoryManager Publishing Integration

- [ ] **Publish queue migration** (`dropSQLBasedPublish()`)
  - One-time migration from old SQL-based format to file-based format
  - Populates checkpoint files from DB history during upgrade
- [ ] **Publication success/failure tracking**
  - `getPublishSuccessCount()`, `getPublishFailureCount()` metrics
  - Medida-based instrumentation in C++
- [ ] **Publication callback** (`historyPublished()`)
  - Callback mechanism for successful/failed publication
  - Dequeues from publish queue after all archives succeed
- [ ] **Wait for checkpoint publish** (`waitForCheckpointPublish()`)
  - Blocking wait for publication completion (utility scenarios)

#### HistoryArchive Remote Operations

- [ ] **Archive initialization** (`initializeHistoryArchive()`)
  - Create `.well-known/stellar-history.json` in new archive
  - Currently Rust only reads from archives
- [x] **Remote put/mkdir commands** - Implemented via `RemoteArchive` in `remote_archive.rs`
  - Supports configurable shell commands for remote upload (`put_cmd`, `mkdir_cmd`)
  - Templates with `{0}` (local) and `{1}` (remote) placeholders matching C++
  - `RemoteArchive::put_file()`, `RemoteArchive::mkdir()`, `RemoteArchive::get_file()`
  - `put_file_with_mkdir()` for convenience with directory creation
- [ ] **Get command templating** (`getFileCmd`)
  - C++ can use shell commands for fetch, not just HTTP
  - Rust has `RemoteArchive::get_file()` but HTTP fetch is still via `reqwest`

#### HistoryArchiveManager

- [ ] **Writable archive detection** (`publishEnabled()`, `getWritableHistoryArchives()`)
  - Based on presence of both `get` and `put` commands in config
- [ ] **Archive configuration validation** (`checkSensibleConfig()`)
  - Verify archive URLs are accessible, commands are valid
- [ ] **History archive report work** (`getHistoryArchiveReportWork()`)
  - Check last-published checkpoint on each configured archive
- [ ] **Ledger header verification work** (`getCheckLedgerHeaderWork()`)
  - Verify a ledger header against archives

#### FutureBucket Support

- [ ] **In-progress merge resolution**
  - HAS `next` field with `state != 0` indicates ongoing bucket merge
  - C++ `resolveAllFutures()`, `resolveAnyReadyFutures()` for completing merges
  - Rust parses `next` field but ignores merge state
- [ ] **Bucket merge persistence**
  - C++ can save/restore in-progress merges across restarts

#### StateSnapshot (`StateSnapshot.h/cpp`)

- [ ] **SCP message writing** (`writeSCPMessages()`)
  - Include SCP history in published snapshots
- [ ] **Differing HAS file computation** (`differingHASFiles()`)
  - Compute what files need uploading vs existing archive state
  - Optimization for incremental publishing

#### Testing Support

- [ ] **Publication enable/disable** (`setPublicationEnabled(bool)`)
  - Testing interface to pause/resume publication
- [ ] **Throw-on-append testing** (`mThrowOnAppend`)
  - Crash testing for checkpoint builder
- [ ] **Accelerated checkpoint frequency**
  - `ARTIFICIALLY_ACCELERATE_TIME_FOR_TESTING` sets frequency to 8

---

### Architectural Differences

#### Async Model

The Rust implementation uses `async/await` with Tokio, while C++ uses a Work-based state machine pattern (WorkScheduler, BasicWork subclasses). The Rust approach is more idiomatic but doesn't map 1:1 to C++ Work classes like `GetRemoteFileWork`, `ApplyBucketsWork`, etc.

#### Database Integration

C++ integrates deeply with its SQL database for persistent state:
- Publish queue in DB (migrated to files in recent versions)
- Transaction/result history from DB during catchup
- LCL tracking for crash recovery

Rust uses `stellar-core-db` more standalone, with dedicated queries for:
- Storing ledger headers and transaction history
- Bucket list snapshots
- SCP history entries

#### Remote Publishing

C++ supports configurable shell commands for remote archive access:
```toml
[HISTORY.archive_name]
get = "curl -sf {0} -o {1}"
put = "aws s3 cp {1} s3://bucket{0} --region us-east-1"
mkdir = "aws s3 mb s3://bucket{0}"
```

Rust currently only writes to local filesystem. Remote upload would need external tooling or a separate upload utility.

#### Crash Safety

C++ `CheckpointBuilder` implements ACID-like semantics:
1. Write to `.dirty` temp files with fsync
2. Atomic rename to final names after commit
3. `cleanup(lcl)` on startup to recover valid state
4. File-based publish queue with `durableRename`

Rust's `PublishManager` writes files directly without explicit crash recovery. The publish queue uses SQLite transactions for atomicity.

#### Metrics and Instrumentation

C++ uses Medida for publish success/failure metrics and timing:
- `history.publish.success` / `history.publish.failure` meters
- `history.publish.time` timer
- StatusManager for publish status messages

Rust uses `tracing` for structured logging but lacks equivalent metrics.

---

### Design Decisions (Rust Extensions)

#### CDP Integration (SEP-0054)

The Rust crate includes first-class CDP support not present in C++:
- `CdpDataLake` for accessing LedgerCloseMeta from cloud storage
- Full `TransactionMeta` extraction for exact replay
- Evicted keys and upgrade metadata extraction

This provides richer data than traditional archives for indexers and replay.

#### Disk-Backed Buckets

During catchup, Rust saves buckets to disk and uses file-backed storage with compact key-to-offset indexes. This is similar in spirit to C++'s bucket management but implemented differently:
- Buckets cached as `{hash}.bucket` files
- Memory-mapped access for large buckets
- Reduces memory from O(entries) to O(unique_keys) for indexes

#### Re-execution Focus

Rust emphasizes transaction re-execution during replay rather than TransactionMeta application:
- Works with traditional archives lacking TransactionMeta
- May produce different intermediate results than C++
- Final state verification at checkpoints ensures correctness

For exact verification, CDP data with `LedgerCloseMeta` can be used.

#### Invariant Integration

The Rust crate integrates with `stellar-core-invariant` for runtime verification:
- Conservation of lumens
- Valid ledger entry structure
- Sequence number progression
- Close time non-decreasing
- Liabilities match offers
- Order book not crossed

These run during replay when `verify_invariants` is enabled.
