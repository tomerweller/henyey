# Deep Comparative Analysis: Henyey vs stellar-core

Automated deep comparison of 7 Henyey crates against their stellar-core counterparts.
Generated 2026-02-17.

---

# Table of Contents

1. [History](#deep-comparison-henyey-history-vs-stellar-core)
2. [Historywork](#deep-comparison-henyey-historywork-vs-stellar-core)
3. [App](#deep-comparison-henyey-app-vs-stellar-core)
4. [Common](#deep-comparison-henyey-common-vs-stellar-core)
5. [Crypto](#deep-comparison-henyey-crypto-vs-stellar-core)
6. [DB](#deep-comparison-henyey-db-vs-stellar-core)
7. [Work](#deep-comparison-henyey-work-vs-stellar-core)

---

# Deep Comparison: henyey-history vs stellar-core

## Overview

| Metric | Henyey | stellar-core |
|--------|--------|--------------|
| Source files | 16 `.rs` | 10 `.h` + 8 `.cpp` (+ 3 test files) |
| Production LOC | 9,406 | ~3,522 (headers + implementation, excl. tests) |
| Test LOC | 2,003 (inline) | ~3,642 (separate test files) |
| Test functions | 107 `#[test]` | 34 `TEST_CASE` / 60 `SECTION` |

The Rust crate is substantially larger than its upstream counterpart. This is partly because it embeds functionality that lives in other upstream directories (catchup Work classes are in `historywork/`, replay logic spans `ledger/` and `main/`), and partly because it includes two Rust-only modules (`cdp.rs` at 1,111 lines, `replay.rs` at 2,062 lines) that have no upstream equivalent within `src/history/`.

## Correctness Assessment

**Verdict**: Minor divergences found in checkpoint arithmetic; functional gaps in HAS and publish.

### Checkpoint Arithmetic (`checkpoint.rs` vs `HistoryManager.h:230-310`)

- **Algorithm match**: Mostly yes, with two divergences:

  1. **`size_of_checkpoint_containing`** (`checkpoint.rs:141`) always returns 64. Upstream (`HistoryManager.h:256-264`) returns `freq - 1` (63) for `ledger < freq`. This means Henyey considers the first checkpoint as having 64 ledgers (0-63) while upstream considers it as 63 ledgers (1-63, excluding genesis ledger 0).

  2. **`first_ledger_in_checkpoint_containing`** (`checkpoint.rs:93-95`) returns 0 for ledgers in the first checkpoint. Upstream (`HistoryManager.h:268-274`) returns 1 (because size=63 and last=63, so 63 - (63-1) = 1). This means Henyey includes ledger 0 in the first checkpoint's range, while upstream excludes it.

  3. **`last_ledger_before_checkpoint_containing`** (`checkpoint.rs:117-124`) returns `None` for ledgers in the first checkpoint. Upstream (`HistoryManager.h:291-299`) returns 0. These are semantically equivalent: upstream's 0 means "genesis/nothing before", Rust's `None` means "nothing before".

- **Edge cases**: Well tested with 21 unit tests covering boundary values.

- **Divergences**:
  - `size_of_checkpoint_containing` returning 64 instead of 63 for first checkpoint: **Cosmetic** -- this function is not called outside its own tests in Henyey.
  - `first_ledger_in_checkpoint_containing` returning 0 instead of 1: **Cosmetic** -- the only production caller guards with `if first_in_checkpoint <= GENESIS_LEDGER_SEQ`.
  - `last_ledger_before_checkpoint_containing` returning `None` vs 0: **Cosmetic** -- callers use `.expect()` or match on `Option`.

### History Archive State (`archive_state.rs` vs `HistoryArchive.h/cpp`)

- **Algorithm match**: Serialization/deserialization matches. JSON format is identical.
- **Edge cases**: `get_bucket_list_hash()` correctly computes combined live + hot-archive hash for protocol 23+.
- **Divergences**:
  - Missing `differingBuckets()`: **Observability-affecting** -- used for differential bucket downloads during publish.
  - Missing `futuresAllClear()`, `futuresAllResolved()`, `resolveAllFutures()`, `resolveAnyReadyFutures()`: **Consensus-affecting** -- used during publish preparation.
  - Missing `containsValidBuckets()`: **Consensus-affecting** -- validates bucket existence before accepting HAS.
  - Missing `MAX_HISTORY_ARCHIVE_BUCKET_SIZE` (100 GB) check: **Consensus-affecting** -- DOS protection.

### Archive Access (`archive.rs`, `remote_archive.rs`)

- **Algorithm match**: Yes. Shell command template substitution matches upstream.
- **Divergences**:
  - Henyey adds native HTTP client via `reqwest`: **Cosmetic** improvement.
  - Archive selection is sequential vs random: **Observability-affecting**.

### Publish Pipeline (`publish.rs`, `publish_queue.rs`, `checkpoint_builder.rs`)

- **Algorithm match**: CheckpointBuilder matches upstream's dirty-file ACID pattern.
- **Divergences**:
  - Missing `writeSCPMessages()`: **P1** -- SCP message history not published.
  - Missing `deletePublishedFiles()`: **P2** -- published files never cleaned up.
  - Missing publish orchestration (`publishQueuedHistory`): **P1** -- lacks end-to-end push-to-remote workflow.

### Catchup Orchestration (`catchup.rs`, `catchup_range.rs`)

- **Algorithm match**: `CatchupRange::calculate()` implements the same 5-case algorithm. All 5 cases tested.
- **Divergences**: None found.

### Ledger Replay (`replay.rs`)

- **Algorithm match**: Both re-execution and metadata-based replay paths implemented.
- **Divergences**: None found.

### Verification (`verify.rs`)

- **Algorithm match**: Header chain, bucket hash, and tx set/result verification all present.
- **Divergences**: None found.

### Path Generation (`paths.rs`)

- **Algorithm match**: Yes. Hex digit extraction, directory structure, and file naming all match.
- **Divergences**: None.

## Performance Comparison

| Area | Henyey | stellar-core | Winner | Impact |
|------|--------|--------------|--------|--------|
| Archive access | Native HTTP with connection pooling | Shell command execution per file | Henyey | Significant for large catchups |
| Bucket downloads | `reqwest` async | Shell command + Work-based async | Henyey | Better parallelism via Tokio |
| Checkpoint building | `flate2` gzip + direct XDR writes | `gzip` via C library | Comparable | Both I/O-bound |
| Archive selection | Sequential failover | Random selection | stellar-core | Better load distribution |
| Differential download | Not implemented | `differingBuckets()` for delta | stellar-core | Significant for incremental publish |

## Gaps (Henyey missing from stellar-core)

| # | Description | Impact | Priority | Location (upstream) |
|---|-------------|--------|----------|---------------------|
| 1 | `containsValidBuckets()` | Corrupted HAS could cause catchup with missing buckets | P0 | `HistoryArchive.cpp:448` |
| 2 | `MAX_HISTORY_ARCHIVE_BUCKET_SIZE` check (100 GB) | DOS protection on bucket size | P1 | `HistoryArchive.h:80` |
| 3 | `resolveAllFutures()` / `futuresAllResolved()` / `futuresAllClear()` | Cannot publish HAS with unresolved merges | P1 | `HistoryArchive.cpp:57-103` |
| 4 | `writeSCPMessages()` | Other nodes cannot verify consensus from archives | P1 | `StateSnapshot.cpp:54` |
| 5 | `publishQueuedHistory()` | Checkpoints queued but not pushed to remote | P1 | `HistoryManagerImpl.cpp` |
| 6 | `historyPublished()` callback | No notification on publish success/failure | P1 | `HistoryManagerImpl.cpp` |
| 7 | `differingBuckets()` | Downloads all buckets instead of changed ones | P1 | `HistoryArchive.cpp:260` |
| 8 | `ledgerToTriggerCatchup()` | Online catchup may trigger at wrong boundary | P1 | `HistoryManager.h:304-310` |
| 9 | `getMissingBucketsReferencedByPublishQueue()` | Cannot verify publish queue integrity | P2 | `HistoryManagerImpl.cpp` |
| 10 | `deletePublishedFiles()` | Disk usage grows unbounded | P2 | `HistoryManagerImpl.cpp` |
| 11 | `selectRandomReadableHistoryArchive()` | Load not distributed evenly | P2 | `HistoryArchiveManager.cpp:130` |
| 12 | Publish metrics | No monitoring of publish health | P2 | `HistoryManagerImpl.h` |
| 13 | `logAndUpdatePublishStatus()` | Missing status reporting | P2 | `HistoryManagerImpl.cpp` |
| 14 | `waitForCheckpointPublish()` | Cannot synchronously wait for publish | P2 | `HistoryManagerImpl.cpp` |
| 15 | `getHistoryArchiveReportWork()` | Cannot generate archive health reports | P2 | `HistoryArchiveManager.h:28` |
| 16 | `getCheckLedgerHeaderWork()` | Cannot perform standalone header verification | P2 | `HistoryArchiveManager.h:32` |
| 17 | `resolveAnyReadyFutures()` | Cannot incrementally resolve merges | P3 | `HistoryArchive.h:193` |
| 18 | `differingHASFiles()` | Uploads all HAS files instead of changed ones | P3 | `StateSnapshot.h:35` |
| 19 | `getHistoryEntryForLedger()` | Minor code organization difference | P3 | `HistoryUtils.h:25` |

## Henyey Improvements (not in stellar-core)

| # | Description | Benefit |
|---|-------------|---------|
| 1 | `CdpDataLake` / `CachedCdpDataLake` (SEP-0054 cloud storage client) | Metadata-based replay from cloud storage without full archive downloads |
| 2 | Native HTTP archive client with `reqwest` | Avoids shell process spawning; connection pooling, retries |
| 3 | Configurable download retries with exponential backoff | More resilient to transient network failures |
| 4 | Auto-detecting XDR stream parser | More robust handling of different archive formats |
| 5 | `Option<u32>` return for `last_ledger_before_checkpoint_containing` | Type-safe handling of "no previous checkpoint" |
| 6 | Comprehensive checkpoint arithmetic test suite (21 tests vs 5 upstream) | Better boundary condition coverage |
| 7 | Dual replay strategy: metadata-based and execution-based | Flexibility to choose approach |

## Recommendations

1. **Implement `containsValidBuckets()`** (P0)
2. **Add `MAX_HISTORY_ARCHIVE_BUCKET_SIZE` check** (P1)
3. **Implement FutureBucket resolution** (P1)
4. **Complete publish orchestration** (P1)
5. **Add `writeSCPMessages()` to publish** (P1)
6. **Fix `size_of_checkpoint_containing()` for first checkpoint** (cosmetic)
7. **Add `ledgerToTriggerCatchup()`** (P1)
8. **Add publish cleanup** (P2)
9. **Add random archive selection** (P2)
10. **Add metrics infrastructure** (P2)

---

# Deep Comparison: henyey-historywork vs stellar-core

## Overview

| Metric | Henyey | stellar-core |
|--------|--------|--------------|
| Source files | 1 (`lib.rs`) | 23 `.h` + 24 `.cpp` = 47 files |
| Production LOC | ~2,309 | ~3,498 |
| Test LOC | ~70 | ~131 |

## Correctness Assessment

**Verdict**: Minor divergences found

### GetHistoryArchiveStateWork

- **Algorithm match**: Yes -- both fetch HAS JSON from the archive and parse it.
- **Edge cases**: Covered. Upstream differentiates corrupt vs stale archive errors; Rust does not.
- **Divergences**:
  - (Observability-affecting) Missing differentiated error messages for HAS fetch failures.
  - (Observability-affecting) Missing `historyArchiveStatesDownloaded()` metrics.

### DownloadBucketsWork

- **Algorithm match**: Partial -- both download bucket files in parallel with hash verification.
- **Divergences**:
  - (Cosmetic) Bucket caching on disk is a Rust-specific optimization.
  - (P1) Missing `MAX_HISTORY_ARCHIVE_BUCKET_SIZE` check. Upstream rejects buckets > 100 GB.
  - (P1) Missing bucket index creation during verification.
  - (P1) Missing `BucketManager.adoptFileAsBucket()` callback.

### CheckSingleLedgerHeaderWork

- **Algorithm match**: Yes.
- **Divergences**:
  - (Observability-affecting) Missing `mCheckSuccess`/`mCheckFailed` metrics.
  - (Observability-affecting) Missing XDR dump of expected vs actual header on mismatch.

### VerifyTxResultsWork

- **Algorithm match**: Mostly equivalent.
- **Divergences**:
  - (P0) **Missing genesis ledger exception**. Upstream has special handling for ledger seq 1 with empty result set. This could cause verification failure when catching up from the first checkpoint.
  - (P1) Missing checkpoint range and ordering validation for result entries.

### DownloadTransactionsWork

- **Algorithm match**: Yes.
- **Divergences**: None observed.

### PutHistoryArchiveStateWork / PublishHistoryArchiveStateWork

- **Algorithm match**: Yes.
- **Divergences**:
  - (P1) Missing `containsValidBuckets()` pre-publish check.

## Performance Comparison

| Area | Henyey | stellar-core | Winner | Impact |
|------|--------|--------------|--------|--------|
| Download transport | Native async HTTP (`reqwest`) | Shell subprocess (`curl`/`wget`) | Henyey | Eliminates subprocess spawn overhead |
| Compression | In-memory `flate2` | Subprocess `gunzip`/`gzip` | Henyey | Avoids disk I/O round-trips |
| Bucket caching | Skips already-downloaded buckets | Always downloads to temp dir | Henyey | Avoids re-downloading during retry |
| Memory usage | Stream + drop per bucket | Files on disk, shared_ptr per bucket | Henyey | Reduces peak memory |

## Gaps (Henyey missing from stellar-core)

| # | Description | Impact | Priority | Location (upstream) |
|---|-------------|--------|----------|---------------------|
| 1 | **Missing genesis ledger exception in tx result verification** | Verification failure on first checkpoint | P0 | `VerifyTxResultsWork.cpp:107-110` |
| 2 | **Missing `MAX_HISTORY_ARCHIVE_BUCKET_SIZE` check** | OOM from malicious oversized bucket | P1 | `VerifyBucketWork.cpp:62-73` |
| 3 | **Missing bucket index creation** | No efficient key-based lookups | P1 | `VerifyBucketWork.cpp:98-100` |
| 4 | **Missing BucketManager bucket adoption** | Raw files without manager tracking | P1 | `DownloadBucketsWork.cpp:76-104` |
| 5 | **Missing `containsValidBuckets()` pre-publish validation** | Could publish malformed HAS | P1 | `PutHistoryArchiveStateWork.cpp:31-33` |
| 6 | **Missing checkpoint range/ordering validation** | Unvalidated result entries | P1 | `VerifyTxResultsWork.cpp:148-161` |
| 7 | **Missing archive failover on retry** | Same archive retried repeatedly | P1 | `GetRemoteFileWork.cpp:37-41` |
| 8 | **WriteSnapshotWork** | Node state snapshot for publishing | P1 | `WriteSnapshotWork.h/.cpp` |
| 9 | **ResolveSnapshotWork** | Bucket reference resolution | P1 | `ResolveSnapshotWork.h/.cpp` |
| 10 | **PutFilesWork** | Differential file upload | P1 | `PutFilesWork.h/.cpp` |
| 11 | **PutSnapshotFilesWork** | Full snapshot publish orchestration | P1 | `PutSnapshotFilesWork.h/.cpp` |
| 12 | **PublishWork** | Top-level publish with callbacks | P1 | `PublishWork.h/.cpp` |
| 13 | **WriteVerifiedCheckpointHashesWork** | Offline verified hash generation | P2 | `WriteVerifiedCheckpointHashesWork.h/.cpp` |
| 14 | **FetchRecentQsetsWork** | Quorum set bootstrap | P2 | `FetchRecentQsetsWork.h/.cpp` |
| 15 | **Metrics reporting** | Download/verification metrics | P2 | Multiple files |
| 16 | **Differentiated HAS error messages** | Corrupt vs stale archive | P2 | `GetHistoryArchiveStateWork.cpp:66-79` |
| 17 | **XDR dump in header mismatch** | Full header comparison | P2 | `CheckSingleLedgerHeaderWork.cpp:140-141` |
| 18 | **Header count guard** | Rejects excess headers | P3 | `CheckSingleLedgerHeaderWork.cpp:113-119` |

## Henyey Improvements (not in stellar-core)

| # | Description | Benefit |
|---|-------------|---------|
| 1 | **Bucket disk caching** | Avoids redundant multi-GB downloads on retry |
| 2 | **Native async HTTP** | Eliminates process spawn overhead |
| 3 | **In-memory compression** | Avoids disk I/O round-trips |
| 4 | **DAG-based work scheduling** | More transparent dependency management |
| 5 | **Builder pattern for work registration** | Encapsulates dependency wiring |
| 6 | **`ArchiveWriter` trait abstraction** | Pluggable publish backends |
| 7 | **Drop-after-write for bucket data** | Reduces peak memory |

## Recommendations

1. **(P0) Fix genesis ledger exception** in tx result verification
2. **(P1) Add `MAX_HISTORY_ARCHIVE_BUCKET_SIZE` guard**
3. **(P1) Add checkpoint range and ordering validation**
4. **(P1) Add `containsValidBuckets()` check** before publishing HAS
5. **(P1) Consider archive failover on retry**
6. **(P1) Implement snapshot publish pipeline**
7. **(P2) Implement `WriteVerifiedCheckpointHashesWork`**
8. **(P2) Implement `FetchRecentQsetsWork`**
9. **(P2) Add metrics reporting**

---

# Deep Comparison: henyey-app vs stellar-core

## Overview

| Metric | Henyey | stellar-core |
|--------|--------|--------------|
| Source files | 16 `.rs` files | 28 `.h`/`.cpp` files (+5 test files) |
| Production LOC | ~17,375 | ~13,265 (excl. test files) |
| Test LOC | ~2,000 (75 `#[test]`) | ~2,040 (in test/ subdirectory) |

**Note**: Henyey `crates/app` bundles several concerns (HTTP server, catchup CLI, run CLI, survey impl, tx flooding) that in stellar-core are split across different source directories.

## Correctness Assessment

**Verdict**: Minor divergences found; no consensus-affecting gaps in the application layer itself.

### Application State Machine

- **Algorithm match**: Partial -- Henyey uses a dedicated `AppState` enum; stellar-core derives state from multiple subsystem states.
- **Divergences**:
  1. **Missing `APP_CONNECTED_STANDBY_STATE`**: Observability-affecting.
  2. **State derivation model**: Cosmetic (risk of bugs, not an active divergence).

### Initialization & Startup

- **Algorithm match**: Yes, with architectural differences.
- **Divergences**:
  1. **Invariant manager**: No invariant checking system. Observability-affecting, but `BucketListIsConsistentWithDatabase` helps catch state divergence.
  2. **Config validation**: Much simpler in Henyey. P1 -- missing validation could allow misconfigured nodes.

### Event Loop

- **Algorithm match**: Different architecture, equivalent purpose.
  - stellar-core: ASIO `io_context::crank()` loop
  - Henyey: `tokio::select!` with ~15 timer branches
- **Divergences**: Cosmetic differences in scheduling.

### Shutdown Sequence

- **Algorithm match**: Partial.
- **Divergences**: Cosmetic (missing 1-second delay, relies on Drop for cleanup).

### Ledger Close Pipeline

- **Algorithm match**: Yes.

### Transaction Flooding

- **Algorithm match**: Yes. Pull-based FloodAdvert/FloodDemand protocol.

### Survey Implementation

- **Algorithm match**: Yes.

### Maintainer

- **Algorithm match**: Yes.
- **Divergences**: (Cosmetic) No parallel ledger close maintenance dispatch.

### Metadata Output Stream

- **Algorithm match**: Yes.

## Performance Comparison

| Area | Henyey | stellar-core | Winner | Impact |
|------|--------|--------------|--------|--------|
| Event loop model | tokio async with select! | ASIO io_context with crank() | Henyey | More efficient for high concurrency |
| Message channel bounds | MAX_DRAIN_PER_TICK=200 | Unbounded within crank | Henyey | Better starvation prevention |
| HTTP server | axum async | Built-in HTTP server | Henyey | More robust and performant |

## Gaps (Henyey missing from stellar-core)

| # | Description | Impact | Priority | Location (upstream) |
|---|-------------|--------|----------|---------------------|
| 1 | **Invariant manager** | Cannot detect state corruption at runtime | P1 | `ApplicationImpl.cpp:318-328` |
| 2 | **Config validation** (`validateAndLogConfig`) | Misconfigured nodes may start | P1 | `ApplicationImpl.cpp:656-760` |
| 3 | **Self-check (full)** | Reduced corruption detection | P2 | `ApplicationUtils.cpp:294-374` |
| 4 | **QueryServer** | Missing advanced query capabilities | P2 | `QueryServer.cpp/h` |
| 5 | **SettingsUpgradeUtils** | Cannot validate Soroban config upgrades | P2 | `SettingsUpgradeUtils.cpp` |
| 6 | **Diagnostics module** | Missing offline bucket analysis | P3 | `Diagnostics.cpp` |
| 7 | **dumpxdr** | Missing XDR dump utility | P3 | `dumpxdr.cpp` |
| 8 | **AppConnector** | Different design choice (Arc-based) | P3 | `AppConnector.cpp/h` |
| 9 | **VirtualClock** | No deterministic testing clock | P3 | Global concept |
| 10 | **Metric system** | Limited observability | P2 | `ApplicationImpl.cpp:121-129` |
| 11 | **Manual close with RUN_STANDALONE** | Reduced testing flexibility | P3 | `ApplicationImpl.cpp:952-1022` |
| 12 | **Thread priority control** | Missing OS-level scheduling hints | P3 | `ApplicationImpl.cpp:177-199` |
| 13 | **Parallel ledger close maintenance** | Minor contention risk | P3 | `Maintainer.cpp:105-114` |
| 14 | **Protocol 23 corruption recovery** | Cannot process P23 recovery CSV | P2 | `ApplicationImpl.cpp:276-294` |
| 15 | **Offer table rebuild** | Cannot handle upgrade-triggered rebuilds | P2 | `PersistentState.cpp:264-291` |

## Henyey Improvements (not in stellar-core)

| # | Description | Benefit |
|---|-------------|---------|
| 1 | **Event loop watchdog** | Automatic deadlock/hang detection |
| 2 | **Tokio async runtime** | Better resource utilization |
| 3 | **TOML configuration** | Cleaner config format |
| 4 | **Axum HTTP server** | Production-grade with graceful shutdown |
| 5 | **Prometheus metrics endpoint** | Direct monitoring integration |
| 6 | **Buffered catchup** | Smoother catchup-to-synced transition |
| 7 | **Catchup message caching with validation** | Prevents applying corrupt cached data |
| 8 | **Auto-survey scheduling** | Hands-free topology monitoring |
| 9 | **Dynamic log level changes** | No restart needed for log changes |

## Recommendations

1. **Implement comprehensive config validation** (P1)
2. **Add invariant checking** (P1) -- at minimum ConservationOfLumens and LedgerEntryIsValid
3. **Enhance self-check** (P2)
4. **Add comprehensive metrics** (P2)
5. **Handle Protocol 23 corruption** (P2)
6. **Add `APP_CONNECTED_STANDBY_STATE`** (P3)
7. **Thread priority hints** (P3)

---

# Deep Comparison: henyey-common vs stellar-core

## Overview

| Metric | Henyey | stellar-core |
|--------|--------|--------------|
| Source files | 12 `.rs` | 8 relevant `.h` + 5 relevant `.cpp` |
| Production LOC | 3,131 | ~2,251 (relevant files only) |
| Test LOC | 781 | ~2,994 |

## Correctness Assessment

**Verdict**: Full parity on all implemented components. Two minor defensive-programming differences in `Resource` operators (cosmetic).

### Protocol Version (`protocol.rs` vs `ProtocolVersion.h/.cpp`)
- **Algorithm match**: Yes. All comparison functions identical.
- **Constants match**: Yes. `SOROBAN_PROTOCOL_VERSION=V20`, `PARALLEL_SOROBAN_PHASE_PROTOCOL_VERSION=V23`, etc.
- **Divergences**: None.

### Types / Hash (`types.rs` vs `types.h/.cpp`)
- **Algorithm match**: Yes. `is_zero()`, `BitXorAssign`, `less_than_xored()` all match.
- **Divergences**: None.

### Asset Utilities (`asset.rs`)
- **Algorithm match**: Yes, for every function: `is_ascii_alphanumeric`, `is_string_valid`, `iequals`, `asset_code_to_str`, `str_to_asset_code`, `is_asset_valid`, `add_balance`, `ledger_entry_key`, `price_ge`, `price_gt`, `price_eq`, `compare_asset`, `format_size`, `round_down`.
- **Divergences**: Cosmetic only (`add_balance` returns `Option<i64>` vs mutating in-place; `unsigned_to_signed` returns `None` vs throwing).

### Math / Numeric (`math.rs`)
- **Algorithm match**: Yes. `big_divide`, `big_divide_unsigned`, `big_divide_128`, `big_multiply`, `big_square_root`, `saturating_multiply`, `is_representable_as_i64`, `double_to_clamped_u32` all match.
- **Divergences**: Cosmetic only.

### Resource (`resource.rs` vs `TxResource.h/.cpp`)
- **Algorithm match**: Yes, with two defensive-programming differences.
- **Divergences**:
  1. `SubAssign`: Missing underflow assertion. **Cosmetic**.
  2. `AddAssign`: Missing overflow assertion. **Cosmetic**.
  3. `Display` trailing comma difference. **Observability-affecting**.

### Metadata Normalization (`meta.rs` vs `MetaUtils.h/.cpp`)
- **Algorithm match**: Yes. Sort key construction, change type ordering, all 5 meta versions and 3 LCM versions handled identically.
- **Divergences**: None.

### XDR Stream (`xdr_stream.rs`)
- **Algorithm match**: Yes, for the output side. Same 4-byte big-endian size header with bit 31 set.
- **Divergences**: None.

## Performance Comparison

| Area | Henyey | stellar-core | Winner | Impact |
|------|--------|--------------|--------|--------|
| 128-bit arithmetic | Native `u128` | Custom `uint128_t` class | Henyey | Minor: compiler-native |
| XDR output | `BufWriter` flush per `write_one` | ASIO buffered stream | stellar-core | Minor: upstream batches I/O better |

No significant performance differences for consensus-critical paths.

## Gaps (Henyey missing from stellar-core)

| # | Description | Impact | Priority | Location (upstream) |
|---|-------------|--------|----------|---------------------|
| 1 | `XDRInputFileStream::readOne()` | Cannot read XDR-framed files from this crate | P1 | `.upstream-v25/src/util/XDRStream.h:119-163` |
| 2 | `XDRInputFileStream::readPage()` | Cannot do page-based bucket entry search | P2 | `.upstream-v25/src/util/XDRStream.h:169-232` |
| 3 | `XDRInputFileStream::getXDRSize()` | Static helper for size headers | P2 | `.upstream-v25/src/util/XDRStream.h:101-115` |
| 4 | `XDROutputFileStream::durableWriteOne()` | No fsync-after-write for crash safety | P2 | `.upstream-v25/src/util/XDRStream.h:452-458` |
| 5 | `hugeDivide()` standalone function | Inlined in tx crate; no reusable utility | P3 | `.upstream-v25/src/util/numeric.cpp:286-332` |
| 6 | `Resource::operator-=` underflow assertion | Missing defensive check | P3 | `.upstream-v25/src/util/TxResource.cpp:166-174` |
| 7 | `Resource::operator+=` overflow assertion | Missing defensive check | P3 | `.upstream-v25/src/util/TxResource.cpp:155-162` |

## Henyey Improvements (not in stellar-core)

| # | Description | Benefit |
|---|-------------|---------|
| 1 | `needs_upgrade_to_version()` helper | Encapsulates upgrade detection |
| 2 | `Hash256` newtype wrapper | Type safety |
| 3 | `Hash256::hash_xdr()` convenience | Combines serialize + hash |
| 4 | `Resource::try_get_val()` and `try_set_val()` | Non-panicking accessors |
| 5 | `SaturatingOps` for `i64` | Extends to signed types |
| 6 | `XdrOutputStream::from_writer()` | Easy testing with in-memory buffers |

## Recommendations

1. **Add defensive assertions to Resource operators** (P3)
2. **Consider implementing `XDRInputFileStream::readOne` equivalent** (P1) -- check if handled elsewhere first
3. **No consensus-affecting gaps found** -- 95% parity claim in PARITY_STATUS.md is accurate

---

# Deep Comparison: henyey-crypto vs stellar-core

## Overview

| Metric | Henyey | stellar-core |
|--------|--------|--------------|
| Source files | 11 `.rs` files | 14 `.h` + 13 `.cpp` = 27 files |
| Production LOC (approx.) | ~1,900 | ~2,460 |
| Test LOC (approx.) | ~1,050 | ~1,710 |
| Test count | 60 `#[test]` | 15 `TEST_CASE` (incl. 6 hidden bench) |

## Correctness Assessment

**Verdict**: Full parity on all consensus-affecting operations. Minor cosmetic divergences.

### SHA-256 Hashing
- **Algorithm match**: Yes. Both compute SHA-256 identically.
- **subSha256**: Both serialize counter as big-endian 8 bytes and concatenate `seed || counter_be`.
- **Divergences**: None consensus-affecting.

### BLAKE2b-256 Hashing
- **Algorithm match**: Yes. Both use BLAKE2b with 32-byte output, no key.
- **Divergences**: None.

### HMAC-SHA256
- **Algorithm match**: Yes. Both use constant-time verification.
- **Divergences**: None.

### HKDF
- **Algorithm match**: Yes. Both implement RFC 5869 correctly.
- **Divergences**: None.

### Hex Encoding/Decoding
- **Algorithm match**: Yes. Both produce lowercase hex. `hexAbbrev` truncates to 3 bytes in both.
- **Divergences**: None.

### Random Number Generation
- **Algorithm match**: Yes. Both use OS CSPRNG.
- **Divergences**: None.

### Curve25519 ECDH
- **Algorithm match**: Yes. Key generation, public key derivation, shared key derivation all match.
- **Divergences**: None consensus-affecting.

### Sealed Box Encryption/Decryption
- **Algorithm match**: Yes.
- **Divergences**: None.

### Ed25519 Keys and Signatures
- **Algorithm match**: Yes. Henyey always uses `ed25519-dalek`, matching upstream's protocol 24+ path.
- **Divergences**: None consensus-affecting.

### Short Hash (SipHash-2-4)
- **Algorithm match**: Yes. Both use SipHash-2-4 with identical seed expansion.
- **Divergences**: None consensus-affecting.

### SignerKey Utilities
- **Algorithm match**: Yes.
- **Divergences**: None consensus-affecting.

## Performance Comparison

| Area | Henyey | stellar-core | Winner | Impact |
|------|--------|--------------|--------|--------|
| XDR hashing | Allocates `Vec<u8>` then hashes | Zero-alloc 256-byte buffered CRTP streaming | stellar-core | Low: one allocation per XDR hash |
| Short hash XDR | Allocates via `to_xdr()` | Zero-alloc `XDRShortHasher` | stellar-core | Low-Medium: could add up for millions of entries |
| Signature verification | Direct verify on every call | BLAKE2-keyed cache (250k entries) | stellar-core | Medium: cache avoids expensive Ed25519 for repeated sigs |

## Gaps (Henyey missing from stellar-core)

| # | Description | Impact | Priority | Location (upstream) |
|---|-------------|--------|----------|---------------------|
| 1 | Signature verification cache (250k-entry) | Performance only; repeated verifications during replay | P3 | `SecretKey.cpp:45-66,447-495` |
| 2 | `SecretKey::isZero()` | Utility check, no consensus callers | P3 | `SecretKey.cpp:126-136` |
| 3 | `PubKeyUtils::random()` | Test utility | P3 | `SecretKey.cpp:497-505` |
| 4 | `StrKeyUtils::logKey()` | Diagnostic logging | P2 | `SecretKey.cpp:531-633` |
| 5 | `KeyUtils::toShortString()` | 5-char StrKey prefix for logging | P2 | `KeyUtils.h:63-74` |
| 6 | Zero-alloc `XDRShortHasher` | Performance: avoids allocation | P3 | `ShortHash.h:28-55` |
| 7 | Zero-alloc `XDRSHA256`/`XDRBLAKE2` | Performance: avoids allocation | P3 | `SHA.h:37-61`, `BLAKE2.h:33-57` |
| 8 | Ed25519 IACR 2020/1244 test vectors (12 cases) | Test gap | P2 | `CryptoTests.cpp:503-641` |
| 9 | Zcash Ed25519 test vectors (196 cases) | Test gap | P2 | `CryptoTests.cpp:643-1645` |

## Henyey Improvements (not in stellar-core)

| # | Description | Benefit |
|---|-------------|---------|
| 1 | Pure Rust crypto stack (no C FFI) | Memory safety guarantees, reproducible builds |
| 2 | `ZeroizeOnDrop` derive for keys | Automatic zeroization via type system |
| 3 | `Sha256Hasher::finalize()` consumes `self` | Prevents double-finish at compile time |
| 4 | `PublicKey` Debug/Display as StrKey | Better log output |
| 5 | Typed error enum `CryptoError` | Richer error information |
| 6 | Multi-chunk hash functions | Avoid intermediate buffer allocation |

## Recommendations

1. **Add Ed25519 edge-case test vectors** (P2) -- port IACR 2020/1244 and Zcash vectors
2. **Add StrKey corruption detection tests** (P2)
3. **Implement signature verification cache** (P3) -- profile first
4. **Implement zero-alloc XDR hashers** (P3) -- profile first
5. **Add HMAC/HKDF test vectors** (P2)

---

# Deep Comparison: henyey-db vs stellar-core

## Overview

| Metric | Henyey | stellar-core |
|--------|--------|--------------|
| Source files | 15 (.rs) | 9 (.h/.cpp) |
| Production LOC | 2758 | ~392 (database/ only) |
| Test LOC | 726 | 529 |
| Effective upstream scope | N/A | ~2500+ (SQL queries spread across many directories) |

Note: Upstream `database/` contains only infrastructure. Actual SQL resides in other crates. Henyey consolidates all SQL into the `db` crate.

## Correctness Assessment

**Verdict**: Minor divergences found -- two behavioral differences in deletion semantics and missing validation checks.

### Connection Management (pool.rs vs Database.h/Database.cpp)
- **Algorithm match**: Yes.
- **Divergences**: Cosmetic only (pragma tuning, pool sizing).

### Schema Versioning (migrations.rs)
- **Algorithm match**: Yes.
- **Divergences**: None.

### Ledger Header Storage (queries/ledger.rs)
- **Algorithm match**: Partial.
- **Divergences**:
  - **Missing header validation on store** (Observability-affecting): No `isValid` check.
  - **Missing sequence cross-check on load** (Observability-affecting): No post-load `ledgerSeq == seq` check.
  - **INSERT OR REPLACE vs INSERT** (Cosmetic): Silently overwrites.

### Delete Old Entries (queries/ledger.rs:121-137)
- **Algorithm match**: **No -- different deletion semantics**.
  - Upstream: range-based (min + count width)
  - Henyey: `LIMIT`-based (exact row count)
- **Divergences**: **Observability-affecting** -- different GC patterns, not consensus-affecting.

### SCP History Persistence (queries/scp.rs)
- **Algorithm match**: Largely equivalent.
- **Divergences**:
  - Node ID format: hex vs StrKey (Cosmetic).
  - Missing explicit transaction scope (Observability-affecting).

## Performance Comparison

| Area | Henyey | stellar-core | Winner | Impact |
|------|--------|--------------|--------|--------|
| XDR storage | Raw BLOB | Base64 TEXT | Henyey | ~33% less storage |
| SCP history insert | Row-by-row | SOCI batch insert | stellar-core | Minimal impact (<20 per ledger) |
| Delete old entries | SQL LIMIT | Range-based (SELECT MIN + DELETE) | Henyey | More predictable |

## Gaps (Henyey missing from stellar-core)

| # | Description | Impact | Priority | Location (upstream) |
|---|-------------|--------|----------|---------------------|
| 1 | `loadByHash` -- load ledger header by hash | Cannot look up headers by hash | P1 | `LedgerHeaderUtils.cpp:107-141` |
| 2 | `quoruminfo` table and `getNodeQuorumSet` | Cannot look up quorum sets per node | P2 | `HerderPersistenceImpl.cpp:114-157` |
| 3 | `copySCPHistoryToStream` | Cannot stream SCP history to checkpoint files | P1 | `HerderPersistenceImpl.cpp:233-319` |
| 4 | `copyToStream` for ledger headers | Cannot stream headers to checkpoint files | P1 | `LedgerHeaderUtils.cpp:200-230` |
| 5 | `populateCheckpointFilesFromDB` | Cannot generate checkpoint files from DB | P1 | `TransactionSQL.h:15-17` |
| 6 | `delete_old_tx_set_data` is a no-op | Unbounded `storestate` growth | P2 | `PersistentState.h:61` |
| 7 | Header validation in `store_ledger_header` | Missing `isValid()` check | P2 | `LedgerHeaderUtils.cpp:49-51` |
| 8 | Header sequence cross-check in `load_ledger_header` | Missing post-load verification | P2 | `LedgerHeaderUtils.cpp:180-186` |
| 9 | Transaction scope in `store_scp_history` | Missing explicit transaction wrapping | P2 | `HerderPersistenceImpl.cpp:53` |
| 10 | MVCC / concurrent access test | No isolation test | P3 | `DatabaseTests.cpp:92-200` |
| 11 | `scpquorums` index on `lastledgerseq` | Missing index for efficient cleanup | P3 | `HerderPersistenceImpl.cpp:403-404` |

## Henyey Improvements (not in stellar-core)

| # | Description | Benefit |
|---|-------------|---------|
| 1 | Raw BLOB storage for XDR data | ~33% space savings, no encode/decode overhead |
| 2 | `BucketListQueries` module | Checkpoint bucket list snapshots in DB |
| 3 | Consolidated query architecture | All SQL in one crate |
| 4 | `delete_state` method | Explicit key deletion |
| 5 | `get_ledger_hash` by sequence | Direct hash lookup without full header decode |
| 6 | Level-gap integrity check in `load_bucket_list` | Catches data corruption |
| 7 | Foreign key enforcement | Referential integrity |
| 8 | Richer error types | Discriminated error enum |

## Recommendations

1. **Add transaction scope to `store_scp_history`** (P2, low effort)
2. **Implement `loadByHash` for ledger headers** (P1, low effort)
3. **Add `scpquorums` index on `lastledgerseq`** (P3, trivial)
4. **Implement `delete_old_tx_set_data` properly** (P2, medium effort)
5. **Add header validation in `store_ledger_header`** (P2, low effort)
6. **Implement history streaming functions** (P1, high effort)
7. **Add MVCC isolation test** (P3, medium effort)

---

# Deep Comparison: henyey-work vs stellar-core

## Overview

| Metric | Henyey | stellar-core |
|--------|--------|--------------|
| Source files | 1 (`lib.rs`) + 1 test file | 7 `.h` + 8 `.cpp` (incl. tests) |
| Production LOC | ~1298 | ~1818 |
| Test LOC | ~300 | ~1026 |

## Correctness Assessment

**Verdict**: Minor divergences, architectural differences by design

### BasicWork / Work trait
- **Algorithm match**: Partial -- Henyey's async `run()` replaces cooperative `crankWork()`/`onRun()`.
- **Divergences**:
  1. **Retry delay strategy** (Observability-affecting): Fixed delay vs exponential backoff with jitter.
  2. **onReset() not called on retry** (Cosmetic): Design difference.
  3. **Retry counter semantics** (Cosmetic): Same number of total attempts.

### WorkScheduler
- **Algorithm match**: Functionally equivalent, architecturally different.
  - stellar-core: cooperative round-robin via ASIO
  - Henyey: flat DAG with Tokio tasks up to `max_concurrency`
- **Divergences**:
  1. **Blocking await during retry** (P3): Scheduler freezes for retry delay duration.

### WorkSequence
- **Algorithm match**: Different design, same sequential semantics.
- **Divergences**: None consensus-affecting.

### WorkWithCallback
- **Algorithm match**: Different purpose in each implementation (Cosmetic).

### BatchWork (not implemented)
- Henyey lacks dynamic work-yielding during execution.

### ConditionalWork (not implemented)
- Henyey lacks condition-gated execution with polling.

## Performance Comparison

| Area | Henyey | stellar-core | Winner | Impact |
|------|--------|--------------|--------|--------|
| Execution model | True async (Tokio tasks) | Cooperative single-threaded | Henyey | Multi-core utilization |
| Retry blocking | Blocks scheduler loop during delay | Non-blocking timer | stellar-core | Henyey freezes all scheduling during retry |
| Dependency resolution | O(n) scan of all entries | Implicit via parent-child cranking | stellar-core | Not an issue for small DAGs |

## Gaps (Henyey missing from stellar-core)

| # | Description | Impact | Priority | Location (upstream) |
|---|-------------|--------|----------|---------------------|
| 1 | Hierarchical parent-child work model | DAG model is sufficient alternative | P1 | `Work.h`, `Work.cpp` |
| 2 | `BatchWork` parallel batching with iterator | Cannot dynamically yield work during execution | P1 | `BatchWork.h/.cpp` |
| 3 | `ConditionalWork` condition-gated execution | Cannot gate work on external conditions | P1 | `ConditionalWork.h/.cpp` |
| 4 | Retry delay blocks scheduler loop | Other work stalls during retry sleep | P3 | `lib.rs:1011-1020` |
| 5 | Exponential backoff with jitter | Less robust against thundering herd | P3 | `.upstream-v25/src/util/Math.cpp:69-76` |
| 6 | Transitive dependents not marked as `Blocked` | Metrics report grandchildren as `pending` | P2 | `lib.rs:1102-1111` |
| 7 | Lifecycle hooks (`onReset`, `onSuccess`, `onFailureRetry`) | Less extensible | P2 | `BasicWork.h:189-192` |
| 8 | `getStatus()` formatted strings | No human-readable status | P2 | `BasicWork.cpp:79-110` |
| 9 | `getRetryETA()` | No retry countdown | P2 | `BasicWork.cpp:399-413` |
| 10 | State transition validation | No legal transition enforcement | P2 | `BasicWork.cpp:20-37` |
| 11 | `stopAtFirstFailure=false` option | Cannot continue past failure | P2 | `WorkSequence.h:23` |
| 12 | Test coverage parity | 6 tests vs 28+ upstream | P2 | `WorkTests.cpp` |

## Henyey Improvements (not in stellar-core)

| # | Description | Benefit |
|---|-------------|---------|
| 1 | True async execution with Tokio | Multi-core parallelism for I/O-bound work |
| 2 | Configurable `max_concurrency` | Explicit concurrency control |
| 3 | DAG-based dependency model | More flexible than tree-based model |
| 4 | Channel-based event monitoring (`WorkEvent`) | Decoupled event system |
| 5 | `WorkSchedulerMetrics` and `WorkSnapshot` | Rich programmatic introspection |
| 6 | Ownership without reference counting | Avoids ref-counting overhead |

## Recommendations

1. **Fix retry-delay blocking** (P3 but high practical impact) -- restructure to not block scheduler
2. **Mark transitive dependents as Blocked** (P2) -- recursive blocking
3. **Add exponential backoff utility** (P3)
4. **Increase test coverage** (P2)
5. **Implement `BatchWork` equivalent when needed** (P1)
6. **Implement `ConditionalWork` equivalent when needed** (P1)

---

# Cross-Crate Summary

## P0 Issues (Correctness)

| Crate | Issue |
|-------|-------|
| history | Missing `containsValidBuckets()` validation |
| historywork | Missing genesis ledger exception in tx result verification |

## P1 Issues (Completeness)

| Crate | Count | Key Issues |
|-------|-------|------------|
| history | 8 | Publish orchestration, FutureBucket resolution, SCP message publishing |
| historywork | 12 | Bucket size guard, bucket indexing, BucketManager adoption, snapshot publish pipeline |
| app | 2 | Config validation, invariant manager |
| db | 4 | loadByHash, history streaming, checkpoint file generation |
| common | 1 | XDR input stream reading |
| work | 3 | BatchWork, ConditionalWork, hierarchical model |
| crypto | 0 | -- |

## Crate Health Summary

| Crate | Correctness | Performance | Test Coverage | Overall |
|-------|------------|-------------|---------------|---------|
| crypto | Full parity | Minor gaps (caching, zero-alloc) | Good (60 tests) | Strong |
| common | Full parity | Comparable | Good | Strong |
| db | Minor divergences | Comparable | Adequate | Good |
| app | No consensus gaps | Henyey often better | Adequate | Good |
| work | By-design differences | Mixed (async better, retry worse) | Weak (6 tests) | Adequate |
| history | Minor gaps in publish | Henyey better for downloads | Strong (107 tests) | Adequate |
| historywork | P0 gap in tx verification | Henyey better for downloads | Weak (70 LOC) | Needs Work |
