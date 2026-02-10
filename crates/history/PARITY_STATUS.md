# Parity Status: henyey-history

**Overall Parity: ~85%**

This document tracks the parity between this Rust crate (`henyey-history`) and stellar-core `stellar-core/src/history/` module. The reference is `.upstream-v25/src/history/`.

## Overview

The `henyey-history` crate provides history archive access, catchup, replay, and publish support for henyey. It corresponds to stellar-core `src/history/` module and related components in `src/catchup/` and `src/historywork/`.

---

## Implemented Features

- [x] HistoryArchive - HTTP client for fetching archive data
- [x] HistoryManager - Multi-archive access with failover
- [x] HistoryArchiveManager - Archive management with writable detection
- [x] HistoryArchiveState - Full JSON parsing/serialization (v1 and v2)
- [x] Checkpoint utilities - Path generation, frequency, boundary detection
- [x] CheckpointBuilder - Crash-safe checkpoint construction with dirty files
- [x] PublishQueue - Persistent SQLite-backed publish queue
- [x] CatchupManager - Full catchup orchestration (7-step process)
- [x] Bucket download/verification - Parallel downloads with hash verification
- [x] Ledger replay - Transaction re-execution and TransactionMeta-based replay
- [x] Header chain verification - Cryptographic hash chain validation
- [x] Transaction set/result verification
- [x] RemoteArchive - Shell command-based upload (put_cmd, mkdir_cmd)
- [x] CDP Integration - SEP-0054 data lake client (Rust-only extension)

## Not Implemented (Gaps)

- [ ] Work-based catchup orchestration (stellar-core uses explicit work graph)
- [ ] FutureBucket in-progress merge resolution
- [ ] Publish success/failure metrics (Medida instrumentation)
- [ ] Publication callback mechanism
- [ ] Get command templating for shell-based fetch
- [ ] History archive report work
- [ ] SCP message writing in published snapshots
- [ ] Accelerated checkpoint frequency for testing

---

## Test Coverage Comparison

### stellar-core Tests (`.upstream-v25/src/history/test/`)

| Test File | Test Name | Rust Equivalent | Status |
|-----------|-----------|-----------------|--------|
| **HistoryTests.cpp** | | | |
| | `checkpoint containing ledger` | `checkpoint.rs::test_checkpoint_containing_matches_stellar_core` | ✅ Covered |
| | `HistoryManager compress` | `download_utils.rs::test_decompress_gzip_roundtrip` | ✅ Covered |
| | `HistoryArchiveState get_put` | `lib.rs::archive_manager_tests` | 🔶 Partial |
| | `History bucket verification` | `catchup_integration.rs::test_catchup_against_local_archive_checkpoint` | ✅ Covered |
| | `History bucket verification (live)` | `catchup_integration.rs` | ✅ Covered |
| | `History bucket verification (hot archive)` | `catchup_integration.rs` | 🔶 Partial (hot archive not tested separately) |
| | `History bucket verification (file not found)` | — | ❌ Missing |
| | `History bucket verification (corrupted zip)` | — | ❌ Missing |
| | `History bucket verification (hash mismatch)` | — | ❌ Missing |
| | `Ledger chain verification` | `verify.rs::test_verify_header_chain_*` | ✅ Covered |
| | `Ledger chain verification (bad hash)` | `verify.rs::test_verify_header_chain_broken` | ✅ Covered |
| | `Ledger chain verification (bad ledger version)` | — | ❌ Missing |
| | `Ledger chain verification (overshot)` | — | ❌ Missing |
| | `Ledger chain verification (undershot)` | — | ❌ Missing |
| | `Ledger chain verification (missing entries)` | — | ❌ Missing |
| | `Tx results verification` | `replay_integration.rs::test_catchup_replay_bucket_hash_verification` | 🔶 Partial |
| | `Tx results verification (header file missing)` | — | ❌ Missing |
| | `Tx results verification (hash mismatch)` | — | ❌ Missing |
| | `History publish` | — | ❌ Missing |
| | `History publish with restart` | — | ❌ Missing |
| | `History publish to multiple archives` | — | ❌ Missing |
| | `History catchup with extra validation` | — | ❌ Missing |
| | `Publish works correctly post shadow removal` | — | ❌ Missing |
| | `History catchup` | `catchup_integration.rs` | 🔶 Partial |
| | `Publish throttles catchup` | — | ❌ Missing |
| | `History catchup with different modes` | — | ❌ Missing |
| | `Retriggering catchups after trimming mSyncingLedgers` | — | ❌ Missing |
| | `History prefix catchup` | — | ❌ Missing |
| | `Catchup with protocol upgrade` | — | ❌ Missing |
| | `Catchup fatal failure` | — | ❌ Missing |
| | `Catchup non-initentry buckets to initentry-supporting works` | — | ❌ Missing |
| | `Publish catchup alternation with stall` | — | ❌ Missing |
| | `Publish catchup via s3` | — | ❌ Missing (hidden test) |
| | `HAS in publishqueue remains in pristine state until publish` | — | ❌ Missing |
| | `persist publish queue` | — | ❌ Missing |
| | `catchup with a gap` | — | ❌ Missing |
| | `Catchup recent` | — | ❌ Missing |
| | `Catchup manual` | — | ❌ Missing |
| | `initialize existing history store fails` | `lib.rs::archive_manager_tests` | 🔶 Partial |
| | `Catchup failure recovery with buffered checkpoint` | — | ❌ Missing |
| | `Change ordering of buffered ledgers` | — | ❌ Missing |
| | `Introduce and fix gap without starting catchup` | — | ❌ Missing |
| | `Receive trigger and checkpoint ledger out of order` | — | ❌ Missing |
| | `Externalize gap while catchup work is running` | — | ❌ Missing |
| | `CheckpointBuilder` | — | ❌ Missing |
| **SerializeTests.cpp** | | | |
| | `Serialization round trip` | `serialize_roundtrip.rs::test_history_archive_state_roundtrip` | ✅ Covered |

### Legend

- ✅ **Covered**: Rust test exists with equivalent functionality
- 🔶 **Partial**: Some aspects tested but not complete coverage
- ❌ **Missing**: No Rust equivalent test

### Rust-only Tests

These tests exist in Rust but have no direct stellar-core equivalent:

| Test File | Test Name | Description |
|-----------|-----------|-------------|
| `serialize_roundtrip.rs` | `test_history_archive_state_roundtrip` | Tests HAS JSON round-trip with real testnet/mainnet fixtures |
| `download_utils.rs` | `test_decompress_gzip_roundtrip` | Gzip compression/decompression |
| `download_utils.rs` | `test_parse_xdr_stream_raw` | Raw XDR stream parsing |
| `download_utils.rs` | `test_parse_xdr_stream_record_marked` | Record-marked XDR parsing (RFC 5531) |
| `catchup_integration.rs` | `test_catchup_against_local_archive_checkpoint` | Full catchup against mock HTTP server |
| `replay_integration.rs` | `test_catchup_replay_bucket_hash_verification` | Replay with bucket list hash verification |
| `checkpoint.rs` | `test_latest_checkpoint_before_or_at` | Checkpoint boundary utility |
| `checkpoint.rs` | `test_next_checkpoint` | Next checkpoint calculation |
| `checkpoint.rs` | `test_checkpoint_start` | First ledger in checkpoint |
| `checkpoint.rs` | `test_checkpoint_range` | Checkpoint ledger range |
| `verify.rs` | `test_verify_header_chain_valid` | Valid header chain verification |
| `verify.rs` | `test_verify_header_chain_broken` | Broken hash chain detection |
| `verify.rs` | `test_verify_header_chain_non_consecutive` | Sequence gap detection |
| `verify.rs` | `test_verify_bucket_hash` | Bucket content hash verification |
| `verify.rs` | `test_verify_header_chain_empty` | Empty chain edge case |
| `verify.rs` | `test_verify_header_chain_single` | Single header edge case |
| `lib.rs` | `test_archive_entry_read_only` | Read-only archive configuration |
| `lib.rs` | `test_archive_entry_write_only` | Write-only archive configuration |
| `lib.rs` | `test_archive_entry_fully_configured` | Full read/write archive |
| `lib.rs` | `test_manager_publish_enabled_*` | Publish capability detection |
| `lib.rs` | `test_manager_get_archive` | Archive lookup by name |
| `lib.rs` | `test_manager_check_sensible_config_*` | Archive config validation |

---

## Known Gaps

### Critical Test Coverage Gaps

1. **Bucket verification failure modes**: The stellar-core tests extensively test bucket download failures (file not found, corrupted zip, hash mismatch). Rust lacks these negative test cases.

2. **Ledger chain verification edge cases**: stellar-core tests `VERIFY_STATUS_ERR_BAD_LEDGER_VERSION`, `VERIFY_STATUS_ERR_OVERSHOT`, `VERIFY_STATUS_ERR_UNDERSHOT`, `VERIFY_STATUS_ERR_MISSING_ENTRIES`. Rust only tests basic chain validation.

3. **Online catchup scenarios**: stellar-core has extensive tests for online catchup with buffered ledgers, gaps, out-of-order delivery, and recovery. Rust tests are primarily offline catchup.

4. **Publish workflow**: stellar-core tests publish with restart, multiple archives, crash recovery with dirty files. Rust lacks publish integration tests.

5. **Protocol upgrade during catchup**: stellar-core tests catching up across protocol upgrades (e.g., generalized tx sets, hot archive buckets). Rust lacks these.

6. **CheckpointBuilder crash scenarios**: stellar-core tests `mThrowOnAppend` for simulating crashes during checkpoint building. Rust lacks crash simulation tests.

### Functionality Gaps

1. **FutureBucket resolution**: stellar-core resolves in-progress bucket merges from HAS `next` field. Rust parses but ignores merge state.

2. **Metrics**: stellar-core tracks publish success/failure counts via Medida. Rust uses only logging.

3. **Online catchup buffering**: stellar-core has sophisticated `mSyncingLedgers` buffer management with trimming. Rust's catchup is simpler.

4. **Archive report work**: stellar-core can check what's published on remote archives. Rust lacks this.

---

## Module Mapping

| Rust Module | stellar-core File(s) | Status |
|-------------|-------------|--------|
| `lib.rs` | `HistoryManager.h`, `HistoryArchiveManager.h` | Complete |
| `archive.rs` | `HistoryArchive.h` | Complete |
| `remote_archive.rs` | `HistoryArchive.h` (putFileCmd, mkdirCmd) | Complete |
| `archive_state.rs` | `HistoryArchive.h` (HistoryArchiveState) | Complete |
| `catchup.rs` | `historywork/*.cpp` (CatchupWork, etc.) | Partial |
| `checkpoint.rs` | `HistoryManager.h` (static methods) | Complete |
| `checkpoint_builder.rs` | `CheckpointBuilder.h` | Complete |
| `download.rs` | `historywork/GetRemoteFileWork.cpp` | Complete |
| `paths.rs` | `HistoryArchive.h` (path helpers) | Complete |
| `publish.rs` | `historywork/PublishWork.cpp`, `StateSnapshot.cpp` | Partial |
| `publish_queue.rs` | `HistoryManagerImpl.cpp` (publish queue) | Partial |
| `replay.rs` | `ledger/LedgerManagerImpl.cpp` (closeLedger) | Complete |
| `verify.rs` | Various verification in catchup works | Complete |
| `cdp.rs` | N/A (Rust-only, SEP-0054) | N/A |
| `error.rs` | stellar-core exceptions | Complete |

---

## Architectural Differences

### Async Model

Rust uses `async/await` with Tokio. stellar-core uses a Work-based state machine pattern (`WorkScheduler`, `BasicWork` subclasses). The Rust approach is more idiomatic but doesn't map 1:1 to stellar-core Work classes.

### Database Integration

stellar-core integrates deeply with its SQL database for persistent state. Rust uses `henyey-db` more standalone.

### Crash Safety

stellar-core `CheckpointBuilder` implements ACID-like semantics with `.dirty` files and atomic renames. Rust's `CheckpointBuilder` mirrors this approach, but `PublishManager` writes files directly.

### Metrics

stellar-core uses Medida for publish success/failure metrics. Rust uses `tracing` for structured logging but lacks equivalent metrics.

---

## Design Decisions (Rust Extensions)

### CDP Integration (SEP-0054)

The Rust crate includes first-class CDP support not present in stellar-core:
- `CdpDataLake` for accessing LedgerCloseMeta from cloud storage
- Full `TransactionMeta` extraction for exact replay

### Disk-Backed Buckets

During catchup, Rust saves buckets to disk and uses file-backed storage with compact key-to-offset indexes.

### Re-execution Focus

Rust emphasizes transaction re-execution during replay rather than TransactionMeta application. Works with traditional archives lacking TransactionMeta.

### Invariant Integration

The Rust crate integrates with `stellar-core-invariant` for runtime verification during replay.

---

## Notes

- The stellar-core test infrastructure (`CatchupSimulation`, `HistoryConfigurator`, etc.) is significantly more sophisticated than the Rust test setup. Many stellar-core tests require this simulation framework.
- Several stellar-core tests use `REAL_TIME` virtual clock mode for timeout testing; Rust tests are primarily unit/integration tests.
- The `[acceptance]` tagged tests in stellar-core are longer-running integration tests; Rust could benefit from similar acceptance-level tests.
- Hot archive bucket testing should be expanded as protocol 23+ features mature.

---

## Recommendations for Improving Parity

### High Priority

1. Add bucket verification failure tests (file not found, corrupted, hash mismatch)
2. Add ledger chain verification edge case tests (overshot, undershot, missing entries)
3. Add publish integration tests with checkpoint completion
4. Add online catchup tests with buffered ledgers

### Medium Priority

5. Add protocol upgrade catchup tests
6. Add CheckpointBuilder crash recovery tests
7. Add multi-archive publish tests
8. Add FutureBucket resolution (or document why it's not needed)

### Low Priority

9. Add metrics tracking
10. Add archive report work
11. Add S3-style remote archive tests
