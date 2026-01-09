# Refactoring Opportunities

This document contains code analysis findings for all crates in the rs-stellar-core workspace. Each section identifies issues and suggests potential fixes without implementing them.

---

## Table of Contents

1. [rs-stellar-core](#rs-stellar-core)
2. [stellar-core-app](#stellar-core-app)
3. [stellar-core-bucket](#stellar-core-bucket)
4. [stellar-core-common](#stellar-core-common)
5. [stellar-core-crypto](#stellar-core-crypto)
6. [stellar-core-db](#stellar-core-db)
7. [stellar-core-herder](#stellar-core-herder)
8. [stellar-core-history](#stellar-core-history)
9. [stellar-core-historywork](#stellar-core-historywork)
10. [stellar-core-invariant](#stellar-core-invariant)
11. [stellar-core-ledger](#stellar-core-ledger)
12. [stellar-core-overlay](#stellar-core-overlay)
13. [stellar-core-scp](#stellar-core-scp)
14. [stellar-core-tx](#stellar-core-tx)
15. [stellar-core-work](#stellar-core-work)

---

## rs-stellar-core

Main binary crate providing CLI interface.

### Potential Panics

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| ~~`main.rs:948-949`~~ | ~~Unchecked `unwrap()` on `checkpoints_to_publish.first()/last()`~~ | ✅ Fixed: Use `.expect()` with descriptive message |
| `main.rs:1826,1828,1927,1934,2281` | `unwrap()` on RwLock operations | Use `.expect("lock should not be poisoned")` |
| `main.rs:1980` | `executor.as_mut().unwrap()` without guard | Use `.expect("executor was just initialized")` |
| `main.rs:2360` | `account_bytes.try_into().unwrap()` | Combine validation and conversion |

### Code Duplication

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `main.rs:1475-1495, 1780-1802` | Repeated bucket hash collection pattern | Extract helper `fn extract_bucket_hashes(has: &HistoryArchiveState)` |
| `main.rs:1427-1431, 1735-1739, 2378-2382` | Repeated archive creation pattern | Create `fn get_first_enabled_archive(config: &AppConfig)` |
| `main.rs:2853-2974` | Duplicated `describe_change` implementations | Refactor `describe_change_detailed` to build on `describe_change` |

### Performance Issues

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| ~~`quorum_intersection.rs:158`~~ | ~~Exponential algorithm without guard~~ | ✅ Fixed: Added MAX_QUORUM_INTERSECTION_NODES guard (20 nodes) |
| ~~`main.rs:1189-1190`~~ | ~~Inefficient hash sorting via hex strings~~ | ✅ Fixed: Use direct byte comparison |

### Security Concerns

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `main.rs:1361-1370` | Shell command injection risk in `run_shell_command` | Validate/sanitize command templates or document trust requirements |

### Code Organization

| Issue | Suggested Fix |
|-------|---------------|
| Monolithic `main.rs` (3370 lines) | Split into modules: `cli.rs`, `commands/mod.rs`, `xdr_utils.rs`, `comparison.rs` |

---

## stellar-core-app

Top-level application layer orchestrating subsystems.

### Potential Panics

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `app.rs:1497` | `unwrap()` on `pop_front()` | Use `if let Some(peer_id) = reporting.queue.pop_front()` |
| `app.rs:2636` | `unwrap()` on `next_back()` | Use match expression or combine empty check with retrieval |
| `app.rs:2736` | `.expect("tx set present")` | Use match or `if let Some(tx_set)` with proper error handling |
| `run_cmd.rs:329,335` | Signal handlers use `.expect()` | Return proper error from `wait_for_shutdown_signal()` |

### Code Duplication

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `app.rs`, `run_cmd.rs` | Peer address parsing duplicated | Extract shared utility function |
| Throughout | `stellar_xdr::curr::Limits::none()` repeated dozens of times | Define constant or helper function |
| `run_cmd.rs:1128-1139` | `node_id_to_strkey` and `peer_id_to_strkey` nearly identical | Unify into single function |

### Performance Issues

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `app.rs` | Over 89 `.clone()` calls, many in hot paths | Review and use references or Arc where possible |
| `app.rs:593` | `samples.remove(0)` is O(n) for Vec | Use `VecDeque` instead |

### API Design Issues

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `app.rs:247-355` | `App` struct has 40+ fields | Extract sub-structs: `SurveyState`, `TxFloodingState`, `ConsensusState` |
| `config.rs:941-943` | Auto-survey validated as unsupported but configurable | Either implement or remove config option |

### Missing Tests

- Integration tests for full application lifecycle
- HTTP handler tests in `run_cmd.rs`
- Survey module test coverage

---

## stellar-core-bucket

Bucket storage and merging.

### Debug Code in Production

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `bucket_list.rs:583-607` | Debug `eprintln!` statements for ledger 310231 | Remove and use proper `tracing` instrumentation |

### Potential Panics

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `bucket.rs:517-524` | `entries()` panics for disk-backed buckets | Return `Result` or `Option` instead |

### Silent Error Handling

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `bucket.rs:630-634` | `BucketIter::DiskBacked` swallows errors | Change `Item` type to `Result<BucketEntry>` |

### Performance Issues

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `manager.rs:286-298` | Non-deterministic cache eviction | Implement proper LRU cache |
| `disk_bucket.rs:350-366` | `DiskBucketIter` loads entire file into memory | Implement streaming iteration |

### Code Duplication

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `bucket_list.rs:68-71`, `merge.rs:50-51` | Protocol constants duplicated | Define in single location and re-export |

---

## stellar-core-common

Foundational types and utilities.

### Unused Dependencies

| Dependency | Status |
|------------|--------|
| `bytes` | Never used - remove |
| `tracing` | Never used - remove |
| `tempfile` (dev) | Not used in tests - remove |

### Silent Error Handling

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `meta.rs:125,127-128` | `unwrap_or_default()` swallows XDR serialization errors | Propagate errors properly |
| `meta.rs:141` | Vector conversion with `unwrap_or_default()` | Add assertion or propagate error |

### Potential Panics

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `resource.rs:101-110,118-120,147-149,156-158` | Multiple methods panic on out-of-bounds access | Return `Option<i64>` from `get_val()` |

### Missing Tests

- `meta.rs` - no unit tests for critical metadata normalization
- `resource.rs` - no unit tests for arithmetic operations
- `config.rs` - no unit tests for configuration parsing

### Missing Validation

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `config.rs:163-181` | `QuorumSetConfig::threshold_percent` not validated 0-100 | Add validation or custom deserializer |
| `config.rs:235-249` | Log level and format are plain strings | Use enums with serde derive |

---

## stellar-core-crypto

Cryptographic primitives.

### Potential Panics

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `keys.rs:305-309` | `.unwrap()` in `From<Signature>` impl | Implement `TryFrom` instead |
| `strkey.rs:150` | `u64::from_be_bytes(...).unwrap()` | Use proper error handling |

### Unused Code

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `keys.rs:110-113` | `inner()` marked `#[allow(dead_code)]` | Remove or document future use |
| `strkey.rs:57-58` | `VERSION_SIGNED_PAYLOAD` unused | Implement signed payload support or remove |

### Code Duplication

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `signature.rs:71-75,96-97,110-112` | Signature hint extraction repeated 3 times | Use `signature_hint()` function everywhere |

### Missing Tests

- `sealed_box.rs` has no test module
- Invalid Base32, truncated StrKey, wrong version tests missing

### Thread Safety

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `short_hash.rs:72-75,85-88` | Global state with Mutex, unclear thread safety | Document exact guarantees |

---

## stellar-core-db

SQLite persistence layer.

### Unused Dependencies

| Dependency | Status |
|------------|--------|
| `tokio` | Never used - remove |
| `async-trait` | Never used - remove |
| `parking_lot` | Never used - remove |

### Error Handling Issues

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `accounts.rs:72-87` | `parse_signers` always returns empty vec | Implement proper XDR deserialization |
| `accounts.rs:97-100` | `signers_to_string` uses `unwrap_or_default()` | Propagate serialization errors |
| `accounts.rs:165-170` | XDR parsing errors silently converted to V0 | Log warning or propagate error |

### Code Duplication

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `peers.rs` (8 locations) | PeerRecord row mapping duplicated | Extract `fn peer_record_from_row(row: &Row)` |
| `peers.rs`, `publish_queue.rs` | Duplicated limit handling pattern | Use single code path with proper parameter binding |

### Schema Issues

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `schema.rs:30` | `SCHEMA_VERSION` is 3 but `CURRENT_VERSION` is 5 | Remove or sync constant |

### Missing Tests

- `ban.rs` - no unit tests
- `publish_queue.rs` - no unit tests
- `scp.rs` - no unit tests
- Database initialization/upgrade tests

---

## stellar-core-herder

SCP coordination and ledger close orchestration.

### Code Duplication

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `herder.rs:224-337` | `new()` and `with_secret_key()` share ~50 lines | Extract common initialization helper |
| `tx_queue.rs` (10+ locations) | TransactionFrame creation pattern repeated | Add method to `QueuedTransaction` or helper to `TransactionQueue` |
| `tx_queue.rs:765-781,833-848` | Lane configuration constructed multiple times | Construct once and reuse |

### Potential Panics

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `surge_pricing.rs:155-159` | `get_lane()` panics on non-Soroban tx | Return `Result` or use `debug_assert!` |

### Unused Code

| Location | Status |
|----------|--------|
| `tx_queue.rs:266` | `tx_size_bytes` marked dead_code |
| `tx_queue.rs:1192` | `select_transactions` marked dead_code |
| `surge_pricing.rs:85,271-279,312` | Multiple items marked dead_code |
| `scp_driver.rs:132` | `PendingQuorumSet` marked dead_code |

### Performance Issues

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `tx_queue.rs` (multiple) | Excessive `TransactionEnvelope` cloning | Use `Arc<TransactionEnvelope>` for shared ownership |
| `scp_driver.rs:237-246` | Linear search in cache eviction | Use LRU cache implementation |

### Documentation Gaps

| Location | Issue |
|----------|-------|
| `tx_queue.rs:73-75` | Constants undocumented |
| Lock ordering not documented | Could lead to deadlocks |

---

## stellar-core-history

History archive interaction.

### Code Duplication

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:210-329` | Failover logic repeated across 5 methods | Extract generic helper method |
| `archive_state.rs` (8 locations) | `"0".repeat(64)` for zero hash | Define constant `ZERO_HASH_HEX` |
| `catchup.rs` (multiple) | XDR error handling pattern repeated | Create helper trait extension |

### Potential Panics

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `catchup.rs:1596-1597` | `unwrap()` on `last_result`/`last_header` | Use `expect()` with descriptive message |
| `checkpoint.rs:105-109` | `checkpoint_range` uses `assert!` | Return `Result` instead |
| `paths.rs:90-96,123-128` | Direct slice indexing without bounds check | Use `get()` with error handling |

### Error Handling

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `archive_state.rs:128,136,143,154,159` | `Hash256::from_hex()` failures silently skipped | Log warning or return `Result` |
| `publish_queue.rs:84,103,117` | Lossy integer casts | Use `try_from` with error handling |

### Performance Issues

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `replay.rs:303-308` | `bucket_list.clone()` for every snapshot | Use `Arc<RwLock<BucketList>>` |
| `catchup.rs:1041-1154` | Sequential ledger data download | Download checkpoints in parallel |

### Security Concerns

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `catchup.rs:656-751` | No timeout on bucket download retries | Add total timeout or max retry count |
| `catchup.rs:709` | Bucket files not written atomically | Write to temp file, then atomic rename |

---

## stellar-core-historywork

Work items for history download/publish.

### Missing Cancellation Support

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| All `Work::run` implementations | None check `ctx.is_cancelled()` | Add cancellation checks in long-running loops |

### Blocking I/O in Async Context

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:781-788` | `LocalArchiveWriter::put_bytes` uses sync I/O | Use `tokio::fs` or `spawn_blocking` |

### Silent Error Handling

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:634-639` | XDR serialization failure silently continues | Return `WorkOutcome::Failed` on error |
| `lib.rs:550,633` | Missing headers silently skipped | Fail verification if header missing |

### Performance Issues

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:545-548,624-627` | Entire headers vector cloned for verification | Store just header hashes or create lookup map |
| `lib.rs:150,389-407` | All buckets held in memory | Stream to/from disk |

### Hardcoded Values

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:405` | Bucket download concurrency hardcoded to 16 | Make configurable via builder |
| `lib.rs:1305-1362` | Retry counts hardcoded (3 for downloads, 2 for publish) | Accept via configuration |

---

## stellar-core-invariant

Ledger state validation.

### Unused Code

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:2963-2967` | `LiabilitiesRounding` enum only has one variant | Remove enum or document future use |
| `lib.rs:1063-1073` | `claimable_balance_reserve` accumulated but unused | Remove or add validation |

### Error Handling

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:1736-1833` | `aggregate_event_diffs` returns `None` for many errors | Return `Result` with specific errors |
| `lib.rs:1368-1370` | Division by zero possible in `price_as_f64` | Check for `price.d == 0` |

### Code Duplication

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:1853-1917` | Balance/diff calculation repeated for each entry type | Create helper function or trait |
| `lib.rs:2632-2648` | `account_liabilities`/`trustline_liabilities` nearly identical | Create trait `HasLiabilities` |

### Missing Tests

- `CloseTimeNondecreasing` invariant
- `LastModifiedLedgerSeqMatchesHeader` invariant
- Comprehensive event consistency tests
- Integration tests

### Correctness Concerns

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:1995-1997` | Protocol 23 special case undocumented | Add comment explaining why |
| `lib.rs:1403-1407` | Floating-point comparison in order book | Use integer-based `compare_price` function |

---

## stellar-core-ledger

Ledger state management and close pipeline.

### Error Handling

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `error.rs:35-41,129-138` | Duplicate error variants `InvalidSequence`/`InvalidLedgerSequence` | Consolidate into single variant |
| `execution.rs:82-98` | `load_config_setting` returns `None` without logging | Log warning on config lookup failure |

### Code Duplication

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `manager.rs:438-451,758-775` | Combined bucket list hash computation duplicated | Extract helper function |
| `soroban_state.rs:234-262` | `contract_data_key_hash`/`contract_code_key_hash` nearly identical | Create generic helper |
| `delta.rs:180-183`, `snapshot.rs:36-39` | `key_to_bytes` duplicated | Define once and re-export |

### Performance Issues

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `close.rs:276-278` | `transactions_owned` creates unnecessary clones | Use `Cow` or reference counting |
| `soroban_state.rs:101-107,124-130` | `xdr_size()` serializes repeatedly | Cache XDR size |
| `delta.rs:218` | HashMap with `Vec<u8>` keys | Use `[u8; 32]` for fixed-size keys |

### Unused Code

| Location | Status |
|----------|--------|
| `manager.rs:216-217` | `bucket_manager` marked dead_code |
| `execution.rs:421-422` | `base_fee` marked dead_code |

### Code Quality

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `execution.rs:1155-2096` | Function over 900 lines | Break into smaller functions |
| `execution.rs:142` | Magic numbers without explanation | Define named constants |

---

## stellar-core-overlay

P2P overlay network protocol.

### Architecture Issues

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `message_handlers.rs:87-88` | `std::sync::Mutex` in async context | Use `tokio::sync::Mutex` or `DashMap` |
| Multiple files | Mixed concurrency primitives | Standardize on consistent primitives |

### Potential Bugs

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `message_handlers.rs:104-105` | Unbounded cache growth | Implement LRU cache with eviction |
| `auth.rs:183-192` | Signature truncation silently | Validate exactly 64 bytes |
| `tx_adverts.rs:179-185` | Non-deterministic eviction | Use proper LRU implementation |

### Performance Issues

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `flow_control.rs:870-882` | `messages_equal` serializes both messages | Compare key fields directly or use hashes |
| `flow_control.rs:836-840` | `msg_body_size` serializes message each time | Cache serialized size |

### Code Duplication

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `codec.rs:266-290`, `flow_control.rs:843-866` | `message_type_name` duplicated | Extract to single location |
| `codec.rs:232-234`, `flood.rs:313-317` | SHA256 message hashing duplicated | Use single implementation |

### Security Concerns

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `manager.rs` | No rate limiting on connection attempts | Add per-IP connection rate limiting |
| `ban_manager.rs` | Not integrated with OverlayManager | Integrate automatic banning for misbehavior |

---

## stellar-core-scp

Stellar Consensus Protocol implementation.

### Silent Error Handling

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `ballot.rs:886-888,1556-1557` | XDR serialization failures with `unwrap_or_default()` | Return `Result` or log warning |
| `nomination.rs:649-651` | Same pattern in `value_key` | Apply same fix |
| `driver.rs:261-264` | Hash computation returns `Hash256::ZERO` on failure | Return `Option<Hash256>` |

### Magic Numbers

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `ballot.rs:901-904` | Recursion limit `50` undocumented | Define `const MAX_ADVANCE_SLOT_RECURSION: u32 = 50;` |

### Performance Issues

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `quorum.rs:407-437` | Redundant clones in `quorum_set_cmp` | Iterate over references directly |
| `quorum.rs:517-531` | TOCTOU race in `SingletonQuorumSetCache` | Use `entry()` API or `dashmap` |

### API Design

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `scp.rs:117-118` | `max_slots` hardcoded to 100 | Add builder or extended constructor |

### Missing Tests

- Ballot invariant verification tests
- Timer callback integration tests

---

## stellar-core-tx

Transaction processing.

### Potential Panics

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `frame.rs:262-264` | `inclusion_fee()` panics on negative resource fee | Return `Result` |
| `events.rs:866` | `make_classic_memo_scval` panics on `Memo::None` | Return `Result` or `Option` |
| `state.rs:435-438` | `next_id()` panics on overflow | Return `Result<i64, TxError>` |

### Unused Code

| Location | Status |
|----------|--------|
| `live_execution.rs:92-93` | `PROTOCOL_VERSION_25` marked dead_code |
| `validation.rs:514` | `context` parameter explicitly discarded |

### Incomplete Implementation

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `signature_checker.rs:302-343` | `verify_ed25519_signed_payload` always returns `true` | Complete verification or document limitation |

### Code Duplication

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `frame.rs` (throughout) | Same envelope matching pattern repeated ~15 times | Extract `inner_transaction()` helper |
| `result.rs:729-783,809-831` | Error mapping duplicated | Extract `fn result_code_to_result()` |

### API Design

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `frame.rs:70-132` | Hash caching doesn't verify network_id | Return `Option<(Hash256, NetworkId)>` or remove caching |
| `validation.rs:166-230` | `ValidationError` doesn't implement `std::error::Error` | Add implementation |

### Missing Tests

- `events.rs` has no test module
- Error path tests in validation

---

## stellar-core-work

Async work scheduler.

### Bugs

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:988-998` | Retry blocking blocks main execution loop | Track retries in `FuturesUnordered`, use `select!` |
| `lib.rs:1084-1093` | Transitive dependent blocking not implemented | Make `block_dependents` recursive |
| `lib.rs:654-686` | Invalid dependency IDs cause silent deadlock | Validate in `add_work`, return error or mark blocked |
| No cycle detection | Cycles cause deadlock | Implement cycle detection or timeout |

### Defensive Programming

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:1152-1163` | `EmptyWork` returns `Success` if executed | Panic or return `Failed` |

### Silent Data Loss

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:1099-1114` | Events dropped without logging | Add `tracing::warn!` or counter |

### Performance

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:129-156,377` | `WorkOutcome::Clone` clones String | Use `Arc<str>` or pass reference |

### API Design

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:162-187` | No `WorkState::is_terminal()` method | Add helper method |
| Multiple methods | Missing `#[must_use]` attributes | Add to `add_work`, `cancel`, `state`, etc. |

### Hardcoded Values

| Location | Issue | Suggested Fix |
|----------|-------|---------------|
| `lib.rs:832` | Channel buffer size hardcoded to 128 | Make configurable via `WorkSchedulerConfig` |

### Missing Tests

- Failure propagation and blocking
- Diamond dependency patterns
- Cycle detection behavior
- Exhausted retries

---

## Summary Statistics

| Category | Total Issues |
|----------|--------------|
| Potential Panics | 35 |
| Silent Error Handling | 26 |
| Code Duplication | 25 |
| Missing Tests | 22 |
| Performance Issues | 20 |
| API Design Issues | 17 |
| Unused/Dead Code | 15 |
| Security Concerns | 6 |
| Documentation Gaps | 12 |
| **Total** | **178** |
