# LEDGER_SPEC.md — Henyey Spec Adherence Evaluation

**Spec**: `stellar-specs/LEDGER_SPEC.md`
**Crate**: `crates/ledger/`
**Date**: 2026-05-10
**Evaluator**: AI-assisted review
**Henyey target**: Protocol 24+ only
**stellar-core baseline**: v26.0.1

---

## Executive Summary

Henyey's ledger crate provides a comprehensive implementation of the stellar-core ledger close pipeline with strong coverage across all major subsystems — the 17-step close pipeline, parallel Soroban execution (stages sequential, clusters parallel via `tokio::task::spawn_blocking`), full `LedgerCloseMeta::V2` generation and streaming, fee calculations, header management, protocol upgrades, network configuration, and bucket list persistence. The state management uses a `LedgerDelta` with savepoints rather than nested `LedgerTxn`, which is architecturally different but functionally equivalent for all rollback patterns.

Since the v25.0.1 evaluation, Henyey has implemented key v26 features including CAP-77 (frozen ledger keys via network configuration) and `createLedgerEntriesForV26`. The remaining gaps are in genesis bootstrapping (`createLedgerEntries` for v20–v25), invariant checking (no `InvariantManager`), and the per-TX module cache (vs shared global cache).

| Section | Rating | Notes |
|---|---|---|
| §1 Introduction | ➖ | Informational only |
| §2 Architecture Overview | ⚠️ | No explicit phase state machine; pipeline logic is correct |
| §3 Data Types & Encoding | ✅ | Full XDR type usage throughout |
| §4 Ledger Close Pipeline | ✅ | 17-step sequence implemented in `close_ledger()` |
| §5 Transaction Application | ✅ | Classic sequential + parallel Soroban (stages/clusters) |
| §6 LedgerTxn Nested State | ✅ | LedgerDelta + savepoints — functionally equivalent to nested LedgerTxn |
| §7 Protocol Upgrades | ✅ | All 7 upgrade types with validation bounds |
| §8 Ledger Header Management | ✅ | Hash computation, skip list, chain verification |
| §9 Network Configuration | ✅ | All 14 Soroban settings + CAP-77 frozen keys loaded and applied |
| §10 Soroban State Management | ⚠️ | In-memory state present; per-TX module cache vs shared |
| §11 Commit & Persistence | ✅ | Bucket list commit, HAS publishing |
| §12 Ledger Close Meta | ✅ | Full V4 `TransactionMeta`, V2 `LedgerCloseMeta`, streaming via `MetaStreamManager` |
| §13 Genesis Ledger | ⚠️ | Basic genesis + v26 entries; missing `createLedgerEntries` for v20–v25 |
| §14 Threading Model | ✅ | Parallel Soroban clusters, background eviction scan, parallel cache init |
| §15 Invariants | ⚠️ | Partial invariant checking; no `InvariantManager` |
| §16 Constants | ✅ | All key constants present and tested |
| §17 References | ➖ | Informational only |
| §18 Appendices | ➖ | Informational only |

**Overall adherence: ~92%**
Self-reported parity: 94% (per `PARITY_STATUS.md`). Behavioral coverage is significantly higher than function-level parity suggests due to architectural consolidation. Up from ~90% at v25.0.1 evaluation due to CAP-77 implementation and genesis improvements.

---

## Evaluation Methodology

Each section of `LEDGER_SPEC.md` is evaluated against the Henyey `crates/ledger/` source code. Requirements are rated:

- ✅ **Implemented** — Behavior matches the spec
- ⚠️ **Partial** — Core behavior present but with architectural differences or missing edge cases
- ❌ **Not Implemented** — Functionality absent or stub only
- ➖ **N/A** — Not applicable (informational section, or pre-protocol-24 only)

Sources consulted:
- `crates/ledger/src/manager.rs` — LedgerManager, `close_ledger()`, `begin_close()`, `commit_close()`, `build_ledger_close_meta()`
- `crates/ledger/src/close.rs` — `LedgerCloseData`, `TransactionSetVariant`, `LedgerCloseResult`, `SorobanPhaseStructure`
- `crates/ledger/src/header.rs` — Header hash, skip list, chain verification
- `crates/ledger/src/delta.rs` — `LedgerDelta`, `EntryChange`, change coalescing
- `crates/ledger/src/execution/mod.rs` — Transaction execution bridge, `SorobanNetworkInfo`, `RefundableFeeTracker`
- `crates/ledger/src/execution/tx_set.rs` — `execute_soroban_parallel_phase()`, cluster isolation, parallel dispatch
- `crates/ledger/src/execution/meta.rs` — `build_transaction_meta()`, `build_entry_changes_with_hot_archive()`, SAC event emission
- `crates/ledger/src/execution/config.rs` — `compute_soroban_resource_fee()`, `FeeConfiguration` loading
- `crates/ledger/src/config_upgrade.rs` — `ConfigUpgradeSetFrame`, min/max validation bounds
- `crates/ledger/src/soroban_state.rs` — `InMemorySorobanState`, TTL co-location
- `crates/ledger/src/lib.rs` — Fees, reserves, trustlines
- `crates/tx/src/meta_builder.rs` — `TransactionMetaBuilder`, `OperationMetaBuilder`, `DiagnosticEventManager`
- `crates/tx/src/state/mod.rs` — `LedgerStateManager`, `Savepoint`, `create_savepoint()` / `rollback_to_savepoint()`
- `crates/common/src/meta.rs` — `normalize_transaction_meta()`, `normalize_ledger_close_meta()`
- `crates/common/src/protocol.rs` — `PARALLEL_SOROBAN_PHASE_PROTOCOL_VERSION`
- `crates/app/src/meta_stream.rs` — `MetaStreamManager`, XDR-framed streaming
- `crates/ledger/PARITY_STATUS.md` — Self-reported parity status

---

## Section-by-Section Evaluation

### §1 Introduction

➖ Informational section. No implementation requirements.

---

### §2 Architecture Overview

**Rating: ⚠️ Partial**

The spec defines a four-phase state machine for ledger close: `SETTING_UP_STATE → READY_TO_APPLY → APPLYING → COMMITTING`.

| Requirement | Status | Notes |
|---|---|---|
| Four-phase state machine (SETTING_UP_STATE, READY_TO_APPLY, APPLYING, COMMITTING) | ⚠️ | No explicit `ApplyState` enum; phases are implicit in `close_ledger()` control flow |
| Phase transitions enforced | ⚠️ | Ordering enforced by sequential function calls, not a state machine guard |
| Pipeline stages execute in order | ✅ | `close_ledger()` calls `begin_close()` → apply → `commit_close()` sequentially |
| Snapshot created before apply | ✅ | Snapshot creation occurs in `begin_close()` before transaction application |

**Analysis**: The pipeline logic in `manager.rs` correctly sequences the phases, but does not model them as an explicit state machine with transition guards. This means invalid phase transitions are prevented by code structure rather than runtime enforcement. Functionally equivalent for a single-threaded implementation, but diverges from the spec's architectural pattern.

---

### §3 Data Types & Encoding

**Rating: ✅ Implemented**

| Requirement | Status | Notes |
|---|---|---|
| XDR encoding for all ledger types | ✅ | Uses `stellar-xdr` crate throughout |
| LedgerHeader XDR structure | ✅ | Full header fields including `bucketListHash`, `skipList` |
| LedgerEntry / LedgerKey types | ✅ | Used in `LedgerDelta`, bucket operations |
| TransactionSet / GeneralizedTransactionSet | ✅ | `TransactionSetVariant` supports both Classic and Generalized |
| Protocol version fields | ✅ | Protocol version checked and used for upgrade logic |

---

### §4 Ledger Close Pipeline

**Rating: ✅ Implemented**

The spec defines a 17-step ledger close sequence. Henyey's `close_ledger()` in `manager.rs` implements this pipeline.

| Requirement | Status | Notes |
|---|---|---|
| Step 1: Receive consensus value | ✅ | `LedgerCloseData` carries consensus value into `close_ledger()` |
| Step 2: Validate ledger sequence number | ✅ | Explicit check: `close_data.ledger_seq == expected_seq` |
| Step 3: Validate previous ledger hash | ✅ | Explicit check against current ledger hash |
| Step 4: Create state snapshot | ✅ | `create_snapshot()` called in `begin_close()` |
| Step 5: Apply protocol upgrades | ✅ | Upgrades applied before transaction execution |
| Step 6: Initialize transaction application | ✅ | `LedgerCloseContext` constructed with close data |
| Step 7: Charge fees and sequence numbers | ✅ | Fee charging in sequential phase via execution bridge |
| Step 8: Apply transactions (sequential phase) | ✅ | Sequential classic transaction application |
| Step 9: Apply transactions (parallel phase) | ✅ | Parallel Soroban via stages/clusters in `execute_soroban_parallel_phase()` |
| Step 10: Collect results and meta | ✅ | Results collected; full `TransactionMeta::V4` and `LedgerCloseMeta::V2` generated |
| Step 11: Apply protocol upgrades to state | ✅ | Config upgrades applied via `ConfigUpgradeSetFrame` |
| Step 12: Update ledger header | ✅ | Header fields updated including fees, id pool |
| Step 13: Compute ledger header hash | ✅ | `compute_header_hash()` = SHA256(XDR) |
| Step 14: Update skip list | ✅ | Skip list computation in `header.rs` |
| Step 15: Commit changes to bucket list | ✅ | `commit_close()` persists via bucket list |
| Step 16: Publish HAS at checkpoints | ✅ | HAS publishing at checkpoint boundaries |
| Step 17: Advance ledger state | ✅ | Ledger number and state advanced after commit |

**Analysis**: All 17 steps are fully implemented. The parallel apply phase (step 9) uses `execute_soroban_parallel_phase()` with stages/clusters. Meta generation (step 10) produces full `TransactionMeta::V4` and `LedgerCloseMeta::V2`. The core close pipeline is functionally complete and deterministic.

---

### §5 Transaction Application

**Rating: ✅ Implemented**

| Requirement | Status | Notes |
|---|---|---|
| Fee charging before execution | ✅ | Fees charged in sequential phase via `pre_deduct_all_fees_on_delta()` |
| Sequence number consumption | ✅ | Sequence numbers validated and consumed |
| Sequential phase (classic txns) | ✅ | All classic transactions applied sequentially via `run_transactions_on_executor()` |
| Parallel phase (Soroban txns) | ✅ | `execute_soroban_parallel_phase()` in `tx_set.rs` — stages sequential, clusters parallel via `tokio::task::spawn_blocking` |
| Cluster isolation | ✅ | Each cluster gets its own `TransactionExecutor` + `LedgerDelta`; merged in deterministic cluster order |
| Prior-stage visibility | ✅ | `delta.current_entries()` passed so clusters see prior stage changes |
| Operation-level rollback on failure | ✅ | Savepoints provide per-operation rollback |
| Transaction-level rollback on failure | ✅ | Transaction changes rolled back on failure |
| Result code mapping | ✅ | XDR result codes mapped via `execution/result_mapping.rs` |
| Soroban resource metering | ✅ | Resource limits enforced via `SorobanNetworkInfo` |

**Analysis**: Transaction application is fully implemented. Classic transactions run sequentially, and Soroban transactions execute in the parallel stages/clusters model matching stellar-core: stages are applied sequentially, and within each stage, clusters execute in parallel via `tokio::task::spawn_blocking` (`tx_set.rs:815`). A single-cluster fast path avoids threading overhead. Results are merged in deterministic cluster order. The protocol gate is `PARALLEL_SOROBAN_PHASE_PROTOCOL_VERSION = V23` (`protocol.rs:102`).

---

### §6 LedgerTxn Nested Transactional State

**Rating: ✅ Implemented (architectural difference, functionally equivalent)**

The spec describes a nested transaction model (`LedgerTxnRoot → LedgerTxn → LedgerTxn → ...`) with commit/rollback at each level. Henyey uses `LedgerStateManager` with a flat model using two explicit rollback mechanisms that cover all the same nesting patterns.

| Requirement | Status | Notes |
|---|---|---|
| Nested transaction hierarchy | ✅ | `LedgerDelta` + composable savepoints cover ledger→TX→operation→sub-operation nesting |
| Root-level state access | ✅ | Direct bucket list + in-memory Soroban state lookup |
| Transaction-level isolation | ✅ | `LedgerDelta` tracks changes; `snapshot_delta()` + `rollback()` for TX-level rollback |
| Operation-level rollback | ✅ | `create_savepoint()` / `rollback_to_savepoint()` with 7-phase state restore |
| Sub-operation speculation | ✅ | Nested savepoints (e.g., `convert_with_offers_and_pools` creates savepoint inside op-level savepoint) |
| Commit propagation (child → parent) | ✅ | Change coalescing in `LedgerDelta`; savepoint drop = implicit commit |
| Entry caching hierarchy | ➖ | No `LedgerTxnRoot` caching; direct bucket list reads with in-memory Soroban state |
| Prefetch support | ❌ | No entry prefetching (performance optimization only) |
| Best-offer tracking | ✅ | Offer sorting implemented in `offer.rs` |

**Analysis**: Henyey's two-level model (transaction rollback via `snapshot_delta()`/`rollback()` + composable savepoints via `create_savepoint()`/`rollback_to_savepoint()`) reproduces all nesting semantics of stellar-core's `LedgerTxn` tree. The savepoint mechanism captures full state (snapshot maps, delta lengths, modified vecs, id_pool, offer indices) and performs 7-phase rollback. Path payment speculation uses nested savepoints within operation-level savepoints, matching the nested `LedgerTxn` pattern. The deeper nesting levels in stellar-core are primarily an artifact of its SQL-backed state model. No correctness gap exists — this is confirmed by extensive testing (savepoint rollback tests for accounts, offers, data entries, claimable balances, id_pool, and offer index consistency).

---

### §7 Protocol Upgrades

**Rating: ✅ Implemented**

| Requirement | Status | Notes |
|---|---|---|
| Protocol version upgrade | ✅ | Supported |
| Base fee upgrade | ✅ | Supported |
| Max transaction set size upgrade | ✅ | Supported |
| Base reserve upgrade | ✅ | Supported |
| Flags upgrade | ✅ | Supported |
| Max Soroban transaction set size upgrade | ✅ | Supported |
| Config upgrade (Soroban settings) | ✅ | `ConfigUpgradeSetFrame` with min/max validation bounds |
| Upgrade validation bounds | ✅ | Min/max bounds enforced for all config settings |
| Upgrade application ordering | ✅ | Applied in spec-defined order |

---

### §8 Ledger Header Management

**Rating: ✅ Implemented**

| Requirement | Status | Notes |
|---|---|---|
| Header hash = SHA256(XDR-encoded header) | ✅ | `compute_header_hash()` in `header.rs` |
| Skip list maintenance | ✅ | Skip list computation with correct intervals |
| Previous ledger hash chain | ✅ | Validated in `close_ledger()` |
| Bucket list hash in header | ✅ | Including protocol 23+ combined live+hot_archive hash |
| Total coins tracking | ✅ | Fee pool and inflation tracking in header |
| ID pool (last generated ID) | ✅ | Updated during transaction application |
| SCP value in header | ✅ | Consensus value stored |

---

### §9 Network Configuration

**Rating: ✅ Implemented**

| Requirement | Status | Notes |
|---|---|---|
| Soroban transaction limits | ✅ | Loaded into `SorobanNetworkInfo` |
| Soroban ledger limits | ✅ | Loaded and enforced |
| Contract data size limits | ✅ | Present |
| Contract code size limits | ✅ | Present |
| Bandwidth limits | ✅ | Present |
| Compute (CPU) limits | ✅ | Present |
| Memory limits | ✅ | Present |
| Contract events limits | ✅ | Present |
| State archival settings | ✅ | TTL settings loaded |
| Fee rate configuration | ✅ | Fee calculation uses network config |
| Rent fee configuration | ✅ | Rent fees calculated per config |
| Write fee configuration | ✅ | Write fees per config |
| Historical data retention | ✅ | Archival settings present |
| Parallel compute config | ✅ | `ContractParallelComputeV0` loaded and validated (max clusters < 128); used in parallel Soroban execution |
| Frozen ledger keys (CAP-77, P26+) | ✅ | `load_frozen_key_config()` loads frozen keys and bypass tx hashes from CONFIG_SETTING entries; enforced during transaction application |

**Analysis**: All 14+ configuration areas are loaded and applied correctly, including parallel compute configuration and the Protocol 26 frozen ledger keys (CAP-77). The frozen key configuration is loaded at ledger close time and passed into execution contexts for enforcement.

---

### §10 Soroban State Management

**Rating: ⚠️ Partial**

| Requirement | Status | Notes |
|---|---|---|
| In-memory Soroban state cache | ✅ | `InMemorySorobanState` with contract data/code maps |
| TTL co-location with entries | ✅ | TTLs stored alongside entries in the cache |
| Entry size tracking | ✅ | Size tracking for cache eviction |
| Background eviction scanning | ✅ | `PendingEvictionScan` between ledger closes |
| Shared module cache (multi-threaded compilation) | ⚠️ | Per-TX `PersistentModuleCache` instead of shared global cache |
| Module cache warm-up | ❌ | No background compilation warm-up |
| Soroban metrics collection | ❌ | Not implemented |
| State archival (TTL expiry) | ✅ | TTL-based eviction supported |
| State restoration | ✅ | Entry restoration from archive |

**Analysis**: The in-memory Soroban state is well-implemented with TTL co-location and eviction scanning. The key difference is module caching: Henyey uses a per-transaction `PersistentModuleCache` rather than a shared, multi-threaded compilation cache. This affects Soroban execution performance but not correctness, since module compilation is deterministic.

---

### §11 Commit & Persistence

**Rating: ✅ Implemented**

| Requirement | Status | Notes |
|---|---|---|
| Seal ledger changes | ✅ | `commit_close()` finalizes changes |
| Store to bucket list | ✅ | Changes committed to bucket list |
| SQL persistence | ➖ | Intentionally omitted; bucket list is sole persistence layer |
| HAS publishing at checkpoints | ✅ | History Archive State published at checkpoint intervals |
| Checkpoint interval (64 ledgers) | ✅ | Standard checkpoint interval used |
| Atomic commit | ✅ | Commit is all-or-nothing |

**Analysis**: Henyey uses bucket list as the sole persistence layer, intentionally omitting the SQL layer that stellar-core maintains. This is a deliberate architectural simplification. All commit and checkpoint publishing logic is present.

---

### §12 Ledger Close Meta

**Rating: ✅ Implemented**

| Requirement | Status | Notes |
|---|---|---|
| TransactionMeta V4 generation | ✅ | `TransactionMetaBuilder` in `crates/tx/src/meta_builder.rs` — full V4 with per-operation changes, events, Soroban fee tracking |
| LedgerCloseMeta V2 assembly | ✅ | `build_ledger_close_meta()` in `manager.rs:3617` — header, generalized tx set, per-tx `TransactionResultMetaV1`, evicted keys, soroban state size, upgrade meta, SCP history |
| Per-operation entry changes (CREATED, UPDATED, REMOVED, STATE, RESTORED) | ✅ | `OperationMetaBuilder` records all change types; `build_entry_changes_with_hot_archive()` in `execution/meta.rs` (600+ lines) handles footprint ordering, hot archive restores, TTL grouping |
| txChangesBefore / txChangesAfter | ✅ | `push_tx_changes_before()` / `push_tx_changes_after()` in `TransactionMetaBuilder` |
| Upgrade meta | ✅ | Included in `LedgerCloseMeta::V2` construction |
| Eviction meta (evicted keys, soroban state size) | ✅ | Evicted keys and state size included in close meta |
| SCP history in meta | ✅ | SCP history entries included; tested in `test_ledger_close_meta_includes_scp_history` |
| Soroban meta (events, return value, diagnostics, fee tracking) | ✅ | `SorobanTransactionMetaV2` with `nonRefundableResourceFeeCharged`, `rentFeeCharged`, `totalRefundableResourceFeeCharged` |
| Meta normalization for deterministic hashing | ✅ | `normalize_transaction_meta()` / `normalize_ledger_close_meta()` in `crates/common/src/meta.rs` — sorts changes into canonical order |
| Meta streaming to external consumers | ✅ | `MetaStreamManager` in `crates/app/src/meta_stream.rs` — XDR-framed output to file/pipe/fd with optional rotating gzip debug stream |
| SAC events for classic operations (P23+) | ✅ | `emit_classic_events_for_operation()` in `execution/meta.rs` — all classic op types |

**Analysis**: Ledger close meta is comprehensively implemented. The full pipeline exists: `TransactionMetaBuilder` produces V4 meta during execution, `build_ledger_close_meta()` assembles `LedgerCloseMeta::V2`, `normalize_ledger_close_meta()` ensures deterministic ordering, and `MetaStreamManager` streams to external consumers. Hash vector tests (`tx_meta_hash_vectors.rs`, `ledger_close_meta_vectors.rs`) verify correctness. The `DiagnosticEventManager` and `OpEventManager` handle Soroban and classic SAC events respectively.

---

### §13 Genesis Ledger

**Rating: ⚠️ Partial**

| Requirement | Status | Notes |
|---|---|---|
| Genesis ledger creation (seq 1) | ✅ | Basic genesis ledger initialization |
| Root account seeding | ✅ | Root account created |
| Initial protocol version | ✅ | Set from configuration |
| `createLedgerEntriesForV20` | ❌ | Not implemented |
| `createLedgerEntriesForV21` | ❌ | Not implemented |
| `createLedgerEntriesForV22` | ❌ | Not implemented |
| `createLedgerEntriesForV23` | ❌ | Not implemented |
| `createLedgerEntriesForV25` | ❌ | Not implemented |
| `createLedgerEntriesForV26` (CAP-77) | ✅ | Creates 2 CONFIG_SETTING entries for frozen keys and bypass tx sets (`manager.rs:3774`) |

**Analysis**: Basic genesis works, and v26 genesis entries are implemented (CAP-77 frozen key CONFIG_SETTING entries). However, the `createLedgerEntries` functions for protocols v20–v25 are still missing. This means Henyey cannot bootstrap a new network from genesis with Soroban support for protocols prior to v26 — it must join an existing network that already has these entries. For the primary use case (validating/watching an existing network), this is acceptable.

---

### §14 Threading Model

**Rating: ✅ Implemented**

| Requirement | Status | Notes |
|---|---|---|
| Parallel Soroban execution stages | ✅ | Stages sequential, clusters parallel via `tokio::task::spawn_blocking` (`tx_set.rs:815`) |
| Single-cluster fast path | ✅ | Inline execution when only one cluster in a stage (`tx_set.rs:790`) |
| Cluster isolation | ✅ | Each cluster gets its own `TransactionExecutor` + `LedgerDelta`; `Send` assertions enforce thread safety |
| Deterministic result merge | ✅ | Results merged in cluster order (`tx_set.rs:909-918`) |
| Background eviction scanning | ✅ | `std::thread::spawn` after committing ledger N scans for evictions at N+1 (`manager.rs:3398`) |
| Parallel cache initialization | ✅ | `scan_parallel()` spawns one OS thread per bucket level (11 threads) via `std::thread::scope` (`manager.rs:455`) |
| Thread-safe state access | ✅ | `TxSetResult` and `LedgerDelta` have static `Send` assertions (`tx_set.rs:3659-3666`) |
| Module cache thread safety | ⚠️ | Per-TX `PersistentModuleCache` instead of shared global cache; no cross-TX compilation sharing |

**Analysis**: Henyey implements the parallel Soroban execution model matching stellar-core: stages are applied sequentially, and within each stage, clusters execute in parallel via `tokio::task::spawn_blocking`. The protocol gate is `PARALLEL_SOROBAN_PHASE_PROTOCOL_VERSION = V23`. Additional parallelism includes background eviction scanning between ledger closes and parallel bucket list cache initialization at startup. The primary architectural difference is per-TX module caching vs. stellar-core's shared multi-threaded compilation cache, which is a performance difference only.

---

### §15 Invariants

**Rating: ⚠️ Partial**

The spec defines 14 invariants (INV-L1 through INV-L14).

| Invariant | Status | Notes |
|---|---|---|
| INV-L1: Ledger sequence monotonically increases | ✅ | Checked in `close_ledger()` |
| INV-L2: Previous hash chain integrity | ✅ | Validated before close |
| INV-L3: Bucket list hash matches header | ✅ | Verified including p23+ combined hash |
| INV-L4: Total coins conservation | ⚠️ | Fee pool tracked but no explicit conservation invariant check |
| INV-L5: Account balance ≥ reserve | ⚠️ | Reserve calculations present; not checked as invariant |
| INV-L6: Sequence number monotonicity | ✅ | Enforced during transaction application |
| INV-L7: Offer validity | ⚠️ | Offer sorting present; no post-close invariant sweep |
| INV-L8: Trustline consistency | ⚠️ | Trustline logic present; no explicit invariant check |
| INV-L9: Sponsorship balance | ⚠️ | Not explicitly verified as invariant |
| INV-L10: LedgerEntry type consistency | ⚠️ | Enforced by type system, not runtime check |
| INV-L11: Soroban entry TTL validity | ⚠️ | TTL logic present but no post-close sweep |
| INV-L12: Config upgrade hash integrity | ✅ | Hash validation in `ConfigUpgradeSetFrame` |
| INV-L13: Minimum protocol version | ✅ | Protocol 24+ enforced |
| INV-L14: No duplicate ledger entries | ⚠️ | Enforced by bucket list structure, not explicit check |

**Analysis**: Many invariants are implicitly maintained through correct implementation rather than explicitly checked post-close. Henyey does not have a dedicated invariant-checking pass equivalent to stellar-core's `InvariantManager`. The critical invariants (sequence, hash chain, bucket list hash) are explicitly verified. The remainder are maintained by construction.

---

### §16 Constants

**Rating: ✅ Implemented**

| Requirement | Status | Notes |
|---|---|---|
| Base reserve (in stroops) | ✅ | Correct value with tests |
| Base fee | ✅ | Correct value |
| Max transaction set size | ✅ | Present |
| Checkpoint frequency (64) | ✅ | Used in HAS publishing |
| Protocol version bounds | ✅ | Protocol 24+ enforced |
| Fee calculation constants | ✅ | Extensive test coverage matching stellar-core |
| Reserve calculation constants | ✅ | Tested against stellar-core values |

---

### §17 References

➖ Informational section. No implementation requirements.

---

### §18 Appendices

➖ Informational section. No implementation requirements.

---

## Gap Summary

### Critical Gaps

None. The two previously-identified critical gaps (ledger close meta and parallel Soroban apply) are in fact fully implemented.

### Moderate Gaps

| Gap | Spec Section | Impact |
|---|---|---|
| **No explicit phase state machine** | §2 | Phase transitions rely on code structure rather than runtime guards. Lower defense-in-depth. |
| **Per-TX module cache vs shared** | §10 | Repeated Wasm compilation across transactions. Performance impact on Soroban-heavy ledgers. |
| **Missing genesis `createLedgerEntries` (v20–v25)** | §13 | Cannot bootstrap a new Soroban-enabled network from genesis for pre-v26 protocols. Must join existing networks. v26 entries (CAP-77) are implemented. |
| **No explicit invariant checking pass** | §15 | Invariants maintained by construction but not independently verified post-close. No `InvariantManager`. Bugs could violate invariants silently. |

### Minor Gaps

| Gap | Spec Section | Impact |
|---|---|---|
| **No entry prefetching** | §6 | Performance optimization only; no correctness impact. |
| **No Soroban metrics** | §10 | Observability gap; no impact on correctness or determinism. |
| **No module cache warm-up** | §10 | First-execution latency for contracts. Performance only. |
| **No SQL persistence layer** | §11 | Intentional architectural choice. Bucket list is sole store. |

### Corrected Items (Previously Reported as Gaps)

| Item | Previous Rating | Actual Rating | Evidence |
|---|---|---|---|
| **Ledger close meta** | ❌ Critical | ✅ Implemented | Full V4 `TransactionMeta`, V2 `LedgerCloseMeta`, `MetaStreamManager` streaming, normalization, hash vector tests |
| **Parallel Soroban apply** | ❌ Critical | ✅ Implemented | `execute_soroban_parallel_phase()` with stages sequential, clusters parallel via `tokio::task::spawn_blocking` |
| **LedgerDelta vs nested LedgerTxn** | ⚠️ Moderate | ✅ Implemented | Composable savepoints with 7-phase rollback cover all nesting patterns (TX→op→sub-op); confirmed by extensive testing |

---

## Risk Assessment

### Determinism Risk: **Low**

All architectural differences (LedgerDelta, per-TX module cache) preserve determinism. The ledger close pipeline produces identical ledger hashes to stellar-core, as verified by the offline verification tool. Parallel Soroban execution is deterministic by design (cluster results merged in fixed order). No gaps introduce non-determinism.

### Correctness Risk: **Low**

The absence of an explicit invariant checking pass means some state corruption could go undetected. However, the critical invariants (hash chain, bucket list hash, sequence numbers) are explicitly verified. The remaining invariants are maintained by correct transaction application logic, which is well-tested. The full meta generation pipeline provides independent correctness verification through hash vector tests.

### Performance Risk: **Low-Medium**

Per-TX module caching is the primary performance concern. The parallel Soroban execution model matches stellar-core's stages/clusters approach, so throughput for Soroban transactions is comparable. Background eviction scanning and parallel cache initialization further reduce latency.

### Feature Completeness Risk: **Low**

Ledger close meta generation and streaming are fully implemented, enabling all downstream consumers (Horizon, RPC, analytics). The remaining feature gap (genesis bootstrapping) only affects new network creation, not participation in existing networks.

---

## Recommendations

1. **Add an invariant checking pass** (§15) — This is the highest-impact remaining gap. Implement at minimum `ConservationOfLumens` (INV-L4), `LedgerEntryIsValid`, and `AccountSubEntriesCountIsValid` as post-close checks. Even a debug-only invariant checker would significantly improve confidence in state correctness.

2. **Add genesis `createLedgerEntries`** (§13) — Required for standalone or test network bootstrapping. Implement `createLedgerEntriesForV20` through `V25` to initialize Soroban configuration entries.

3. **Consider shared module cache** (§10) — Replace per-TX `PersistentModuleCache` with a shared cache that persists across transactions within a ledger close. This is a moderate-effort change with significant Soroban performance benefits.

4. **Consider explicit phase state machine** (§2) — Low priority but improves code clarity and defense-in-depth. An enum-based state machine for the close pipeline would make invalid transitions a compile-time error.

---

## v26.0.1 Implementation Delta

This section summarizes changes in stellar-core between v25.0.1 and v26.0.1 (`src/ledger/`) and their impact on Henyey parity.

### Changes Implemented in Henyey

| stellar-core Change | Henyey Status | Location |
|---|---|---|
| **CAP-77: Freeze ledger keys via network configuration** | ✅ Implemented | `execution/config.rs:load_frozen_key_config()`, `manager.rs:3928` — loads frozen keys and bypass tx hashes from CONFIG_SETTING entries at ledger close; enforced during tx application |
| **`createLedgerEntriesForV26`** | ✅ Implemented | `manager.rs:3774` — creates 2 CONFIG_SETTING entries for frozen key and bypass tx sets |
| **Restored keys tracking cleanup** | ✅ Implemented | `execution/apply.rs:collect_soroban_restored_entries()` — tracks restored entries per-TX with `hot_archive_restored_keys`; v26 cleanup of `LedgerTxn` restore tracking doesn't apply (Henyey uses `LedgerDelta`) |

### Changes Not Applicable to Henyey

| stellar-core Change | Why N/A |
|---|---|
| **Remove maintenance mode** | Henyey never implemented maintenance mode; bucket list is the sole persistence layer with no SQL sync |
| **Background apply with RUN_STANDALONE** | Henyey's `close_ledger()` is always synchronous inline; no background apply thread model |
| **DB dead code cleanup** | Henyey has no SQL persistence layer for ledger state |
| **SQLite parallel apply (split database)** | Henyey has no SQL persistence layer; parallelism is achieved via `tokio::task::spawn_blocking` on `LedgerDelta` clones |
| **Drop prepared statement cache** | No SQL layer |
| **Fix race on startup with HTTP server** | Henyey's HTTP server has independent lifecycle management |
| **BucketListStateConsistency snapshot invariant** | Henyey has no `InvariantManager`; bucket list consistency verified by hash matching |
| **Snapshot access race fixes** | Henyey snapshots are immutable Rust `Arc<>` values; no races possible due to ownership model |
| **MSVS project updates** | Build system not applicable |
| **C++20 upgrade** | Language not applicable |

### Changes with Indirect Parity Impact

| stellar-core Change | Henyey Impact |
|---|---|
| **CAP-80 updates** | Henyey does not reference CAP-80 explicitly; any behavioral changes from CAP-80 would need to be verified through integration tests. No explicit code paths found in `crates/ledger/`. |
| **`markRestoredFromLiveBucketList`** | stellar-core added explicit tracking of entries restored from the live bucket list (vs hot archive). Henyey tracks restores via `collect_soroban_restored_entries()` and `hot_archive_restored_keys` but does not distinguish live-bucket-list restores. This is a tracking detail, not a consensus-affecting difference. |
| **Concurrency thread safety annotations** | stellar-core added annotations and fixed concurrency gaps. Henyey's Rust type system (`Send`/`Sync` bounds, `Arc<>`, ownership) provides compile-time concurrency safety without runtime annotations. |
| **Log state rebuild timings** | Observability only; Henyey logs rebuild progress via `tracing` crate |
| **Remove P26 ifdefs / Bump to P26** | Henyey uses runtime protocol version checks (`ledger_version >= 26`) rather than compile-time ifdefs; no action needed |
| **Refactored `ParallelTxReturnVal`** | Henyey's parallel return type is `TxSetResult` in `tx_set.rs`; structurally different but functionally equivalent |
| **Cost types recalibration (arkworks)** | Soroban cost model is loaded from network config at runtime; no hardcoded cost tables in `crates/ledger/` |

### Summary

Of the ~40 commits to `src/ledger/` between v25.0.1 and v26.0.1:
- **3 changes** are directly implemented in Henyey (CAP-77, genesis v26, restore tracking)
- **10 changes** are not applicable (SQL/maintenance/build system/C++ specifics)
- **7 changes** have indirect impact requiring monitoring but no code changes
- Remaining commits are test additions, minor renames, and review feedback iterations

**Net parity change**: Improved. CAP-77 implementation brings Henyey up to date with the primary Protocol 26 ledger feature. Self-reported parity increased from ~64% (function-level, v25) to 94% (area-level, v26) reflecting both new implementations and a more accurate measurement methodology.
