# Bug Analysis Report

**Date**: February 21, 2026
**Scope**: 50 most recent bug fix commits (Feb 13 - Feb 21, 2026)
**Purpose**: Identify recurring bug categories, root causes, and structural refactoring opportunities

---

## Executive Summary

Analysis of 50 bug fixes reveals five dominant categories. **Parity divergences** with stellar-core account for 60% of all bugs (30/50), followed by **async/event loop issues** (16%, 8/50), **state management bugs** (10%, 5/50), **Soroban-specific issues** (8%, 4/50), and **configuration/wiring errors** (6%, 3/50).

The most impactful finding is that the majority of bugs stem from a structural problem: the codebase reimplements stellar-core's validation logic across many individual operation files without a shared framework that enforces the upstream's evaluation order, liability accounting, and error code precedence. This decentralized approach makes each operation an independent site for parity regressions.

### Bug Distribution by Crate

| Crate | Files Changed | Bug Fixes Touching Crate |
|-------|--------------|--------------------------|
| `tx` | 46 | 28 |
| `ledger` | 36 | 18 |
| `app` | 27 | 11 |
| `overlay` | 7 | 5 |
| `bucket` | 4 | 4 |
| `common` | 1 | 1 |

### Hotspot Files

| File | Times Changed | Bug Categories |
|------|--------------|----------------|
| `crates/ledger/src/manager.rs` | 9 | Parity, state management |
| `crates/tx/src/state/mod.rs` | 7 | Snapshot/rollback, liabilities |
| `crates/tx/src/state/entries.rs` | 6 | Snapshot overwrite, LML stamping |
| `crates/ledger/src/execution/tx_set.rs` | 6 | Fee deduction, TTL flush, PRNG |
| `crates/ledger/src/execution/mod.rs` | 6 | Validation ordering, fee refund |
| `crates/app/src/app/lifecycle.rs` | 5 | Event loop freeze/starvation |
| `crates/app/src/app/mod.rs` | 6 | Blocking operations, state management |

---

## Category 1: Parity Divergences (30 bugs, 60%)

The largest category. These are cases where henyey's behavior differs from stellar-core, producing different transaction results, error codes, or ledger hashes.

### 1A. Validation Check Ordering (10 bugs)

**Pattern**: stellar-core checks conditions in a specific order, and the first failing check determines the result code. Henyey checked conditions in a different order, returning the wrong error code when multiple conditions failed simultaneously.

| Commit | Bug | Correct Order |
|--------|-----|---------------|
| `86295f5` | CreateAccount: sponsor reserve vs source balance | Sponsor reserve first (LowReserve before Underfunded) |
| `3928141` | ChangeTrust: issuer existence vs subentry limit | Issuer check first (NoIssuer before TooManySubentries) |
| `61d00c8` | SetTrustLineFlags: AUTH_REVOCABLE vs trustline lookup | Revocable check first (CantRevoke before NoTrustLine) |
| `da4bcfe` | ClawbackClaimableBalance: issuer check vs flag check | Return NotIssuer, not NotClawbackEnabled |
| `7311e8c` | ManageBuyOffer: LineFull vs Underfunded | LineFull before Underfunded |
| `fcac75b` | SetOptions: apply flags before validating | Apply clear/set, then validate result |
| `2affd80` | AccountMerge: ImmutableSet check ordering | ImmutableSet first |
| `ddc8270` | Fee-bump inner TX signature threshold | THRESHOLD_LOW, not THRESHOLD_MEDIUM |
| `7fc05d2` | Soroban memo validation scope | InvokeHostFunction only, not all Soroban ops |
| `cffa290` | TX envelope size limit in execution | Not applied during execution (overlay-only) |

**Root cause**: No systematic mechanism ensures check ordering matches stellar-core. Each operation is hand-coded.

### 1B. Selling Liabilities Not Deducted (7 bugs)

**Pattern**: stellar-core's `getAvailableBalance()` deducts selling liabilities from the raw balance before underfunded checks. Henyey used raw balances, allowing operations that should fail with Underfunded.

| Commit | Operation |
|--------|-----------|
| `a8e5332` | CreateClaimableBalance (native + non-native) |
| `8e3e56e` | LiquidityPoolDeposit |
| `a289f34` | LiquidityPoolWithdraw (T-04) |
| `2c070e8` | Clawback (T-03) |
| `181e2fe` | CreateAccount (sponsor delta) |
| `bea47aa` | ClaimClaimableBalance (i64 overflow in limit check) |
| `a289f34` | Pool deposit share calculation (T-05) |

**Root cause**: No shared `get_available_balance()` helper. Each operation reimplemented its own balance check, often omitting the liability deduction.

### 1C. Fee Processing Order (3 bugs)

**Pattern**: stellar-core deducts ALL fees in a single pre-pass before executing any transaction body. Henyey deducted fees interleaved with execution.

| Commit | Bug |
|--------|-----|
| `a176c15` | Classic fees deducted one-at-a-time instead of upfront |
| `34e3093` | Cross-phase fee deduction: Soroban fees missing during classic execution |
| `e625cd3` | Failed Soroban TXs not getting refundable fee subtracted |

**Root cause**: The fee deduction lifecycle was not modeled as a distinct phase separated from execution.

### 1D. Missing Functionality (6 bugs)

**Pattern**: Entire algorithms or protocol behaviors from stellar-core that were never implemented.

| Commit | Missing Feature |
|--------|----------------|
| `292a2e7` | prepare_liabilities for base reserve increase (L-03) |
| `eee5019` | Pool share trustline redemption during deauthorization (T-02) |
| `bc64db4` | Cost params validation by protocol version (L-04) |
| `e3c834d` | V24 mainnet fee pool correction (L-02) |
| `ae34f1e` | Pool share trustline loading from secondary index (VE-02) |
| `c0726f0` | RO TTL bump flushing for write footprint keys |

### 1E. Error Code Mismatches (4 bugs)

| Commit | Bug |
|--------|-----|
| `da4bcfe` | ClawbackClaimableBalance: wrong error enum variants |
| `be214be` | PathPayment: OpExceededWorkLimit vs TooFewOffers |
| `a2d3855` | Double offer deletion during AllowTrust (wrong liabilities) |
| `45c4150` | min_seq_num precondition: txBAD_SEQ vs BadMinSeqAgeOrGap |

---

## Category 2: Async / Event Loop Issues (8 bugs, 16%)

All 8 bugs were in the `app` crate's main event loop, which uses a tokio `select!` loop. These caused the node to freeze, sometimes for 20+ minutes, during mainnet/testnet operation.

### 2A. Blocking Operations in Async Context (4 bugs)

| Commit | Blocking Call |
|--------|---------------|
| `d29f40f` | `resolve_pending_bucket_merges()` via `block_in_place()` inside async catchup |
| `0c37331` | Same issue recurring: bucket GC in main select! loop |
| `c0d4152` | Sequential per-peer broadcast with overlay behind TokioMutex |
| `ce7f9b9` | `send_to().await` blocking on full peer channel in flood handler |

### 2B. Unbounded Drain Loops (3 bugs)

| Commit | Unbounded Loop |
|--------|----------------|
| `4d1d76a` | `try_apply_buffered_ledgers()` processing all buffered ledgers sequentially |
| `610cc58` | SCP message drain loop never yielding (messages arrive faster than processed) |
| `1ae915b` | Broadcast channel drain starving all other select! branches |

### 2C. State Machine Errors (1 bug)

| Commit | Bug |
|--------|-----|
| `0c37331` | Failed catchup left node permanently stuck in `CatchingUp` state |

**Root cause**: The event loop has no structural protection against blocking calls or unbounded iterations. The single-threaded select! loop means any blocking call or tight loop freezes the entire node.

---

## Category 3: State Management / Snapshot Bugs (5 bugs, 10%)

These are bugs in the transaction state management system (`crates/tx/src/state/`), which manages snapshots for operation-level rollback.

| Commit | Bug |
|--------|-----|
| `0fb052d` | `update_contract_data/code` overwrote snapshot with post-update value |
| `d482c43` | Same bug in `update_account`, `update_data`, `update_claimable_balance` |
| `a56ad63` | `flush_all_accounts` overwrote snapshot, breaking rollback |
| `8646b99` | `last_modified_ledger_seq` not stamped on entries touched via `get_*_mut` |
| `828ef06` | `process_entry_update/delete` silently handled missing entries |

**Root cause**: The snapshot system uses a manual snapshot-per-method approach where each `update_*` method is responsible for correctly managing its own snapshot. The identical "snapshot overwrite" bug appeared in 5 separate methods, suggesting the pattern itself is error-prone.

---

## Category 4: Soroban-Specific Issues (4 bugs, 8%)

| Commit | Bug |
|--------|-----|
| `2dab19f` + `10d80d4` | PRNG seed offset used wrong tx count (fixed twice; second fix reverted first) |
| `eaa4a32` | Footprint entry index misalignment (skipped entries instead of empty buffers) |
| `e0ddac8` | Snapshot adapter discarded original entry metadata (LML, sponsorship ext) |
| `626be70` | Empty entry buffers caused XDR deserialization failures |

**Root cause**: The Soroban execution path has complex index-alignment and metadata-preservation requirements that are easy to violate when translating from C++ to Rust.

---

## Category 5: Configuration / Wiring Errors (3 bugs, 6%)

| Commit | Bug |
|--------|-----|
| `8a0d23f` | BucketListDB caching config never wired to bucket list |
| `5bf99d6` | TxQueueConfig hardcoded testnet network_id |
| `6139a1b` | Hello message port hardcoded instead of reading config |

**Root cause**: Config propagation is manual and there is no validation that all config values are actually consumed.

---

## Trend Analysis

### Temporal Progression

| Period | Dominant Bug Type | Context |
|--------|-------------------|---------|
| Feb 13-14 | Event loop freezes, config wiring | Initial mainnet validator testing |
| Feb 14-16 | Operation parity (check ordering, liabilities) | Mainnet verify-execution sweep |
| Feb 16-17 | Soroban parity (PRNG, snapshots, fees) | Soroban-specific verification |
| Feb 17-19 | Deep-compare audit fixes (T-xx, L-xx, B-xx) | Systematic parity audit |
| Feb 19-21 | VE-01/VE-02 snapshot and secondary index bugs | Live mainnet divergence investigation |

### Recurrence Patterns

1. **Selling liabilities omission**: The same bug (not deducting selling liabilities) appeared independently in 7 different operations. Each was fixed separately.

2. **Snapshot overwrite**: The same snapshot-overwriting pattern appeared in 5 different `update_*` methods. Fixed in two commits.

3. **Event loop blocking**: 4 separate instances of blocking calls in the async event loop, discovered one at a time during live testing.

4. **Check ordering**: 10 different operations had checks in the wrong order. Each required manual comparison with stellar-core.

5. **PRNG seed offset**: Fixed, then the fix was reverted by a subsequent "fix" that misread the phase ordering, requiring a third commit.

---

## Refactoring Opportunities

### R1: Centralized Balance/Liability Helpers (High Priority)

**Problem**: 7 operations independently reimplemented balance checks without deducting selling liabilities.

**Proposal**: Create a `BalanceOps` trait or module in `crates/tx/src/state/` that provides:
- `get_available_balance(account) -> i64` (deducts selling liabilities + minimum balance)
- `get_available_trustline_balance(trustline) -> i64` (deducts selling liabilities)
- `check_underfunded(account, amount) -> Result<()>` (uses available balance)
- Overflow-safe arithmetic helpers (the `tl.limit - tl.balance < amount` pattern)

Make the raw balance fields private and force all operation code to go through these helpers. This would have prevented 7 of 50 bugs (14%).

### R2: Operation Check Ordering Framework (High Priority)

**Problem**: 10 operations had checks in the wrong order relative to stellar-core.

**Proposal**: Instead of ad-hoc conditional chains in each operation's `execute()`, introduce a declarative check pipeline:

```rust
// Pseudocode for the pattern
fn execute_create_account(&mut self, op: &CreateAccountOp) -> Result<OpResult> {
    self.check_pipeline()
        .check_sponsor_reserve()?     // Returns LowReserve
        .check_source_balance(amount)? // Returns Underfunded
        .check_destination_exists()?   // Returns AlreadyExists
        .execute(|state| { ... })
}
```

Each check function would document which stellar-core function it mirrors and be tested independently. The ordering would be visible in the pipeline definition. This would have prevented 10 of 50 bugs (20%).

### R3: Automatic Snapshot Management (High Priority)

**Problem**: 5 methods had the identical "snapshot overwrite" bug because each `update_*` method manually manages its own snapshot.

**Proposal**: Replace manual snapshot management with an RAII guard:

```rust
// Pseudocode
fn update_entry(&mut self, key: K, value: V) -> Result<()> {
    let _guard = self.snapshot_guard(&key); // Saves snapshot on creation
    self.live_map.insert(key, value);
    // Guard drops: snapshot is NOT overwritten
}
```

The `SnapshotGuard` takes a snapshot on creation and never allows the caller to overwrite it. Rollback reads from the guard's saved value. This eliminates the entire class of snapshot overwrite bugs.

### R4: Non-Blocking Event Loop Enforcement (High Priority)

**Problem**: 8 bugs from blocking calls or unbounded loops in the async event loop.

**Proposal**:
1. **Bounded iteration**: Wrap all drain loops with a `MAX_PER_TICK` constant and emit a warning when hit.
2. **No-block lint**: Add a clippy/custom lint or code review checklist item that flags `block_in_place()`, `block_on()`, unbounded `while let` on channels, and sequential `await` in loops within the `app` crate's event loop module.
3. **Timeout wrappers**: Create a `try_send_timeout()` helper used by all overlay send paths, with a configurable timeout (e.g., 5s). This is partially done but should be systematic.
4. **Structured event loop**: Consider splitting the monolithic `select!` loop into sub-loops per concern (consensus, catchup, peer management) running in separate tokio tasks that communicate via bounded channels. This isolates blocking in one subsystem from starving others.

### R5: Fee Lifecycle as a Distinct Phase (Medium Priority)

**Problem**: 3 bugs from incorrect fee deduction timing.

**Proposal**: Model the fee lifecycle explicitly as a pipeline stage:

```
Phase 1: Pre-deduct ALL fees (classic + Soroban) -> FeeDeductionResult
Phase 2: Execute classic TXs (with fee already deducted)
Phase 3: Execute Soroban TXs (with fee already deducted)
Phase 4: Refund Soroban fees
```

Each phase is a separate function that takes the output of the previous phase. The type system would enforce that execution cannot proceed without fee deduction completing first (i.e., `execute_classic(FeeDeductionResult, ...)` instead of `execute_classic(delta, ...)`).

### R6: Config Validation at Startup (Low Priority)

**Problem**: 3 bugs from config values not being wired through.

**Proposal**: Add a `validate_config()` function called at startup that:
- Asserts all config sections are consumed (no dead config)
- Validates config consistency (e.g., `network_id` matches expected value)
- Logs all effective config values at startup for debugging

### R7: Soroban Entry Alignment Type Safety (Medium Priority)

**Problem**: 4 Soroban bugs from index misalignment, metadata loss, and off-by-one phase ordering.

**Proposal**:
- Use a newtype `FootprintAlignedEntries(Vec<Option<Vec<u8>>>)` that preserves 1:1 alignment with the footprint by construction (None for missing entries, not skipping).
- Create a `LedgerEntryReconstructor` that takes raw entry data + the metadata maps and produces a complete `LedgerEntry`. All code paths (snapshot adapter, P24, P25) would go through this single reconstruction point.
- For the PRNG seed offset: derive it from the phase execution order at the call site rather than hardcoding assumptions about which phase is 0 vs 1.

---

## Quantitative Impact Summary

| Refactoring | Bugs Prevented | % of Total | Effort |
|-------------|---------------|------------|--------|
| R1: Balance/liability helpers | 7 | 14% | Medium |
| R2: Check ordering framework | 10 | 20% | Large |
| R3: Automatic snapshots | 5 | 10% | Medium |
| R4: Non-blocking event loop | 8 | 16% | Large |
| R5: Fee lifecycle phases | 3 | 6% | Medium |
| R6: Config validation | 3 | 6% | Small |
| R7: Soroban type safety | 4 | 8% | Medium |
| **Total** | **40** | **80%** | |

Implementing R1-R4 alone would have structurally prevented **30 of 50 bugs (60%)**.

---

## Appendix: All 50 Bug Fixes

| # | Date | Commit | Category | Summary |
|---|------|--------|----------|---------|
| 1 | Feb 21 | `ae34f1e` | 1D: Missing | Load pool share trustlines from secondary index (VE-02) |
| 2 | Feb 20 | `d482c43` | 3: Snapshot | Snapshot overwrite in update_account/data/claimable_balance |
| 3 | Feb 20 | `5ef1c78` | 5: Config | PeerManager thread-safety (Mutex vs RwLock) |
| 4 | Feb 20 | `0fb052d` | 3: Snapshot | Snapshot overwrite in update_contract_data/code |
| 5 | Feb 19 | `eaa4a32` | 4: Soroban | Footprint entry index alignment |
| 6 | Feb 19 | `292a2e7` | 1D: Missing | prepare_liabilities for base reserve increase |
| 7 | Feb 19 | `0ee8c92` | 1E: Error code | Warn on unreachable level 0 curr eviction iterator |
| 8 | Feb 19 | `c50337f` | 1E: Error code | Warn when deduplicate_entries removes duplicates |
| 9 | Feb 19 | `828ef06` | 3: Snapshot | Assert entry exists in process_entry_update/delete |
| 10 | Feb 19 | `e3c834d` | 1D: Missing | V24 mainnet fee pool correction |
| 11 | Feb 19 | `eee5019` | 1D: Missing | Pool share trustline redemption during deauthorization |
| 12 | Feb 19 | `bc64db4` | 1D: Missing | Cost params validation by protocol version |
| 13 | Feb 19 | `b81abb0` | 1D: Missing | Remove ConfigSetting from in-memory Soroban state types |
| 14 | Feb 19 | `7fc05d2` | 1A: Ordering | Narrow Soroban memo validation to InvokeHostFunction only |
| 15 | Feb 19 | `a289f34` | 1B: Liabilities | Pool withdraw/deposit correctness |
| 16 | Feb 19 | `2c070e8` | 1B: Liabilities | Account for selling liabilities in clawback |
| 17 | Feb 19 | `a8ca331` | 1E: Error code | Panic on LIVE+INIT and INIT+INIT in merge_entries |
| 18 | Feb 18 | `8646b99` | 3: Snapshot | last_modified_ledger_seq stamping in record_flush_update |
| 19 | Feb 17 | `45c4150` | 1E: Error code | min_seq_num precondition test |
| 20 | Feb 17 | `e0ddac8` | 4: Soroban | Snapshot adapter discarding original entry metadata |
| 21 | Feb 17 | `2dab19f` | 4: Soroban | PRNG seed offset: use classic_tx_count |
| 22 | Feb 17 | `10d80d4` | 4: Soroban | PRNG seed index offset (reverted previous fix) |
| 23 | Feb 17 | `e625cd3` | 1C: Fees | Soroban TX validation fee refund and sequence bump |
| 24 | Feb 17 | `2affd80` | 1A: Ordering | tx crate P0/P1 deep-compare parity issues |
| 25 | Feb 17 | `a8e5332` | 1B: Liabilities | CreateClaimableBalance selling liabilities |
| 26 | Feb 17 | `181e2fe` | 1B: Liabilities | CreateAccount sponsoring delta in balance check |
| 27 | Feb 17 | `fcac75b` | 1A: Ordering | SetOptions clawback/revocable resulting flags |
| 28 | Feb 16 | `8e3e56e` | 1B: Liabilities | LiquidityPoolDeposit selling liabilities |
| 29 | Feb 16 | `c9d95b9` | 1A: Ordering | isSynced check and trigger consensus |
| 30 | Feb 16 | `3928141` | 1A: Ordering | ChangeTrust check ordering |
| 31 | Feb 16 | `ddc8270` | 1A: Ordering | Fee-bump inner TX signature threshold |
| 32 | Feb 16 | `ce7f9b9` | 2A: Blocking | Event loop freeze from blocking flood demand sends |
| 33 | Feb 16 | `4d1d76a` | 2B: Drain | Event loop starvation from unbounded ledger close loop |
| 34 | Feb 16 | `7311e8c` | 1A: Ordering | ManageBuyOffer error code ordering |
| 35 | Feb 16 | `c0726f0` | 1D: Missing | Flush RO TTL bumps for write footprint keys |
| 36 | Feb 16 | `d29f40f` | 2A: Blocking | Event loop freeze during catchup bucket cleanup |
| 37 | Feb 16 | `cffa290` | 1A: Ordering | Remove incorrect 100KB tx envelope size limit |
| 38 | Feb 16 | `61d00c8` | 1A: Ordering | SetTrustLineFlags check order |
| 39 | Feb 16 | `da4bcfe` | 1E: Error code | ClawbackClaimableBalance error codes and flag check |
| 40 | Feb 16 | `a176c15` | 1C: Fees | Deduct classic fees upfront before TX execution |
| 41 | Feb 16 | `0c37331` | 2A+2C | Two event loop freeze bugs: blocking GC + stuck state |
| 42 | Feb 16 | `610cc58` | 2B: Drain | Mainnet event loop starvation from unbounded SCP drain |
| 43 | Feb 16 | `a2d3855` | 1B: Liabilities | Double offer deletion during AllowTrust |
| 44 | Feb 15 | `a56ad63` | 3: Snapshot | Rollback corruption from flush_all_accounts |
| 45 | Feb 15 | `bcdc2bb` | 2A: Blocking | Bucket GC deleting files needed by async merges |
| 46 | Feb 15 | `da47265` | 1D: Missing | Prefetch to match stellar-core |
| 47 | Feb 15 | `1ae915b` | 2B: Drain | Broadcast channel drain starving event loop |
| 48 | Feb 14 | `86295f5` | 1A: Ordering | CreateAccount check order: sponsor before source |
| 49 | Feb 14 | `8a0d23f` | 5: Config | BucketListDB caching config never wired |
| 50 | Feb 14 | `8878e97` | 2A: Blocking | Event loop freeze from unbounded sends |

Additional bugs in the same timeframe (not counted in 50):
- `c0d4152` | 2A: Blocking | Main event loop deadlock from sequential broadcast
- `bea47aa` | 1B: Liabilities | i64 overflow in ClaimClaimableBalance
- `5bf99d6` | 5: Config | TxQueueConfig hardcoded testnet network_id
- `34e3093` | 1C: Fees | Cross-phase fee deduction unification
- `626be70` | 4: Soroban | Skip missing entries in e2e_invoke
- `a1a02bb` | 5: Config | Peer query parameter index mismatch
