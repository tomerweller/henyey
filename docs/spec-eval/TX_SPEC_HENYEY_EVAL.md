# Henyey TX Crate — Specification Adherence Evaluation

**Evaluated against:** `stellar-specs/TX_SPEC.md` (stellar-core v26.0.1 / Protocol 26)
**Crate:** `crates/tx/` (henyey-tx)
**Self-reported parity:** See `crates/tx/PARITY_STATUS.md` for current function-level counts
**Date:** 2026-05-10

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Evaluation Methodology](#2-evaluation-methodology)
3. [Section-by-Section Evaluation](#3-section-by-section-evaluation)
   - [§1–2 Introduction & Processing Overview](#31-introduction--processing-overview)
   - [§3 Data Types and Encoding](#32-data-types-and-encoding)
   - [§4 Transaction Validation](#33-transaction-validation)
   - [§5 Fee Framework](#34-fee-framework)
   - [§6 Transaction Application Pipeline](#35-transaction-application-pipeline)
   - [§7 Operation Execution](#36-operation-execution)
   - [§8 Soroban Execution](#37-soroban-execution)
   - [§9 State Management](#38-state-management)
   - [§10 Metadata Construction](#39-metadata-construction)
   - [§11 Event Emission](#310-event-emission)
   - [§12 Error Handling](#311-error-handling)
   - [§13 Invariants and Safety Properties](#312-invariants-and-safety-properties)
   - [§14 Constants](#313-constants)
4. [Gap Summary](#4-gap-summary)
5. [Risk Assessment](#5-risk-assessment)
6. [Recommendations](#6-recommendations)

---

## 1. Executive Summary

The henyey-tx crate implements the Stellar transaction processing subsystem with **very high fidelity** to the TX_SPEC. All 27 operation types are implemented with full `doCheckValid` and `doApply` logic. The transaction validation pipeline (structural, stateful, signature checking), fee framework (classic and Soroban), application pipeline (fee/seqnum pre-processing, operation dispatch, post-apply refunds), metadata construction (v2/v3/v4), SAC event emission, and Protocol 26 features (CAP-77 frozen ledger keys, CAP-73 SAC trust fixes, discount rounding changes, pre-v23 restore meta cleanup) are all present and verified against testnet with 100% parity across 14,651 transactions in the 30000–36000 ledger range.

### Overall Adherence Rating

| Category | Rating | Notes |
|----------|--------|-------|
| **Data Types & Encoding (§3)** | **Full** | All envelope types (V0, V1, FeeBump), Soroban data, preconditions, signature types |
| **Transaction Validation (§4)** | **Full** | Structural, precondition, source account, signature, fee balance, Soroban resource validation |
| **Fee Framework (§5)** | **High** | Classic/Soroban fee split, fee-bump semantics, refunds, fee/seqnum pre-processing; missing static `computeSorobanResourceFee()` |
| **Application Pipeline (§6)** | **Full** | Pre-apply, commonValid, operation application with per-op rollback, threshold levels, source resolution |
| **Operation Execution (§7)** | **Full** | All 27 operations implemented with doCheckValid + doApply; all result codes; DEX conversion engine; sponsorship framework |
| **Soroban Execution (§8)** | **Full** | InvokeHostFunction, ExtendFootprintTTL, RestoreFootprint all present; parallel execution implemented at ledger crate level |
| **State Management (§9)** | **Full** | Nested ledger transactions with savepoint/rollback; entry restore tracking for P23+ |
| **Metadata Construction (§10)** | **Full** | V2/V3/V4 meta; txChangesBefore/After; per-operation changes; Soroban meta with events/return/diagnostics |
| **Event Emission (§11)** | **Full** | Soroban contract events; classic SAC events (P23+); XLM balance reconciliation |
| **Error Handling (§12)** | **Full** | All 17 tx-level result codes; all 7 op-level codes; sponsorship pairing check; error monotonicity |
| **Invariants (§13)** | **Full** | Determinism, fee irrevocability, balance conservation, seq monotonicity, reserve sufficiency, liability consistency |
| **Constants (§14)** | **Full** | All protocol constants, fee constants, Soroban config parameters match |

**Estimated spec behavioral coverage: ~97%** of the TX_SPEC is fully implemented (see `crates/tx/PARITY_STATUS.md` for exact function counts). The remaining ~3% falls into: (1) static Soroban fee computation functions used for surge pricing (low priority — delegated to soroban-env-host at execution time), and (2) a few minor utility/interface gaps. Parallel Soroban execution is implemented at the ledger crate level (`execute_soroban_parallel_phase()` with stages/clusters via `tokio::task::spawn_blocking`).

---

## 2. Evaluation Methodology

This evaluation compares the henyey-tx implementation against every section of `stellar-specs/TX_SPEC.md`. The evaluation uses:

1. **Spec requirements**: Each MUST/SHALL/REQUIRED statement in TX_SPEC is treated as a requirement.
2. **Source code inspection**: Key Rust source files (`frame.rs`, `validation.rs`, `live_execution.rs`, `fee_bump.rs`, `signature_checker.rs`, `result.rs`, `meta_builder.rs`, `events.rs`, `lumen_reconciler.rs`, `operations/execute/*.rs`, `soroban/*.rs`, `state/*.rs`) were read and cross-referenced.
3. **Parity status**: `PARITY_STATUS.md` provides detailed function-level mapping (201 implemented, 6 gaps, 31 intentional omissions).
4. **Test verification**: 944 unit tests plus testnet verification across multiple ledger ranges (100% match for 14,651 txns in 30000–36000).

Ratings per requirement:

| Symbol | Meaning |
|--------|---------|
| ✅ | Fully implemented and matches spec |
| ⚠️ | Partially implemented or minor deviation |
| ❌ | Not implemented |
| ➖ | Not applicable (intentional architectural departure or pre-P24) |

Source file references use the format `file.rs:line`.

---

## 3. Section-by-Section Evaluation

### 3.1 Introduction & Processing Overview

**Spec sections:** §1, §2
**Source files:** `lib.rs`, `live_execution.rs`, `apply.rs`

The crate supports the two-phase ledger model (classic then Soroban), fee/seqnum pre-processing before any operations, and the full transaction lifecycle.

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Transaction lifecycle (construct → validate → fee/seq → apply → post-apply → result/meta) | ✅ | `live_execution.rs` implements all phases; `lib.rs` documents workflow |
| Two-phase model (classic then Soroban) | ✅ | Phase ordering enforced at ledger-close level (ledger crate), tx crate applies per-phase |
| Fee/seqnum pre-processing for ALL transactions before any operations | ✅ | `process_fee_seq_num()` in `live_execution.rs:~150` |
| Classic phase before Soroban phase | ✅ | Enforced by caller (ledger crate); tx crate is phase-agnostic |
| Parallel Soroban (§2.4, stages/clusters) | ✅ | Implemented at the ledger crate level via `execute_soroban_parallel_phase()` (stages sequential, clusters parallel via `tokio::task::spawn_blocking`) |

### 3.2 Data Types and Encoding

**Spec section:** §3
**Source files:** `frame.rs`, `fee_bump.rs`, `operations/mod.rs`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Support `ENVELOPE_TYPE_TX_V0` | ✅ | `frame.rs` handles V0 with `v0_to_v1_transaction()` conversion |
| Support `ENVELOPE_TYPE_TX` | ✅ | Primary envelope type |
| Support `ENVELOPE_TYPE_TX_FEE_BUMP` | ✅ | `fee_bump.rs`: `FeeBumpFrame` with full validation |
| Transaction body fields (source, fee, seqNum, cond, memo, operations, ext) | ✅ | Accessed via `frame.rs` accessor methods |
| FeeBumpTransaction fields (feeSource, fee, innerTx) | ✅ | `fee_bump.rs`: `FeeBumpFrame` struct |
| All 27 operation types enumerated | ✅ | `operations/mod.rs`: `OperationType` enum with all 27 variants |
| SorobanTransactionData fields (resources, footprint, resourceFee, ext) | ✅ | `frame.rs`: `soroban_data()` accessor |
| Preconditions (NONE, TIME, V2 with ledgerBounds, minSeqNum, etc.) | ✅ | `frame.rs`: `preconditions()`, `min_seq_num()`, `min_seq_age()`, `min_seq_ledger_gap()` |
| Signature types (ED25519, PRE_AUTH_TX, HASH_X, ED25519_SIGNED_PAYLOAD) | ✅ | `signature_checker.rs`: all four types handled |
| TransactionResult structure (feeCharged, result union, fee-bump nesting) | ✅ | `result.rs`: `TxResultWrapper`, `MutableTransactionResult`; `fee_bump.rs`: `wrap_inner_result_in_fee_bump()` |
| MuxedAccount support | ✅ | `frame.rs`: `muxed_to_account_id()`, `muxed_to_ed25519()` |

### 3.3 Transaction Validation

**Spec section:** §4
**Source files:** `validation.rs`, `fee_bump.rs`, `signature_checker.rs`

#### Structural Validation (§4.2)

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Envelope type check | ✅ | `validate_structure()` in `validation.rs` |
| Operation count ≥ 1 (`txMISSING_OPERATION`) | ✅ | `validate_structure()` |
| Fee-bump inner must be `ENVELOPE_TYPE_TX` (`txMALFORMED`) | ✅ | `validate_fee_bump()` in `fee_bump.rs` |
| Fee-bump fee floor ≥ inner fee (`txINSUFFICIENT_FEE`) | ✅ | `validate_fee_bump()`: `InsufficientOuterFee` error |
| Fee-bump fee overflow check | ✅ | `validate_fee_bump()` checks `innerBaseFee * (numInnerOps + 1)` |
| Soroban consistency (single op, ext.v==1) (`txMALFORMED`) | ✅ | `validate_structure()` |
| Soroban memo restriction @version(≥25) (`txMALFORMED`) | ✅ | `validate_structure()` checks `MEMO_NONE` for InvokeHostFunction |
| Soroban muxed account restriction @version(≥25) (`txMALFORMED`) | ✅ | `validate_structure()` checks source not muxed for InvokeHostFunction |
| Frozen key access check @version(≥26) (`txFROZEN_KEY_ACCESSED`) | ✅ | `frozen_keys.rs`: `FrozenKeyConfig::accesses_frozen_key()` with bypass hash set |

#### Precondition Validation (§4.3)

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Time bounds (minTime, maxTime) → `txTOO_EARLY` / `txTOO_LATE` | ✅ | `is_too_early()` / `is_too_late()` |
| Ledger bounds @version(≥19) → `txTOO_EARLY` / `txTOO_LATE` | ✅ | `is_too_early()` / `is_too_late()` |
| Minimum fee ≥ baseFee × numOps → `txINSUFFICIENT_FEE` | ✅ | `validate_fee()` |

#### Source Account Validation (§4.4)

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Source account existence → `txNO_ACCOUNT` | ✅ | `validate_full()` checks existence |
| Sequence number validation (normal and minSeqNum) → `txBAD_SEQ` | ✅ | `validate_sequence()`, `validate_min_seq_num()` |
| `MAX_SEQ_NUM_INCREASE` (2^31) gap check | ✅ | `validate_sequence()` |
| Min sequence age → `txBAD_MIN_SEQ_AGE_OR_GAP` | ✅ | Checked via `BadMinAccountSequenceAge` error |
| Min sequence ledger gap → `txBAD_MIN_SEQ_AGE_OR_GAP` | ✅ | `BadMinAccountSequenceLedgerGap` error |

#### Signature Validation (§4.5–4.7)

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Transaction-level LOW threshold check | ✅ | `validate_signatures()` |
| Signature checking algorithm (weight accumulation, dedup) | ✅ | `SignatureChecker::check_signature()` in `signature_checker.rs` |
| PRE_AUTH_TX signer consumption | ✅ | `remove_one_time_signers()` in `live_execution.rs` |
| HASH_X verification (sha256 preimage) | ✅ | `verify_hash_x()` |
| ED25519 verification with hint matching | ✅ | `verify_ed25519()` |
| ED25519_SIGNED_PAYLOAD @version(≥19) | ✅ | `verify_ed25519_signed_payload()` |
| Weight capping @version(≥10) (min(totalWeight, UINT8_MAX)) | ✅ | `cap_weight()` method |
| Extra signers @version(≥19) → `txBAD_AUTH_EXTRA` | ✅ | `validate_extra_signers()` |
| Unused signature check → `txBAD_AUTH` | ✅ | `check_all_signatures_used()` |

#### Fee & Soroban Resource Validation (§4.6, §4.9)

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Fee source balance check → `txINSUFFICIENT_BALANCE` | ✅ | `validate_full()` checks available balance |
| Soroban resource limits (instructions, diskRead, writeBytes) | ✅ | `validate_soroban_resources()` |
| Footprint entry count limits | ✅ | `validate_soroban_resources()` |
| No duplicate footprint keys | ✅ | `validate_soroban_resources()` |
| `resourceFee` ≤ total fee; ≤ `MAX_RESOURCE_FEE` (2^50) | ✅ | `validate_soroban_resources()` |
| Footprint key size limit | ✅ | `validate_soroban_resources()` |
| @version(≥23) archived entry index validation | ✅ | `validate_soroban_resources()` |

### 3.4 Fee Framework

**Spec section:** §5
**Source files:** `live_execution.rs`, `result.rs`, `fee_bump.rs`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Classic fee: `totalFee = inclusionFee = envelope.fee` | ✅ | `frame.rs`: `inclusion_fee()` |
| Soroban fee: `inclusionFee = envelope.fee - sorobanData.resourceFee` | ✅ | `frame.rs`: `inclusion_fee()` delegates to Soroban-aware calculation |
| Fee-bump fee: `totalFee = feeBumpEnvelope.fee` | ✅ | `fee_bump.rs`: `FeeBumpFrame` |
| Effective fee computation with `min(inclusionFee, baseFee * numOps)` | ✅ | `calculate_fee_to_charge()` in `live_execution.rs` |
| Fee/seqnum pre-processing (deduct fee, advance seq, commit) | ✅ | `process_fee_seq_num()` |
| Fee deduction: `min(feeSource.balance, feeCharged)` | ✅ | `process_fee_seq_num()` |
| Sequence number advance @version(≥10) in pre-processing | ✅ | `process_seq_num()` |
| `MAX_SEQ_NUM_TO_APPLY` entry creation @version(≥19) for AccountMerge | ✅ | `process_fee_seq_num()` |
| Soroban fee refund (refundable - consumed rent - consumed events) | ✅ | `refund_soroban_fee()` |
| Refund timing: pre-P23 per-transaction, P23+ per-stage | ✅ | `process_post_apply()` vs `process_post_tx_set_apply()` with P23 check |
| Fee-bump result nesting (`txFEE_BUMP_INNER_SUCCESS`/`FAILED`) | ✅ | `wrap_inner_result_in_fee_bump()` |
| @version(≥25) inner feeCharged adjustment | ✅ | `calculate_inner_fee_charged()` with protocol version branching |
| Static `computeSorobanResourceFee()` for surge pricing | ⚠️ | Not implemented as standalone; fee computation delegated to soroban-env-host during execution. Gap per `PARITY_STATUS.md` |
| `RefundableFeeTracker` initialization and tracking | ✅ | `RefundableFeeTracker` in `result.rs` |

### 3.5 Transaction Application Pipeline

**Spec section:** §6
**Source files:** `live_execution.rs`, `operations/execute/mod.rs`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Application entry point: commonPreApply → applyOperations → verify sigs → postApply | ✅ | `apply_transaction()` in `live_execution.rs` |
| commonPreApply: child ltx, SignatureChecker, commonValid, sig check | ✅ | `process_fee_seq_num()` + signature validation in ledger crate |
| commonValid: pre-seq checks, seq check, age/gap, balance | ✅ | Validation functions in `validation.rs` |
| Sequential operation application with per-op rollback | ✅ | `state/mod.rs`: `create_savepoint()` / `rollback_to_savepoint()` |
| @version(≥14) stop on first failure | ✅ | Operation dispatch breaks on first failure |
| Operation threshold levels (LOW/MEDIUM/HIGH) | ✅ | `get_threshold_level()` in `operations/mod.rs` |
| Source account resolution (operation override or tx source) | ✅ | `get_operation_source()` |
| Muxed account Ed25519 extraction for ledger lookups | ✅ | `muxed_to_account_id()` in `frame.rs` |
| Per-operation metadata recording | ✅ | `OperationMetaBuilder` in `meta_builder.rs` |
| txChangesBefore recording | ✅ | `push_tx_changes_before()` in `TransactionMetaBuilder` |
| Sponsorship pairing check post-operations → `txBAD_SPONSORSHIP` | ✅ | Checked after all operations in apply path |

### 3.6 Operation Execution

**Spec section:** §7
**Source files:** `operations/execute/*.rs`

All 27 operation types are implemented with full `doCheckValid` and `doApply` logic, matching the spec's validation and execution descriptions. The PARITY_STATUS.md confirms "Full" for every operation.

#### Classic Operations (§7.1–§7.14)

| Operation | Validation | Execution | Result Codes | Status |
|-----------|-----------|-----------|-------------|--------|
| CreateAccount (§7.1) | `startingBalance > 0`, dest ≠ source | Create account, debit source, sponsorship | `MALFORMED`, `UNDERFUNDED`, `ALREADY_EXIST`, `LOW_RESERVE` | ✅ |
| Payment (§7.2) | `amount > 0`, valid asset | Delegates to PathPaymentStrictReceive | All mapped from path payment | ✅ |
| PathPaymentStrictReceive (§7.3) | `destAmount > 0`, `sendMax > 0`, valid assets | DEX conversion with pool+orderbook, `MAX_OFFERS_TO_CROSS` | `MALFORMED`, `NO_DESTINATION`, `OVER_SENDMAX`, `EXCEEDED_WORK_LIMIT`, etc. | ✅ |
| PathPaymentStrictSend (§7.4) | `sendAmount > 0`, `destMin > 0` | Forward path, `ROUND_TYPE_STRICT_SEND` | `UNDER_DESTMIN`, etc. | ✅ |
| ManageSellOffer (§7.5) | `amount ≥ 0`, valid price, different assets | Cross offers, pool exchange, create/update/delete | `MALFORMED`, `CROSS_SELF`, `LOW_RESERVE`, etc. | ✅ |
| ManageBuyOffer (§7.6) | Same with inverted price | Price inversion, buy-side capping | Same result codes | ✅ |
| CreatePassiveSellOffer (§7.7) | Same as sell, `passive = true` | No crossing at same price | Same result codes | ✅ |
| SetOptions (§7.8) | Flag validity, signer checks | Ordered: inflation dest → flags → home domain → thresholds → signer | `UNKNOWN_FLAG`, `BAD_FLAGS`, `BAD_SIGNER`, `TOO_MANY_SIGNERS`, etc. | ✅ |
| ChangeTrust (§7.9) | Valid asset, not self-issuer | Create/update/remove trustline with sponsorship | `MALFORMED`, `SELF_NOT_ALLOWED`, `NO_ISSUER`, `LOW_RESERVE`, etc. | ✅ |
| AllowTrust (§7.10) | Non-native asset, valid authorize value | Set auth flags, deauth cleanup | `MALFORMED`, `TRUST_NOT_REQUIRED`, `CANT_REVOKE`, `NO_TRUST_LINE` | ✅ |
| AccountMerge (§7.11) | MAX_SEQ_NUM_TO_APPLY check @version(≥19) | No sub-entries, no sponsoring, transfer balance | `HAS_SUB_ENTRIES`, `IMMUTABLE_SET`, `NO_ACCOUNT`, `DEST_FULL`, `SEQNUM_TOO_FAR` | ✅ |
| Inflation (§7.12) | Timing check | Top 2000 vote-getters, proportional distribution | `NOT_TIME` | ✅ |
| ManageData (§7.13) | `dataName` length ≥ 1 | Create/update/delete data entry | `INVALID_NAME`, `LOW_RESERVE`, `NAME_NOT_FOUND` | ✅ |
| BumpSequence (§7.14) | `bumpTo ≥ 0` | Conditional update if bumpTo > current | `BAD_SEQ` | ✅ |

#### Claimable Balances & Sponsorship (§7.15–§7.19)

| Operation | Status | Evidence |
|-----------|--------|----------|
| CreateClaimableBalance (§7.15) | ✅ | `claimable_balance.rs`: predicate validation (depth 4), balance ID generation, relative→absolute time conversion |
| ClaimClaimableBalance (§7.16) | ✅ | `claimable_balance.rs`: predicate evaluation, credit source, sponsorship cleanup |
| BeginSponsoringFutureReserves (§7.17) | ✅ | `sponsorship.rs`: no-self, no-recursive, create sponsorship entry |
| EndSponsoringFutureReserves (§7.18) | ✅ | `sponsorship.rs`: load sponsorship, decrement counter, remove entry |
| RevokeSponsorship (§7.19) | ✅ | `sponsorship.rs`: 4-case transfer logic, `ONLY_TRANSFERABLE` for claimable balances |

#### Clawback & Trust Flags (§7.20–§7.22)

| Operation | Status | Evidence |
|-----------|--------|----------|
| Clawback (§7.20) | ✅ | `clawback.rs`: issuer check, trustline flag check, debit without auth check |
| ClawbackClaimableBalance (§7.21) | ✅ | `clawback.rs`: issuer check, clawback flag, remove balance |
| SetTrustLineFlags (§7.22) | ✅ | `trust_flags.rs`: flag computation, auth validation, deauth cleanup |

#### Liquidity Pools (§7.23–§7.24)

| Operation | Status | Evidence |
|-----------|--------|----------|
| LiquidityPoolDeposit (§7.23) | ✅ | `liquidity_pool.rs`: empty/non-empty pool logic, price bounds, proportional amounts |
| LiquidityPoolWithdraw (§7.24) | ✅ | `liquidity_pool.rs`: share computation, min amount checks |

#### Sponsorship Framework (§7.28)

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Creating entry with sponsorship (check active Begin, increment counts) | ✅ | `state/sponsorship.rs`: `apply_entry_sponsorship()` |
| Removing entry with sponsorship (decrement counts, release reserve) | ✅ | `remove_entry_sponsorship_and_update_counts()` |
| Reserve multipliers (ACCOUNT=2, TRUSTLINE=1/2, OFFER=1, etc.) | ✅ | Inline in operation modules |

#### DEX Conversion Engine (§7.29)

| Requirement | Status | Evidence |
|-------------|--------|----------|
| `convertWithOffersAndPools()` — best-price comparison | ✅ | `path_payment.rs`: `convert_with_offers_and_pools()` |
| Order book crossing with liability adjustment @version(≥10) | ✅ | `manage_offer.rs` / `offer_exchange.rs` |
| Liquidity pool constant-product exchange with 30bps fee | ✅ | `path_payment.rs`: `exchange_with_pool()` |
| `MAX_OFFERS_TO_CROSS` (1000) enforcement | ✅ | Tracked in conversion loop |
| Self-crossing prevention → `OFFER_CROSS_SELF` | ✅ | Checked in offer crossing logic |
| `exchangeV10()` with price error thresholds | ✅ | `offer_exchange.rs`: `exchange_v10()` |

### 3.7 Soroban Execution

**Spec section:** §8
**Source files:** `soroban/*.rs`, `operations/execute/invoke_host_function.rs`, `operations/execute/extend_footprint_ttl.rs`, `operations/execute/restore_footprint.rs`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Soroban tx: exactly one Soroban op + SorobanTransactionData | ✅ | Validated in `validate_structure()` |
| Fee model: inclusionFee + declaredResourceFee, non-refundable/refundable split | ✅ | `result.rs`: `RefundableFeeTracker` |
| Soroban validation (resource limits, footprint rules) | ✅ | `validate_soroban_resources()` |
| InvokeHostFunction execution (footprint load, host invocation, storage write, events) | ✅ | `invoke_host_function.rs` + `soroban/host.rs` |
| Host function types (invoke, create, upload, create_v2) | ✅ | Delegated to soroban-env-host |
| Entry liveness check (TTL-based) | ✅ | `soroban/storage.rs`: `state/ttl.rs` |
| Auto-restore @version(≥23) | ✅ | `invoke_host_function.rs` |
| ExtendFootprintTTL (§8.5): validation + rent fee computation | ✅ | `extend_footprint_ttl.rs` |
| RestoreFootprint (§8.6): validation + persistent-only + rent | ✅ | `restore_footprint.rs` |
| Parallel Soroban execution (§8.7): stages/clusters | ✅ | Implemented at ledger crate level: `execute_soroban_parallel_phase()` — stages sequential, clusters parallel via `tokio::task::spawn_blocking`; each cluster gets isolated `TransactionExecutor` + `LedgerDelta` |
| WASM module cache (pre-compilation) | ✅ | `soroban/host.rs`: `PersistentModuleCache` |
| Protocol-versioned Soroban hosts (P24, P25) | ✅ | `soroban/protocol/p24.rs`, `soroban/protocol/p25.rs` |
| Resource fee computation (fee rates from network config) | ⚠️ | Fee rates used at execution time via soroban-env-host; static `computeSorobanResourceFee()` not exposed as standalone function |
| Disk read/write byte metering | ✅ | Metered during footprint loading |
| Event size validation (≤ txMaxContractEventsSizeBytes) | ✅ | `soroban/host.rs` |
| Rent fee charging against refundable budget | ✅ | `soroban/host.rs` |
| Result hashing (success preimage) | ✅ | Computed in invoke_host_function |

### 3.8 State Management

**Spec section:** §9
**Source files:** `state/mod.rs`, `state/entries.rs`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Nested ledger transaction model (commit/rollback) | ✅ | `LedgerStateManager` with `Savepoint`; per `PARITY_STATUS.md` |
| Per-operation rollback on failure | ✅ | `create_savepoint()` / `rollback_to_savepoint()` with three-phase restore |
| Entry types: accounts, trustlines, offers, data, contract_data, contract_code, TTL, claimable_balances, liquidity_pools | ✅ | All supported per `PARITY_STATUS.md` savepoint section |
| @version(≥23) restored entry tracking (hot archive, live BucketList) | ✅ | Entry restore tracking present |
| Delta truncation on rollback | ✅ | `LedgerDelta::truncate_to()` |

### 3.9 Metadata Construction

**Spec section:** §10
**Source files:** `meta_builder.rs`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Meta version selection (v2 for <20, v3 for 20–22, v4 for ≥23) | ✅ | `TransactionMetaBuilder::finalize()` |
| `txChangesBefore` (fee deduction, sequence bump) | ✅ | `push_tx_changes_before()` |
| `operations[]` (per-operation changes) | ✅ | `OperationMetaBuilder` |
| `txChangesAfter` (Soroban refunds) | ✅ | `push_tx_changes_after()` |
| `sorobanMeta` (events, return value, diagnostics) | ✅ | V3 `SorobanTransactionMeta` and V4 `SorobanTransactionMetaV2` |
| @version(≥23) v4: per-operation events, tx-level events | ✅ | `OperationMetaV2` with events |
| @version(≥23) v4: `nonRefundableResourceFeeCharged`, `rentFeeCharged`, `totalRefundableResourceFeeCharged` | ✅ | `SorobanTransactionMetaExtV1` |
| Change types: CREATED, UPDATED, REMOVED, STATE, RESTORED | ✅ | `record_create/update/delete/restore()` |
| Change pairing (STATE→UPDATED, STATE→REMOVED, CREATED alone, RESTORED) | ✅ | Change recording logic |

### 3.10 Event Emission

**Spec section:** §11
**Source files:** `events.rs`, `lumen_reconciler.rs`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Soroban contract events in metadata (v3: sorobanMeta.events; v4: per-op) | ✅ | `DiagnosticEventManager`, event collection |
| Classic SAC events @version(≥23): transfer, mint, burn, clawback, set_authorized | ✅ | `OpEventManager` with all event types |
| SAC events from Payment, PathPayment, CreateAccount, AccountMerge, Clawback, AllowTrust/SetTrustLineFlags, ClaimableBalance, LiquidityPool, Inflation | ✅ | Per `PARITY_STATUS.md` events section — 18 event functions |
| XLM balance reconciliation @version(≥23) | ✅ | `lumen_reconciler.rs`: `reconcile_events()`, `LumenEventReconciler` |
| Muxed account address in events | ✅ | `make_muxed_account_address()` |
| Contract ID computation from asset | ✅ | `contract_id_from_asset()` |

### 3.11 Error Handling

**Spec section:** §12
**Source files:** `result.rs`, `live_execution.rs`, `validation.rs`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| All 17 transaction-level result codes (txSUCCESS through txSOROBAN_INVALID) | ✅ | `TxResultCode` enum; `MutableTransactionResult::set_error()` |
| All 7 operation-level result codes (opINNER through opTOO_MANY_SPONSORING) | ✅ | `OpResultCode` enum |
| Sponsorship pairing check → `txBAD_SPONSORSHIP` | ✅ | Post-operation sponsorship check |
| Error monotonicity (success → error only, never back) | ✅ | `set_error()` behavior |
| Soroban error: refundable fee tracker reset on error | ✅ | `reset_consumed_fee()` on error path |
| `txINTERNAL_ERROR` for unexpected errors | ✅ | Error handling in apply path |

### 3.12 Invariants and Safety Properties

**Spec section:** §13
**Source files:** Various (validation, execution, state)

| Invariant | Status | Evidence |
|-----------|--------|----------|
| Determinism (identical inputs → identical outputs) | ✅ | 100% match on 14,651 testnet transactions |
| Fee irrevocability (fee charged regardless of op success) | ✅ | `process_fee_seq_num()` commits before operation dispatch |
| Balance conservation | ✅ | `LumenEventReconciler` verifies XLM conservation |
| Sequence number monotonicity | ✅ | `process_seq_num()` advances sequence |
| Reserve sufficiency (balance ≥ minReserve except for fees) | ✅ | Reserve checks in operations; fee deduction may go below reserve |
| Liability consistency @version(≥10) | ✅ | `ensure_account_liabilities()`, `ensure_trustline_liabilities()` in operations |
| Soroban footprint containment | ✅ | Enforced by soroban-env-host storage layer |
| Soroban resource bounds | ✅ | Budget tracking in `soroban/budget.rs` |
| PRE_AUTH_TX signer consumption | ✅ | `remove_one_time_signers()` |
| Sponsorship pairing | ✅ | Post-operations check |

### 3.13 Constants

**Spec section:** §14
**Source files:** `operations/execute/mod.rs`, `validation.rs`, `live_execution.rs`

| Constant | Spec Value | Status | Evidence |
|----------|-----------|--------|----------|
| `MAX_OPS_PER_TX` | 100 | ✅ | XDR-enforced via `VecM` |
| `MAX_SIGNATURES_PER_ENVELOPE` | 20 | ✅ | XDR-enforced |
| `MAX_OFFERS_TO_CROSS` | 1000 | ✅ | Used in path payment and offer crossing |
| `ACCOUNT_SUBENTRY_LIMIT` | 1000 | ✅ | `operations/execute/mod.rs:26`: `const ACCOUNT_SUBENTRY_LIMIT: u32 = 1000` |
| `MAX_SIGNERS_PER_ACCOUNT` | 20 | ✅ | Enforced in set_options |
| `MAX_EXTRA_SIGNERS` | 2 | ✅ | Enforced in extra signer validation |
| `CLAIM_PREDICATE_MAX_DEPTH` | 4 | ✅ | Enforced in claimable balance validation |
| `MAX_SEQ_NUM_INCREASE` | 2^31 | ✅ | `validate_sequence()` |
| `EXPECTED_CLOSE_TIME_MULT` | 2 | ✅ | Used in sequence age computation |
| `GENESIS_LEDGER_BASE_FEE` | 100 | ✅ | Default in `LedgerContext` |
| `MAX_RESOURCE_FEE` | 2^50 | ✅ | Checked in Soroban resource validation |
| `LIQUIDITY_POOL_FEE_V18` | 30 bps | ✅ | Used in pool exchange computation |
| Soroban network config parameters | Various | ✅ | Loaded from CONFIG_SETTING entries |

---

## 4. Gap Summary

### Critical Gaps

None. All consensus-critical, determinism-affecting behavior specified in TX_SPEC is implemented.

### Moderate Gaps

| Gap | Spec Section | Impact | Priority |
|-----|-------------|--------|----------|
| Static `computeSorobanResourceFee()` | §5, §8.2 | Needed for surge pricing fee computation outside of execution; currently delegated to soroban-env-host during execution | Low |
| `computePreApplySorobanResourceFee()` | §8.2 | Pre-apply resource fee estimation | Low |

### Minor Gaps

| Gap | Spec Section | Impact | Priority |
|-----|-------------|--------|----------|
| `checkValidWithOptionallyChargedFee()` | §4 | Fee-optional validation interface for tx acceptance queue | Low |
| `setInsufficientFeeErrorWithFeeCharged()` | §4 | Specific error-with-fee interface | Low |
| `hasMuxedAccount()` utility | §3 | Muxed account detection on envelope | Low |
| `getUpperBoundCloseTimeOffset()` | §4 | Close time offset for validation | Low |
| `validateSorobanOpsConsistency()` explicit function | §4.2 | Checked implicitly in validate_structure; not exposed as named function | Low |

---

## 5. Risk Assessment

### Low Risk

The henyey-tx crate presents **low consensus risk**. Evidence:

1. **100% testnet verification** across 14,651 transactions (ledgers 30000–36000), covering both classic and Soroban operations.

2. **All MUST/SHALL requirements met**: Every requirement in the spec tagged with MUST/SHALL/REQUIRED is implemented. No consensus-critical behavior is missing.

3. **Full operation coverage**: All 27 operation types have both validation and execution logic matching the spec.

4. **Self-reported 97% parity** with detailed function-level mapping (see `crates/tx/PARITY_STATUS.md`). The 3% gap consists of utility functions and interfaces that do not affect transaction execution correctness.

5. **Comprehensive test suite**: 944 unit tests covering all major code paths, plus integration testing against testnet CDP metadata.

### Areas Requiring Monitoring

1. **Soroban CPU metering variance**: Historical testnet ledgers show 0.01–8% CPU consumption differences due to different soroban-env-host versions. This only affects replay of old ledgers, not live execution at current protocol.

2. **Bucket list state dependency**: Transaction execution correctness depends on bucket list state. The tx crate itself is correct, but parity depends on the bucket list crate for state initialization.

3. **Protocol 26 features**: The P26-specific behaviors (CAP-77 frozen ledger keys, CAP-73 SAC trust fixes, discount rounding, pre-v23 restore meta cleanup) are implemented. The P25-specific behaviors (Soroban memo restriction, muxed account restriction, inner feeCharged adjustment) are also present and covered by testnet verification.

---

## 6. Recommendations

### Near-Term (Low Effort, High Value)

1. **Expose `computeSorobanResourceFee()` as standalone**: Even though it's delegated to soroban-env-host during execution, having a standalone function would support surge pricing computation and tx set validation without requiring full execution context.

2. **Verify P26 frozen-key edge cases on testnet**: CAP-77 introduces `txFROZEN_KEY_ACCESSED` rejection with a bypass-hash whitelist. Ensure coverage of multi-op transactions that touch frozen keys mid-execution.

### Medium-Term

3. **Mainnet verification**: The TX_SPEC evaluation would benefit from mainnet verification (more consistent stellar-core versions across history). Use `henyey offline verify-execution` against mainnet ledger ranges.

4. **Parallel Soroban is implemented**: The parallel stages/clusters model is fully operational at the ledger crate level, eliminating the previously-noted gap. No further action needed.

### Low Priority

5. **Expose missing utility interfaces**: The 5 minor gaps (`checkValidWithOptionallyChargedFee`, `hasMuxedAccount`, etc.) could be implemented as thin wrappers to reach 100% function parity, but they have no correctness impact.

---

## 7. v26.0.1 Implementation Delta

This section summarizes the key changes between stellar-core v25.0.1 and v26.0.1 in `src/transactions/` and their henyey-tx implementation status.

### stellar-core v26 Transaction Changes

The `git log v25.0.1..v26.0.1 -- src/transactions/` shows ~40 commits. Key behavioral changes:

| Change | Commit | henyey-tx Status |
|--------|--------|-----------------|
| **CAP-77: Frozen ledger keys** | `87e2161bc` | ✅ Full — `frozen_keys.rs`: `FrozenKeyConfig`, per-op `accesses_frozen_key()` dispatch, bypass hash set |
| **CAP-73: SAC trust (native SAC)** | `3e947211f`, `356286b74` | ✅ Full — InvokeHostFunction trust handling for native SAC |
| **TxSet validation improvements** | `e4e3b93e8`, `45d371c13`, `a5393933f` | ✅ Full — `tx_set_xdr.rs` validates parallel phase structure |
| **Pre-v23 restore meta cleanup** | `53d138c5a`, `c69069ed1` | ✅ Full — Clean restore key tracking in `meta_builder.rs`, `state/mod.rs` |
| **Discount rounding change** | `706520aad` | ✅ Full — Updated rounding in offer exchange |
| **ParallelTxReturnVal refactor** | `589044435`, `b8e6d0753` | ➖ N/A — Architectural; henyey uses its own parallel execution model at ledger crate level |
| **Banned accounts config** | `36aeb36ae` | ➖ N/A — Herder-level (not tx crate); implemented in `henyey-herder` |
| **LedgerEntry scope refactor** | `42d784fa3`, `3203d9b43`, `df43e98e2` | ➖ N/A — Internal C++ safety; Rust ownership model provides equivalent guarantees |
| **Overlay signature verification** | `9e5838e9d` | ➖ N/A — Overlay-level; not in tx crate scope |
| **Remove p26 ifdefs** | `79258890b` | ➖ N/A — Code cleanup |
| **Remove maintenance** | `dc44d5bd6`, `eb0030727` | ➖ N/A — Maintenance operations not relevant |
| **Expired entry modification guard** | `0cb85be74`, `8f2c51a71` | ✅ Full — Enforced in `state/mod.rs` entry access layer |

### New henyey-tx Functionality Since v25 Evaluation

1. **`frozen_keys.rs`** (57 functions): Complete CAP-77 implementation with `FrozenKeyConfig`, per-operation-type key extraction, bypass transaction hash set, and centralized checking.
2. **Updated offer exchange rounding**: Aligned with `706520aad` discount rounding change.
3. **Restore key tracking cleanup**: Aligned with pre-v23 restore meta simplification.
4. **Test count growth**: 815 → 944 unit tests, with 33 new frozen-key tests covering all operation types.

### Items Not Applicable to henyey-tx

The following v26 changes affect other subsystems and are intentionally not tracked in this crate:

- `ParallelTxReturnVal` refactor — internal stellar-core apply return type; henyey's parallel model uses `LedgerDelta` per cluster
- Banned accounts — herder/overlay concern, not transaction execution
- `LedgerEntryScope`/`ScopedLedgerEntry` — C++ memory safety pattern; Rust's ownership handles this
- `SimpleTimer` class — profiling infrastructure
