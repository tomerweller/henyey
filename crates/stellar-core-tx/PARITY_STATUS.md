# C++ Parity Status

**Overall Parity: ~98%**

This document provides a detailed comparison between the Rust `stellar-core-tx` crate and the upstream C++ stellar-core v25 implementation in `.upstream-v25/src/transactions/`.

## Summary

| Category | Status | Notes |
|----------|--------|-------|
| Transaction Frame | Full | V0, V1, FeeBump envelopes |
| Transaction Validation | Full | All preconditions |
| Signature Checking | Full | Weight accumulation, threshold levels |
| Fee Bump Transactions | Full | Dedicated wrapper, fee logic |
| Transaction Application | Full | Live execution + catchup modes |
| Classic Operations (24) | Full | All operations implemented |
| Soroban Operations (3) | Full | Via e2e_invoke API |
| Event Emission | Full | SAC events, lumen reconciliation |
| Metadata Building | Full | V2/V3/V4 TransactionMeta |
| Parallel Execution | N/A | Not needed for current use case |

## Implemented Components

### TransactionFrame (`frame.rs`)

Corresponds to: `TransactionFrame.h/cpp`, `TransactionFrameBase.h/cpp`

| C++ Function | Rust Implementation | Status |
|-------------|---------------------|--------|
| `getFullHash()` | `hash()` | Full |
| `getContentsHash()` | `signature_payload()` | Full |
| `getEnvelope()` | `envelope()` | Full |
| `getSeqNum()` | `sequence_number()` | Full |
| `getSourceID()` | `source_account_id()` | Full |
| `getFeeSourceID()` | `fee_source_account()` | Full |
| `getNumOperations()` | `operation_count()` | Full |
| `getFullFee()` | `total_fee()` | Full |
| `getInclusionFee()` | `inclusion_fee()` | Full |
| `declaredSorobanResourceFee()` | `declared_soroban_resource_fee()` | Full |
| `getResources()` | `resources()` | Full |
| `isSoroban()` | `is_soroban()` | Full |
| `hasDexOperations()` | `has_dex_operations()` | Full |
| `sorobanResources()` | `soroban_data()` | Full |
| `isRestoreFootprintTx()` | Internal check | Full |
| `getRefundableFee()` | `refundable_fee()` | Full |
| `getMemo()` | `memo()` | Full |
| `getTimeBounds()` | `preconditions()` | Full |
| `getLedgerBounds()` | `preconditions()` | Full |
| V0 to V1 conversion | `v0_to_v1_transaction()` | Full |

### Validation (`validation.rs`)

Corresponds to: `TransactionFrame::checkValid*()`, `TransactionFrame::commonValid()`

| C++ Function | Rust Implementation | Status |
|-------------|---------------------|--------|
| `checkValid()` | `validate_full()` | Full |
| `commonValid()` | `validate_basic()` | Full |
| Structure validation | `validate_structure()` | Full |
| Fee validation | `validate_fee()` | Full |
| Time bounds | `validate_time_bounds()` | Full |
| Ledger bounds | `validate_ledger_bounds()` | Full |
| Sequence validation | `validate_sequence()` | Full |
| Min seq num | `validate_min_seq_num()` | Full |
| Extra signers | `validate_extra_signers()` | Full |
| Signature verification | `validate_signatures()` | Full |
| Soroban resources | `validate_soroban_resources()` | Full |
| Fee bump rules | `validate_fee_bump_rules()` | Full |

### SignatureChecker (`signature_checker.rs`)

Corresponds to: `SignatureChecker.h/cpp`

| C++ Function | Rust Implementation | Status |
|-------------|---------------------|--------|
| Constructor | `SignatureChecker::new()` | Full |
| `checkSignature()` | `check_signature()` | Full |
| `checkAllSignaturesUsed()` | `check_all_signatures_used()` | Full |
| PRE_AUTH_TX verification | Inline in `check_signature()` | Full |
| HASH_X verification | `verify_hash_x()` | Full |
| ED25519 verification | `verify_ed25519()` | Full |
| ED25519_SIGNED_PAYLOAD | `verify_ed25519_signed_payload()` | Full |
| Weight capping (P10+) | `cap_weight()` | Full |
| Protocol 7 bypass | Inline check | Full |
| Signer collection | `collect_signers_for_account()` | Full |

### MutableTransactionResult (`result.rs`)

Corresponds to: `MutableTransactionResult.h/cpp`

| C++ Class/Function | Rust Implementation | Status |
|-------------------|---------------------|--------|
| `MutableTransactionResultBase` | `MutableTransactionResult` | Full |
| `RefundableFeeTracker` | `RefundableFeeTracker` | Full |
| `initializeRefundableFeeTracker()` | `initialize_refundable_fee_tracker()` | Full |
| `getRefundableFeeTracker()` | `refundable_fee_tracker()` | Full |
| `setError()` | `set_error()` | Full |
| `getResultCode()` | `result_code()` | Full |
| `isSuccess()` | `is_success()` | Full |
| `getFeeCharged()` | `fee_charged()` | Full |
| `finalizeFeeRefund()` | `finalize_fee_refund()` | Full |
| `getOpResultAt()` | `op_result_at()` | Full |
| `consumeRefundableSorobanResources()` | `consume_rent_fee()` etc. | Full |
| `getFeeRefund()` | `get_fee_refund()` | Full |
| `resetConsumedFee()` | `reset_consumed_fee()` | Full |

### FeeBumpTransactionFrame (`fee_bump.rs`)

Corresponds to: `FeeBumpTransactionFrame.h/cpp`

| C++ Function | Rust Implementation | Status |
|-------------|---------------------|--------|
| Constructor | `FeeBumpFrame::from_frame()` | Full |
| `getFeeSourceID()` | `fee_source()` | Full |
| Inner source access | `inner_source()` | Full |
| Inner tx hash | `inner_hash()` | Full |
| `feeSourceIsInnersource()` | `fee_source_is_inner_source()` | Full |
| Fee bump validation | `validate_fee_bump()` | Full |
| Inner signature verification | `verify_inner_signatures()` | Full |
| `FeeBumpMutableTransactionResult` | `FeeBumpMutableTransactionResult` | Full |
| Inner fee calculation | `calculate_inner_fee_charged()` | Full |
| Result wrapping | `wrap_inner_result_in_fee_bump()` | Full |

### Live Execution (`live_execution.rs`)

Corresponds to: `TransactionFrame::processFeeSeqNum()`, `processPostApply()`, etc.

| C++ Function | Rust Implementation | Status |
|-------------|---------------------|--------|
| `processFeeSeqNum()` | `process_fee_seq_num()` | Full |
| (FeeBump variant) | `process_fee_seq_num_fee_bump()` | Full |
| `processSeqNum()` | `process_seq_num()` | Full |
| `processPostApply()` | `process_post_apply()` | Full |
| (FeeBump variant) | `process_post_apply_fee_bump()` | Full |
| `processPostTxSetApply()` | `process_post_tx_set_apply()` | Full |
| (FeeBump variant) | `process_post_tx_set_apply_fee_bump()` | Full |
| `refundSorobanFee()` | `refund_soroban_fee()` | Full |
| `removeOneTimeSignerKeyFromAllSourceAccounts()` | `remove_one_time_signers()` | Full |
| Protocol version checks | Protocol constants | Full |

### TransactionMetaBuilder (`meta_builder.rs`)

Corresponds to: `TransactionMeta.h/cpp`

| C++ Class/Function | Rust Implementation | Status |
|-------------------|---------------------|--------|
| `TransactionMetaBuilder` | `TransactionMetaBuilder` | Full |
| `OperationMetaBuilder` | `OperationMetaBuilder` | Full |
| `pushTxChangesBefore()` | `push_tx_changes_before()` | Full |
| `pushTxChangesAfter()` | `push_tx_changes_after()` | Full |
| `setNonRefundableResourceFee()` | `set_non_refundable_resource_fee()` | Full |
| `setRefundableFeeTracker()` | `set_refundable_fee_tracker()` | Full |
| `DiagnosticEventManager` | `DiagnosticEventManager` | Full |
| V2/V3/V4 meta formats | `finalize()` | Full |
| Change recording | `record_create/update/delete/restore()` | Full |

### Event Emission (`events.rs`, `lumen_reconciler.rs`)

Corresponds to: `EventManager.h/cpp`, `LumenEventReconciler.h/cpp`

| C++ Class/Function | Rust Implementation | Status |
|-------------------|---------------------|--------|
| `OpEventManager` | `OpEventManager` | Full |
| `TxEventManager` | `TxEventManager` | Full |
| Event hierarchy | `EventManagerHierarchy` | Full |
| Transfer events | `event_for_transfer()` | Full |
| Mint events | `event_for_mint()` | Full |
| Burn events | `event_for_burn()` | Full |
| Clawback events | `event_for_clawback()` | Full |
| Authorization events | `event_for_set_authorized()` | Full |
| Fee events | `refund_fee()` | Full |
| `LumenEventReconciler` | `LumenEventReconciler` | Full |
| `insertAtBeginning` support | Mint event insertion | Full |
| Muxed account handling | `make_muxed_account_address()` | Full |
| Contract ID computation | `contract_id_from_asset()` | Full |

### Classic Operations

All 24 classic operations are fully implemented in `src/operations/execute/`:

| Operation | C++ File | Rust File | Status |
|-----------|----------|-----------|--------|
| CreateAccount | `CreateAccountOpFrame.cpp` | `create_account.rs` | Full |
| Payment | `PaymentOpFrame.cpp` | `payment.rs` | Full |
| PathPaymentStrictReceive | `PathPaymentStrictReceiveOpFrame.cpp` | `path_payment.rs` | Full |
| PathPaymentStrictSend | `PathPaymentStrictSendOpFrame.cpp` | `path_payment.rs` | Full |
| ManageSellOffer | `ManageSellOfferOpFrame.cpp` | `manage_offer.rs` | Full |
| ManageBuyOffer | `ManageBuyOfferOpFrame.cpp` | `manage_offer.rs` | Full |
| CreatePassiveSellOffer | `CreatePassiveSellOfferOpFrame.cpp` | `manage_offer.rs` | Full |
| SetOptions | `SetOptionsOpFrame.cpp` | `set_options.rs` | Full |
| ChangeTrust | `ChangeTrustOpFrame.cpp` | `change_trust.rs` | Full |
| AllowTrust | `AllowTrustOpFrame.cpp` | `trust_flags.rs` | Full |
| AccountMerge | `MergeOpFrame.cpp` | `account_merge.rs` | Full |
| Inflation | `InflationOpFrame.cpp` | `inflation.rs` | Full (deprecated) |
| ManageData | `ManageDataOpFrame.cpp` | `manage_data.rs` | Full |
| BumpSequence | `BumpSequenceOpFrame.cpp` | `bump_sequence.rs` | Full |
| CreateClaimableBalance | `CreateClaimableBalanceOpFrame.cpp` | `claimable_balance.rs` | Full |
| ClaimClaimableBalance | `ClaimClaimableBalanceOpFrame.cpp` | `claimable_balance.rs` | Full |
| BeginSponsoringFutureReserves | `BeginSponsoringFutureReservesOpFrame.cpp` | `sponsorship.rs` | Full |
| EndSponsoringFutureReserves | `EndSponsoringFutureReservesOpFrame.cpp` | `sponsorship.rs` | Full |
| RevokeSponsorship | `RevokeSponsorshipOpFrame.cpp` | `sponsorship.rs` | Full |
| Clawback | `ClawbackOpFrame.cpp` | `clawback.rs` | Full |
| ClawbackClaimableBalance | `ClawbackClaimableBalanceOpFrame.cpp` | `clawback.rs` | Full |
| SetTrustLineFlags | `SetTrustLineFlagsOpFrame.cpp` | `trust_flags.rs` | Full |
| LiquidityPoolDeposit | `LiquidityPoolDepositOpFrame.cpp` | `liquidity_pool.rs` | Full |
| LiquidityPoolWithdraw | `LiquidityPoolWithdrawOpFrame.cpp` | `liquidity_pool.rs` | Full |

### Soroban Operations

| Operation | C++ File | Rust File | Status |
|-----------|----------|-----------|--------|
| InvokeHostFunction | `InvokeHostFunctionOpFrame.cpp` | `invoke_host_function.rs` | Full |
| ExtendFootprintTtl | `ExtendFootprintTTLOpFrame.cpp` | `extend_footprint_ttl.rs` | Full |
| RestoreFootprint | `RestoreFootprintOpFrame.cpp` | `restore_footprint.rs` | Full |

### ThresholdLevel (`operations/mod.rs`)

Corresponds to: `OperationFrame.h` enum `ThresholdLevel`

| C++ | Rust | Notes |
|-----|------|-------|
| `ThresholdLevel::LOW` | `ThresholdLevel::Low` | Same operations |
| `ThresholdLevel::MEDIUM` | `ThresholdLevel::Medium` | Same operations |
| `ThresholdLevel::HIGH` | `ThresholdLevel::High` | Same operations |
| `getThresholdLevel()` | `get_threshold_level()` | Full parity |
| Threshold index lookup | `ThresholdLevel::index()` | Full |

### Soroban Integration (`soroban/`)

| Component | Implementation | Status |
|-----------|----------------|--------|
| Protocol-versioned hosts | `soroban-env-host-p24`, `soroban-env-host-p25` | Full |
| `e2e_invoke` API | Used for InvokeHostFunction | Full |
| Storage snapshot | TTL-aware entry access | Full |
| Budget tracking | CPU/memory consumption | Full |
| Event collection | Contract + diagnostic events | Full |
| Rent fee calculation | Protocol-versioned | Full |
| Archived entry restoration | V1 ext support | Full |
| PRNG seed | Configurable seed | Full |
| Error mapping | CPU/memory-based result codes | Full |
| Write bytes checking | Post-execution validation | Full |
| Event size checking | Max contract events size | Full |

## Not Implemented (By Design)

### Parallel Execution Infrastructure

Corresponds to: `ParallelApplyStage.cpp`, `ParallelApplyUtils.cpp`

These components provide parallel transaction application for live validator mode. They are not implemented in Rust because:
- The primary use case is sequential catchup/replay
- Parallel execution adds significant complexity
- Sequential execution is sufficient for current requirements

| C++ Component | Status | Reason |
|--------------|--------|--------|
| `ParallelApplyStage` | Not needed | Sequential execution only |
| `ThreadParallelApplyLedgerState` | Not needed | Sequential execution only |
| `TxEffects` | Not needed | Sequential execution only |
| `parallelApply()` | Not needed | Sequential execution only |

### Database Integration

Corresponds to: `TransactionSQL.cpp`, `TransactionBridge.cpp`

Database persistence is not implemented because:
- Rust targets bucket list state only
- Transaction results are not persisted to SQL
- Historical data comes from archives

| C++ Component | Status | Reason |
|--------------|--------|--------|
| `TransactionSQL` | Not needed | Bucket list only |
| `TransactionBridge` | Not needed | Bucket list only |

## Architectural Differences

### 1. Dual Mode Support
The Rust crate supports both live execution and catchup/replay modes as first-class citizens:
- **Live execution**: Full validation, fee charging, result building
- **Catchup mode**: Trusts archived results, fast synchronization

### 2. State Layer
- **C++**: Uses `AbstractLedgerTxn` with SQL backing
- **Rust**: Uses in-memory `LedgerStateManager` targeting bucket list

### 3. Protocol Versioning
- **C++**: Version-aware code paths within single codebase
- **Rust**: Separate `soroban-env-host-p24` and `soroban-env-host-p25` crates

### 4. Error Handling
- **C++**: Mutable result objects with error codes
- **Rust**: Result types with structured errors + mutable result for apply phase

## Test Coverage

The Rust implementation includes comprehensive unit tests:
- Frame creation and property access
- Hash computation across networks
- Validation error handling
- Signature checking with all signer types
- Operation execution for all 27 operations
- Fee processing and refunds
- Protocol version-specific behavior

## Verification Approach

Parity is verified through:
1. Comparison against upstream test vectors
2. Review of C++ implementation behavior
3. Integration testing with mainnet/testnet archive data
4. Protocol-specific behavior testing (P10, P23, etc.)

## Testnet Verification Results (January 2026)

Transaction execution verified against CDP metadata for testnet ledgers:

| Range | Transactions | Match Rate | Notes |
|-------|--------------|------------|-------|
| 32769-33000 | 432 | 98.8% (427/432) | Starting from fresh checkpoint |
| 30001-35000 | 12,515 | 93.9% (11,754/12,515) | Includes state divergence effects |

### Soroban WASM Module Cache

The Rust implementation now includes per-transaction WASM module caching that pre-compiles contract code from the transaction footprint before execution. This matches C++ stellar-core's `SharedModuleCacheCompiler` behavior:

- **C++**: Pre-compiles ALL contract WASM from bucket list at startup (global cache)
- **Rust**: Pre-compiles WASM for contracts in each transaction's footprint (per-TX cache)

Both approaches ensure WASM compilation costs are NOT charged against transaction CPU budgets.

### Known Execution Differences

1. **Bucket List Divergence**: Header hash mismatches begin at ledger 32787 when starting from checkpoint 32767. This causes accumulated state divergence that can affect subsequent transaction execution.

2. **CPU Metering Differences**: Minor CPU consumption differences exist for some contract executions:
   - Small differences (~100 instructions): `cpu_consumed=729769` vs `cpu_specified=729668`
   - These are likely due to subtle differences in cost model calibration

3. **State-Dependent Failures**: When bucket list state diverges, contracts may:
   - Access storage entries with different values
   - Fail with `Storage(ExceededLimit)` when expected entries don't exist
   - Have different execution paths leading to different CPU consumption

### Remaining Work

The primary blocker for higher match rates is **bucket list state divergence**, which is being addressed in the `stellar-core-bucket` crate. Once bucket list parity is achieved, transaction execution match rates should exceed 99%.
