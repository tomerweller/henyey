## C++ Parity Status

This section documents the parity between this Rust crate and the upstream C++ stellar-core implementation in `.upstream-v25/src/transactions/`.

### Implemented

#### Transaction Frame & Envelope Handling
- **TransactionFrame** (`frame.rs`): Full envelope handling for V0, V1, and FeeBump transactions
- **Hash computation**: Network-bound transaction hash with signature payload
- **Resource extraction**: Surge pricing resource calculation for both classic and Soroban
- **Soroban detection**: Proper identification of Soroban vs classic transactions
- **Fee calculations**: Total fee, inclusion fee, Soroban resource fee separation

#### Transaction Validation
- **Structure validation**: Operation count, fee checks, Soroban single-op requirement
- **Time bounds validation**: Min/max time checks against ledger close time
- **Ledger bounds validation**: Min/max ledger sequence checks
- **Fee validation**: Minimum fee per operation
- **Sequence validation**: Sequence number matching with account
- **Signature validation**: Ed25519 signature verification with hint matching
- **Extra signers**: V2 precondition extra signer validation (Ed25519, PreAuthTx, HashX, SignedPayload)
- **Min sequence preconditions**: V2 min_seq_num, min_seq_age, min_seq_ledger_gap
- **Soroban resource validation**: Archived entry indices, footprint validation

#### Transaction Processing (Newly Implemented)
- **SignatureChecker** (`signature_checker.rs`): Full signer weight checking
  - Weight accumulation across multiple signers
  - Threshold level checking (LOW/MEDIUM/HIGH)
  - Ordered processing: PRE_AUTH_TX → HASH_X → ED25519 → ED25519_SIGNED_PAYLOAD
  - Weight cap at u8::MAX for protocol 10+
  - Tracks which signatures have been used
  - `check_all_signatures_used()` for unused signature detection
- **ThresholdLevel** (`operations/mod.rs`): Operation-specific threshold requirements
  - LOW: AllowTrust, SetTrustLineFlags, BumpSequence, ClaimClaimableBalance, Inflation, ExtendFootprintTtl, RestoreFootprint
  - MEDIUM: Most operations (Payment, CreateAccount, ChangeTrust, etc.)
  - HIGH: AccountMerge, SetOptions (when modifying thresholds/signers)
- **MutableTransactionResult** (`result.rs`): Mutable result wrapper for execution
  - Result code mutation during apply
  - Refundable fee tracker integration
  - `set_error()` resets refundable fees
  - `finalize_fee_refund()` for final fee calculation
- **RefundableFeeTracker** (`result.rs`): Detailed Soroban fee tracking
  - Tracks max_refundable_fee, consumed_events_size, consumed_rent_fee
  - `consume_rent_fee()` and `update_consumed_refundable_fee()`
  - `get_fee_refund()` returns max - consumed
  - `reset_consumed_fee()` for error cases (full refund)
- **One-time signer removal** (`state.rs`): Pre-auth TX signer cleanup
  - `remove_one_time_signers_from_all_sources()` for transaction cleanup
  - `remove_account_signer()` for individual signer removal
  - Sponsorship cleanup when removing sponsored signers
  - Protocol 7 bypass (matches C++ behavior)

#### Fee Bump Transactions (Newly Implemented)
- **FeeBumpFrame** (`fee_bump.rs`): Dedicated fee bump transaction wrapper
  - Wraps inner V1 transaction with fee bump envelope
  - Separate accessors for outer fee source and inner source
  - Inner transaction hash computation and caching
  - `fee_source_is_inner_source()` for same-account detection
- **FeeBumpMutableTransactionResult** (`fee_bump.rs`): Result tracking for fee bumps
  - Tracks both outer fee and inner fee separately
  - Inner transaction hash stored in `InnerTransactionResultPair`
  - Protocol-versioned fee refund logic (P24 vs P25+)
  - Inner operation results management
- **Fee bump validation** (`fee_bump.rs`, `validation.rs`): Complete fee bump validation
  - Outer fee >= inner fee validation
  - Outer fee >= base_fee * (op_count + 1) validation
  - Inner signature format validation
  - Integration with basic and full validation paths
- **Helper functions** (`fee_bump.rs`):
  - `calculate_inner_fee_charged()`: Protocol-versioned inner fee calculation
  - `wrap_inner_result_in_fee_bump()`: Convert inner result to fee bump result
  - `extract_inner_hash_from_result()`: Extract inner hash from result
  - `verify_inner_signatures()`: Cryptographic inner signature verification

#### Transaction Metadata Building (Newly Implemented)
- **TransactionMetaBuilder** (`meta_builder.rs`): Full meta construction for live execution
  - Creates OperationMetaBuilder for each operation
  - Manages transaction-level and operation-level events
  - Supports V2, V3, and V4 TransactionMeta XDR formats
  - `push_tx_changes_before()` and `push_tx_changes_after()` for tx-level changes
  - `set_non_refundable_resource_fee()` and `set_refundable_fee_tracker()` for Soroban
  - One-time `finalize(success)` produces final TransactionMeta XDR
- **OperationMetaBuilder** (`meta_builder.rs`): Per-operation metadata
  - Records ledger changes: `record_create()`, `record_update()`, `record_delete()`, `record_restore()`
  - Manages OpEventManager for operation-level contract events
  - Soroban return value tracking via `set_soroban_return_value()`
  - `finalize_v2()` for V2/V3 meta, `finalize_v4()` for V4 meta with per-op events
- **DiagnosticEventManager** (`meta_builder.rs`): Diagnostic event collection
  - `create_for_apply()` for Soroban transaction apply phase
  - `create_for_validation()` for transaction submission validation
  - `push_error()` for validation/execution errors (ScError, message, args)
  - `push_metrics()` for execution metrics (CPU, memory, I/O)
  - `push_event()` and `push_events()` for Soroban host diagnostic events
  - Disabled mode is complete no-op for performance
- **DiagnosticConfig**: Configuration for diagnostic event collection
  - `enable_soroban_diagnostic_events` for apply phase
  - `enable_diagnostics_for_tx_submission` for validation phase
- **ExecutionMetrics**: Struct for execution metrics diagnostic events
  - cpu_insn, mem_byte, ledger_read_byte, ledger_write_byte
  - emit_event, emit_event_byte, invoke_time_nsecs

#### Transaction Application (Catchup Mode)
- **LedgerDelta**: State change accumulation with proper ordering
- **Change ordering preservation**: ChangeRef tracking for metadata construction
- **Pre-state tracking**: STATE entries for UPDATED/REMOVED metadata
- **TransactionMeta parsing**: V0, V1, V2, V3, V4 meta format support
- **Fee charging**: Fee accumulation and refund tracking

#### Classic Operations (All 24 Operations)
| Operation | Status | Notes |
|-----------|--------|-------|
| CreateAccount | Implemented | Full reserve checking |
| Payment | Implemented | Native and credit assets |
| PathPaymentStrictReceive | Implemented | Path finding with offers |
| PathPaymentStrictSend | Implemented | Path finding with offers |
| ManageSellOffer | Implemented | Create/update/delete offers |
| ManageBuyOffer | Implemented | Create/update/delete offers |
| CreatePassiveSellOffer | Implemented | Non-crossing offers |
| SetOptions | Implemented | Thresholds, signers, flags |
| ChangeTrust | Implemented | Credit and pool shares |
| AllowTrust | Implemented | Authorization flags (deprecated) |
| AccountMerge | Implemented | Balance transfer and deletion |
| Inflation | Implemented | Returns NotTime (deprecated since P12) |
| ManageData | Implemented | 64-byte data entries |
| BumpSequence | Implemented | Sequence number advancement |
| CreateClaimableBalance | Implemented | Predicate validation |
| ClaimClaimableBalance | Implemented | Predicate evaluation |
| BeginSponsoringFutureReserves | Implemented | Sponsorship stack |
| EndSponsoringFutureReserves | Implemented | Sponsorship stack |
| RevokeSponsorship | Implemented | Entry and signer revocation |
| Clawback | Implemented | Trustline clawback |
| ClawbackClaimableBalance | Implemented | Balance clawback |
| SetTrustLineFlags | Implemented | Authorization flags |
| LiquidityPoolDeposit | Implemented | AMM deposits |
| LiquidityPoolWithdraw | Implemented | AMM withdrawals |

#### Soroban Operations
| Operation | Status | Notes |
|-----------|--------|-------|
| InvokeHostFunction | Implemented | Via e2e_invoke API |
| ExtendFootprintTtl | Implemented | TTL extension with rent fee |
| RestoreFootprint | Implemented | Archived entry restoration |

#### Soroban Integration
- **Protocol-versioned hosts**: P24 and P25 soroban-env-host support
- **e2e_invoke API**: Using same high-level API as C++ stellar-core
- **Storage snapshot**: TTL-aware entry access (expired = archived)
- **Budget tracking**: CPU and memory consumption
- **Event collection**: Contract events and diagnostic events
- **Rent fee calculation**: Protocol-versioned rent fee computation
- **Archived entry restoration**: V1 ext archived_soroban_entries support
- **PRNG seed**: Configurable seed for deterministic execution

#### Event Emission (SAC Events)
- **Protocol 23+ events**: Native classic event emission
- **Event types**: transfer, mint, burn, clawback, set_authorized, fee
- **Backfill support**: Pre-P23 event backfilling
- **Muxed account handling**: Proper address extraction
- **Memo encoding**: Classic memo to ScVal conversion

#### State Management
- **LedgerStateManager**: In-memory state with HashMap-based storage
- **Entry types**: Account, Trustline, Offer, Data, ContractData, ContractCode, TTL, ClaimableBalance, LiquidityPool
- **Snapshots**: Per-operation snapshots for rollback
- **Sponsorship stack**: Active sponsorship context tracking
- **Minimum balance**: Reserve calculations with sponsorship

### Not Yet Implemented (Gaps)

#### Parallel Execution (Not Applicable)
- **ParallelApplyStage**: Parallel transaction application infrastructure
  - C++: `ParallelApplyStage.cpp`, `ParallelApplyUtils.cpp`
  - Rust: Not needed - sequential execution for catchup mode
- **ThreadParallelApplyLedgerState**: Thread-local ledger state for parallel apply
- **TxEffects**: Per-transaction effect tracking for parallel merge

#### Database Integration (Not Applicable)
- **TransactionSQL**: Transaction persistence to SQL database
  - C++: `TransactionSQL.cpp` - stores tx results in database
  - Rust: Not needed - bucket list only
- **TransactionBridge**: Bridge between transaction frames and database

#### Event Management (Implemented)
- **EventManager hierarchy**: Full C++ EventManager/OpEventManager/TxEventManager structure
  - C++: `EventManager.cpp` - 500+ lines with LumenEventReconciler
  - Rust: Full implementation in `events.rs` with `OpEventManager`, `TxEventManager`, and `EventManagerHierarchy`
  - Features: finalization guards, insert-at-beginning for mint events, disabled mode for performance
- **LumenEventReconciler**: XLM balance reconciliation for event emission
  - C++: `LumenEventReconciler.cpp` - reconciles XLM movements for fee events
  - Rust: Full implementation in `lumen_reconciler.rs` with `LumenEventReconciler` and `ReconcilerConfig`
  - Features: pre-protocol 8 balance tracking, account delta calculation, mint event insertion

#### Signature Utilities
- **SignatureUtils**: Signature verification helpers
  - C++: `SignatureUtils.cpp` - hint computation, verification helpers
  - Rust: Basic signature functions in stellar-core-crypto

#### Live Execution Mode
- **processFeeSeqNum**: Fee charging and sequence number processing
  - C++: Separate step before operation application
  - Rust: Not implemented for live mode
- **processPostApply**: Post-apply processing (refunds, cleanup)
  - C++: Soroban fee refunds, signer cleanup
  - Rust: Refund applied during catchup only
- **processPostTxSetApply**: Per-transaction-set post processing

### Implementation Notes

#### Architectural Differences

1. **Replay vs Execute**: The Rust crate is primarily designed for catchup/replay mode where transaction results and metadata are trusted from archives. The C++ implementation focuses on live execution with full validation and result building.

2. **State Layer**: Rust uses an in-memory `LedgerStateManager` while C++ uses `AbstractLedgerTxn` with SQL backing. This is intentional as Rust targets bucket list state.

3. **Protocol Versioning**: Rust uses separate `soroban-env-host-p24` and `soroban-env-host-p25` crates, while C++ uses version-aware code paths within a single codebase.

4. **Signature Checking**: The Rust `SignatureChecker` now matches C++ behavior with stateful tracking of which signatures have been used across the transaction, weight accumulation, and threshold checking.

5. **Meta Building**: Rust now has `TransactionMetaBuilder` for live execution mode, matching C++ behavior. The catchup mode still parses metadata from archives.

6. **Event Reconciliation**: Rust now has a full `LumenEventReconciler` implementation matching C++ behavior for pre-protocol 8 XLM balance tracking, ensuring fee events are correctly attributed with proper mint event insertion at the beginning of event lists.

7. **Fee Bump Handling**: Rust now has a dedicated `FeeBumpFrame` wrapper that provides fee bump-specific functionality matching C++ `FeeBumpTransactionFrame`. The implementation includes proper inner transaction hash tracking, protocol-versioned fee logic, and result wrapping.

#### Priority Gaps for Full Parity

**High Priority** (needed for validator mode):
1. ~~SignatureChecker with weight accumulation and threshold checking~~ ✓ Implemented
2. ~~TransactionMetaBuilder for generating metadata during execution~~ ✓ Implemented
3. ~~MutableTransactionResult with RefundableFeeTracker~~ ✓ Implemented
4. ~~Complete fee bump transaction handling~~ ✓ Implemented

**Medium Priority** (needed for complete validation):
1. ~~Unused signature checking~~ ✓ Implemented (via SignatureChecker)
2. ~~One-time signer removal~~ ✓ Implemented
3. ~~DiagnosticEventManager integration~~ ✓ Implemented
4. ~~LumenEventReconciler for event consistency~~ ✓ Implemented

**Low Priority** (not needed for current use cases):
1. Parallel execution infrastructure
2. SQL database integration
3. TransactionBridge

**All high-priority and medium-priority gaps have been addressed.**
