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

#### Transaction Metadata Building
- **TransactionMetaBuilder**: Full meta construction during live execution
  - C++: `TransactionMeta.cpp` - builds meta during apply, manages operation builders
  - Rust: Meta is parsed from archive, not built during execution
- **OperationMetaBuilder**: Per-operation meta with event management
- **DiagnosticEventManager**: Diagnostic event collection during validation/apply
  - C++: Tracks validation errors, budget exceedance, etc.
  - Rust: Diagnostic events extracted from soroban-env-host only

#### Fee Bump Transactions
- **FeeBumpTransactionFrame**: Separate frame class for fee bump handling
  - C++: `FeeBumpTransactionFrame.cpp` - 600+ lines of fee bump-specific logic
  - Rust: Handled within TransactionFrame, may miss edge cases
- **Inner transaction result wrapping**: Proper inner result in outer result

#### Database Integration (Not Applicable)
- **TransactionSQL**: Transaction persistence to SQL database
  - C++: `TransactionSQL.cpp` - stores tx results in database
  - Rust: Not needed - bucket list only
- **TransactionBridge**: Bridge between transaction frames and database

#### Event Management (Full Implementation)
- **EventManager hierarchy**: Full C++ EventManager/OpEventManager/TxEventManager structure
  - C++: `EventManager.cpp` - 500+ lines with LumenEventReconciler
  - Rust: Simplified event managers without full reconciliation
- **LumenEventReconciler**: XLM balance reconciliation for event emission
  - C++: `LumenEventReconciler.cpp` - reconciles XLM movements for fee events
  - Rust: Direct fee event emission without reconciliation

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

4. **Signature Checking**: The C++ `SignatureChecker` is a stateful class that tracks which signatures have been used across the transaction. The Rust implementation does per-signature verification without this tracking, which could allow replay of signatures across operations (though this is caught by other validation).

5. **Meta Building**: C++ builds transaction metadata during execution. Rust parses it from archives. For full live execution, Rust would need a `TransactionMetaBuilder` equivalent.

6. **Event Reconciliation**: C++ uses `LumenEventReconciler` to ensure fee events are correctly attributed. Rust emits fee events directly without reconciliation, which may produce different event sequences in edge cases.

#### Priority Gaps for Full Parity

**High Priority** (needed for validator mode):
1. SignatureChecker with weight accumulation and threshold checking
2. TransactionMetaBuilder for generating metadata during execution
3. MutableTransactionResult with RefundableFeeTracker
4. Complete fee bump transaction handling

**Medium Priority** (needed for complete validation):
1. Unused signature checking
2. One-time signer removal
3. DiagnosticEventManager integration
4. LumenEventReconciler for event consistency

**Low Priority** (not needed for current use cases):
1. Parallel execution infrastructure
2. SQL database integration
3. TransactionBridge
