# henyey-tx

Transaction validation and execution for henyey.

## Overview

This crate provides the core transaction processing logic for the Stellar network, supporting both classic Stellar operations and Soroban smart contract execution. It is the heart of ledger state changes in henyey.

### Operating Modes

The crate supports two first-class modes of operation:

1. **Live Execution Mode**: Validates and executes transactions in real-time, producing deterministic results that match stellar-core. This is the mode used by validators to close ledgers and enables full participation in the Stellar network consensus.

2. **Catchup/Replay Mode**: Applies historical transactions from archives by trusting the recorded results and replaying state changes. This enables fast synchronization with the network without re-executing every transaction.

### Why Two Modes?

Re-executing historical transactions is problematic for several reasons:

- **Protocol Evolution**: Older transactions may have been validated under different rules. Re-execution with current code could reject valid historical transactions or produce different results.

- **State Dependencies**: Full execution requires the exact ledger state at the time of original execution, which may not be available during initial catchup.

- **Soroban Determinism**: Smart contract execution depends on PRNG seeds, network configuration, and host function semantics that must match exactly.

- **Performance**: Replaying metadata is significantly faster than re-executing complex operations like path payments or contract calls.

## Architecture

```
                              Transaction Pipeline

    +-----------------+     +------------------+     +------------------+
    | TransactionFrame|---->| TransactionValidator|->| TransactionExecutor|
    |   (frame.rs)    |     |   (validation.rs)|    |    (apply.rs)    |
    +-----------------+     +------------------+     +------------------+
           |                        |                        |
           v                        v                        v
    +-------------+         +---------------+        +---------------+
    | - Envelope  |         | - Structure   |        | - Historical  |
    | - Hash      |         | - Signatures  |        |   Replay      |
    | - Resources |         | - Time/Ledger |        | - State       |
    | - Detection |         |   Bounds      |        |   Changes     |
    +-------------+         +---------------+        +---------------+
                                                            |
                                                            v
                            +--------------------------------------+
                            |       LedgerStateManager             |
                            |       (state.rs)                     |
                            |                                      |
                            |  In-memory entries + snapshots       |
                            |  Per-operation Savepoint rollback    |
                            +------------------+-------------------+
                                               |
                                               v
                            +--------------------------------------+
                            |           LedgerDelta                |
                            | (Accumulates state changes)          |
                            |                                      |
                            | - Creates (new entries)              |
                            | - Updates (modified entries)         |
                            | - Deletes (removed entries)          |
                            | - Change ordering for metadata       |
                            +--------------------------------------+
                                               |
                                               v
                                        To Bucket List
```

### Module Structure

```
henyey-tx/
├── src/
│   ├── lib.rs              # Public API, re-exports, high-level types
│   ├── frame.rs            # TransactionFrame - envelope wrapper
│   ├── apply.rs            # Historical transaction application (catchup mode)
│   ├── live_execution.rs   # Live transaction execution (validator mode)
│   ├── validation.rs       # Transaction validation logic
│   ├── result.rs           # Result type wrappers (TxApplyResult, etc.)
│   ├── error.rs            # Error types (TxError, etc.)
│   ├── state.rs            # LedgerStateManager - in-memory state
│   ├── events.rs           # Classic SAC event emission
│   ├── lumen_reconciler.rs # XLM balance reconciliation for events
│   ├── meta_builder.rs     # Transaction metadata construction
│   ├── fee_bump.rs         # Fee bump transaction handling
│   ├── signature_checker.rs # Multi-sig threshold checking
│   ├── operations/
│   │   ├── mod.rs          # Operation types and validation
│   │   └── execute/        # Per-operation execution implementations
│   └── soroban/
│       ├── mod.rs          # Soroban module entry point
│       ├── host.rs         # Host function execution via e2e_invoke
│       ├── budget.rs       # Resource budget tracking
│       ├── storage.rs      # Contract storage interface
│       ├── events.rs       # Contract event handling
│       ├── error.rs        # Protocol version error conversion
│       └── protocol/       # Protocol-versioned host implementations
```

## Key Types

### Transaction Processing

#### `TransactionFrame`

Wrapper around XDR `TransactionEnvelope` providing a unified API regardless of envelope version:

```rust
use henyey_tx::TransactionFrame;
use henyey_common::NetworkId;

let frame = TransactionFrame::new(envelope);

// Access properties uniformly
println!("Fee: {} stroops", frame.fee());
println!("Operations: {}", frame.operation_count());
println!("Is Soroban: {}", frame.is_soroban());

// Compute network-bound hash
let hash = frame.hash(&NetworkId::testnet())?;
```

Handles:
- V0 transactions (legacy with raw Ed25519 public key)
- V1 transactions (modern with MuxedAccount support)
- Fee bump transactions (wrapper with higher fee)

#### `TransactionValidator`

High-level validator for transaction envelopes:

```rust
use henyey_tx::{TransactionValidator, ValidationResult};

let validator = TransactionValidator::testnet(ledger_seq, close_time);

match validator.validate(&envelope) {
    ValidationResult::Valid => { /* proceed */ }
    ValidationResult::TooLate => { /* transaction expired */ }
    ValidationResult::InsufficientFee => { /* fee too low */ }
    _ => { /* other failure */ }
}
```

#### `TransactionExecutor`

Executor for applying transactions:

```rust
use henyey_tx::{TransactionExecutor, ApplyContext, LedgerDelta};

let executor = TransactionExecutor::new(context);

// For catchup mode (recommended)
let result = executor.apply_historical(&envelope, &tx_result, &tx_meta, &mut delta)?;
```

### Ledger State

#### `LedgerDelta`

Accumulates all state changes during transaction execution:

```rust
use henyey_tx::LedgerDelta;

let mut delta = LedgerDelta::new(ledger_seq);

// After applying transactions:
for entry in delta.created_entries() {
    bucket_list.add(entry)?;
}
for entry in delta.updated_entries() {
    bucket_list.update(entry)?;
}
for key in delta.deleted_keys() {
    bucket_list.delete(key)?;
}
```

The delta preserves change ordering through `ChangeRef`, which is critical for correct transaction metadata construction:

```
Transaction Meta Structure:
+---------------------------+
| tx_changes_before         |  <- Fee deduction, sequence bump
+---------------------------+
| operation[0].changes      |  <- First operation's state changes
| operation[1].changes      |  <- Second operation's state changes
| ...                       |
+---------------------------+
| tx_changes_after          |  <- Post-operation adjustments
+---------------------------+
```

#### `LedgerStateManager`

In-memory ledger state for transaction execution:

```rust
use henyey_tx::LedgerStateManager;

let state = LedgerStateManager::new();

// Load accounts from bucket list
state.load_account(&account_id)?;

// Query state
if let Some(account) = state.get_account(&account_id) {
    println!("Balance: {}", account.balance);
}
```

Features:
- **Savepoint-based rollback**: Lightweight state checkpoints (`Savepoint`) that can undo all entry types on failure (see [Savepoint Architecture](#savepoint-architecture) below)
- Per-operation savepoints for automatic rollback of failed operations
- Speculative orderbook exchange savepoints (path payments)
- Multi-operation transaction tracking
- Sponsorship stack management
- Minimum balance calculations
- BTreeMap-based offer index for O(log n) best-offer lookups

#### `LedgerContext`

Provides ledger-level context needed for validation and execution:

```rust
use henyey_tx::LedgerContext;

let context = LedgerContext {
    sequence: 12345678,
    close_time: 1625000000,
    protocol_version: 21,
    network_id: NetworkId::mainnet(),
    base_fee: 100,
    base_reserve: 5000000,
    // ... other fields
};
```

### Results

#### `TxApplyResult`

Complete result of applying a transaction:

```rust
let result = apply_from_history(&frame, &tx_result, &meta, &mut delta)?;

if result.success {
    println!("Fee charged: {} stroops", result.fee_charged);
    // Access detailed results via result.result (TxResultWrapper)
}
```

#### `ValidationError`

Detailed validation failure information:

```rust
use henyey_tx::ValidationError;

match validate_full(&frame, &context, &account) {
    Ok(()) => { /* valid */ }
    Err(errors) => {
        for error in errors {
            match error {
                ValidationError::TooLate { max_time, close_time } => {
                    println!("Expired at {}, ledger close at {}", max_time, close_time);
                }
                // ... handle other errors
            }
        }
    }
}
```

## Supported Operations

### Classic Operations

| Category | Operations | Notes |
|----------|-----------|-------|
| **Account** | `CreateAccount`, `AccountMerge`, `SetOptions`, `BumpSequence` | Core account management |
| **Payments** | `Payment`, `PathPaymentStrictReceive`, `PathPaymentStrictSend` | Asset transfers with optional path finding |
| **DEX** | `ManageSellOffer`, `ManageBuyOffer`, `CreatePassiveSellOffer` | Decentralized exchange operations |
| **Trust** | `ChangeTrust`, `AllowTrust`, `SetTrustLineFlags` | Trustline management |
| **Data** | `ManageData` | Account data entries (64 byte values) |
| **Claimable Balances** | `CreateClaimableBalance`, `ClaimClaimableBalance` | Conditional balance claims |
| **Sponsorship** | `BeginSponsoringFutureReserves`, `EndSponsoringFutureReserves`, `RevokeSponsorship` | Reserve sponsorship |
| **Clawback** | `Clawback`, `ClawbackClaimableBalance` | Asset issuer clawback |
| **Liquidity Pools** | `LiquidityPoolDeposit`, `LiquidityPoolWithdraw` | AMM operations |
| **Deprecated** | `Inflation` | No longer functional |

### Soroban Operations

| Operation | Description |
|-----------|-------------|
| `InvokeHostFunction` | Execute contract functions with full state access |
| `ExtendFootprintTtl` | Extend the time-to-live of contract state entries |
| `RestoreFootprint` | Restore archived contract state from the hot archive |

## Soroban Integration

### Architecture

Soroban execution follows this pipeline:

```
Transaction with InvokeHostFunction
           |
           v
+---------------------+
| Footprint Validation |  <- Verify declared read/write keys
+---------------------+
           |
           v
+---------------------+
| Build Storage Map    |  <- Load entries from bucket list
+---------------------+
           |
           v
+---------------------+
| Execute via e2e_invoke |  <- soroban-env-host execution
+---------------------+
           |
           v
+---------------------+
| Collect Changes      |  <- Storage changes, events, fees
+---------------------+
           |
           v
Apply to LedgerDelta
```

### Protocol Versioning

The crate uses protocol-versioned `soroban-env-host` implementations to ensure deterministic replay:

| Protocol | soroban-env-host Version | Notes |
|----------|-------------------------|-------|
| 24       | `soroban-env-host-p24`  | Initial Soroban support |
| 25+      | `soroban-env-host-p25`  | Current version |

This versioning is critical because:
- Host function semantics may change between versions
- Cost model parameters differ per protocol
- PRNG behavior must match exactly for determinism

### Key Components

- **`SorobanConfig`**: Network configuration including cost parameters, TTL limits, and fee configuration. Loaded from `ConfigSettingEntry` entries.

- **`SorobanBudget`**: Tracks resource consumption (CPU, memory, I/O) against declared limits.

- **`SorobanStorage`**: Provides the storage interface for contract state, tracking reads and writes during execution.

- **`execute_host_function`**: Main entry point that dispatches to the correct protocol-versioned host.

### Entry TTL and Archival

Soroban entries (ContractData, ContractCode) have time-to-live (TTL) values:

- **Temporary entries**: Short-lived, cheaper storage. Automatically deleted when TTL expires.

- **Persistent entries**: Long-lived storage. When TTL expires, entries move to the "hot archive" and can be restored via `RestoreFootprint`.

The storage adapter checks TTL values and excludes expired entries from the snapshot, matching stellar-core behavior.

## Classic Events (SAC Events)

Starting with Protocol 23, classic operations emit SEP-0041 compatible events for asset movements:

| Event | Description | Operations |
|-------|-------------|------------|
| `transfer` | Asset moved between non-issuer accounts | Payment, PathPayment, AccountMerge |
| `mint` | Asset issued from the issuer | Payment from issuer |
| `burn` | Asset returned to the issuer | Payment to issuer |
| `clawback` | Asset forcibly clawed back | Clawback |
| `set_authorized` | Authorization status changed | SetTrustLineFlags, AllowTrust |
| `fee` | Transaction fee payment | All transactions |

### Event Backfilling

Events can be backfilled for pre-Protocol 23 ledgers:

```rust
use henyey_tx::{TxEventManager, ClassicEventConfig};

let config = ClassicEventConfig {
    emit_events: true,
    emit_diagnostic_events: false,
    backfill_mode: true,  // For pre-P23 ledgers
};

let mut event_manager = TxEventManager::new(config, ledger_seq);
// ... apply operations
let events = event_manager.build_events()?;
```

## Usage Examples

### Live Execution Mode

Live execution mode is used by validators to process transactions and close ledgers:

```rust
use henyey_tx::{
    TransactionFrame, LiveExecutionContext, LedgerContext, LedgerStateManager,
    process_fee_seq_num, process_post_apply, process_post_tx_set_apply,
};

// Set up execution context with ledger state
let ledger_ctx = LedgerContext::new(
    ledger_seq,
    close_time,
    base_fee,
    base_reserve,
    protocol_version,
    network_id,
);
let state = LedgerStateManager::new(base_reserve, ledger_seq);
let mut ctx = LiveExecutionContext::new(ledger_ctx, state);

// Phase 1: Process fees and sequence numbers for all transactions
let mut results = Vec::new();
for frame in &transaction_set {
    let fee_result = process_fee_seq_num(frame, &mut ctx, None)?;
    results.push((frame, fee_result));
}

// Phase 2: Apply operations for each transaction
for (frame, fee_result) in &mut results {
    if !fee_result.should_apply {
        continue; // Skip failed transactions
    }

    // Apply operations (operation execution code)
    // ... apply_operations(frame, &mut ctx, &mut fee_result.tx_result)?;

    // Phase 3: Post-apply processing (pre-P23 Soroban refunds)
    process_post_apply(frame, &mut ctx, &mut fee_result.tx_result, None)?;
}

// Phase 4: Transaction set post-apply (P23+ Soroban refunds)
for (frame, fee_result) in &mut results {
    process_post_tx_set_apply(frame, &mut ctx, &mut fee_result.tx_result, None)?;
}

// Collect fee pool delta and finalize
println!("Total fees collected: {}", ctx.fee_pool_delta());
```

### Catchup/Replay Mode

```rust
use henyey_tx::{TransactionFrame, apply_from_history, LedgerDelta};
use stellar_xdr::curr::{TransactionEnvelope, TransactionResult, TransactionMeta};

// Parse transaction from archive
let envelope: TransactionEnvelope = /* from archive */;
let result: TransactionResult = /* from archive */;
let meta: TransactionMeta = /* from archive */;

// Create frame wrapper
let frame = TransactionFrame::new(envelope);

// Apply historical transaction to accumulate state changes
let mut delta = LedgerDelta::new(ledger_seq);
let apply_result = apply_from_history(&frame, &result, &meta, &mut delta)?;

// Delta now contains all state changes in execution order
for entry in delta.created_entries() {
    bucket_list.add(entry)?;
}
for entry in delta.updated_entries() {
    bucket_list.update(entry)?;
}
for key in delta.deleted_keys() {
    bucket_list.delete(key)?;
}
```

### Transaction Validation

```rust
use henyey_tx::{TransactionValidator, ValidationResult};

// Create validator for testnet
let validator = TransactionValidator::testnet(ledger_seq, close_time);

// Basic validation (structure, bounds)
match validator.validate(&envelope) {
    ValidationResult::Valid => println!("Transaction is valid"),
    ValidationResult::InsufficientFee => println!("Fee too low"),
    ValidationResult::TooLate => println!("Transaction expired"),
    other => println!("Validation failed: {:?}", other),
}

// Full validation with account data
let result = validator.validate_with_account(&envelope, &source_account);
```

### Processing a Transaction Set

```rust
use henyey_tx::apply_transaction_set_from_history;

// Apply entire transaction set from historical ledger
let ledger_changes = apply_transaction_set_from_history(
    &tx_set,
    &results,
    &metas,
    ledger_seq,
    &state,
)?;
```

## Design Notes

### Savepoint Architecture

The crate provides a `Savepoint` mechanism for lightweight, granular rollback of
state changes. This is the Rust equivalent of stellar-core's nested `LedgerTxn`
commit/rollback pattern.

```
                     Savepoint / Rollback Flow

  +-----------------------+
  | LedgerStateManager    |
  |                       |       create_savepoint()
  |  accounts             | ─────────────────────────────> +------------------+
  |  trustlines           |                                |    Savepoint     |
  |  offers               |                                |                  |
  |  data_entries         |       rollback_to_savepoint()  | - snapshot maps  |
  |  contract_data        | <───────────────────────────── | - pre-values     |
  |  contract_code        |                                | - created sets   |
  |  ttl_entries          |         (on failure)           | - delta lengths  |
  |  claimable_balances   |                                | - modified lens  |
  |  liquidity_pools      |                                | - metadata state |
  |  ...                  |                                | - id_pool        |
  +-----------+-----------+                                +------------------+
              |
              | flush_modified_entries()
              v
  +-----------------------+
  |     LedgerDelta       |  (output change log)
  |                       |
  |  - created entries    |  Savepoint rollback also
  |  - updated entries    |  truncates the delta back
  |  - deleted entries    |  to its pre-savepoint lengths.
  |  - restored entries   |
  +-----------------------+
              |
              v
       To Bucket List /
       Transaction Meta
```

**Key concepts:**

- **Savepoint**: A lightweight state checkpoint that captures the current values of all
  entry types (accounts, trustlines, offers, data, contract_data, contract_code, TTL,
  claimable_balances, liquidity_pools), along with metadata tracking, delta vector lengths,
  modified tracking vec lengths, created entry sets, and the id_pool. Creating a savepoint
  is O(k) where k is the number of entries modified so far in the current transaction.

- **Per-operation rollback**: Each operation in a multi-operation transaction gets a
  savepoint before execution (in the `henyey-ledger` execution loop). If the
  operation fails, `rollback_to_savepoint()` undoes all state changes so subsequent
  operations see clean state. This matches stellar-core's nested `LedgerTxn`
  behavior where each operation runs in a child transaction that is committed on
  success or rolled back on failure.

- **Speculative orderbook exchange**: Path payment operations use savepoints when
  comparing orderbook vs. liquidity pool routes. The orderbook path is executed
  speculatively on the real state; if the pool provides a better rate, the savepoint
  rolls back the speculative orderbook changes. This avoids cloning the entire state
  (which would be O(n) for 911K+ offers).

- **LedgerDelta vs Savepoint**: `LedgerDelta` is the output change log that records
  creates, updates, and deletes for transaction metadata and bucket list updates.
  `Savepoint` is the internal undo mechanism. They interact because savepoint rollback
  also truncates the delta's vectors back to their pre-savepoint lengths, ensuring no
  stale entries from failed operations appear in the final output.

- **Three-phase rollback** (`rollback_to_savepoint`):
  1. **Phase 1 -- Restore newly snapshot'd entries**: Entries that were first touched
     after the savepoint have their snapshot values restored (these snapshots hold the
     pre-TX bucket list values).
  2. **Phase 2 -- Restore pre-savepoint entries**: Entries that were already in the
     snapshot map at savepoint creation time are restored to their pre-savepoint
     current values (captured in the savepoint's `*_pre_values` vecs).
  3. **Phase 3 -- Restore tracking state**: Snapshot maps, created entry sets,
     modified vec lengths, entry metadata (last_modified, sponsorships), delta vector
     lengths, op_entry_snapshots, and id_pool are all restored to their savepoint values.

- **No manual rollback in operations**: Individual operation implementations (e.g.,
  `claimable_balance.rs`, `payment.rs`, `change_trust.rs`) do not contain manual
  rollback code. All rollback is handled automatically by the per-operation savepoint
  in the execution loop.

### State Management Philosophy

The crate separates state reading (via `LedgerReader` trait) from state modification (via `LedgerDelta`). This allows:

1. **Lazy loading**: State is loaded on-demand from the bucket list
2. **Atomic updates**: All changes are accumulated then applied together
3. **Savepoint rollback**: Failed operations are automatically rolled back via per-operation savepoints, matching stellar-core's nested `LedgerTxn` pattern (see [Savepoint Architecture](#savepoint-architecture) above)

### Delta Tracking

`LedgerDelta` records all state changes in execution order, preserving:

- Pre-state for updates and deletes (for building proper transaction metadata)
- Change ordering via `ChangeRef` enum
- Fee accumulation
- Soroban-specific changes (TTL updates, events)

### Error Handling

The crate uses a layered error approach:

1. **`TxError`**: Top-level errors for transaction processing
2. **`ValidationError`**: Specific validation failures with context
3. **`OperationValidationError`**: Per-operation validation errors

## stellar-core Mapping

This crate corresponds to the following stellar-core components:

| Rust Module | stellar-core Component |
|------------|---------------|
| `frame.rs` | `src/transactions/TransactionFrame.cpp` |
| `live_execution.rs` | `src/transactions/TransactionFrame.cpp` (processFeeSeqNum, processPostApply, etc.) |
| `validation.rs` | `src/transactions/TransactionUtils.cpp` |
| `apply.rs` | `src/ledger/LedgerTxn.cpp` |
| `state.rs` | `src/ledger/LedgerStateSnapshot.cpp`, `src/ledger/LedgerTxn.cpp` (nested commit/rollback via Savepoint) |
| `meta_builder.rs` | `src/transactions/TransactionMetaBuilder.cpp` |
| `fee_bump.rs` | `src/transactions/FeeBumpTransactionFrame.cpp` |
| `signature_checker.rs` | `src/transactions/SignatureChecker.cpp` |
| `events.rs` | `src/transactions/EventManager.cpp` |
| `lumen_reconciler.rs` | `src/transactions/LumenEventReconciler.cpp` |
| `operations/` | `src/transactions/OperationFrame.cpp`, `src/transactions/*OpFrame.cpp` |
| `soroban/` | `src/transactions/InvokeHostFunctionOpFrame.cpp` |

## Testing

Integration tests should cover:

- Per-operation edge cases (offers, trustlines, claimable balances)
- Soroban footprint and resource limit scenarios
- Transaction metadata hash verification against stellar-core
- Multi-operation transaction rollback behavior
- Fee bump transaction handling
- Sponsorship chains
- Classic event emission correctness

## stellar-core Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed stellar-core parity analysis.

## License

Same as the parent henyey project.
