# stellar-core-tx

Transaction validation and execution for rs-stellar-core.

## Overview

This crate provides the core transaction processing logic for the Stellar network, supporting both classic Stellar operations and Soroban smart contract execution. It is the heart of ledger state changes in rs-stellar-core.

### Operating Modes

The crate supports two primary modes of operation:

1. **Catchup/Replay Mode**: Applies historical transactions from archives by trusting the recorded results and replaying state changes. This is the primary use case for rs-stellar-core today.

2. **Live Execution Mode**: Validates and executes transactions in real-time, producing deterministic results that match C++ stellar-core. This enables future validator functionality.

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
stellar-core-tx/
├── src/
│   ├── lib.rs              # Public API, re-exports, high-level types
│   ├── frame.rs            # TransactionFrame - envelope wrapper
│   ├── apply.rs            # Historical transaction application
│   ├── validation.rs       # Transaction validation logic
│   ├── result.rs           # Result type wrappers (TxApplyResult, etc.)
│   ├── error.rs            # Error types (TxError, etc.)
│   ├── state.rs            # LedgerStateManager - in-memory state
│   ├── events.rs           # Classic SAC event emission
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
use stellar_core_tx::TransactionFrame;
use stellar_core_common::NetworkId;

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
use stellar_core_tx::{TransactionValidator, ValidationResult};

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
use stellar_core_tx::{TransactionExecutor, ApplyContext, LedgerDelta};

let executor = TransactionExecutor::new(context);

// For catchup mode (recommended)
let result = executor.apply_historical(&envelope, &tx_result, &tx_meta, &mut delta)?;
```

### Ledger State

#### `LedgerDelta`

Accumulates all state changes during transaction execution:

```rust
use stellar_core_tx::LedgerDelta;

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
use stellar_core_tx::LedgerStateManager;

let state = LedgerStateManager::new();

// Load accounts from bucket list
state.load_account(&account_id)?;

// Query state
if let Some(account) = state.get_account(&account_id) {
    println!("Balance: {}", account.balance);
}
```

Features:
- Per-operation snapshots for rollback on failure
- Multi-operation transaction tracking
- Sponsorship stack management
- Minimum balance calculations

#### `LedgerContext`

Provides ledger-level context needed for validation and execution:

```rust
use stellar_core_tx::LedgerContext;

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
use stellar_core_tx::ValidationError;

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

The storage adapter checks TTL values and excludes expired entries from the snapshot, matching C++ stellar-core behavior.

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
use stellar_core_tx::{TxEventManager, ClassicEventConfig};

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

### Catchup/Replay Mode

```rust
use stellar_core_tx::{TransactionFrame, apply_from_history, LedgerDelta};
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
use stellar_core_tx::{TransactionValidator, ValidationResult};

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
use stellar_core_tx::apply_transaction_set_from_history;

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

### State Management Philosophy

The crate separates state reading (via `LedgerReader` trait) from state modification (via `LedgerDelta`). This allows:

1. **Lazy loading**: State is loaded on-demand from the bucket list
2. **Atomic updates**: All changes are accumulated then applied together
3. **Rollback support**: Failed operations don't corrupt state

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

## Upstream Mapping

This crate corresponds to the following C++ stellar-core components:

| Rust Module | C++ Component |
|------------|---------------|
| `frame.rs` | `src/transactions/TransactionFrame.cpp` |
| `validation.rs` | `src/transactions/TransactionUtils.cpp` |
| `apply.rs` | `src/ledger/LedgerTxn.cpp` |
| `state.rs` | `src/ledger/LedgerStateSnapshot.cpp` |
| `operations/` | `src/transactions/OperationFrame.cpp`, `src/transactions/*OpFrame.cpp` |
| `soroban/` | `src/transactions/InvokeHostFunctionOpFrame.cpp` |

## Testing

Integration tests should cover:

- Per-operation edge cases (offers, trustlines, claimable balances)
- Soroban footprint and resource limit scenarios
- Transaction metadata hash verification against C++ stellar-core
- Multi-operation transaction rollback behavior
- Fee bump transaction handling
- Sponsorship chains
- Classic event emission correctness

## License

Same as the parent rs-stellar-core project.
