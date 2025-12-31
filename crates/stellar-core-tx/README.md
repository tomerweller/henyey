# stellar-core-tx

Transaction processing for rs-stellar-core.

## Overview

This crate handles transaction validation and execution, including:

- Transaction validation (signatures, fees, sequence numbers)
- Operation execution (all Stellar operation types)
- Soroban smart contract execution
- Transaction result generation

## Workflow

For catchup/sync mode:

1. Parse transactions from history archives
2. Create `TransactionFrame` wrappers for each transaction
3. Apply the known results using `apply_from_history`
4. State changes are recorded in `LedgerDelta`

## Classic Operations

| Operation | Description |
|-----------|-------------|
| CreateAccount | Create a new account |
| Payment | Send XLM or assets |
| PathPayment | Cross-asset payment |
| ManageSellOffer | Create/modify sell offer |
| ManageBuyOffer | Create/modify buy offer |
| CreatePassiveSellOffer | Create passive sell offer |
| SetOptions | Modify account options |
| ChangeTrust | Create/modify trustline |
| AllowTrust | Authorize trustline |
| AccountMerge | Merge accounts |
| ManageData | Set account data |
| BumpSequence | Increase sequence number |
| CreateClaimableBalance | Create claimable balance |
| ClaimClaimableBalance | Claim a balance |
| BeginSponsoringFutureReserves | Start sponsorship |
| EndSponsoringFutureReserves | End sponsorship |
| RevokeSponsorship | Revoke sponsorship |
| Clawback | Asset clawback |
| SetTrustLineFlags | Modify trustline flags |
| LiquidityPoolDeposit | Deposit to AMM |
| LiquidityPoolWithdraw | Withdraw from AMM |

## Soroban Operations

| Operation | Description |
|-----------|-------------|
| InvokeHostFunction | Smart contract execution |
| ExtendFootprintTtl | Extend state TTL |
| RestoreFootprint | Restore archived state |

## Usage

### Transaction Frame

```rust
use stellar_core_tx::TransactionFrame;

let frame = TransactionFrame::new(envelope);

// Get transaction properties
let ops = frame.operation_count();
let fee = frame.fee();
let seq = frame.sequence_number();
let is_soroban = frame.is_soroban();
let is_fee_bump = frame.is_fee_bump();

// Get source account
let source = frame.source_account();
```

### Validation

```rust
use stellar_core_tx::{TransactionValidator, ValidationResult};

let validator = TransactionValidator::testnet(ledger_seq, close_time);

// Basic validation
let result = validator.validate(&envelope);
match result {
    ValidationResult::Valid => { /* OK */ }
    ValidationResult::InvalidSignature => { /* Bad sig */ }
    ValidationResult::InsufficientFee => { /* Fee too low */ }
    ValidationResult::BadSequence => { /* Wrong seq */ }
    _ => { /* Other error */ }
}

// Full validation with account
let result = validator.validate_with_account(&envelope, &account);
```

### Applying from History

```rust
use stellar_core_tx::{apply_from_history, LedgerDelta, TransactionFrame};

let frame = TransactionFrame::new(envelope);
let mut delta = LedgerDelta::new(ledger_seq);

let result = apply_from_history(&frame, &tx_result, &tx_meta, &mut delta)?;

// Delta now contains all state changes
for entry in delta.created_entries() {
    // Process created entries
}
```

### Ledger Delta

```rust
use stellar_core_tx::LedgerDelta;

let mut delta = LedgerDelta::new(ledger_seq);

// Check ledger sequence
assert_eq!(delta.ledger_seq(), 100);

// Track fees
delta.add_fee(500);
assert_eq!(delta.fee_charged(), 500);

// Check for changes
assert!(!delta.has_changes());
```

### Ledger State Manager

```rust
use stellar_core_tx::LedgerStateManager;

let mut state = LedgerStateManager::new(base_reserve, max_tx_set_size);

// Query state
let account = state.get_account(&account_id);
let trustline = state.get_trustline(&account_id, &asset);

// Modify state
state.create_account(account_entry);
state.update_account(&account_id, |acc| {
    acc.balance += 1000;
});
```

## Key Types

### TransactionFrame

Wraps a transaction envelope:

```rust
let frame = TransactionFrame::new(envelope);

// Access inner transaction
let tx = frame.transaction();
let ops = frame.operations();
```

### TxApplyResult

Result of applying a transaction:

```rust
let result = apply_from_history(&frame, &result, &meta, &mut delta)?;

println!("Fee charged: {}", result.fee_charged);
println!("Success: {}", result.success);
```

### ValidationError

Validation error types:

```rust
match err {
    ValidationError::InvalidStructure(_) => { /* Malformed */ }
    ValidationError::InvalidSignature => { /* Bad sig */ }
    ValidationError::MissingSignatures => { /* Need more sigs */ }
    ValidationError::BadSequence { .. } => { /* Wrong seq */ }
    ValidationError::InsufficientFee { .. } => { /* Low fee */ }
    ValidationError::TooLate { .. } => { /* Expired */ }
    ValidationError::TooEarly { .. } => { /* Not yet valid */ }
    _ => {}
}
```

### LedgerContext

Context for validation and execution:

```rust
use stellar_core_tx::LedgerContext;

// Create for testnet
let ctx = LedgerContext::testnet(ledger_seq, close_time);

// Create for mainnet
let ctx = LedgerContext::mainnet(ledger_seq, close_time);

// Access properties
let network_id = ctx.network_id();
let seq = ctx.ledger_seq();
```

## Operation Types

```rust
use stellar_core_tx::OperationType;

let op_type = OperationType::Payment;

// Check operation category
assert!(!op_type.is_soroban());
assert_eq!(op_type.name(), "Payment");

// Soroban operations
let op_type = OperationType::InvokeHostFunction;
assert!(op_type.is_soroban());
```

## Soroban Execution

```rust
use stellar_core_tx::soroban;

// Execute a Soroban host function
let result = soroban::execute_host_function(
    &host_function,
    &auth_entries,
    &source,
    &state,
    &context,
    &soroban_data,
)?;
```

## Signature Verification

```rust
use stellar_core_tx::{validate_signatures, verify_signature_with_key};

// Validate all signatures
validate_signatures(&frame, &context)?;

// Verify a single signature
let valid = verify_signature_with_key(&frame, &public_key, &signature)?;
```

## Dependencies

- `stellar-xdr` - Transaction types
- `soroban-env-host` - Smart contract execution
- `stellar-core-crypto` - Signature verification
- `sha2` - Transaction hashing

## License

Apache 2.0
