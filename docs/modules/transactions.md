# Transactions Module Specification

**Crate**: `stellar-core-tx`
**stellar-core mapping**: `src/transactions/`

## 1. Overview

The transactions module handles:
- Transaction validation (signatures, sequence numbers, fees)
- Operation execution (both classic and Soroban)
- Result generation
- Fee processing

## 2. stellar-core Reference

In stellar-core, the transactions module (`src/transactions/`) contains:
- `TransactionFrame.h/cpp` - Transaction wrapper
- `TransactionUtils.h/cpp` - Utilities
- `FeeBumpTransactionFrame.h/cpp` - Fee bump handling
- `InvokeHostFunctionOpFrame.h/cpp` - Soroban invocation
- `MutableTransactionResult.h/cpp` - Result building
- Individual operation files (`*OpFrame.h/cpp`)

### 2.1 Operation Types

Classic operations:
- CreateAccount, Payment, PathPaymentStrictReceive, PathPaymentStrictSend
- ManageSellOffer, ManageBuyOffer, CreatePassiveSellOffer
- SetOptions, ChangeTrust, AllowTrust
- AccountMerge, Inflation (deprecated), ManageData
- BumpSequence, CreateClaimableBalance, ClaimClaimableBalance
- BeginSponsoringFutureReserves, EndSponsoringFutureReserves
- RevokeSponsorship, Clawback, ClawbackClaimableBalance
- SetTrustLineFlags, LiquidityPoolDeposit, LiquidityPoolWithdraw

Soroban operations:
- InvokeHostFunction
- ExtendFootprintTTL
- RestoreFootprint

## 3. Rust Implementation

### 3.1 Dependencies

```toml
[dependencies]
stellar-xdr = { version = "25.0.0", features = ["std", "curr"] }
stellar-core-crypto = { path = "../stellar-core-crypto" }
stellar-core-ledger = { path = "../stellar-core-ledger" }

# Soroban host for smart contract execution
soroban-env-host = "23"
soroban-env-common = "23"

# Utilities
thiserror = "1"
tracing = "0.1"
num-traits = "0.2"
num-bigint = "0.4"
```

### 3.2 Module Structure

```
stellar-core-tx/
├── src/
│   ├── lib.rs
│   ├── transaction.rs         # Transaction wrapper
│   ├── fee_bump.rs            # Fee bump transactions
│   ├── validation.rs          # Validation logic
│   ├── processor.rs           # Transaction processor
│   ├── result.rs              # Result types
│   ├── fees.rs                # Fee calculation
│   ├── operations/
│   │   ├── mod.rs
│   │   ├── create_account.rs
│   │   ├── payment.rs
│   │   ├── path_payment.rs
│   │   ├── manage_offer.rs
│   │   ├── set_options.rs
│   │   ├── change_trust.rs
│   │   ├── account_merge.rs
│   │   ├── manage_data.rs
│   │   ├── bump_sequence.rs
│   │   ├── claimable_balance.rs
│   │   ├── sponsorship.rs
│   │   ├── clawback.rs
│   │   ├── liquidity_pool.rs
│   │   └── soroban.rs         # Soroban operations
│   └── error.rs
└── tests/
```

### 3.3 Core Types

#### TransactionFrame

```rust
use stellar_xdr::curr::{
    TransactionEnvelope, Transaction, TransactionV1Envelope,
    FeeBumpTransactionEnvelope, Operation, OperationResult,
    TransactionResult, TransactionResultCode,
};

/// Wrapper around a transaction envelope with validation state
pub struct TransactionFrame {
    envelope: TransactionEnvelope,
    /// Cached hash
    hash: Hash256,
    /// Fee to charge (may differ from envelope for fee bumps)
    fee: i64,
    /// Source account
    source_account: AccountId,
    /// Operations
    operations: Vec<Operation>,
}

impl TransactionFrame {
    pub fn from_envelope(
        envelope: TransactionEnvelope,
        network_passphrase: &str,
    ) -> Result<Self, TransactionError> {
        let hash = compute_tx_hash(&envelope, network_passphrase)?;

        let (source_account, fee, operations) = match &envelope {
            TransactionEnvelope::TxV0(e) => {
                (e.tx.source_account_ed25519.clone().into(), e.tx.fee as i64, e.tx.operations.to_vec())
            }
            TransactionEnvelope::Tx(e) => {
                (e.tx.source_account.clone().into(), e.tx.fee as i64, e.tx.operations.to_vec())
            }
            TransactionEnvelope::TxFeeBump(e) => {
                // Fee bump wraps inner transaction
                let inner = &e.tx.inner_tx;
                match inner {
                    FeeBumpTransactionInnerTx::Tx(inner_env) => {
                        (inner_env.tx.source_account.clone().into(), e.tx.fee as i64, inner_env.tx.operations.to_vec())
                    }
                }
            }
        };

        Ok(Self {
            envelope,
            hash,
            fee,
            source_account,
            operations,
        })
    }

    pub fn hash(&self) -> &Hash256 {
        &self.hash
    }

    pub fn fee(&self) -> i64 {
        self.fee
    }

    pub fn source_account(&self) -> &AccountId {
        &self.source_account
    }

    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    pub fn sequence_number(&self) -> i64 {
        match &self.envelope {
            TransactionEnvelope::TxV0(e) => e.tx.seq_num.0,
            TransactionEnvelope::Tx(e) => e.tx.seq_num.0,
            TransactionEnvelope::TxFeeBump(e) => {
                match &e.tx.inner_tx {
                    FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.seq_num.0,
                }
            }
        }
    }

    /// Check if this is a Soroban transaction
    pub fn is_soroban(&self) -> bool {
        self.operations.iter().any(|op| {
            matches!(
                op.body,
                OperationBody::InvokeHostFunction(_) |
                OperationBody::ExtendFootprintTtl(_) |
                OperationBody::RestoreFootprint(_)
            )
        })
    }
}

fn compute_tx_hash(
    envelope: &TransactionEnvelope,
    network_passphrase: &str,
) -> Result<Hash256, TransactionError> {
    let network_id = Hash256::hash(network_passphrase.as_bytes());

    let tagged = match envelope {
        TransactionEnvelope::TxV0(e) => {
            // V0 uses network ID + ENVELOPE_TYPE_TX_V0 + tx
            let mut data = network_id.as_bytes().to_vec();
            data.extend_from_slice(&EnvelopeType::TxV0.to_xdr(stellar_xdr::Limits::none())?);
            data.extend_from_slice(&e.tx.to_xdr(stellar_xdr::Limits::none())?);
            data
        }
        TransactionEnvelope::Tx(e) => {
            let mut data = network_id.as_bytes().to_vec();
            data.extend_from_slice(&EnvelopeType::Tx.to_xdr(stellar_xdr::Limits::none())?);
            data.extend_from_slice(&e.tx.to_xdr(stellar_xdr::Limits::none())?);
            data
        }
        TransactionEnvelope::TxFeeBump(e) => {
            let mut data = network_id.as_bytes().to_vec();
            data.extend_from_slice(&EnvelopeType::TxFeeBump.to_xdr(stellar_xdr::Limits::none())?);
            data.extend_from_slice(&e.tx.to_xdr(stellar_xdr::Limits::none())?);
            data
        }
    };

    Ok(Hash256::hash(&tagged))
}
```

#### TransactionProcessor

```rust
use stellar_core_ledger::{LedgerTxn, LedgerDelta, LedgerSnapshot};

/// Processes and applies transactions
pub struct TransactionProcessor<'a> {
    delta: &'a mut LedgerDelta,
    network_passphrase: String,
    protocol_version: u32,
    soroban_host: Option<SorobanHost>,
}

impl<'a> TransactionProcessor<'a> {
    pub fn new(
        delta: &'a mut LedgerDelta,
        network_passphrase: &str,
        protocol_version: u32,
    ) -> Self {
        Self {
            delta,
            network_passphrase: network_passphrase.to_string(),
            protocol_version,
            soroban_host: None,
        }
    }

    /// Apply a transaction
    pub fn apply(&mut self, envelope: &TransactionEnvelope) -> Result<TransactionResult, TransactionError> {
        let frame = TransactionFrame::from_envelope(envelope.clone(), &self.network_passphrase)?;

        // Validate signatures
        self.validate_signatures(&frame)?;

        // Check sequence number
        self.validate_sequence(&frame)?;

        // Check fee
        self.validate_fee(&frame)?;

        // Apply operations
        let op_results = self.apply_operations(&frame)?;

        // Consume sequence number and fee
        self.consume_sequence_and_fee(&frame)?;

        Ok(TransactionResult {
            fee_charged: frame.fee(),
            result: TransactionResultResult::TxSuccess(op_results.try_into().unwrap()),
            ext: TransactionResultExt::V0,
        })
    }

    fn validate_signatures(&self, frame: &TransactionFrame) -> Result<(), TransactionError> {
        let signatures = match &frame.envelope {
            TransactionEnvelope::TxV0(e) => &e.signatures,
            TransactionEnvelope::Tx(e) => &e.signatures,
            TransactionEnvelope::TxFeeBump(e) => &e.signatures,
        };

        if signatures.is_empty() {
            return Err(TransactionError::NoSignatures);
        }

        // For each required signer, verify at least one signature matches
        let required_signers = self.get_required_signers(frame)?;

        for signer in &required_signers {
            let mut found = false;
            for sig in signatures.iter() {
                if self.verify_signature(frame.hash(), signer, sig)? {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(TransactionError::MissingSignature(signer.clone()));
            }
        }

        Ok(())
    }

    fn validate_sequence(&self, frame: &TransactionFrame) -> Result<(), TransactionError> {
        let source = frame.source_account();
        let account = self.load_account(source)?
            .ok_or_else(|| TransactionError::SourceNotFound)?;

        let expected_seq = account.seq_num.0 + 1;
        if frame.sequence_number() != expected_seq {
            return Err(TransactionError::BadSequence {
                expected: expected_seq,
                got: frame.sequence_number(),
            });
        }

        Ok(())
    }

    fn validate_fee(&self, frame: &TransactionFrame) -> Result<(), TransactionError> {
        let source = frame.source_account();
        let account = self.load_account(source)?
            .ok_or_else(|| TransactionError::SourceNotFound)?;

        if account.balance < frame.fee() {
            return Err(TransactionError::InsufficientBalance {
                required: frame.fee(),
                available: account.balance,
            });
        }

        // Check against base fee and surge pricing
        let min_fee = self.calculate_min_fee(frame)?;
        if frame.fee() < min_fee {
            return Err(TransactionError::InsufficientFee {
                required: min_fee,
                provided: frame.fee(),
            });
        }

        Ok(())
    }

    fn apply_operations(&mut self, frame: &TransactionFrame) -> Result<Vec<OperationResult>, TransactionError> {
        let mut results = Vec::new();

        for (index, op) in frame.operations().iter().enumerate() {
            let result = self.apply_operation(frame, op, index)?;
            results.push(result);
        }

        Ok(results)
    }

    fn apply_operation(
        &mut self,
        frame: &TransactionFrame,
        op: &Operation,
        index: usize,
    ) -> Result<OperationResult, TransactionError> {
        let source = op.source_account
            .as_ref()
            .unwrap_or(&frame.source_account().into());

        match &op.body {
            OperationBody::CreateAccount(op) => {
                self.apply_create_account(source, op)
            }
            OperationBody::Payment(op) => {
                self.apply_payment(source, op)
            }
            OperationBody::PathPaymentStrictReceive(op) => {
                self.apply_path_payment_strict_receive(source, op)
            }
            OperationBody::ManageSellOffer(op) => {
                self.apply_manage_sell_offer(source, op)
            }
            OperationBody::ManageBuyOffer(op) => {
                self.apply_manage_buy_offer(source, op)
            }
            OperationBody::CreatePassiveSellOffer(op) => {
                self.apply_create_passive_sell_offer(source, op)
            }
            OperationBody::SetOptions(op) => {
                self.apply_set_options(source, op)
            }
            OperationBody::ChangeTrust(op) => {
                self.apply_change_trust(source, op)
            }
            OperationBody::AllowTrust(op) => {
                self.apply_allow_trust(source, op)
            }
            OperationBody::AccountMerge(destination) => {
                self.apply_account_merge(source, destination)
            }
            OperationBody::ManageData(op) => {
                self.apply_manage_data(source, op)
            }
            OperationBody::BumpSequence(op) => {
                self.apply_bump_sequence(source, op)
            }
            OperationBody::CreateClaimableBalance(op) => {
                self.apply_create_claimable_balance(source, op)
            }
            OperationBody::ClaimClaimableBalance(op) => {
                self.apply_claim_claimable_balance(source, op)
            }
            OperationBody::LiquidityPoolDeposit(op) => {
                self.apply_liquidity_pool_deposit(source, op)
            }
            OperationBody::LiquidityPoolWithdraw(op) => {
                self.apply_liquidity_pool_withdraw(source, op)
            }
            // Soroban operations
            OperationBody::InvokeHostFunction(op) => {
                self.apply_invoke_host_function(source, op, frame)
            }
            OperationBody::ExtendFootprintTtl(op) => {
                self.apply_extend_footprint_ttl(source, op, frame)
            }
            OperationBody::RestoreFootprint(op) => {
                self.apply_restore_footprint(source, op, frame)
            }
            _ => {
                Err(TransactionError::UnsupportedOperation)
            }
        }
    }

    fn consume_sequence_and_fee(&mut self, frame: &TransactionFrame) -> Result<(), TransactionError> {
        let source = frame.source_account();

        // Update sequence number
        let mut account = self.load_account_mut(source)?
            .ok_or_else(|| TransactionError::SourceNotFound)?;

        account.seq_num.0 += 1;
        account.balance -= frame.fee();

        self.delta.add_fee(frame.fee());

        Ok(())
    }
}
```

### 3.4 Classic Operations

#### Payment

```rust
impl<'a> TransactionProcessor<'a> {
    pub fn apply_payment(
        &mut self,
        source: &MuxedAccount,
        op: &PaymentOp,
    ) -> Result<OperationResult, TransactionError> {
        let source_id = muxed_to_account_id(source)?;
        let dest_id = muxed_to_account_id(&op.destination)?;

        // Load source account
        let mut source_account = self.load_account_mut(&source_id)?
            .ok_or(TransactionError::SourceNotFound)?;

        // Load or create destination account (for native asset)
        let mut dest_account = self.load_account_mut(&dest_id)?;

        match &op.asset {
            Asset::Native => {
                let dest = dest_account.as_mut()
                    .ok_or(TransactionError::DestinationNotFound)?;

                // Check source balance
                if source_account.balance < op.amount {
                    return Err(TransactionError::Underfunded);
                }

                // Transfer
                source_account.balance -= op.amount;
                dest.balance += op.amount;

                Ok(OperationResult {
                    code: OperationResultCode::OpInner,
                    tr: Some(OperationResultTr::Payment(PaymentResult::PaymentSuccess)),
                })
            }
            Asset::CreditAlphanum4(asset) | Asset::CreditAlphanum12(asset) => {
                // Load trustlines and transfer
                self.transfer_credit_asset(&source_id, &dest_id, &op.asset, op.amount)
            }
        }
    }
}
```

#### Create Account

```rust
impl<'a> TransactionProcessor<'a> {
    pub fn apply_create_account(
        &mut self,
        source: &MuxedAccount,
        op: &CreateAccountOp,
    ) -> Result<OperationResult, TransactionError> {
        let source_id = muxed_to_account_id(source)?;

        // Check if destination already exists
        if self.load_account(&op.destination)?.is_some() {
            return Err(TransactionError::AccountExists);
        }

        // Check starting balance meets minimum reserve
        let min_balance = self.calculate_min_balance(1)?; // 1 sub-entry for the account itself
        if op.starting_balance < min_balance {
            return Err(TransactionError::LowReserve);
        }

        // Debit source
        let mut source_account = self.load_account_mut(&source_id)?
            .ok_or(TransactionError::SourceNotFound)?;

        if source_account.balance < op.starting_balance {
            return Err(TransactionError::Underfunded);
        }

        source_account.balance -= op.starting_balance;

        // Create new account
        let new_account = AccountEntry {
            account_id: op.destination.clone(),
            balance: op.starting_balance,
            seq_num: SequenceNumber(0),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]), // Master weight 1, thresholds 0
            signers: Vec::new().try_into().unwrap(),
            ext: AccountEntryExt::V0,
        };

        self.delta.record_create(LedgerEntry {
            last_modified_ledger_seq: self.delta.ledger_seq(),
            data: LedgerEntryData::Account(new_account),
            ext: LedgerEntryExt::V0,
        });

        Ok(OperationResult {
            code: OperationResultCode::OpInner,
            tr: Some(OperationResultTr::CreateAccount(CreateAccountResult::CreateAccountSuccess)),
        })
    }
}
```

### 3.5 Soroban Operations

```rust
use soroban_env_host::{Host, HostError, LedgerInfo};
use soroban_env_common::xdr as soroban_xdr;

impl<'a> TransactionProcessor<'a> {
    pub fn apply_invoke_host_function(
        &mut self,
        source: &MuxedAccount,
        op: &InvokeHostFunctionOp,
        frame: &TransactionFrame,
    ) -> Result<OperationResult, TransactionError> {
        let source_id = muxed_to_account_id(source)?;

        // Get Soroban resources from transaction
        let resources = self.get_soroban_resources(frame)?;

        // Create Soroban host
        let ledger_info = LedgerInfo {
            protocol_version: self.protocol_version,
            sequence_number: self.delta.ledger_seq(),
            timestamp: current_timestamp(),
            network_id: Hash256::hash(self.network_passphrase.as_bytes()).0,
            base_reserve: self.get_base_reserve(),
            min_temp_entry_ttl: 16,
            min_persistent_entry_ttl: 120960,
            max_entry_ttl: 6312000,
        };

        // Load footprint entries
        let footprint = self.load_footprint(&resources.footprint)?;

        // Create and configure host
        let host = Host::with_storage_and_budget(
            footprint,
            resources.budget.clone(),
        );
        host.set_ledger_info(ledger_info)?;
        host.set_source_account(source_id.clone())?;

        // Invoke the host function
        let result = match &op.host_function {
            HostFunction::InvokeContract(args) => {
                host.invoke_function(soroban_xdr::HostFunction::InvokeContract(args.clone()))?
            }
            HostFunction::CreateContract(args) => {
                host.invoke_function(soroban_xdr::HostFunction::CreateContract(args.clone()))?
            }
            HostFunction::UploadWasm(wasm) => {
                host.invoke_function(soroban_xdr::HostFunction::UploadWasm(wasm.clone()))?
            }
        };

        // Extract storage changes and apply to delta
        let storage_changes = host.recover_storage()?;
        for (key, entry) in storage_changes {
            match entry {
                Some(e) => self.delta.record_update(e),
                None => self.delta.record_delete(key),
            }
        }

        // Extract events
        let events = host.get_events()?;

        Ok(OperationResult {
            code: OperationResultCode::OpInner,
            tr: Some(OperationResultTr::InvokeHostFunction(
                InvokeHostFunctionResult::InvokeHostFunctionSuccess(result)
            )),
        })
    }

    pub fn apply_extend_footprint_ttl(
        &mut self,
        source: &MuxedAccount,
        op: &ExtendFootprintTtlOp,
        frame: &TransactionFrame,
    ) -> Result<OperationResult, TransactionError> {
        let resources = self.get_soroban_resources(frame)?;

        // Extend TTL for all read-only keys in footprint
        for key in &resources.footprint.read_only {
            self.extend_entry_ttl(key, op.extend_to)?;
        }

        Ok(OperationResult {
            code: OperationResultCode::OpInner,
            tr: Some(OperationResultTr::ExtendFootprintTtl(
                ExtendFootprintTtlResult::ExtendFootprintTtlSuccess
            )),
        })
    }

    pub fn apply_restore_footprint(
        &mut self,
        source: &MuxedAccount,
        op: &RestoreFootprintOp,
        frame: &TransactionFrame,
    ) -> Result<OperationResult, TransactionError> {
        let resources = self.get_soroban_resources(frame)?;

        // Restore all keys in read-write footprint
        for key in &resources.footprint.read_write {
            self.restore_entry(key)?;
        }

        Ok(OperationResult {
            code: OperationResultCode::OpInner,
            tr: Some(OperationResultTr::RestoreFootprint(
                RestoreFootprintResult::RestoreFootprintSuccess
            )),
        })
    }
}
```

### 3.6 Fee Calculation

```rust
pub mod fees {
    use stellar_xdr::curr::*;

    /// Calculate minimum fee for a transaction
    pub fn calculate_min_fee(
        tx: &TransactionFrame,
        base_fee: u32,
        ledger_capacity_usage: f64,
    ) -> i64 {
        let op_count = tx.operations().len() as u32;
        let base = base_fee as i64 * op_count as i64;

        // Surge pricing when network is congested
        let surge_multiplier = if ledger_capacity_usage > 0.5 {
            1.0 + (ledger_capacity_usage - 0.5) * 2.0
        } else {
            1.0
        };

        (base as f64 * surge_multiplier) as i64
    }

    /// Calculate Soroban resource fees
    pub fn calculate_soroban_fees(resources: &SorobanResources) -> i64 {
        let mut fee: i64 = 0;

        // CPU instructions
        fee += (resources.instructions as i64 * INSTRUCTION_FEE) / 10000;

        // Read bytes
        fee += resources.read_bytes as i64 * READ_BYTE_FEE;

        // Write bytes
        fee += resources.write_bytes as i64 * WRITE_BYTE_FEE;

        // Entry access
        fee += resources.footprint.read_only.len() as i64 * READ_ENTRY_FEE;
        fee += resources.footprint.read_write.len() as i64 * WRITE_ENTRY_FEE;

        fee
    }

    // Fee constants (in stroops)
    const INSTRUCTION_FEE: i64 = 25;
    const READ_BYTE_FEE: i64 = 100;
    const WRITE_BYTE_FEE: i64 = 1000;
    const READ_ENTRY_FEE: i64 = 6250;
    const WRITE_ENTRY_FEE: i64 = 10000;
}
```

## 4. Error Types

```rust
#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("No signatures")]
    NoSignatures,

    #[error("Missing signature for {0:?}")]
    MissingSignature(SignerKey),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Source account not found")]
    SourceNotFound,

    #[error("Destination not found")]
    DestinationNotFound,

    #[error("Bad sequence: expected {expected}, got {got}")]
    BadSequence { expected: i64, got: i64 },

    #[error("Insufficient fee: required {required}, provided {provided}")]
    InsufficientFee { required: i64, provided: i64 },

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: i64, available: i64 },

    #[error("Account already exists")]
    AccountExists,

    #[error("Underfunded")]
    Underfunded,

    #[error("Low reserve")]
    LowReserve,

    #[error("Unsupported operation")]
    UnsupportedOperation,

    #[error("Soroban error: {0}")]
    Soroban(#[from] HostError),

    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::Error),
}
```

## 5. Tests to Port from stellar-core

From `src/transactions/test/`:
- Each operation type has dedicated tests
- Fee calculation tests
- Signature validation tests
- Sequence number tests
- Soroban integration tests

## 6. Protocol 23 Specifics

### 6.1 Parallel Execution (CAP-0063)

Protocol 23 allows parallel execution of Soroban transactions with non-overlapping footprints. Our implementation should:
1. Group transactions by footprint overlap
2. Execute non-overlapping groups in parallel
3. Maintain deterministic ordering for results

### 6.2 Automatic Restoration (CAP-0066)

InvokeHostFunction automatically restores archived entries in the footprint. No explicit RestoreFootprint needed for read-write entries.

### 6.3 Unified Events (CAP-0067)

Classic asset operations now emit SAC-format events. Payment, PathPayment, and other asset operations emit `transfer` events compatible with Soroban tokens.
