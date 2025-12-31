//! Transaction execution during ledger close.
//!
//! This module integrates the transaction processing from stellar-core-tx
//! with the ledger close process.

use std::collections::HashMap;

use stellar_core_common::{Hash256, NetworkId};
use stellar_core_tx::{
    operations::execute::execute_operation,
    LedgerContext, LedgerStateManager, TransactionFrame, TxError,
};
use stellar_xdr::curr::{
    AccountEntry, AccountId, DataEntry, LedgerEntry, LedgerEntryData, LedgerEntryExt,
    OfferEntry, OperationBody, OperationResult, TransactionEnvelope, TransactionResult,
    TransactionResultCode, TransactionResultResult, TrustLineEntry,
};
use tracing::{debug, info, warn};

use crate::delta::LedgerDelta;
use crate::snapshot::SnapshotHandle;
use crate::{LedgerError, Result};

/// Result of executing a transaction.
#[derive(Debug, Clone)]
pub struct TransactionExecutionResult {
    /// Whether the transaction succeeded.
    pub success: bool,
    /// Fee charged (always charged even on failure).
    pub fee_charged: i64,
    /// Operation results.
    pub operation_results: Vec<OperationResult>,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Context for executing transactions during ledger close.
pub struct TransactionExecutor {
    /// Ledger sequence being processed.
    ledger_seq: u32,
    /// Close time.
    close_time: u64,
    /// Base fee.
    base_fee: u32,
    /// Base reserve.
    base_reserve: u32,
    /// Protocol version.
    protocol_version: u32,
    /// Network ID.
    network_id: NetworkId,
    /// State manager for execution.
    state: LedgerStateManager,
    /// Accounts loaded from snapshot.
    loaded_accounts: HashMap<[u8; 32], bool>,
}

impl TransactionExecutor {
    /// Create a new transaction executor.
    pub fn new(
        ledger_seq: u32,
        close_time: u64,
        base_fee: u32,
        base_reserve: u32,
        protocol_version: u32,
        network_id: NetworkId,
    ) -> Self {
        Self {
            ledger_seq,
            close_time,
            base_fee,
            base_reserve,
            protocol_version,
            network_id,
            state: LedgerStateManager::new(base_reserve as i64, ledger_seq),
            loaded_accounts: HashMap::new(),
        }
    }

    /// Load an account from the snapshot into the state manager.
    pub fn load_account(&mut self, snapshot: &SnapshotHandle, account_id: &AccountId) -> Result<bool> {
        let key_bytes = account_id_to_key(account_id);

        // Check if already loaded
        if self.loaded_accounts.contains_key(&key_bytes) {
            return Ok(self.state.get_account(account_id).is_some());
        }

        // Mark as loaded (even if not found)
        self.loaded_accounts.insert(key_bytes, true);

        // Try to load from snapshot
        let key = stellar_xdr::curr::LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
            account_id: account_id.clone(),
        });

        if let Some(entry) = snapshot.get_entry(&key)? {
            if let LedgerEntryData::Account(account) = entry.data {
                self.state.create_account(account);
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Load a trustline from the snapshot into the state manager.
    pub fn load_trustline(
        &mut self,
        snapshot: &SnapshotHandle,
        account_id: &AccountId,
        asset: &stellar_xdr::curr::TrustLineAsset,
    ) -> Result<bool> {
        let key = stellar_xdr::curr::LedgerKey::Trustline(stellar_xdr::curr::LedgerKeyTrustLine {
            account_id: account_id.clone(),
            asset: asset.clone(),
        });

        if let Some(entry) = snapshot.get_entry(&key)? {
            if let LedgerEntryData::Trustline(trustline) = entry.data {
                self.state.create_trustline(trustline);
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Execute a transaction.
    pub fn execute_transaction(
        &mut self,
        snapshot: &SnapshotHandle,
        tx_envelope: &TransactionEnvelope,
    ) -> Result<TransactionExecutionResult> {
        let frame = TransactionFrame::new(tx_envelope.clone());
        let source_account_id = frame.source_account_id();

        // Load source account
        if !self.load_account(snapshot, &source_account_id)? {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                operation_results: vec![],
                error: Some("Source account not found".into()),
            });
        }

        // Get source account for validation
        let source_account = match self.state.get_account(&source_account_id) {
            Some(acc) => acc.clone(),
            None => {
                return Ok(TransactionExecutionResult {
                    success: false,
                    fee_charged: 0,
                    operation_results: vec![],
                    error: Some("Source account not found".into()),
                });
            }
        };

        // Validate sequence number
        let expected_seq = source_account.seq_num.0 + 1;
        if frame.sequence_number() != expected_seq {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                operation_results: vec![],
                error: Some(format!(
                    "Bad sequence: expected {}, got {}",
                    expected_seq,
                    frame.sequence_number()
                )),
            });
        }

        // Validate fee
        let fee = frame.total_fee();
        if source_account.balance < fee {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                operation_results: vec![],
                error: Some("Insufficient balance for fee".into()),
            });
        }

        // Deduct fee and increment sequence
        if let Some(acc) = self.state.get_account_mut(&source_account_id) {
            acc.balance -= fee;
            acc.seq_num.0 += 1;
        }

        // Create ledger context for operation execution
        let ledger_context = LedgerContext::new(
            self.ledger_seq,
            self.close_time,
            self.base_fee,
            self.base_reserve,
            self.protocol_version,
            self.network_id.clone(),
        );

        // Execute operations
        let mut operation_results = Vec::new();
        let mut all_success = true;

        for op in frame.operations() {
            // Load any accounts needed for this operation
            self.load_operation_accounts(snapshot, op, &source_account_id)?;

            // Get operation source
            let op_source = op
                .source_account
                .as_ref()
                .map(|m| stellar_core_tx::muxed_to_account_id(m))
                .unwrap_or_else(|| source_account_id.clone());

            // Execute the operation
            let result = self.execute_single_operation(op, &op_source, &ledger_context);

            match result {
                Ok(op_result) => {
                    // Check if operation succeeded
                    if !is_operation_success(&op_result) {
                        all_success = false;
                    }
                    operation_results.push(op_result);
                }
                Err(e) => {
                    all_success = false;
                    warn!(error = %e, "Operation execution failed");
                    operation_results.push(OperationResult::OpNotSupported);
                }
            }

            // If operation failed and this is a required operation, stop
            if !all_success {
                break;
            }
        }

        Ok(TransactionExecutionResult {
            success: all_success,
            fee_charged: fee,
            operation_results,
            error: if all_success {
                None
            } else {
                Some("One or more operations failed".into())
            },
        })
    }

    /// Load accounts needed for an operation.
    fn load_operation_accounts(
        &mut self,
        snapshot: &SnapshotHandle,
        op: &stellar_xdr::curr::Operation,
        source_id: &AccountId,
    ) -> Result<()> {
        // Load operation source if different from transaction source
        if let Some(ref muxed) = op.source_account {
            let op_source = stellar_core_tx::muxed_to_account_id(muxed);
            self.load_account(snapshot, &op_source)?;
        }

        // Load destination accounts based on operation type
        match &op.body {
            OperationBody::CreateAccount(op_data) => {
                // Don't load destination - it shouldn't exist
            }
            OperationBody::Payment(op_data) => {
                let dest = stellar_core_tx::muxed_to_account_id(&op_data.destination);
                self.load_account(snapshot, &dest)?;
            }
            OperationBody::AccountMerge(dest) => {
                let dest = stellar_core_tx::muxed_to_account_id(dest);
                self.load_account(snapshot, &dest)?;
            }
            _ => {
                // Other operations typically work on source account
            }
        }

        Ok(())
    }

    /// Execute a single operation using the central dispatcher.
    fn execute_single_operation(
        &mut self,
        op: &stellar_xdr::curr::Operation,
        source: &AccountId,
        context: &LedgerContext,
    ) -> std::result::Result<OperationResult, TxError> {
        // Use the central operation dispatcher which handles all operation types
        execute_operation(op, source, &mut self.state, context)
    }

    /// Apply all state changes to the delta.
    pub fn apply_to_delta(&self, delta: &mut LedgerDelta) -> Result<()> {
        let state_delta = self.state.delta();

        // Apply created entries
        for entry in state_delta.created_entries() {
            delta.record_create(entry.clone())?;
        }

        // Apply updated entries
        for entry in state_delta.updated_entries() {
            // For updates, we need the previous entry too
            // For now, just record as create (simplified)
            delta.record_create(entry.clone())?;
        }

        // Apply deleted entries
        for key in state_delta.deleted_keys() {
            // We need the previous entry for deletion
            // This is simplified - in practice we'd track the previous state
        }

        Ok(())
    }

    /// Get total fees collected.
    pub fn total_fees(&self) -> i64 {
        self.state.delta().fee_charged()
    }

    /// Get the state manager.
    pub fn state(&self) -> &LedgerStateManager {
        &self.state
    }

    /// Get mutable state manager.
    pub fn state_mut(&mut self) -> &mut LedgerStateManager {
        &mut self.state
    }
}

/// Convert AccountId to key bytes.
fn account_id_to_key(account_id: &AccountId) -> [u8; 32] {
    match &account_id.0 {
        stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key) => key.0,
    }
}

/// Check if an operation result indicates success.
fn is_operation_success(result: &OperationResult) -> bool {
    match result {
        OperationResult::OpInner(inner) => {
            use stellar_xdr::curr::OperationResultTr;
            use stellar_xdr::curr::*;
            match inner {
                OperationResultTr::CreateAccount(r) => {
                    matches!(r, CreateAccountResult::Success)
                }
                OperationResultTr::Payment(r) => {
                    matches!(r, PaymentResult::Success)
                }
                OperationResultTr::PathPaymentStrictReceive(r) => {
                    matches!(r, PathPaymentStrictReceiveResult::Success(_))
                }
                OperationResultTr::ManageSellOffer(r) => {
                    matches!(r, ManageSellOfferResult::Success(_))
                }
                OperationResultTr::CreatePassiveSellOffer(r) => {
                    matches!(r, ManageSellOfferResult::Success(_))
                }
                OperationResultTr::SetOptions(r) => {
                    matches!(r, SetOptionsResult::Success)
                }
                OperationResultTr::ChangeTrust(r) => {
                    matches!(r, ChangeTrustResult::Success)
                }
                OperationResultTr::AllowTrust(r) => {
                    matches!(r, AllowTrustResult::Success)
                }
                OperationResultTr::AccountMerge(r) => {
                    matches!(r, AccountMergeResult::Success(_))
                }
                OperationResultTr::Inflation(r) => {
                    matches!(r, InflationResult::Success(_))
                }
                OperationResultTr::ManageData(r) => {
                    matches!(r, ManageDataResult::Success)
                }
                OperationResultTr::BumpSequence(r) => {
                    matches!(r, BumpSequenceResult::Success)
                }
                OperationResultTr::ManageBuyOffer(r) => {
                    matches!(r, ManageBuyOfferResult::Success(_))
                }
                OperationResultTr::PathPaymentStrictSend(r) => {
                    matches!(r, PathPaymentStrictSendResult::Success(_))
                }
                OperationResultTr::CreateClaimableBalance(r) => {
                    matches!(r, CreateClaimableBalanceResult::Success(_))
                }
                OperationResultTr::ClaimClaimableBalance(r) => {
                    matches!(r, ClaimClaimableBalanceResult::Success)
                }
                OperationResultTr::BeginSponsoringFutureReserves(r) => {
                    matches!(r, BeginSponsoringFutureReservesResult::Success)
                }
                OperationResultTr::EndSponsoringFutureReserves(r) => {
                    matches!(r, EndSponsoringFutureReservesResult::Success)
                }
                OperationResultTr::RevokeSponsorship(r) => {
                    matches!(r, RevokeSponsorshipResult::Success)
                }
                OperationResultTr::Clawback(r) => {
                    matches!(r, ClawbackResult::Success)
                }
                OperationResultTr::ClawbackClaimableBalance(r) => {
                    matches!(r, ClawbackClaimableBalanceResult::Success)
                }
                OperationResultTr::SetTrustLineFlags(r) => {
                    matches!(r, SetTrustLineFlagsResult::Success)
                }
                OperationResultTr::LiquidityPoolDeposit(r) => {
                    matches!(r, LiquidityPoolDepositResult::Success)
                }
                OperationResultTr::LiquidityPoolWithdraw(r) => {
                    matches!(r, LiquidityPoolWithdrawResult::Success)
                }
                OperationResultTr::InvokeHostFunction(r) => {
                    matches!(r, InvokeHostFunctionResult::Success(_))
                }
                OperationResultTr::ExtendFootprintTtl(r) => {
                    matches!(r, ExtendFootprintTtlResult::Success)
                }
                OperationResultTr::RestoreFootprint(r) => {
                    matches!(r, RestoreFootprintResult::Success)
                }
            }
        }
        OperationResult::OpNotSupported => false, // Unsupported operations fail
        _ => false,
    }
}

/// Execute a full transaction set.
pub fn execute_transaction_set(
    snapshot: &SnapshotHandle,
    transactions: &[TransactionEnvelope],
    ledger_seq: u32,
    close_time: u64,
    base_fee: u32,
    base_reserve: u32,
    protocol_version: u32,
    network_id: NetworkId,
    delta: &mut LedgerDelta,
) -> Result<Vec<TransactionExecutionResult>> {
    let mut executor = TransactionExecutor::new(
        ledger_seq,
        close_time,
        base_fee,
        base_reserve,
        protocol_version,
        network_id,
    );

    let mut results = Vec::with_capacity(transactions.len());

    for tx in transactions {
        let result = executor.execute_transaction(snapshot, tx)?;

        info!(
            success = result.success,
            fee = result.fee_charged,
            ops = result.operation_results.len(),
            "Executed transaction"
        );

        results.push(result);
    }

    // Apply all changes to the delta
    executor.apply_to_delta(delta)?;

    // Add fees to fee pool
    let total_fees = executor.total_fees();
    delta.record_fee_pool_delta(total_fees);

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_executor_creation() {
        let executor = TransactionExecutor::new(
            100,
            1234567890,
            100,
            5_000_000,
            21,
            NetworkId::testnet(),
        );

        assert_eq!(executor.ledger_seq, 100);
        assert_eq!(executor.close_time, 1234567890);
    }
}
