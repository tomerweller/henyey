//! Operation execution dispatcher.
//!
//! This module provides the main entry point for executing Stellar operations.
//! Each operation type has its own submodule with the specific execution logic.

use stellar_xdr::curr::{
    AccountId, ContractEvent, DiagnosticEvent, Operation, OperationBody, OperationResult,
    SorobanTransactionData,
};

use crate::frame::muxed_to_account_id;
use crate::soroban::SorobanConfig;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;

mod account_merge;
mod bump_sequence;
mod change_trust;
mod claimable_balance;
mod clawback;
mod create_account;
mod extend_footprint_ttl;
mod inflation;
mod invoke_host_function;
mod liquidity_pool;
mod manage_data;
mod manage_offer;
mod offer_exchange;
mod path_payment;
mod payment;
mod restore_footprint;
mod set_options;
mod sponsorship;
mod trust_flags;

pub use account_merge::execute_account_merge;
pub use bump_sequence::execute_bump_sequence;
pub use change_trust::execute_change_trust;
pub use claimable_balance::{execute_claim_claimable_balance, execute_create_claimable_balance};
pub use create_account::execute_create_account;
pub use extend_footprint_ttl::execute_extend_footprint_ttl;
pub use invoke_host_function::execute_invoke_host_function;
pub use manage_data::execute_manage_data;
pub use manage_offer::{
    execute_create_passive_sell_offer, execute_manage_buy_offer, execute_manage_sell_offer,
};
pub use offer_exchange::{exchange_v10, ExchangeError, ExchangeResult, RoundingType};
pub use path_payment::{execute_path_payment_strict_receive, execute_path_payment_strict_send};
pub use payment::execute_payment;
pub use restore_footprint::execute_restore_footprint;
pub use set_options::execute_set_options;
pub use sponsorship::{
    execute_begin_sponsoring_future_reserves, execute_end_sponsoring_future_reserves,
    execute_revoke_sponsorship,
};
pub use clawback::{execute_clawback, execute_clawback_claimable_balance};
pub use inflation::execute_inflation;
pub use liquidity_pool::{execute_liquidity_pool_deposit, execute_liquidity_pool_withdraw};
pub use trust_flags::{execute_allow_trust, execute_set_trust_line_flags};

/// Execute a single operation.
///
/// This is the main dispatch function that routes to the appropriate
/// operation-specific executor based on the operation type.
///
/// # Arguments
///
/// * `op` - The operation to execute
/// * `source_account_id` - The transaction's source account (used if operation has no explicit source)
/// * `state` - The ledger state manager
/// * `context` - The ledger context
///
/// # Returns
///
/// Returns the operation result, which may indicate success or a specific failure code.
pub struct SorobanOperationMeta {
    /// Contract/system events emitted by the operation.
    pub events: Vec<ContractEvent>,
    /// Diagnostic events emitted during execution.
    pub diagnostic_events: Vec<DiagnosticEvent>,
    /// Return value for invoke host function (if any).
    pub return_value: Option<stellar_xdr::curr::ScVal>,
}

pub struct OperationExecutionResult {
    pub result: OperationResult,
    pub soroban_meta: Option<SorobanOperationMeta>,
}

impl OperationExecutionResult {
    fn new(result: OperationResult) -> Self {
        Self {
            result,
            soroban_meta: None,
        }
    }

    fn with_soroban_meta(result: OperationResult, meta: SorobanOperationMeta) -> Self {
        Self {
            result,
            soroban_meta: Some(meta),
        }
    }
}

pub fn execute_operation(
    op: &Operation,
    source_account_id: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationExecutionResult> {
    execute_operation_with_soroban(
        op,
        source_account_id,
        source_account_id,
        0,
        0,
        state,
        context,
        None,
        None,
    )
}

/// Execute a single operation with optional Soroban transaction data.
///
/// This variant is used for Soroban operations that need access to the footprint
/// and network configuration.
///
/// # Arguments
///
/// * `soroban_config` - Optional Soroban config with cost parameters. Required for
///   accurate Soroban transaction execution. If None, uses default config which may
///   produce incorrect results.
pub fn execute_operation_with_soroban(
    op: &Operation,
    source_account_id: &AccountId,
    tx_source_id: &AccountId,
    tx_seq: i64,
    op_index: u32,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
    soroban_data: Option<&SorobanTransactionData>,
    soroban_config: Option<&SorobanConfig>,
) -> Result<OperationExecutionResult> {
    // Get the actual source for this operation
    // If the operation has an explicit source, use it; otherwise use the transaction source
    let op_source = op
        .source_account
        .as_ref()
        .map(|m| muxed_to_account_id(m))
        .unwrap_or_else(|| source_account_id.clone());

    match &op.body {
        OperationBody::CreateAccount(op_data) => {
            Ok(OperationExecutionResult::new(
                create_account::execute_create_account(op_data, &op_source, state, context)?,
            ))
        }
        OperationBody::Payment(op_data) => {
            Ok(OperationExecutionResult::new(
                payment::execute_payment(op_data, &op_source, state, context)?,
            ))
        }
        OperationBody::ChangeTrust(op_data) => {
            Ok(OperationExecutionResult::new(
                change_trust::execute_change_trust(op_data, &op_source, state, context)?,
            ))
        }
        OperationBody::ManageData(op_data) => {
            Ok(OperationExecutionResult::new(
                manage_data::execute_manage_data(op_data, &op_source, state, context)?,
            ))
        }
        OperationBody::BumpSequence(op_data) => {
            Ok(OperationExecutionResult::new(
                bump_sequence::execute_bump_sequence(op_data, &op_source, state, context)?,
            ))
        }
        OperationBody::AccountMerge(dest) => {
            Ok(OperationExecutionResult::new(
                account_merge::execute_account_merge(dest, &op_source, state, context)?,
            ))
        }
        OperationBody::SetOptions(op_data) => {
            Ok(OperationExecutionResult::new(
                set_options::execute_set_options(op_data, &op_source, state, context)?,
            ))
        }
        // Soroban operations
        OperationBody::InvokeHostFunction(op_data) => {
            // Use provided config or default for Soroban execution
            let default_config = SorobanConfig::default();
            let config = soroban_config.unwrap_or(&default_config);
            invoke_host_function::execute_invoke_host_function(
                op_data,
                &op_source,
                state,
                context,
                soroban_data,
                config,
            )
        }
        OperationBody::ExtendFootprintTtl(op_data) => {
            Ok(OperationExecutionResult::new(
                extend_footprint_ttl::execute_extend_footprint_ttl(
                    op_data,
                    &op_source,
                    state,
                    context,
                    soroban_data,
                )?,
            ))
        }
        OperationBody::RestoreFootprint(op_data) => {
            Ok(OperationExecutionResult::new(
                restore_footprint::execute_restore_footprint(
                    op_data,
                    &op_source,
                    state,
                    context,
                    soroban_data,
                )?,
            ))
        }
        // DEX operations
        OperationBody::PathPaymentStrictReceive(op_data) => {
            Ok(OperationExecutionResult::new(
                path_payment::execute_path_payment_strict_receive(
                    op_data, &op_source, state, context,
                )?,
            ))
        }
        OperationBody::PathPaymentStrictSend(op_data) => {
            Ok(OperationExecutionResult::new(
                path_payment::execute_path_payment_strict_send(
                    op_data, &op_source, state, context,
                )?,
            ))
        }
        OperationBody::ManageSellOffer(op_data) => {
            Ok(OperationExecutionResult::new(
                manage_offer::execute_manage_sell_offer(op_data, &op_source, state, context)?,
            ))
        }
        OperationBody::ManageBuyOffer(op_data) => {
            Ok(OperationExecutionResult::new(
                manage_offer::execute_manage_buy_offer(op_data, &op_source, state, context)?,
            ))
        }
        OperationBody::CreatePassiveSellOffer(op_data) => {
            Ok(OperationExecutionResult::new(
                manage_offer::execute_create_passive_sell_offer(
                    op_data, &op_source, state, context,
                )?,
            ))
        }
        OperationBody::AllowTrust(op_data) => {
            Ok(OperationExecutionResult::new(
                trust_flags::execute_allow_trust(op_data, &op_source, state, context)?,
            ))
        }
        OperationBody::Inflation => Ok(OperationExecutionResult::new(
            inflation::execute_inflation(&op_source, state, context)?,
        )),
        OperationBody::CreateClaimableBalance(op_data) => {
            Ok(OperationExecutionResult::new(
                claimable_balance::execute_create_claimable_balance(
                    op_data, &op_source, tx_source_id, tx_seq, op_index, state, context,
                )?,
            ))
        }
        OperationBody::ClaimClaimableBalance(op_data) => {
            Ok(OperationExecutionResult::new(
                claimable_balance::execute_claim_claimable_balance(
                    op_data, &op_source, state, context,
                )?,
            ))
        }
        OperationBody::BeginSponsoringFutureReserves(op_data) => {
            Ok(OperationExecutionResult::new(
                sponsorship::execute_begin_sponsoring_future_reserves(
                    op_data, &op_source, state, context,
                )?,
            ))
        }
        OperationBody::EndSponsoringFutureReserves => {
            Ok(OperationExecutionResult::new(
                sponsorship::execute_end_sponsoring_future_reserves(&op_source, state, context)?,
            ))
        }
        OperationBody::RevokeSponsorship(op_data) => {
            Ok(OperationExecutionResult::new(
                sponsorship::execute_revoke_sponsorship(op_data, &op_source, state, context)?,
            ))
        }
        OperationBody::Clawback(op_data) => {
            Ok(OperationExecutionResult::new(
                clawback::execute_clawback(op_data, &op_source, state, context)?,
            ))
        }
        OperationBody::ClawbackClaimableBalance(op_data) => {
            Ok(OperationExecutionResult::new(
                clawback::execute_clawback_claimable_balance(op_data, &op_source, state, context)?,
            ))
        }
        OperationBody::SetTrustLineFlags(op_data) => {
            Ok(OperationExecutionResult::new(
                trust_flags::execute_set_trust_line_flags(op_data, &op_source, state, context)?,
            ))
        }
        OperationBody::LiquidityPoolDeposit(op_data) => {
            Ok(OperationExecutionResult::new(
                liquidity_pool::execute_liquidity_pool_deposit(
                    op_data, &op_source, state, context,
                )?,
            ))
        }
        OperationBody::LiquidityPoolWithdraw(op_data) => {
            Ok(OperationExecutionResult::new(
                liquidity_pool::execute_liquidity_pool_withdraw(
                    op_data, &op_source, state, context,
                )?,
            ))
        }
    }
}

/// Create an OperationResult for unsupported operations.
fn make_not_supported_result() -> OperationResult {
    OperationResult::OpNotSupported
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_account_id() -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32])))
    }

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    #[test]
    fn test_inflation_operation_dispatch() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id();

        // Test that Inflation returns NotTime (deprecated since Protocol 12)
        let op = Operation {
            source_account: None,
            body: OperationBody::Inflation,
        };

        let result = execute_operation(&op, &source, &mut state, &context)
            .expect("execute op");

        // Inflation is deprecated and returns NotTime
        match result.result {
            OperationResult::OpInner(OperationResultTr::Inflation(r)) => {
                assert!(matches!(r, InflationResult::NotTime));
            }
            _ => panic!("Expected Inflation result"),
        }
    }
}
