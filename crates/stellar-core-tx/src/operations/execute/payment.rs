//! Payment operation execution.
//!
//! This module implements the execution logic for the Payment operation,
//! which transfers assets between accounts.

use stellar_xdr::curr::{
    AccountId, Asset, OperationResult, OperationResultTr, PaymentOp, PaymentResult,
    PaymentResultCode,
};

use crate::frame::muxed_to_account_id;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::{Result, TxError};

/// Execute a Payment operation.
///
/// This operation transfers assets from the source account to the destination.
/// For native assets, the transfer is direct. For credit assets, both accounts
/// must have trustlines for the asset.
///
/// # Arguments
///
/// * `op` - The Payment operation data
/// * `source` - The source account ID
/// * `state` - The ledger state manager
/// * `context` - The ledger context
///
/// # Returns
///
/// Returns the operation result indicating success or a specific failure reason.
pub fn execute_payment(
    op: &PaymentOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    let dest = muxed_to_account_id(&op.destination);

    // Amount must be positive
    if op.amount <= 0 {
        return Ok(make_result(PaymentResultCode::Malformed));
    }

    match &op.asset {
        Asset::Native => execute_native_payment(source, &dest, op.amount, state),
        Asset::CreditAlphanum4(_) | Asset::CreditAlphanum12(_) => {
            execute_credit_payment(source, &dest, &op.asset, op.amount, state)
        }
    }
}

/// Execute a native (XLM) payment.
fn execute_native_payment(
    source: &AccountId,
    dest: &AccountId,
    amount: i64,
    state: &mut LedgerStateManager,
) -> Result<OperationResult> {
    // Check destination exists
    if state.get_account(dest).is_none() {
        return Ok(make_result(PaymentResultCode::NoDestination));
    }

    // Get source account and check balance
    let source_account = match state.get_account(source) {
        Some(account) => account,
        None => return Err(TxError::SourceAccountNotFound),
    };

    // Check source has sufficient available balance
    let source_min_balance = state.minimum_balance(source_account.num_sub_entries);
    let available = source_account.balance - source_min_balance;
    if available < amount {
        return Ok(make_result(PaymentResultCode::Underfunded));
    }

    // Deduct from source
    let source_account_mut = state
        .get_account_mut(source)
        .ok_or(TxError::SourceAccountNotFound)?;
    source_account_mut.balance -= amount;

    // Credit to destination
    let dest_account_mut = state
        .get_account_mut(dest)
        .ok_or_else(|| TxError::Internal("destination account disappeared".into()))?;
    dest_account_mut.balance += amount;

    Ok(make_result(PaymentResultCode::Success))
}

/// Execute a credit asset payment.
fn execute_credit_payment(
    source: &AccountId,
    dest: &AccountId,
    asset: &Asset,
    amount: i64,
    state: &mut LedgerStateManager,
) -> Result<OperationResult> {
    // Check destination exists
    if state.get_account(dest).is_none() {
        return Ok(make_result(PaymentResultCode::NoDestination));
    }

    // Check source trustline exists
    let source_trustline = match state.get_trustline(source, asset) {
        Some(tl) => tl,
        None => return Ok(make_result(PaymentResultCode::SrcNoTrust)),
    };

    // Check source has sufficient balance
    if source_trustline.balance < amount {
        return Ok(make_result(PaymentResultCode::Underfunded));
    }

    // Check destination trustline exists
    let dest_trustline = match state.get_trustline(dest, asset) {
        Some(tl) => tl,
        None => return Ok(make_result(PaymentResultCode::NoTrust)),
    };

    // Check destination trustline has room (limit check)
    let dest_available = dest_trustline.limit - dest_trustline.balance;
    if dest_available < amount {
        return Ok(make_result(PaymentResultCode::LineFull));
    }

    // Update source trustline balance
    let source_trustline_mut = state
        .get_trustline_mut(source, asset)
        .ok_or_else(|| TxError::Internal("source trustline disappeared".into()))?;
    source_trustline_mut.balance -= amount;

    // Update destination trustline balance
    let dest_trustline_mut = state
        .get_trustline_mut(dest, asset)
        .ok_or_else(|| TxError::Internal("destination trustline disappeared".into()))?;
    dest_trustline_mut.balance += amount;

    Ok(make_result(PaymentResultCode::Success))
}

/// Create an OperationResult from a PaymentResultCode.
fn make_result(code: PaymentResultCode) -> OperationResult {
    let result = match code {
        PaymentResultCode::Success => PaymentResult::Success,
        PaymentResultCode::Malformed => PaymentResult::Malformed,
        PaymentResultCode::Underfunded => PaymentResult::Underfunded,
        PaymentResultCode::SrcNoTrust => PaymentResult::SrcNoTrust,
        PaymentResultCode::SrcNotAuthorized => PaymentResult::SrcNotAuthorized,
        PaymentResultCode::NoDestination => PaymentResult::NoDestination,
        PaymentResultCode::NoTrust => PaymentResult::NoTrust,
        PaymentResultCode::NotAuthorized => PaymentResult::NotAuthorized,
        PaymentResultCode::LineFull => PaymentResult::LineFull,
        PaymentResultCode::NoIssuer => PaymentResult::NoIssuer,
    };

    OperationResult::OpInner(OperationResultTr::Payment(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    fn create_test_muxed_account(seed: u8) -> MuxedAccount {
        MuxedAccount::Ed25519(Uint256([seed; 32]))
    }

    fn create_test_account(account_id: AccountId, balance: i64) -> AccountEntry {
        AccountEntry {
            account_id,
            balance,
            seq_num: SequenceNumber(1),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: vec![].try_into().unwrap(),
            ext: AccountEntryExt::V0,
        }
    }

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    #[test]
    fn test_native_payment_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);

        // Create both accounts
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 50_000_000));

        let op = PaymentOp {
            destination: create_test_muxed_account(1),
            asset: Asset::Native,
            amount: 10_000_000,
        };

        let result = execute_payment(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        // Verify balances changed
        assert_eq!(state.get_account(&source_id).unwrap().balance, 90_000_000);
        assert_eq!(state.get_account(&dest_id).unwrap().balance, 60_000_000);
    }

    #[test]
    fn test_payment_no_destination() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = PaymentOp {
            destination: create_test_muxed_account(1), // Non-existent destination
            asset: Asset::Native,
            amount: 10_000_000,
        };

        let result = execute_payment(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::Payment(r)) => {
                assert!(matches!(r, PaymentResult::NoDestination));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_payment_underfunded() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);

        // Source has 15M, minimum is 10M, so only 5M available
        state.create_account(create_test_account(source_id.clone(), 15_000_000));
        state.create_account(create_test_account(dest_id.clone(), 50_000_000));

        let op = PaymentOp {
            destination: create_test_muxed_account(1),
            asset: Asset::Native,
            amount: 10_000_000, // More than available
        };

        let result = execute_payment(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::Payment(r)) => {
                assert!(matches!(r, PaymentResult::Underfunded));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_payment_malformed() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = PaymentOp {
            destination: create_test_muxed_account(1),
            asset: Asset::Native,
            amount: 0, // Invalid amount
        };

        let result = execute_payment(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::Payment(r)) => {
                assert!(matches!(r, PaymentResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }
}
