//! CreateAccount operation execution.

use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountId, CreateAccountOp, CreateAccountResult,
    CreateAccountResultCode, OperationResult, OperationResultTr, SequenceNumber, Thresholds,
    String32,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::{Result, TxError};

/// Execute a CreateAccount operation.
pub fn execute_create_account(
    op: &CreateAccountOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Check starting balance meets minimum
    let min_balance = state.minimum_balance(0);
    if op.starting_balance < min_balance {
        return Ok(make_result(CreateAccountResultCode::LowReserve));
    }

    // Check destination doesn't already exist
    if state.get_account(&op.destination).is_some() {
        return Ok(make_result(CreateAccountResultCode::AlreadyExist));
    }

    // Get source account and check balance
    let source_account = match state.get_account(source) {
        Some(account) => account,
        None => return Err(TxError::SourceAccountNotFound),
    };

    // Check source has sufficient available balance
    let source_min_balance = state.minimum_balance(source_account.num_sub_entries);
    let available = source_account.balance - source_min_balance;
    if available < op.starting_balance {
        return Ok(make_result(CreateAccountResultCode::Underfunded));
    }

    // Deduct from source
    let source_account_mut = state
        .get_account_mut(source)
        .ok_or(TxError::SourceAccountNotFound)?;
    source_account_mut.balance -= op.starting_balance;

    // Create new account
    let new_account = AccountEntry {
        account_id: op.destination.clone(),
        balance: op.starting_balance,
        seq_num: SequenceNumber(0),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: vec![].try_into().unwrap(),
        ext: AccountEntryExt::V0,
    };

    state.create_account(new_account);

    Ok(make_result(CreateAccountResultCode::Success))
}

fn make_result(code: CreateAccountResultCode) -> OperationResult {
    let result = match code {
        CreateAccountResultCode::Success => CreateAccountResult::Success,
        CreateAccountResultCode::Malformed => CreateAccountResult::Malformed,
        CreateAccountResultCode::Underfunded => CreateAccountResult::Underfunded,
        CreateAccountResultCode::LowReserve => CreateAccountResult::LowReserve,
        CreateAccountResultCode::AlreadyExist => CreateAccountResult::AlreadyExist,
    };
    OperationResult::OpInner(OperationResultTr::CreateAccount(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
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
    fn test_create_account_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);

        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = CreateAccountOp {
            destination: dest_id.clone(),
            starting_balance: 20_000_000,
        };

        let result = execute_create_account(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        // Verify destination was created
        let dest_acc = state.get_account(&dest_id);
        assert!(dest_acc.is_some());
        assert_eq!(dest_acc.unwrap().balance, 20_000_000);

        // Verify source was deducted
        assert_eq!(state.get_account(&source_id).unwrap().balance, 80_000_000);
    }

    #[test]
    fn test_create_account_already_exists() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);

        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 50_000_000));

        let op = CreateAccountOp {
            destination: dest_id.clone(),
            starting_balance: 20_000_000,
        };

        let result = execute_create_account(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::CreateAccount(r)) => {
                assert!(matches!(r, CreateAccountResult::AlreadyExist));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_create_account_low_reserve() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);

        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = CreateAccountOp {
            destination: dest_id.clone(),
            starting_balance: 5_000_000, // Below minimum balance of 10M
        };

        let result = execute_create_account(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::CreateAccount(r)) => {
                assert!(matches!(r, CreateAccountResult::LowReserve));
            }
            _ => panic!("Unexpected result type"),
        }
    }
}
