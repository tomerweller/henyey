//! ManageData operation execution.
//!
//! This module implements the execution logic for the ManageData operation,
//! which allows accounts to attach arbitrary key-value data.

use stellar_xdr::curr::{
    AccountId, DataEntry, DataEntryExt, ManageDataOp, ManageDataResult, ManageDataResultCode,
    OperationResult, OperationResultTr,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::{Result, TxError};

/// Maximum length for data names.
const MAX_DATA_NAME_LENGTH: usize = 64;

/// Maximum length for data values.
const MAX_DATA_VALUE_LENGTH: usize = 64;

/// Execute a ManageData operation.
///
/// This operation creates, updates, or removes a data entry. Setting the value
/// to None removes the entry.
pub fn execute_manage_data(
    op: &ManageDataOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Validate data name
    let data_name = op.data_name.to_string();
    if data_name.is_empty() || data_name.len() > MAX_DATA_NAME_LENGTH {
        return Ok(make_result(ManageDataResultCode::NameNotFound));
    }

    // Validate data value if present
    if let Some(value) = &op.data_value {
        if value.len() > MAX_DATA_VALUE_LENGTH {
            return Ok(make_result(ManageDataResultCode::InvalidName));
        }
    }

    // Check source account exists
    if state.get_account(source).is_none() {
        return Err(TxError::SourceAccountNotFound);
    }

    // Check if data entry exists
    let existing_entry = state.get_data(source, &data_name);

    match &op.data_value {
        None => {
            // Deleting data entry
            if existing_entry.is_some() {
                state.delete_data(source, &data_name);

                // Decrease sub-entry count
                if let Some(account) = state.get_account_mut(source) {
                    if account.num_sub_entries > 0 {
                        account.num_sub_entries -= 1;
                    }
                }
            }
            // If entry doesn't exist, deletion is a no-op (success)
        }
        Some(value) => {
            if existing_entry.is_some() {
                // Update existing entry
                if let Some(entry) = state.get_data_mut(source, &data_name) {
                    entry.data_value = value.clone();
                }
            } else {
                // Check source can afford new sub-entry
                let source_account = state
                    .get_account(source)
                    .ok_or(TxError::SourceAccountNotFound)?;
                let new_min_balance = state.minimum_balance(source_account.num_sub_entries + 1);
                if source_account.balance < new_min_balance {
                    return Ok(make_result(ManageDataResultCode::LowReserve));
                }

                // Create new data entry
                let new_entry = DataEntry {
                    account_id: source.clone(),
                    data_name: op.data_name.clone(),
                    data_value: value.clone(),
                    ext: DataEntryExt::V0,
                };

                state.create_data(new_entry);

                // Increase sub-entry count
                if let Some(account) = state.get_account_mut(source) {
                    account.num_sub_entries += 1;
                }
            }
        }
    }

    Ok(make_result(ManageDataResultCode::Success))
}

/// Create an OperationResult from a ManageDataResultCode.
fn make_result(code: ManageDataResultCode) -> OperationResult {
    let result = match code {
        ManageDataResultCode::Success => ManageDataResult::Success,
        ManageDataResultCode::NotSupportedYet => ManageDataResult::NotSupportedYet,
        ManageDataResultCode::NameNotFound => ManageDataResult::NameNotFound,
        ManageDataResultCode::LowReserve => ManageDataResult::LowReserve,
        ManageDataResultCode::InvalidName => ManageDataResult::InvalidName,
    };

    OperationResult::OpInner(OperationResultTr::ManageData(result))
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

    fn make_string64(s: &str) -> String64 {
        String64::try_from(s.as_bytes().to_vec()).unwrap()
    }

    #[test]
    fn test_manage_data_create_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = ManageDataOp {
            data_name: make_string64("test_key"),
            data_value: Some(vec![1, 2, 3, 4].try_into().unwrap()),
        };

        let result = execute_manage_data(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        // Verify data entry was created
        let entry = state.get_data(&source_id, "test_key");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().data_value.as_slice(), &[1, 2, 3, 4]);

        // Verify sub-entries increased
        assert_eq!(state.get_account(&source_id).unwrap().num_sub_entries, 1);
    }

    #[test]
    fn test_manage_data_delete_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let mut account = create_test_account(source_id.clone(), 100_000_000);
        account.num_sub_entries = 1;
        state.create_account(account);

        // Create initial data entry
        let initial_entry = DataEntry {
            account_id: source_id.clone(),
            data_name: make_string64("test_key"),
            data_value: vec![1, 2, 3, 4].try_into().unwrap(),
            ext: DataEntryExt::V0,
        };
        state.create_data(initial_entry);

        // Delete the entry
        let op = ManageDataOp {
            data_name: make_string64("test_key"),
            data_value: None,
        };

        let result = execute_manage_data(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        // Verify data entry was removed
        assert!(state.get_data(&source_id, "test_key").is_none());

        // Verify sub-entries decreased
        assert_eq!(state.get_account(&source_id).unwrap().num_sub_entries, 0);
    }

    #[test]
    fn test_manage_data_low_reserve() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        // Source only has minimum balance
        state.create_account(create_test_account(source_id.clone(), 10_000_000));

        let op = ManageDataOp {
            data_name: make_string64("test_key"),
            data_value: Some(vec![1, 2, 3, 4].try_into().unwrap()),
        };

        let result = execute_manage_data(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ManageData(r)) => {
                assert!(matches!(r, ManageDataResult::LowReserve));
            }
            _ => panic!("Unexpected result type"),
        }
    }
}
