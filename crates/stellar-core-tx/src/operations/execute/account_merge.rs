//! AccountMerge operation execution.

use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountEntryExtensionV1, AccountEntryExtensionV1Ext, AccountId,
    AccountMergeResult, AccountMergeResultCode, Liabilities, MuxedAccount, OperationResult,
    OperationResultTr,
};

use crate::frame::muxed_to_account_id;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::{Result, TxError};

/// Execute an AccountMerge operation.
pub fn execute_account_merge(
    dest: &MuxedAccount,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    let dest_account_id = muxed_to_account_id(dest);

    // Check destination exists
    if state.get_account(&dest_account_id).is_none() {
        return Ok(make_result(AccountMergeResultCode::NoAccount));
    }
    if &dest_account_id == source {
        return Ok(make_result(AccountMergeResultCode::Malformed));
    }

    // Get source account
    let source_account = match state.get_account(source) {
        Some(account) => account,
        None => return Err(TxError::SourceAccountNotFound),
    };

    // Check source has no sub-entries besides signers
    if source_account.num_sub_entries != source_account.signers.len() as u32 {
        return Ok(make_result(AccountMergeResultCode::HasSubEntries));
    }

    // Check source is not immutable
    const AUTH_IMMUTABLE_FLAG: u32 = 0x4;
    if source_account.flags & AUTH_IMMUTABLE_FLAG != 0 {
        return Ok(make_result(AccountMergeResultCode::ImmutableSet));
    }

    let source_balance = source_account.balance;

    let dest_account = state
        .get_account(&dest_account_id)
        .ok_or_else(|| TxError::Internal("destination account disappeared".into()))?;
    let max_receive = i64::MAX - dest_account.balance - account_liabilities(dest_account).buying;
    if max_receive < source_balance {
        return Ok(make_result(AccountMergeResultCode::DestFull));
    }

    // Transfer balance to destination
    if let Some(dest_acc) = state.get_account_mut(&dest_account_id) {
        dest_acc.balance += source_balance;
    }

    // Delete source account
    state.delete_account(source);

    Ok(OperationResult::OpInner(OperationResultTr::AccountMerge(
        AccountMergeResult::Success(source_balance),
    )))
}

fn make_result(code: AccountMergeResultCode) -> OperationResult {
    let result = match code {
        AccountMergeResultCode::Success => unreachable!("success handled in execute_account_merge"),
        AccountMergeResultCode::Malformed => AccountMergeResult::Malformed,
        AccountMergeResultCode::NoAccount => AccountMergeResult::NoAccount,
        AccountMergeResultCode::ImmutableSet => AccountMergeResult::ImmutableSet,
        AccountMergeResultCode::HasSubEntries => AccountMergeResult::HasSubEntries,
        AccountMergeResultCode::SeqnumTooFar => AccountMergeResult::SeqnumTooFar,
        AccountMergeResultCode::DestFull => AccountMergeResult::DestFull,
        AccountMergeResultCode::IsSponsor => AccountMergeResult::IsSponsor,
    };
    OperationResult::OpInner(OperationResultTr::AccountMerge(result))
}

fn account_liabilities(account: &AccountEntry) -> Liabilities {
    match &account.ext {
        AccountEntryExt::V0 => Liabilities {
            buying: 0,
            selling: 0,
        },
        AccountEntryExt::V1(v1) => v1.liabilities.clone(),
    }
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

    fn create_test_account_with_liabilities(
        account_id: AccountId,
        balance: i64,
        buying: i64,
        selling: i64,
    ) -> AccountEntry {
        let mut entry = create_test_account(account_id, balance);
        entry.ext = AccountEntryExt::V1(AccountEntryExtensionV1 {
            liabilities: Liabilities { buying, selling },
            ext: AccountEntryExtensionV1Ext::V0,
        });
        entry
    }

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    #[test]
    fn test_account_merge_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);

        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 50_000_000));

        let result = execute_account_merge(
            &create_test_muxed_account(1),
            &source_id,
            &mut state,
            &context,
        );
        let result = result.expect("account merge");
        match result {
            OperationResult::OpInner(OperationResultTr::AccountMerge(AccountMergeResult::Success(amount))) => {
                assert_eq!(amount, 100_000_000);
            }
            other => panic!("unexpected result: {:?}", other),
        }

        // Source should be gone
        assert!(state.get_account(&source_id).is_none());

        // Dest should have combined balance
        assert_eq!(state.get_account(&dest_id).unwrap().balance, 150_000_000);
    }

    #[test]
    fn test_account_merge_malformed_self() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let result = execute_account_merge(
            &create_test_muxed_account(0),
            &source_id,
            &mut state,
            &context,
        )
        .unwrap();

        match result {
            OperationResult::OpInner(OperationResultTr::AccountMerge(r)) => {
                assert!(matches!(r, AccountMergeResult::Malformed));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_account_merge_dest_full() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);

        state.create_account(create_test_account(source_id.clone(), 100));
        state.create_account(create_test_account_with_liabilities(
            dest_id.clone(),
            i64::MAX - 50,
            60,
            0,
        ));

        let result = execute_account_merge(
            &create_test_muxed_account(1),
            &source_id,
            &mut state,
            &context,
        )
        .unwrap();

        match result {
            OperationResult::OpInner(OperationResultTr::AccountMerge(r)) => {
                assert!(matches!(r, AccountMergeResult::DestFull));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }
}
