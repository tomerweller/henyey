//! AccountMerge operation execution.

use stellar_xdr::curr::{
    AccountId, AccountMergeResult, AccountMergeResultCode, MuxedAccount, OperationResult,
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

    // Get source account
    let source_account = match state.get_account(source) {
        Some(account) => account,
        None => return Err(TxError::SourceAccountNotFound),
    };

    // Check source has no sub-entries
    if source_account.num_sub_entries > 0 {
        return Ok(make_result(AccountMergeResultCode::HasSubEntries));
    }

    // Check source is not immutable
    const AUTH_IMMUTABLE_FLAG: u32 = 0x4;
    if source_account.flags & AUTH_IMMUTABLE_FLAG != 0 {
        return Ok(make_result(AccountMergeResultCode::ImmutableSet));
    }

    let source_balance = source_account.balance;

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
        AccountMergeResultCode::Success => return OperationResult::OpNotSupported,
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
        assert!(result.is_ok());

        // Source should be gone
        assert!(state.get_account(&source_id).is_none());

        // Dest should have combined balance
        assert_eq!(state.get_account(&dest_id).unwrap().balance, 150_000_000);
    }
}
