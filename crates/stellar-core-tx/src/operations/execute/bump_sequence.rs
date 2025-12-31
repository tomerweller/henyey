//! BumpSequence operation execution.

use stellar_xdr::curr::{
    AccountId, BumpSequenceOp, BumpSequenceResult, BumpSequenceResultCode, OperationResult,
    OperationResultTr,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::{Result, TxError};

/// Execute a BumpSequence operation.
pub fn execute_bump_sequence(
    op: &BumpSequenceOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Get source account
    let source_account = state
        .get_account_mut(source)
        .ok_or(TxError::SourceAccountNotFound)?;

    // Only bump if new sequence is higher
    if op.bump_to.0 > source_account.seq_num.0 {
        source_account.seq_num.0 = op.bump_to.0;
    }

    Ok(make_result(BumpSequenceResultCode::Success))
}

fn make_result(code: BumpSequenceResultCode) -> OperationResult {
    let result = match code {
        BumpSequenceResultCode::Success => BumpSequenceResult::Success,
        BumpSequenceResultCode::BadSeq => BumpSequenceResult::BadSeq,
    };
    OperationResult::OpInner(OperationResultTr::BumpSequence(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    fn create_test_account(account_id: AccountId, balance: i64, seq_num: i64) -> AccountEntry {
        AccountEntry {
            account_id,
            balance,
            seq_num: SequenceNumber(seq_num),
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
    fn test_bump_sequence_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000, 100));

        let op = BumpSequenceOp {
            bump_to: SequenceNumber(200),
        };

        let result = execute_bump_sequence(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        // Verify sequence was bumped
        assert_eq!(state.get_account(&source_id).unwrap().seq_num.0, 200);
    }

    #[test]
    fn test_bump_sequence_no_effect() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000, 100));

        let op = BumpSequenceOp {
            bump_to: SequenceNumber(50), // Lower than current
        };

        let result = execute_bump_sequence(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        // Verify sequence was NOT changed
        assert_eq!(state.get_account(&source_id).unwrap().seq_num.0, 100);
    }
}
