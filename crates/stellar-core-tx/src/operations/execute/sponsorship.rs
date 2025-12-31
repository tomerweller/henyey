//! Sponsorship operation execution.
//!
//! This module implements the execution logic for sponsorship operations:
//! - BeginSponsoringFutureReserves
//! - EndSponsoringFutureReserves
//! - RevokeSponsorship

use stellar_xdr::curr::{
    AccountId, BeginSponsoringFutureReservesOp, BeginSponsoringFutureReservesResult,
    BeginSponsoringFutureReservesResultCode, EndSponsoringFutureReservesResult,
    EndSponsoringFutureReservesResultCode, OperationResult, OperationResultTr,
    RevokeSponsorshipOp, RevokeSponsorshipResult, RevokeSponsorshipResultCode,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;

/// Execute a BeginSponsoringFutureReserves operation.
///
/// This operation marks the beginning of a sponsorship relationship where
/// the source account will pay reserves for entries created by the sponsored account.
///
/// Note: In a full implementation, this would require transaction-level state
/// to track the sponsorship stack. For now, we validate basic conditions.
pub fn execute_begin_sponsoring_future_reserves(
    op: &BeginSponsoringFutureReservesOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Check source account exists
    if state.get_account(source).is_none() {
        return Ok(make_begin_result(
            BeginSponsoringFutureReservesResultCode::Malformed,
        ));
    }

    // Check sponsored account exists
    if state.get_account(&op.sponsored_id).is_none() {
        return Ok(make_begin_result(
            BeginSponsoringFutureReservesResultCode::Malformed,
        ));
    }

    // Cannot sponsor yourself
    if source == &op.sponsored_id {
        return Ok(make_begin_result(
            BeginSponsoringFutureReservesResultCode::Malformed,
        ));
    }

    // In a full implementation:
    // 1. Check that there's no existing sponsorship being set up (recursive)
    // 2. Push the sponsorship onto the transaction's sponsorship stack
    // 3. The EndSponsoringFutureReserves must be called by the sponsored account

    Ok(make_begin_result(
        BeginSponsoringFutureReservesResultCode::Success,
    ))
}

/// Execute an EndSponsoringFutureReserves operation.
///
/// This operation ends a sponsorship relationship that was begun with
/// BeginSponsoringFutureReserves.
///
/// Note: In a full implementation, this would pop from the sponsorship stack.
pub fn execute_end_sponsoring_future_reserves(
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Check source account exists
    if state.get_account(source).is_none() {
        return Ok(make_end_result(
            EndSponsoringFutureReservesResultCode::NotSponsored,
        ));
    }

    // In a full implementation:
    // 1. Check that there's an active sponsorship on the stack
    // 2. Verify the source is the sponsored account
    // 3. Pop the sponsorship from the stack

    Ok(make_end_result(EndSponsoringFutureReservesResultCode::Success))
}

/// Execute a RevokeSponsorship operation.
///
/// This operation revokes sponsorship of a ledger entry, transferring
/// the reserve responsibility back to the entry owner.
pub fn execute_revoke_sponsorship(
    op: &RevokeSponsorshipOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    use stellar_xdr::curr::RevokeSponsorshipOp as RSO;

    // Check source account exists
    if state.get_account(source).is_none() {
        return Ok(make_revoke_result(RevokeSponsorshipResultCode::NotSponsor));
    }

    match op {
        RSO::LedgerEntry(ledger_key) => {
            // Check if the entry exists
            if state.get_entry(ledger_key).is_none() {
                return Ok(make_revoke_result(RevokeSponsorshipResultCode::DoesNotExist));
            }

            // In a full implementation:
            // 1. Check that the source is the current sponsor
            // 2. Transfer reserve responsibility to the entry owner
            // 3. Update the entry's ext field to remove sponsorship

            Ok(make_revoke_result(RevokeSponsorshipResultCode::Success))
        }
        RSO::Signer(signer_key) => {
            // Check if the account exists
            if state.get_account(&signer_key.account_id).is_none() {
                return Ok(make_revoke_result(RevokeSponsorshipResultCode::DoesNotExist));
            }

            // In a full implementation:
            // 1. Find the signer on the account
            // 2. Check that the source is the current sponsor
            // 3. Transfer reserve responsibility

            Ok(make_revoke_result(RevokeSponsorshipResultCode::Success))
        }
    }
}

/// Create a BeginSponsoringFutureReserves result.
fn make_begin_result(code: BeginSponsoringFutureReservesResultCode) -> OperationResult {
    let result = match code {
        BeginSponsoringFutureReservesResultCode::Success => {
            BeginSponsoringFutureReservesResult::Success
        }
        BeginSponsoringFutureReservesResultCode::Malformed => {
            BeginSponsoringFutureReservesResult::Malformed
        }
        BeginSponsoringFutureReservesResultCode::AlreadySponsored => {
            BeginSponsoringFutureReservesResult::AlreadySponsored
        }
        BeginSponsoringFutureReservesResultCode::Recursive => {
            BeginSponsoringFutureReservesResult::Recursive
        }
    };

    OperationResult::OpInner(OperationResultTr::BeginSponsoringFutureReserves(result))
}

/// Create an EndSponsoringFutureReserves result.
fn make_end_result(code: EndSponsoringFutureReservesResultCode) -> OperationResult {
    let result = match code {
        EndSponsoringFutureReservesResultCode::Success => EndSponsoringFutureReservesResult::Success,
        EndSponsoringFutureReservesResultCode::NotSponsored => {
            EndSponsoringFutureReservesResult::NotSponsored
        }
    };

    OperationResult::OpInner(OperationResultTr::EndSponsoringFutureReserves(result))
}

/// Create a RevokeSponsorship result.
fn make_revoke_result(code: RevokeSponsorshipResultCode) -> OperationResult {
    let result = match code {
        RevokeSponsorshipResultCode::Success => RevokeSponsorshipResult::Success,
        RevokeSponsorshipResultCode::DoesNotExist => RevokeSponsorshipResult::DoesNotExist,
        RevokeSponsorshipResultCode::NotSponsor => RevokeSponsorshipResult::NotSponsor,
        RevokeSponsorshipResultCode::LowReserve => RevokeSponsorshipResult::LowReserve,
        RevokeSponsorshipResultCode::OnlyTransferable => RevokeSponsorshipResult::OnlyTransferable,
        RevokeSponsorshipResultCode::Malformed => RevokeSponsorshipResult::Malformed,
    };

    OperationResult::OpInner(OperationResultTr::RevokeSponsorship(result))
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
    fn test_begin_sponsoring_self() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = BeginSponsoringFutureReservesOp {
            sponsored_id: source_id.clone(), // Sponsor self
        };

        let result =
            execute_begin_sponsoring_future_reserves(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::BeginSponsoringFutureReserves(r)) => {
                assert!(matches!(r, BeginSponsoringFutureReservesResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_begin_sponsoring_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let sponsor_id = create_test_account_id(0);
        let sponsored_id = create_test_account_id(1);
        state.create_account(create_test_account(sponsor_id.clone(), 100_000_000));
        state.create_account(create_test_account(sponsored_id.clone(), 10_000_000));

        let op = BeginSponsoringFutureReservesOp {
            sponsored_id: sponsored_id.clone(),
        };

        let result =
            execute_begin_sponsoring_future_reserves(&op, &sponsor_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::BeginSponsoringFutureReserves(r)) => {
                assert!(matches!(r, BeginSponsoringFutureReservesResult::Success));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_end_sponsoring_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let result = execute_end_sponsoring_future_reserves(&source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::EndSponsoringFutureReserves(r)) => {
                assert!(matches!(r, EndSponsoringFutureReservesResult::Success));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_revoke_sponsorship_not_exists() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let nonexistent_id = create_test_account_id(99);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = RevokeSponsorshipOp::LedgerEntry(LedgerKey::Account(LedgerKeyAccount {
            account_id: nonexistent_id,
        }));

        let result = execute_revoke_sponsorship(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::RevokeSponsorship(r)) => {
                assert!(matches!(r, RevokeSponsorshipResult::DoesNotExist));
            }
            _ => panic!("Unexpected result type"),
        }
    }
}
