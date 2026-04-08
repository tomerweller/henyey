//! Parity tests for ClaimClaimableBalance operation result codes.
//!
//! Covers gap not exercised by inline unit tests:
//! - `CannotClaim` — source is not a valid claimant or predicate doesn't match

use super::super::claimable_balance::execute_claim_claimable_balance;
use super::assert_op_result;
use crate::state::LedgerStateManager;
use crate::test_utils::*;
use stellar_xdr::curr::*;

fn create_test_context() -> crate::validation::LedgerContext {
    crate::validation::LedgerContext::testnet(1, 1000)
}

/// ClaimClaimableBalance returns CannotClaim when the source account is not
/// listed as a claimant in the claimable balance entry.
#[test]
fn test_claim_claimable_balance_cannot_claim_not_a_claimant() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let claimer_id = create_test_account_id(0); // NOT in claimant list
    let actual_claimant_id = create_test_account_id(1);

    state.create_account(create_test_account(claimer_id.clone(), 100_000_000));
    state.create_account(create_test_account(actual_claimant_id.clone(), 100_000_000));

    // Create a claimable balance that lists actual_claimant_id, not claimer_id
    let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([42; 32]));
    let cb_entry = ClaimableBalanceEntry {
        balance_id: balance_id.clone(),
        claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: actual_claimant_id,
            predicate: ClaimPredicate::Unconditional,
        })]
        .try_into()
        .unwrap(),
        asset: Asset::Native,
        amount: 1_000_000,
        ext: ClaimableBalanceEntryExt::V0,
    };
    state.create_claimable_balance(cb_entry);

    let op = ClaimClaimableBalanceOp {
        balance_id: balance_id.clone(),
    };

    // claimer_id is not in the claimant list, should return CannotClaim
    let result = execute_claim_claimable_balance(&op, &claimer_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::ClaimClaimableBalance(ClaimClaimableBalanceResult::CannotClaim)
    );
}
