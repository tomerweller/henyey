//! Parity tests for CreateClaimableBalance operation result codes.
//!
//! Covers gap not exercised by inline unit tests:
//! - `Success` — basic successful creation with native asset

use super::super::claimable_balance::execute_create_claimable_balance;
use super::super::TxIdentity;
use crate::state::LedgerStateManager;
use crate::test_utils::*;
use stellar_xdr::curr::*;

fn create_test_context() -> crate::validation::LedgerContext {
    crate::validation::LedgerContext::testnet(1, 1000)
}

/// CreateClaimableBalance succeeds with a native asset and a single unconditional claimant.
#[test]
fn test_create_claimable_balance_success_native() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let claimant_id = create_test_account_id(1);

    // Source needs enough balance: min_balance (10M) + amount (1M) + sponsorship reserve
    state.create_account(create_test_account(source_id.clone(), 100_000_000));

    let op = CreateClaimableBalanceOp {
        asset: Asset::Native,
        amount: 1_000_000,
        claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: claimant_id,
            predicate: ClaimPredicate::Unconditional,
        })]
        .try_into()
        .unwrap(),
    };

    let tx_id = TxIdentity {
        source_id: &source_id,
        seq: 1,
        op_index: 0,
    };

    let result = execute_create_claimable_balance(&op, &source_id, &tx_id, &mut state, &context);
    // Success carries a ClaimableBalanceId
    let result = result.expect("should not error");
    match &result {
        OperationResult::OpInner(OperationResultTr::CreateClaimableBalance(
            CreateClaimableBalanceResult::Success(_id),
        )) => {} // OK
        other => panic!("expected CreateClaimableBalance::Success, got {:?}", other),
    }
}
