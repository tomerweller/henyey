//! Parity tests for BeginSponsoringFutureReserves operation result codes.
//!
//! Covers gap not exercised by inline unit tests:
//! - `Recursive` — source is already sponsored or sponsored_id is already sponsoring

use super::super::sponsorship::execute_begin_sponsoring_future_reserves;
use super::assert_op_result;
use crate::state::LedgerStateManager;
use crate::test_utils::*;
use stellar_xdr::curr::*;

fn create_test_context() -> crate::validation::LedgerContext {
    crate::validation::LedgerContext::testnet(1, 1000)
}

/// BeginSponsoring returns Recursive when the source account is already being sponsored.
/// stellar-core checks `is_sponsored(source) || is_sponsoring(sponsored_id)`.
#[test]
fn test_begin_sponsoring_recursive_source_already_sponsored() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let _context = create_test_context();

    let account_a = create_test_account_id(0);
    let account_b = create_test_account_id(1);
    let account_c = create_test_account_id(2);

    state.create_account(create_test_account(account_a.clone(), 100_000_000));
    state.create_account(create_test_account(account_b.clone(), 100_000_000));
    state.create_account(create_test_account(account_c.clone(), 100_000_000));

    // C sponsors A — so A is_sponsored
    state.push_sponsorship(account_c.clone(), account_a.clone());

    // Now A tries to sponsor B. Since A is_sponsored, this is recursive.
    let op = BeginSponsoringFutureReservesOp {
        sponsored_id: account_b.clone(),
    };

    let result = execute_begin_sponsoring_future_reserves(&op, &account_a, &mut state, &_context);
    assert_op_result!(
        result,
        OperationResultTr::BeginSponsoringFutureReserves(
            BeginSponsoringFutureReservesResult::Recursive
        )
    );
}

/// BeginSponsoring returns Recursive when the sponsored account is already sponsoring someone.
#[test]
fn test_begin_sponsoring_recursive_sponsored_already_sponsoring() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let _context = create_test_context();

    let account_a = create_test_account_id(0);
    let account_b = create_test_account_id(1);
    let account_c = create_test_account_id(2);

    state.create_account(create_test_account(account_a.clone(), 100_000_000));
    state.create_account(create_test_account(account_b.clone(), 100_000_000));
    state.create_account(create_test_account(account_c.clone(), 100_000_000));

    // B sponsors C — so B is_sponsoring
    state.push_sponsorship(account_b.clone(), account_c.clone());

    // A tries to sponsor B. Since B is_sponsoring, this is recursive.
    let op = BeginSponsoringFutureReservesOp {
        sponsored_id: account_b.clone(),
    };

    let result = execute_begin_sponsoring_future_reserves(&op, &account_a, &mut state, &_context);
    assert_op_result!(
        result,
        OperationResultTr::BeginSponsoringFutureReserves(
            BeginSponsoringFutureReservesResult::Recursive
        )
    );
}
