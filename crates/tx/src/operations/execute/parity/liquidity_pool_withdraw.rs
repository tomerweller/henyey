//! Parity tests for LiquidityPoolWithdraw operation result codes.
//!
//! Covers gaps not exercised by inline unit tests:
//! - `Malformed` — invalid amounts
//! - `TrustlineFrozen` — frozen key check (CAP-77)

use super::super::liquidity_pool::execute_liquidity_pool_withdraw;
use super::assert_op_result;
use crate::state::LedgerStateManager;
use crate::test_utils::*;
use stellar_xdr::curr::*;

fn create_test_context() -> crate::validation::LedgerContext {
    crate::validation::LedgerContext::testnet(1, 1000)
}

/// LiquidityPoolWithdraw returns Malformed when amount is zero.
#[test]
fn test_liquidity_pool_withdraw_malformed_zero_amount() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    state.create_account(create_test_account(source_id.clone(), 100_000_000));

    let op = LiquidityPoolWithdrawOp {
        liquidity_pool_id: PoolId(Hash([0; 32])),
        amount: 0, // Invalid
        min_amount_a: 0,
        min_amount_b: 0,
    };

    let result = execute_liquidity_pool_withdraw(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::LiquidityPoolWithdraw(LiquidityPoolWithdrawResult::Malformed)
    );
}

/// LiquidityPoolWithdraw returns Malformed when min_amount_a is negative.
#[test]
fn test_liquidity_pool_withdraw_malformed_negative_min_amount() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    state.create_account(create_test_account(source_id.clone(), 100_000_000));

    let op = LiquidityPoolWithdrawOp {
        liquidity_pool_id: PoolId(Hash([0; 32])),
        amount: 1000,
        min_amount_a: -1, // Invalid
        min_amount_b: 0,
    };

    let result = execute_liquidity_pool_withdraw(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::LiquidityPoolWithdraw(LiquidityPoolWithdrawResult::Malformed)
    );
}

/// TrustlineFrozen requires CAP-77 frozen key configuration which is complex to set up.
#[test]
#[ignore]
fn test_liquidity_pool_withdraw_trustline_frozen() {
    // TODO(#1126): Requires setting up frozen_key_config with specific frozen keys
    // in the LedgerContext. This is a CAP-77 feature that needs dedicated test
    // infrastructure for frozen key simulation.
    todo!()
}
