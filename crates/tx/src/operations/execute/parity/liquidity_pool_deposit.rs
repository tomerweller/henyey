//! Parity tests for LiquidityPoolDeposit operation result codes.
//!
//! Covers gaps not exercised by inline unit tests:
//! - `Malformed` — invalid amounts or price bounds
//! - `PoolFull` — reserve overflow (unreachable in current implementation)

use super::super::liquidity_pool::execute_liquidity_pool_deposit;
use super::assert_op_result;
use crate::state::LedgerStateManager;
use crate::test_utils::*;
use stellar_xdr::curr::*;

fn create_test_context() -> crate::validation::LedgerContext {
    crate::validation::LedgerContext::testnet(1, 1000)
}

/// LiquidityPoolDeposit returns Malformed when max_amount_a is zero or negative.
#[test]
fn test_liquidity_pool_deposit_malformed_zero_amount() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    state.create_account(create_test_account(source_id.clone(), 100_000_000));

    let op = LiquidityPoolDepositOp {
        liquidity_pool_id: PoolId(Hash([0; 32])),
        max_amount_a: 0, // Invalid
        max_amount_b: 1000,
        min_price: Price { n: 1, d: 1 },
        max_price: Price { n: 1, d: 1 },
    };

    let result = execute_liquidity_pool_deposit(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::LiquidityPoolDeposit(LiquidityPoolDepositResult::Malformed)
    );
}

/// LiquidityPoolDeposit returns Malformed when min_price has zero denominator.
#[test]
fn test_liquidity_pool_deposit_malformed_invalid_price() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    state.create_account(create_test_account(source_id.clone(), 100_000_000));

    let op = LiquidityPoolDepositOp {
        liquidity_pool_id: PoolId(Hash([0; 32])),
        max_amount_a: 1000,
        max_amount_b: 1000,
        min_price: Price { n: 1, d: 0 }, // Invalid
        max_price: Price { n: 1, d: 1 },
    };

    let result = execute_liquidity_pool_deposit(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::LiquidityPoolDeposit(LiquidityPoolDepositResult::Malformed)
    );
}

/// LiquidityPoolDeposit returns Malformed when min_price > max_price.
#[test]
fn test_liquidity_pool_deposit_malformed_min_exceeds_max_price() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    state.create_account(create_test_account(source_id.clone(), 100_000_000));

    let op = LiquidityPoolDepositOp {
        liquidity_pool_id: PoolId(Hash([0; 32])),
        max_amount_a: 1000,
        max_amount_b: 1000,
        min_price: Price { n: 2, d: 1 }, // 2.0
        max_price: Price { n: 1, d: 1 }, // 1.0 -- less than min
    };

    let result = execute_liquidity_pool_deposit(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::LiquidityPoolDeposit(LiquidityPoolDepositResult::Malformed)
    );
}

/// PoolFull is defined in XDR but not returned by the current implementation.
/// Reserve overflow is handled by LineFull or checked via i64 arithmetic limits.
#[test]
#[ignore]
fn test_liquidity_pool_deposit_pool_full() {
    // TODO(#1126): PoolFull exists in XDR but may be unreachable in the current
    // implementation. Needs investigation to determine if this is dead code.
    todo!()
}
