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

/// LiquidityPoolWithdraw returns TrustlineFrozen when one of the pool's
/// asset trustlines is frozen via CAP-77 frozen key configuration.
#[test]
fn test_liquidity_pool_withdraw_trustline_frozen() {
    let mut state = LedgerStateManager::new(5_000_000, 100);

    let source_id = create_test_account_id(0);
    let issuer_a = create_test_account_id(1);
    let issuer_b = create_test_account_id(2);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_a.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_b.clone(), 100_000_000));

    let asset_a = create_test_asset(b"AAA\0", issuer_a.clone());
    let asset_b = create_test_asset(b"BBB\0", issuer_b.clone());

    // Source has authorized trustlines for both assets
    state.create_trustline(create_test_trustline(
        source_id.clone(),
        create_test_trustline_asset(b"AAA\0", issuer_a),
        0,
        10_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));
    state.create_trustline(create_test_trustline(
        source_id.clone(),
        create_test_trustline_asset(b"BBB\0", issuer_b),
        0,
        10_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    // Create pool with reserves and shares
    let pool_id = PoolId(Hash([99; 32]));
    state.create_liquidity_pool(stellar_xdr::curr::LiquidityPoolEntry {
        liquidity_pool_id: pool_id.clone(),
        body: stellar_xdr::curr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(
            stellar_xdr::curr::LiquidityPoolEntryConstantProduct {
                params: stellar_xdr::curr::LiquidityPoolConstantProductParameters {
                    asset_a: asset_a.clone(),
                    asset_b: asset_b.clone(),
                    fee: LIQUIDITY_POOL_FEE_V18 as i32,
                },
                reserve_a: 10_000,
                reserve_b: 10_000,
                total_pool_shares: 10_000,
                pool_shares_trust_line_count: 1,
            },
        ),
    });

    // Source has pool share trustline with balance
    let pool_share_asset = TrustLineAsset::PoolShare(pool_id.clone());
    state.create_trustline(create_test_trustline(
        source_id.clone(),
        pool_share_asset,
        1_000, // has shares
        10_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    // Freeze source's trustline for asset_a via CAP-77
    let frozen_key = crate::frozen_keys::trustline_key(&source_id, &asset_a);
    let frozen_key_bytes = stellar_xdr::curr::WriteXdr::to_xdr(&frozen_key, Limits::none())
        .expect("encode frozen key");

    let mut context = crate::validation::LedgerContext::testnet(1, 1000);
    context.frozen_key_config =
        crate::frozen_keys::FrozenKeyConfig::new(vec![frozen_key_bytes], vec![]);

    let op = LiquidityPoolWithdrawOp {
        liquidity_pool_id: pool_id,
        amount: 100,
        min_amount_a: 0,
        min_amount_b: 0,
    };

    let result = execute_liquidity_pool_withdraw(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::LiquidityPoolWithdraw(LiquidityPoolWithdrawResult::TrustlineFrozen)
    );
}
