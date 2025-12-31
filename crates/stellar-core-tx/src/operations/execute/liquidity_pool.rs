//! Liquidity Pool operation execution.
//!
//! This module implements the execution logic for:
//! - LiquidityPoolDeposit
//! - LiquidityPoolWithdraw

use stellar_xdr::curr::{
    AccountId, Asset, LiquidityPoolDepositOp, LiquidityPoolDepositResult,
    LiquidityPoolDepositResultCode, LiquidityPoolEntry, LiquidityPoolWithdrawOp,
    LiquidityPoolWithdrawResult, LiquidityPoolWithdrawResultCode, OperationResult,
    OperationResultTr, PoolId, TrustLineAsset,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;

/// Execute a LiquidityPoolDeposit operation.
///
/// This operation deposits assets into a liquidity pool in exchange for
/// pool shares.
pub fn execute_liquidity_pool_deposit(
    op: &LiquidityPoolDepositOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Validate amounts
    if op.max_amount_a <= 0 || op.max_amount_b <= 0 {
        return Ok(make_deposit_result(LiquidityPoolDepositResultCode::Malformed));
    }

    // Check min/max price bounds
    if op.min_price.n <= 0 || op.min_price.d <= 0 || op.max_price.n <= 0 || op.max_price.d <= 0 {
        return Ok(make_deposit_result(LiquidityPoolDepositResultCode::Malformed));
    }

    // Get the liquidity pool
    let pool = match state.get_liquidity_pool(&op.liquidity_pool_id) {
        Some(p) => p.clone(),
        None => {
            return Ok(make_deposit_result(LiquidityPoolDepositResultCode::NoTrust));
        }
    };

    // Get pool parameters
    let (asset_a, asset_b, reserve_a, reserve_b, total_shares, _fee) = match &pool.body {
        stellar_xdr::curr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => {
            let params = &cp.params;
            (
                params.asset_a.clone(),
                params.asset_b.clone(),
                cp.reserve_a,
                cp.reserve_b,
                cp.total_pool_shares,
                params.fee,
            )
        }
    };

    // Check source has pool share trustline
    let pool_share_asset = TrustLineAsset::PoolShare(op.liquidity_pool_id.clone());
    if state
        .get_trustline_by_trustline_asset(source, &pool_share_asset)
        .is_none()
    {
        return Ok(make_deposit_result(LiquidityPoolDepositResultCode::NoTrust));
    }

    // Check source has trustlines for both assets (unless native)
    if !matches!(&asset_a, Asset::Native) {
        if state.get_trustline(source, &asset_a).is_none() {
            return Ok(make_deposit_result(LiquidityPoolDepositResultCode::NoTrust));
        }
    }

    if !matches!(&asset_b, Asset::Native) {
        if state.get_trustline(source, &asset_b).is_none() {
            return Ok(make_deposit_result(LiquidityPoolDepositResultCode::NoTrust));
        }
    }

    // Calculate deposit amounts based on current pool ratio
    let (deposit_a, deposit_b, shares_received) = if total_shares == 0 {
        // First deposit - use provided amounts directly
        let shares = calculate_initial_shares(op.max_amount_a, op.max_amount_b);
        (op.max_amount_a, op.max_amount_b, shares)
    } else {
        // Calculate based on existing pool ratio
        calculate_deposit_amounts(
            reserve_a,
            reserve_b,
            total_shares,
            op.max_amount_a,
            op.max_amount_b,
        )
    };

    // Check price bounds
    let current_price_n = deposit_a as i128;
    let current_price_d = deposit_b as i128;
    let min_price_value = op.min_price.n as i128 * current_price_d;
    let min_price_compare = current_price_n * op.min_price.d as i128;
    let max_price_value = op.max_price.n as i128 * current_price_d;
    let max_price_compare = current_price_n * op.max_price.d as i128;

    if min_price_compare < min_price_value || max_price_compare > max_price_value {
        return Ok(make_deposit_result(LiquidityPoolDepositResultCode::BadPrice));
    }

    // Deduct assets from source
    if matches!(&asset_a, Asset::Native) {
        if let Some(account) = state.get_account_mut(source) {
            if account.balance < deposit_a {
                return Ok(make_deposit_result(
                    LiquidityPoolDepositResultCode::Underfunded,
                ));
            }
            account.balance -= deposit_a;
        }
    } else {
        if let Some(tl) = state.get_trustline_mut(source, &asset_a) {
            if tl.balance < deposit_a {
                return Ok(make_deposit_result(
                    LiquidityPoolDepositResultCode::Underfunded,
                ));
            }
            tl.balance -= deposit_a;
        }
    }

    if matches!(&asset_b, Asset::Native) {
        if let Some(account) = state.get_account_mut(source) {
            if account.balance < deposit_b {
                return Ok(make_deposit_result(
                    LiquidityPoolDepositResultCode::Underfunded,
                ));
            }
            account.balance -= deposit_b;
        }
    } else {
        if let Some(tl) = state.get_trustline_mut(source, &asset_b) {
            if tl.balance < deposit_b {
                return Ok(make_deposit_result(
                    LiquidityPoolDepositResultCode::Underfunded,
                ));
            }
            tl.balance -= deposit_b;
        }
    }

    // Credit pool shares to source
    if let Some(tl) = state.get_trustline_by_trustline_asset_mut(source, &pool_share_asset) {
        tl.balance += shares_received;
    }

    // Update pool reserves
    if let Some(pool_mut) = state.get_liquidity_pool_mut(&op.liquidity_pool_id) {
        match &mut pool_mut.body {
            stellar_xdr::curr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => {
                cp.reserve_a += deposit_a;
                cp.reserve_b += deposit_b;
                cp.total_pool_shares += shares_received;
            }
        }
    }

    Ok(make_deposit_result(LiquidityPoolDepositResultCode::Success))
}

/// Execute a LiquidityPoolWithdraw operation.
///
/// This operation withdraws assets from a liquidity pool by redeeming
/// pool shares.
pub fn execute_liquidity_pool_withdraw(
    op: &LiquidityPoolWithdrawOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Validate amounts
    if op.amount <= 0 {
        return Ok(make_withdraw_result(
            LiquidityPoolWithdrawResultCode::Malformed,
        ));
    }

    if op.min_amount_a < 0 || op.min_amount_b < 0 {
        return Ok(make_withdraw_result(
            LiquidityPoolWithdrawResultCode::Malformed,
        ));
    }

    // Get the liquidity pool
    let pool = match state.get_liquidity_pool(&op.liquidity_pool_id) {
        Some(p) => p.clone(),
        None => {
            return Ok(make_withdraw_result(LiquidityPoolWithdrawResultCode::NoTrust));
        }
    };

    // Get pool parameters
    let (asset_a, asset_b, reserve_a, reserve_b, total_shares) = match &pool.body {
        stellar_xdr::curr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => {
            let params = &cp.params;
            (
                params.asset_a.clone(),
                params.asset_b.clone(),
                cp.reserve_a,
                cp.reserve_b,
                cp.total_pool_shares,
            )
        }
    };

    // Check source has pool share trustline with sufficient balance
    let pool_share_asset = TrustLineAsset::PoolShare(op.liquidity_pool_id.clone());
    let shares_balance = match state.get_trustline_by_trustline_asset(source, &pool_share_asset) {
        Some(tl) => tl.balance,
        None => {
            return Ok(make_withdraw_result(LiquidityPoolWithdrawResultCode::NoTrust));
        }
    };

    if shares_balance < op.amount {
        return Ok(make_withdraw_result(
            LiquidityPoolWithdrawResultCode::Underfunded,
        ));
    }

    // Calculate withdrawal amounts
    let withdraw_a = (reserve_a as i128 * op.amount as i128 / total_shares as i128) as i64;
    let withdraw_b = (reserve_b as i128 * op.amount as i128 / total_shares as i128) as i64;

    // Check minimum amounts
    if withdraw_a < op.min_amount_a || withdraw_b < op.min_amount_b {
        return Ok(make_withdraw_result(
            LiquidityPoolWithdrawResultCode::UnderMinimum,
        ));
    }

    // Deduct pool shares from source
    if let Some(tl) = state.get_trustline_by_trustline_asset_mut(source, &pool_share_asset) {
        tl.balance -= op.amount;
    }

    // Credit assets to source
    if matches!(&asset_a, Asset::Native) {
        if let Some(account) = state.get_account_mut(source) {
            account.balance += withdraw_a;
        }
    } else {
        if let Some(tl) = state.get_trustline_mut(source, &asset_a) {
            tl.balance += withdraw_a;
        } else {
            return Ok(make_withdraw_result(LiquidityPoolWithdrawResultCode::NoTrust));
        }
    }

    if matches!(&asset_b, Asset::Native) {
        if let Some(account) = state.get_account_mut(source) {
            account.balance += withdraw_b;
        }
    } else {
        if let Some(tl) = state.get_trustline_mut(source, &asset_b) {
            tl.balance += withdraw_b;
        } else {
            return Ok(make_withdraw_result(LiquidityPoolWithdrawResultCode::NoTrust));
        }
    }

    // Update pool reserves
    if let Some(pool_mut) = state.get_liquidity_pool_mut(&op.liquidity_pool_id) {
        match &mut pool_mut.body {
            stellar_xdr::curr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => {
                cp.reserve_a -= withdraw_a;
                cp.reserve_b -= withdraw_b;
                cp.total_pool_shares -= op.amount;
            }
        }
    }

    Ok(make_withdraw_result(LiquidityPoolWithdrawResultCode::Success))
}

/// Calculate initial pool shares for first deposit.
fn calculate_initial_shares(amount_a: i64, amount_b: i64) -> i64 {
    // Use geometric mean for initial share calculation
    let product = (amount_a as f64) * (amount_b as f64);
    product.sqrt() as i64
}

/// Calculate deposit amounts to maintain pool ratio.
fn calculate_deposit_amounts(
    reserve_a: i64,
    reserve_b: i64,
    total_shares: i64,
    max_amount_a: i64,
    max_amount_b: i64,
) -> (i64, i64, i64) {
    // Calculate based on maintaining constant product
    let ratio_a = max_amount_a as i128 * reserve_b as i128;
    let ratio_b = max_amount_b as i128 * reserve_a as i128;

    let (deposit_a, deposit_b) = if ratio_a <= ratio_b {
        // Use all of max_amount_a
        let deposit_b = (max_amount_a as i128 * reserve_b as i128 / reserve_a as i128) as i64;
        (max_amount_a, deposit_b)
    } else {
        // Use all of max_amount_b
        let deposit_a = (max_amount_b as i128 * reserve_a as i128 / reserve_b as i128) as i64;
        (deposit_a, max_amount_b)
    };

    // Calculate shares received
    let shares = (deposit_a as i128 * total_shares as i128 / reserve_a as i128) as i64;

    (deposit_a, deposit_b, shares)
}

/// Create a LiquidityPoolDeposit result.
fn make_deposit_result(code: LiquidityPoolDepositResultCode) -> OperationResult {
    let result = match code {
        LiquidityPoolDepositResultCode::Success => LiquidityPoolDepositResult::Success,
        LiquidityPoolDepositResultCode::Malformed => LiquidityPoolDepositResult::Malformed,
        LiquidityPoolDepositResultCode::NoTrust => LiquidityPoolDepositResult::NoTrust,
        LiquidityPoolDepositResultCode::NotAuthorized => LiquidityPoolDepositResult::NotAuthorized,
        LiquidityPoolDepositResultCode::Underfunded => LiquidityPoolDepositResult::Underfunded,
        LiquidityPoolDepositResultCode::LineFull => LiquidityPoolDepositResult::LineFull,
        LiquidityPoolDepositResultCode::BadPrice => LiquidityPoolDepositResult::BadPrice,
        LiquidityPoolDepositResultCode::PoolFull => LiquidityPoolDepositResult::PoolFull,
    };

    OperationResult::OpInner(OperationResultTr::LiquidityPoolDeposit(result))
}

/// Create a LiquidityPoolWithdraw result.
fn make_withdraw_result(code: LiquidityPoolWithdrawResultCode) -> OperationResult {
    let result = match code {
        LiquidityPoolWithdrawResultCode::Success => LiquidityPoolWithdrawResult::Success,
        LiquidityPoolWithdrawResultCode::Malformed => LiquidityPoolWithdrawResult::Malformed,
        LiquidityPoolWithdrawResultCode::NoTrust => LiquidityPoolWithdrawResult::NoTrust,
        LiquidityPoolWithdrawResultCode::Underfunded => LiquidityPoolWithdrawResult::Underfunded,
        LiquidityPoolWithdrawResultCode::LineFull => LiquidityPoolWithdrawResult::LineFull,
        LiquidityPoolWithdrawResultCode::UnderMinimum => LiquidityPoolWithdrawResult::UnderMinimum,
    };

    OperationResult::OpInner(OperationResultTr::LiquidityPoolWithdraw(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    #[test]
    fn test_liquidity_pool_deposit_no_pool() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);

        let op = LiquidityPoolDepositOp {
            liquidity_pool_id: PoolId(Hash([0u8; 32])),
            max_amount_a: 1000,
            max_amount_b: 1000,
            min_price: Price { n: 1, d: 2 },
            max_price: Price { n: 2, d: 1 },
        };

        let result = execute_liquidity_pool_deposit(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::LiquidityPoolDeposit(r)) => {
                assert!(matches!(r, LiquidityPoolDepositResult::NoTrust));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_liquidity_pool_withdraw_no_pool() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);

        let op = LiquidityPoolWithdrawOp {
            liquidity_pool_id: PoolId(Hash([0u8; 32])),
            amount: 100,
            min_amount_a: 0,
            min_amount_b: 0,
        };

        let result = execute_liquidity_pool_withdraw(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::LiquidityPoolWithdraw(r)) => {
                assert!(matches!(r, LiquidityPoolWithdrawResult::NoTrust));
            }
            _ => panic!("Unexpected result type"),
        }
    }
}
