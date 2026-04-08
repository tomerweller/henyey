//! Parity tests for ChangeTrust operation result codes.
//!
//! Covers gaps not exercised by inline unit tests:
//! - `TrustLineMissing` — not actually a result code returned by execute_change_trust
//! - `NotAuthMaintainLiabilities` — not returned by execute_change_trust either
//!
//! After analysis, ChangeTrust in Henyey does not return TrustLineMissing or
//! NotAuthMaintainLiabilities. These exist in the XDR but are handled via
//! other code paths (e.g., InvalidLimit for missing trustline on removal).
//! Tests document these findings.

use super::super::change_trust::execute_change_trust;
use super::assert_op_result;
use crate::state::LedgerStateManager;
use crate::test_utils::*;
use stellar_xdr::curr::*;

fn create_test_context() -> crate::validation::LedgerContext {
    crate::validation::LedgerContext::testnet(1, 1000)
}

/// ChangeTrust returns InvalidLimit (not TrustLineMissing) when trying to
/// remove a trustline that doesn't exist (limit=0 with no existing trustline).
/// The TrustLineMissing variant exists in XDR but is not used by this implementation.
#[test]
fn test_change_trust_remove_nonexistent_returns_invalid_limit() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let issuer_id = create_test_account_id(1);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

    let op = ChangeTrustOp {
        line: ChangeTrustAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_id,
        }),
        limit: 0, // Remove a trustline that doesn't exist
    };

    let result = execute_change_trust(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::ChangeTrust(ChangeTrustResult::InvalidLimit)
    );
}

/// ChangeTrust returns NotAuthMaintainLiabilities when creating a pool share
/// trustline and one of the underlying asset trustlines is not authorized
/// (lacks both AUTHORIZED_FLAG and AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG).
/// This is triggered by validate_pool_share_trustlines() in change_trust.rs.
#[test]
fn test_change_trust_not_auth_maintain_liabilities() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let issuer_a = create_test_account_id(1);
    let issuer_b = create_test_account_id(2);

    // Source needs plenty of balance for reserves
    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_a.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_b.clone(), 100_000_000));

    let asset_a = create_test_asset(b"AAA\0", issuer_a.clone());
    let asset_b = create_test_asset(b"BBB\0", issuer_b.clone());

    // Source has trustline for asset A — authorized
    state.create_trustline(create_test_trustline(
        source_id.clone(),
        create_test_trustline_asset(b"AAA\0", issuer_a),
        0,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    // Source has trustline for asset B — NOT authorized (flags=0)
    // This triggers NotAuthMaintainLiabilities when creating a pool share
    state.create_trustline(create_test_trustline(
        source_id.clone(),
        create_test_trustline_asset(b"BBB\0", issuer_b),
        0,
        1_000_000,
        0, // Not authorized — neither AUTHORIZED nor AUTHORIZED_TO_MAINTAIN_LIABILITIES
    ));

    // Try to create a pool share trustline for the A/B pool
    let pool_params = LiquidityPoolParameters::LiquidityPoolConstantProduct(
        LiquidityPoolConstantProductParameters {
            asset_a,
            asset_b,
            fee: LIQUIDITY_POOL_FEE_V18 as i32,
        },
    );

    let op = ChangeTrustOp {
        line: ChangeTrustAsset::PoolShare(pool_params),
        limit: 1_000_000,
    };

    let result = execute_change_trust(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::ChangeTrust(ChangeTrustResult::NotAuthMaintainLiabilities)
    );
}
