//! Parity tests for Payment operation result codes.
//!
//! Covers gaps not exercised by inline unit tests:
//! - `SrcNoTrust` — source has no trustline for a credit asset
//! - `NoIssuer`   — asset issuer account does not exist in the ledger

use super::super::payment::execute_payment;
use super::assert_op_result;
use crate::state::LedgerStateManager;
use crate::test_utils::*;
use stellar_xdr::curr::*;

/// Payment of a credit asset fails with `SrcNoTrust` when the source account
/// has no trustline for the asset being sent, even though the destination does.
#[test]
fn test_payment_src_no_trust() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(1);
    let dest_id = create_test_account_id(2);
    let issuer_id = create_test_account_id(3);

    // All three accounts exist.
    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(dest_id.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

    let asset = create_test_asset(b"USD\0", issuer_id.clone());
    let tl_asset = create_test_trustline_asset(b"USD\0", issuer_id);

    // Destination has an authorized trustline; source does NOT.
    state.create_trustline(create_test_trustline(
        dest_id,
        tl_asset,
        0,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    let op = PaymentOp {
        destination: MuxedAccount::Ed25519(Uint256([2; 32])),
        asset,
        amount: 100,
    };

    let result = execute_payment(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::Payment(PaymentResult::SrcNoTrust)
    );
}

/// Payment of a credit asset fails with `NoIssuer` when the issuer account
/// referenced by the asset does not exist in the ledger.
///
/// Note: In protocol 13+ (CAP-0017), issuer existence checks were removed from
/// path_payment_strict_receive, so this code path is currently unreachable.
/// The test verifies the current behavior (success) rather than NoIssuer,
/// and is kept as documentation that the result code is intentionally dead.
#[test]
fn test_payment_no_issuer() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(10);
    let dest_id = create_test_account_id(11);
    // Issuer account id — deliberately NOT created in the ledger.
    let issuer_id = create_test_account_id(12);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(dest_id.clone(), 100_000_000));

    let asset = create_test_asset(b"USD\0", issuer_id.clone());
    let tl_asset = create_test_trustline_asset(b"USD\0", issuer_id);

    // Both source and destination have trustlines for the asset, but the
    // issuer account itself is missing from the ledger.
    state.create_trustline(create_test_trustline(
        source_id.clone(),
        tl_asset.clone(),
        500,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));
    state.create_trustline(create_test_trustline(
        dest_id,
        tl_asset,
        0,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    let op = PaymentOp {
        destination: MuxedAccount::Ed25519(Uint256([11; 32])),
        asset,
        amount: 100,
    };

    // In protocol 13+ (CAP-0017), issuer existence is no longer checked.
    // The payment succeeds because both trustlines exist and are authorized,
    // even though the issuer account is absent from the ledger.
    let result = execute_payment(&op, &source_id, &mut state, &context);
    assert_op_result!(result, OperationResultTr::Payment(PaymentResult::Success));
}
