//! Parity tests for PathPaymentStrictReceive operation result codes.
//!
//! Covers gaps not exercised by inline unit tests:
//! - `SrcNotAuthorized` — source trustline not authorized for sending
//! - `NoIssuer` — dead code in protocol 13+ (CAP-0017)
//! - `TooFewOffers` — no matching offers in the DEX
//! - `OfferCrossSelf` — path would cross source's own offer
//! - `OverSendmax` — computed send amount exceeds send_max

use super::super::path_payment::execute_path_payment_strict_receive;
use super::assert_op_result;
use crate::state::LedgerStateManager;
use crate::test_utils::*;
use stellar_xdr::curr::*;

fn create_test_context() -> crate::validation::LedgerContext {
    crate::validation::LedgerContext::testnet(1, 1000)
}

/// PathPaymentStrictReceive returns SrcNotAuthorized when the source has a
/// trustline for the send asset but it is not authorized.
#[test]
fn test_path_payment_strict_receive_src_not_authorized() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let dest_id = create_test_account_id(1);
    let issuer_id = create_test_account_id(2);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(dest_id.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

    let asset = create_test_asset(b"USD\0", issuer_id.clone());
    let tl_asset = create_test_trustline_asset(b"USD\0", issuer_id.clone());

    // Source has trustline but NOT authorized (flags=0)
    state.create_trustline(create_test_trustline(
        source_id.clone(),
        tl_asset.clone(),
        500,
        1_000_000,
        0, // Not authorized
    ));

    // Dest has authorized trustline
    state.create_trustline(create_test_trustline(
        dest_id.clone(),
        tl_asset,
        0,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    // Direct payment (same send/dest asset, no path)
    let op = PathPaymentStrictReceiveOp {
        send_asset: asset.clone(),
        send_max: 500,
        destination: MuxedAccount::Ed25519(Uint256([1; 32])),
        dest_asset: asset,
        dest_amount: 100,
        path: vec![].try_into().unwrap(),
    };

    let result = execute_path_payment_strict_receive(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::PathPaymentStrictReceive(
            PathPaymentStrictReceiveResult::SrcNotAuthorized
        )
    );
}

/// NoIssuer is unreachable in protocol 13+ (CAP-0017). The check_issuer function
/// always returns Ok(()). This test documents that the code path is dead.
#[test]
#[ignore]
fn test_path_payment_strict_receive_no_issuer() {
    // TODO(#1126): NoIssuer is unreachable in protocol 13+ (CAP-0017).
    // check_issuer() is a no-op that always returns Ok(()).
    todo!()
}

/// PathPaymentStrictReceive returns TooFewOffers when there are no matching
/// offers in the DEX and send_asset != dest_asset.
#[test]
fn test_path_payment_strict_receive_too_few_offers() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let dest_id = create_test_account_id(1);
    let issuer_a = create_test_account_id(2);
    let issuer_b = create_test_account_id(3);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(dest_id.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_a.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_b.clone(), 100_000_000));

    let asset_a = create_test_asset(b"AAA\0", issuer_a.clone());
    let asset_b = create_test_asset(b"BBB\0", issuer_b.clone());
    let tl_a = create_test_trustline_asset(b"AAA\0", issuer_a);
    let tl_b = create_test_trustline_asset(b"BBB\0", issuer_b);

    // Source has asset A
    state.create_trustline(create_test_trustline(
        source_id.clone(),
        tl_a,
        10_000,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));
    // Dest needs asset B but no offers exist to convert A→B
    state.create_trustline(create_test_trustline(
        dest_id.clone(),
        tl_b,
        0,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    let op = PathPaymentStrictReceiveOp {
        send_asset: asset_a,
        send_max: 10_000,
        destination: MuxedAccount::Ed25519(Uint256([1; 32])),
        dest_asset: asset_b,
        dest_amount: 100,
        path: vec![].try_into().unwrap(),
    };

    let result = execute_path_payment_strict_receive(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::PathPaymentStrictReceive(PathPaymentStrictReceiveResult::TooFewOffers)
    );
}

/// OfferCrossSelf and OverSendmax require offer setup that is complex.
/// These are marked as ignored for now.
#[test]
#[ignore]
fn test_path_payment_strict_receive_offer_cross_self() {
    // TODO(#1126): Requires creating an offer from the source account in the DEX,
    // then routing a path payment through that offer.
    todo!()
}

#[test]
#[ignore]
fn test_path_payment_strict_receive_over_sendmax() {
    // TODO(#1126): Requires offers in the DEX that convert at an unfavorable rate,
    // causing the computed send amount to exceed send_max.
    todo!()
}
