//! Parity tests for PathPaymentStrictSend operation result codes.
//!
//! Most codes are gap tests since inline tests only cover Malformed.

use super::super::path_payment::execute_path_payment_strict_send;
use super::assert_op_result;
use crate::state::LedgerStateManager;
use crate::test_utils::*;
use stellar_xdr::curr::*;

fn create_test_context() -> crate::validation::LedgerContext {
    crate::validation::LedgerContext::testnet(1, 1000)
}

/// PathPaymentStrictSend succeeds for a direct same-asset payment.
#[test]
fn test_path_payment_strict_send_success() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let dest_id = create_test_account_id(1);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(dest_id.clone(), 50_000_000));

    // Native-to-native direct payment
    let op = PathPaymentStrictSendOp {
        send_asset: Asset::Native,
        send_amount: 1_000_000,
        destination: MuxedAccount::Ed25519(Uint256([1; 32])),
        dest_asset: Asset::Native,
        dest_min: 1_000_000,
        path: vec![].try_into().unwrap(),
    };

    let result = execute_path_payment_strict_send(&op, &source_id, &mut state, &context);
    let result = result.expect("should not error");
    match &result {
        OperationResult::OpInner(OperationResultTr::PathPaymentStrictSend(
            PathPaymentStrictSendResult::Success(_),
        )) => {} // OK
        other => panic!("expected Success, got {:?}", other),
    }
}

/// PathPaymentStrictSend returns Underfunded when source doesn't have enough native balance.
#[test]
fn test_path_payment_strict_send_underfunded() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let dest_id = create_test_account_id(1);

    // Source has only minimum balance (10M), no available balance to send
    state.create_account(create_test_account(source_id.clone(), 10_000_000));
    state.create_account(create_test_account(dest_id.clone(), 50_000_000));

    let op = PathPaymentStrictSendOp {
        send_asset: Asset::Native,
        send_amount: 5_000_000,
        destination: MuxedAccount::Ed25519(Uint256([1; 32])),
        dest_asset: Asset::Native,
        dest_min: 5_000_000,
        path: vec![].try_into().unwrap(),
    };

    let result = execute_path_payment_strict_send(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::PathPaymentStrictSend(PathPaymentStrictSendResult::Underfunded)
    );
}

/// PathPaymentStrictSend returns SrcNoTrust when source has no trustline for the send asset.
#[test]
fn test_path_payment_strict_send_src_no_trust() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let dest_id = create_test_account_id(1);
    let issuer_id = create_test_account_id(2);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(dest_id.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

    let asset = create_test_asset(b"USD\0", issuer_id.clone());
    let tl_asset = create_test_trustline_asset(b"USD\0", issuer_id);

    // Dest has trustline, source does NOT
    state.create_trustline(create_test_trustline(
        dest_id.clone(),
        tl_asset,
        0,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    let op = PathPaymentStrictSendOp {
        send_asset: asset.clone(),
        send_amount: 100,
        destination: MuxedAccount::Ed25519(Uint256([1; 32])),
        dest_asset: asset,
        dest_min: 100,
        path: vec![].try_into().unwrap(),
    };

    let result = execute_path_payment_strict_send(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::PathPaymentStrictSend(PathPaymentStrictSendResult::SrcNoTrust)
    );
}

/// PathPaymentStrictSend returns SrcNotAuthorized when source trustline is not authorized.
#[test]
fn test_path_payment_strict_send_src_not_authorized() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let dest_id = create_test_account_id(1);
    let issuer_id = create_test_account_id(2);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(dest_id.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

    let asset = create_test_asset(b"USD\0", issuer_id.clone());
    let tl_asset = create_test_trustline_asset(b"USD\0", issuer_id);

    // Source trustline NOT authorized
    state.create_trustline(create_test_trustline(
        source_id.clone(),
        tl_asset.clone(),
        500,
        1_000_000,
        0, // Not authorized
    ));
    state.create_trustline(create_test_trustline(
        dest_id.clone(),
        tl_asset,
        0,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    let op = PathPaymentStrictSendOp {
        send_asset: asset.clone(),
        send_amount: 100,
        destination: MuxedAccount::Ed25519(Uint256([1; 32])),
        dest_asset: asset,
        dest_min: 100,
        path: vec![].try_into().unwrap(),
    };

    let result = execute_path_payment_strict_send(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::PathPaymentStrictSend(PathPaymentStrictSendResult::SrcNotAuthorized)
    );
}

/// PathPaymentStrictSend returns NoDestination when the dest account doesn't exist.
#[test]
fn test_path_payment_strict_send_no_destination() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    // dest NOT created

    let op = PathPaymentStrictSendOp {
        send_asset: Asset::Native,
        send_amount: 1_000_000,
        destination: MuxedAccount::Ed25519(Uint256([99; 32])), // doesn't exist
        dest_asset: Asset::Native,
        dest_min: 1_000_000,
        path: vec![].try_into().unwrap(),
    };

    let result = execute_path_payment_strict_send(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::PathPaymentStrictSend(PathPaymentStrictSendResult::NoDestination)
    );
}

/// PathPaymentStrictSend returns NoTrust when dest has no trustline for credit asset.
#[test]
fn test_path_payment_strict_send_no_trust() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let dest_id = create_test_account_id(1);
    let issuer_id = create_test_account_id(2);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(dest_id.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

    let asset = create_test_asset(b"USD\0", issuer_id.clone());
    let tl_asset = create_test_trustline_asset(b"USD\0", issuer_id);

    // Source has trustline, dest does NOT
    state.create_trustline(create_test_trustline(
        source_id.clone(),
        tl_asset,
        500,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    let op = PathPaymentStrictSendOp {
        send_asset: asset.clone(),
        send_amount: 100,
        destination: MuxedAccount::Ed25519(Uint256([1; 32])),
        dest_asset: asset,
        dest_min: 100,
        path: vec![].try_into().unwrap(),
    };

    let result = execute_path_payment_strict_send(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::PathPaymentStrictSend(PathPaymentStrictSendResult::NoTrust)
    );
}

/// PathPaymentStrictSend returns NotAuthorized when dest trustline is not authorized.
#[test]
fn test_path_payment_strict_send_not_authorized() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let dest_id = create_test_account_id(1);
    let issuer_id = create_test_account_id(2);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(dest_id.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

    let asset = create_test_asset(b"USD\0", issuer_id.clone());
    let tl_asset = create_test_trustline_asset(b"USD\0", issuer_id);

    state.create_trustline(create_test_trustline(
        source_id.clone(),
        tl_asset.clone(),
        500,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));
    // Dest trustline NOT authorized
    state.create_trustline(create_test_trustline(
        dest_id.clone(),
        tl_asset,
        0,
        1_000_000,
        0, // Not authorized
    ));

    let op = PathPaymentStrictSendOp {
        send_asset: asset.clone(),
        send_amount: 100,
        destination: MuxedAccount::Ed25519(Uint256([1; 32])),
        dest_asset: asset,
        dest_min: 100,
        path: vec![].try_into().unwrap(),
    };

    let result = execute_path_payment_strict_send(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::PathPaymentStrictSend(PathPaymentStrictSendResult::NotAuthorized)
    );
}

/// PathPaymentStrictSend returns LineFull when dest trustline can't hold the amount.
#[test]
fn test_path_payment_strict_send_line_full() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let dest_id = create_test_account_id(1);
    let issuer_id = create_test_account_id(2);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(dest_id.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

    let asset = create_test_asset(b"USD\0", issuer_id.clone());
    let tl_asset = create_test_trustline_asset(b"USD\0", issuer_id);

    state.create_trustline(create_test_trustline(
        source_id.clone(),
        tl_asset.clone(),
        10_000,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));
    // Dest trustline is nearly full (limit=1000, balance=999)
    state.create_trustline(create_test_trustline(
        dest_id.clone(),
        tl_asset,
        999,
        1_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    let op = PathPaymentStrictSendOp {
        send_asset: asset.clone(),
        send_amount: 100,
        destination: MuxedAccount::Ed25519(Uint256([1; 32])),
        dest_asset: asset,
        dest_min: 100,
        path: vec![].try_into().unwrap(),
    };

    let result = execute_path_payment_strict_send(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::PathPaymentStrictSend(PathPaymentStrictSendResult::LineFull)
    );
}

/// Dead code: NoIssuer is unreachable in protocol 13+ (CAP-0017).
/// check_issuer() always returns Ok(()). The variant exists in XDR but cannot be triggered.
#[test]
#[ignore = "Dead code: CAP-0017 (protocol 13+) removed issuer existence checks"]
fn test_path_payment_strict_send_no_issuer() {}

/// TooFewOffers when no offers exist for a cross-asset path.
#[test]
fn test_path_payment_strict_send_too_few_offers() {
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

    state.create_trustline(create_test_trustline(
        source_id.clone(),
        create_test_trustline_asset(b"AAA\0", issuer_a),
        10_000,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));
    state.create_trustline(create_test_trustline(
        dest_id.clone(),
        create_test_trustline_asset(b"BBB\0", issuer_b),
        0,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    let op = PathPaymentStrictSendOp {
        send_asset: asset_a,
        send_amount: 100,
        destination: MuxedAccount::Ed25519(Uint256([1; 32])),
        dest_asset: asset_b,
        dest_min: 1,
        path: vec![].try_into().unwrap(),
    };

    let result = execute_path_payment_strict_send(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::PathPaymentStrictSend(PathPaymentStrictSendResult::TooFewOffers)
    );
}

/// PathPaymentStrictSend returns OfferCrossSelf when the path would cross
/// the source's own offer in the DEX.
#[test]
fn test_path_payment_strict_send_offer_cross_self() {
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

    state.create_trustline(create_test_trustline(
        source_id.clone(),
        create_test_trustline_asset(b"AAA\0", issuer_a.clone()),
        100_000,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));
    state.create_trustline(create_test_trustline(
        source_id.clone(),
        create_test_trustline_asset(b"BBB\0", issuer_b.clone()),
        100_000,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));
    state.create_trustline(create_test_trustline(
        dest_id.clone(),
        create_test_trustline_asset(b"BBB\0", issuer_b),
        0,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    // Source's own offer: selling B for A. Path payment sends A→B crosses it.
    state.create_offer(OfferEntry {
        seller_id: source_id.clone(),
        offer_id: 1,
        selling: asset_b.clone(),
        buying: asset_a.clone(),
        amount: 10_000,
        price: Price { n: 1, d: 1 },
        flags: 0,
        ext: OfferEntryExt::V0,
    });

    let op = PathPaymentStrictSendOp {
        send_asset: asset_a,
        send_amount: 100,
        destination: MuxedAccount::Ed25519(Uint256([1; 32])),
        dest_asset: asset_b,
        dest_min: 1,
        path: vec![].try_into().unwrap(),
    };

    let result = execute_path_payment_strict_send(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::PathPaymentStrictSend(PathPaymentStrictSendResult::OfferCrossSelf)
    );
}

/// PathPaymentStrictSend returns UnderDestmin when the received amount
/// (after going through offers) is less than dest_min.
#[test]
fn test_path_payment_strict_send_under_destmin() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let dest_id = create_test_account_id(1);
    let seller_id = create_test_account_id(2);
    let issuer_a = create_test_account_id(3);
    let issuer_b = create_test_account_id(4);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(dest_id.clone(), 100_000_000));
    state.create_account(create_test_account(seller_id.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_a.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_b.clone(), 100_000_000));

    let asset_a = create_test_asset(b"AAA\0", issuer_a.clone());
    let asset_b = create_test_asset(b"BBB\0", issuer_b.clone());

    state.create_trustline(create_test_trustline(
        source_id.clone(),
        create_test_trustline_asset(b"AAA\0", issuer_a.clone()),
        1_000_000,
        10_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));
    state.create_trustline(create_test_trustline(
        dest_id.clone(),
        create_test_trustline_asset(b"BBB\0", issuer_b.clone()),
        0,
        10_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));
    // Seller has A trustline (buying A via offer)
    state.create_trustline(create_trustline_with_liabilities(
        seller_id.clone(),
        create_test_trustline_asset(b"AAA\0", issuer_a),
        0,
        10_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
        100_000, // buying liabilities — seller buys A
        0,
    ));
    // Seller has B trustline (selling B via offer)
    state.create_trustline(create_trustline_with_liabilities(
        seller_id.clone(),
        create_test_trustline_asset(b"BBB\0", issuer_b),
        1_000_000,
        10_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
        0,      // buying liabilities
        10_000, // selling liabilities matching offer amount
    ));

    // Seller offers B for A at price 10:1 (expensive: 10 A buys 1 B)
    state.create_offer(OfferEntry {
        seller_id: seller_id.clone(),
        offer_id: 1,
        selling: asset_b.clone(),
        buying: asset_a.clone(),
        amount: 10_000,
        price: Price { n: 10, d: 1 },
        flags: 0,
        ext: OfferEntryExt::V0,
    });

    // Source sends exactly 100 A. At 10:1 rate, gets ~10 B. dest_min=1000 is way too high.
    let op = PathPaymentStrictSendOp {
        send_asset: asset_a,
        send_amount: 100,
        destination: MuxedAccount::Ed25519(Uint256([1; 32])),
        dest_asset: asset_b,
        dest_min: 1000,
        path: vec![].try_into().unwrap(),
    };

    let result = execute_path_payment_strict_send(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::PathPaymentStrictSend(PathPaymentStrictSendResult::UnderDestmin)
    );
}
