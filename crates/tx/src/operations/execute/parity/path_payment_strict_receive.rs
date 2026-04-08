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

/// Dead code: NoIssuer is unreachable in protocol 13+ (CAP-0017).
/// check_issuer() always returns Ok(()). The variant exists in XDR but cannot be triggered.
#[test]
#[ignore = "Dead code: CAP-0017 (protocol 13+) removed issuer existence checks"]
fn test_path_payment_strict_receive_no_issuer() {}

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

/// PathPaymentStrictReceive returns OfferCrossSelf when the path would cross
/// the source's own offer in the DEX.
#[test]
fn test_path_payment_strict_receive_offer_cross_self() {
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

    // Source has trustlines for both assets
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
    // Dest has trustline for asset B
    state.create_trustline(create_test_trustline(
        dest_id.clone(),
        create_test_trustline_asset(b"BBB\0", issuer_b),
        0,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    // Source has an offer selling B for A in the DEX.
    // The path payment sends A and receives B, which would cross source's own offer.
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
        OperationResultTr::PathPaymentStrictReceive(PathPaymentStrictReceiveResult::OfferCrossSelf)
    );
}

/// PathPaymentStrictReceive returns OverSendmax when the computed send amount
/// (after going through offers) exceeds the specified send_max.
/// Uses native XLM as send asset to simplify the test (no trustline needed for source).
#[test]
fn test_path_payment_strict_receive_over_sendmax() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let dest_id = create_test_account_id(1);
    let seller_id = create_test_account_id(2);
    let issuer_b = create_test_account_id(3);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(dest_id.clone(), 100_000_000));
    // Seller needs enough native balance for liabilities (selling liabilities on native)
    state.create_account(create_test_account_with_liabilities(
        seller_id.clone(),
        100_000_000,
        0,      // buying liabilities
        10_000, // selling liabilities matching offer amount
    ));
    state.create_account(create_test_account(issuer_b.clone(), 100_000_000));

    let asset_b = create_test_asset(b"BBB\0", issuer_b.clone());

    // Dest wants asset B
    state.create_trustline(create_test_trustline(
        dest_id.clone(),
        create_test_trustline_asset(b"BBB\0", issuer_b.clone()),
        0,
        10_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));
    // Seller has asset B trustline (with buying liabilities for the offer)
    state.create_trustline(create_trustline_with_liabilities(
        seller_id.clone(),
        create_test_trustline_asset(b"BBB\0", issuer_b.clone()),
        0,
        10_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
        100_000, // buying liabilities — seller is buying B via the offer
        0,
    ));

    // Seller offers native XLM for B at price 10:1 (10 XLM per 1 B — expensive)
    state.create_offer(OfferEntry {
        seller_id: seller_id.clone(),
        offer_id: 1,
        selling: Asset::Native,
        buying: asset_b.clone(),
        amount: 10_000,
        price: Price { n: 10, d: 1 },
        flags: 0,
        ext: OfferEntryExt::V0,
    });

    // Source sends B, wants to receive native XLM at dest.
    // Wait — let's flip: source sends native, dest receives B.
    // Offer: seller sells native for B at 10:1.
    // Path: source sends B → offer converts B to native → dest gets native.
    // Actually, let me think again...
    //
    // Offer sells native, buys B. Price 10/1 means seller wants 10 B per 1 native sold.
    // Path payment: source sends B, dest receives native.
    // Source sends B → crosses offer (seller gives native, gets B) → dest gets native.
    // For dest_amount=1000 native, seller needs to sell 1000 native (and buy 10000 B).
    // Source would need to send 10000 B. With send_max=100 B, this is OverSendmax.

    // Source has B trustline
    state.create_trustline(create_test_trustline(
        source_id.clone(),
        create_test_trustline_asset(b"BBB\0", issuer_b.clone()),
        1_000_000,
        10_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    let op = PathPaymentStrictReceiveOp {
        send_asset: asset_b,
        send_max: 100, // Way too low for the conversion rate
        destination: MuxedAccount::Ed25519(Uint256([1; 32])),
        dest_asset: Asset::Native,
        dest_amount: 1_000,
        path: vec![].try_into().unwrap(),
    };

    let result = execute_path_payment_strict_receive(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::PathPaymentStrictReceive(PathPaymentStrictReceiveResult::OverSendmax)
    );
}
