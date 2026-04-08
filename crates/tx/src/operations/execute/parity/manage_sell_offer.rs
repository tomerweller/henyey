//! Parity tests for ManageSellOffer operation result codes.
//!
//! Covers gaps not exercised by inline unit tests:
//! - `SellNoIssuer` — dead code in protocol 13+ (CAP-0017)
//! - `BuyNoIssuer` — dead code in protocol 13+ (CAP-0017)

/// SellNoIssuer is defined in XDR but unreachable in protocol 13+ (CAP-0017).
/// Issuer existence checks were removed from the offer creation path.
/// This test documents the dead code path.
#[test]
#[ignore]
fn test_manage_sell_offer_sell_no_issuer() {
    // TODO(#1126): SellNoIssuer is unreachable in protocol 13+ (CAP-0017).
    // The ManageSellOfferResultCode::SellNoIssuer variant exists in XDR and
    // make_result but is never returned by execute_manage_offer.
    todo!()
}

/// BuyNoIssuer is defined in XDR but unreachable in protocol 13+ (CAP-0017).
#[test]
#[ignore]
fn test_manage_sell_offer_buy_no_issuer() {
    // TODO(#1126): BuyNoIssuer is unreachable in protocol 13+ (CAP-0017).
    todo!()
}
