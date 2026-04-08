//! Parity tests for ManageBuyOffer operation result codes.
//!
//! ManageBuyOffer shares the same execute_manage_offer code path as ManageSellOffer.
//! Covers the same gaps:
//! - `SellNoIssuer` — dead code in protocol 13+ (CAP-0017)
//! - `BuyNoIssuer` — dead code in protocol 13+ (CAP-0017)

/// SellNoIssuer is defined in XDR but unreachable in protocol 13+ (CAP-0017).
#[test]
#[ignore]
fn test_manage_buy_offer_sell_no_issuer() {
    // TODO(#1126): SellNoIssuer is unreachable in protocol 13+ (CAP-0017).
    // ManageBuyOffer delegates to the same execute_manage_offer code path.
    todo!()
}

/// BuyNoIssuer is defined in XDR but unreachable in protocol 13+ (CAP-0017).
#[test]
#[ignore]
fn test_manage_buy_offer_buy_no_issuer() {
    // TODO(#1126): BuyNoIssuer is unreachable in protocol 13+ (CAP-0017).
    todo!()
}
