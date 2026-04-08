//! Parity tests for ManageBuyOffer operation result codes.
//!
//! ManageBuyOffer shares the same execute_manage_offer code path as ManageSellOffer.
//! Covers the same gaps:
//! - `SellNoIssuer` — dead code in protocol 13+ (CAP-0017)
//! - `BuyNoIssuer` — dead code in protocol 13+ (CAP-0017)

/// Dead code: SellNoIssuer is unreachable in protocol 13+ (CAP-0017).
#[test]
#[ignore = "Dead code: CAP-0017 (protocol 13+) removed issuer existence checks"]
fn test_manage_buy_offer_sell_no_issuer() {}

/// Dead code: BuyNoIssuer is unreachable in protocol 13+ (CAP-0017).
#[test]
#[ignore = "Dead code: CAP-0017 (protocol 13+) removed issuer existence checks"]
fn test_manage_buy_offer_buy_no_issuer() {}
