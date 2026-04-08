//! Parity tests for ManageSellOffer operation result codes.
//!
//! Covers gaps not exercised by inline unit tests:
//! - `SellNoIssuer` — dead code in protocol 13+ (CAP-0017)
//! - `BuyNoIssuer` — dead code in protocol 13+ (CAP-0017)

/// Dead code: SellNoIssuer is unreachable in protocol 13+ (CAP-0017).
/// The variant exists in XDR and make_result but is never returned.
#[test]
#[ignore = "Dead code: CAP-0017 (protocol 13+) removed issuer existence checks"]
fn test_manage_sell_offer_sell_no_issuer() {}

/// Dead code: BuyNoIssuer is unreachable in protocol 13+ (CAP-0017).
#[test]
#[ignore = "Dead code: CAP-0017 (protocol 13+) removed issuer existence checks"]
fn test_manage_sell_offer_buy_no_issuer() {}
