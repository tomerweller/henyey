//! Operation parity test matrix — systematic ResultCode coverage.
//!
//! This module provides one test file per operation type, with one `#[test]` per
//! `ResultCode` variant. The goal is to ensure every error path is exercised,
//! catching missing input validation that could diverge from stellar-core.
//!
//! See: <https://github.com/stellar-experimental/henyey/issues/1126>
//!
//! # Coverage Index
//!
//! Each entry below shows the operation, result code, and coverage status:
//! - **T** = Tested in this parity module
//! - **I** = Tested in inline unit tests (existing coverage)
//! - **X** = `#[ignore]` stub (needs implementation)
//!
//! ## CreateAccount (5 codes) — all I
//! | Code          | Status | Notes |
//! |---------------|--------|-------|
//! | Success       | I | create_account.rs inline |
//! | Malformed     | I | create_account.rs inline |
//! | Underfunded   | I | create_account.rs inline |
//! | LowReserve    | I | create_account.rs inline |
//! | AlreadyExist  | I | create_account.rs inline |
//!
//! ## Payment (10 codes) — 2 gaps
//! | Code             | Status |
//! |------------------|--------|
//! | Success          | I |
//! | Malformed        | I |
//! | Underfunded      | I |
//! | SrcNoTrust       | T |
//! | SrcNotAuthorized | I |
//! | NoDestination    | I |
//! | NoTrust          | I |
//! | NotAuthorized    | I |
//! | LineFull         | I |
//! | NoIssuer         | T |
//!
//! ## PathPaymentStrictReceive (13 codes) — 5 gaps
//! | Code           | Status |
//! |----------------|--------|
//! | Success        | I |
//! | Malformed      | I |
//! | Underfunded    | I |
//! | SrcNoTrust     | I |
//! | SrcNotAuthorized | T |
//! | NoDestination  | I |
//! | NoTrust        | I |
//! | NotAuthorized  | I |
//! | LineFull       | I |
//! | NoIssuer       | T |
//! | TooFewOffers   | T |
//! | OfferCrossSelf | T |
//! | OverSendmax    | T |
//!
//! ## PathPaymentStrictSend (13 codes) — 12 gaps
//! | Code           | Status |
//! |----------------|--------|
//! | Success        | T |
//! | Malformed      | I |
//! | Underfunded    | T |
//! | SrcNoTrust     | T |
//! | SrcNotAuthorized | T |
//! | NoDestination  | T |
//! | NoTrust        | T |
//! | NotAuthorized  | T |
//! | LineFull       | T |
//! | NoIssuer       | T |
//! | TooFewOffers   | T |
//! | OfferCrossSelf | T |
//! | UnderDestmin   | T |
//!
//! ## ManageSellOffer (13 codes) — 2 gaps
//! | Code              | Status |
//! |-------------------|--------|
//! | Success           | I |
//! | Malformed         | I |
//! | SellNoTrust       | I |
//! | BuyNoTrust        | I |
//! | SellNotAuthorized | I |
//! | BuyNotAuthorized  | I |
//! | LineFull          | I |
//! | Underfunded       | I |
//! | CrossSelf         | I |
//! | SellNoIssuer      | T |
//! | BuyNoIssuer       | T |
//! | NotFound          | I |
//! | LowReserve        | I |
//!
//! ## ManageBuyOffer (13 codes) — same structure as ManageSellOffer
//! | Code              | Status |
//! |-------------------|--------|
//! | Success           | I |
//! | Malformed         | I |
//! | SellNoTrust       | I |
//! | BuyNoTrust        | I |
//! | SellNotAuthorized | I |
//! | BuyNotAuthorized  | I |
//! | LineFull          | I |
//! | Underfunded       | I |
//! | CrossSelf         | I |
//! | SellNoIssuer      | T |
//! | BuyNoIssuer       | T |
//! | NotFound          | I |
//! | LowReserve        | I |
//!
//! ## CreatePassiveSellOffer (13 codes) — same structure as ManageSellOffer
//! (shares execute_manage_sell_offer code path)
//!
//! ## SetOptions (11 codes) — all I
//! | Code                 | Status |
//! |----------------------|--------|
//! | Success              | I |
//! | LowReserve           | I |
//! | TooManySigners       | I |
//! | BadFlags             | I |
//! | InvalidInflation     | I |
//! | CantChange           | I |
//! | UnknownFlag          | I |
//! | ThresholdOutOfRange  | I |
//! | BadSigner            | I |
//! | InvalidHomeDomain    | I |
//! | AuthRevocableRequired| I |
//!
//! ## ChangeTrust (9 codes) — 2 gaps
//! | Code                         | Status |
//! |------------------------------|--------|
//! | Success                      | I |
//! | Malformed                    | I |
//! | NoIssuer                     | I |
//! | InvalidLimit                 | I |
//! | LowReserve                   | I |
//! | SelfNotAllowed               | I |
//! | TrustLineMissing             | T |
//! | CannotDelete                 | I |
//! | NotAuthMaintainLiabilities   | T |
//!
//! ## AllowTrust (7 codes) — 3 gaps
//! | Code             | Status |
//! |------------------|--------|
//! | Success          | I |
//! | Malformed        | T |
//! | NoTrustLine      | I |
//! | TrustNotRequired | T |
//! | CantRevoke       | I |
//! | SelfNotAllowed   | I |
//! | LowReserve       | X |
//!
//! ## SetTrustLineFlags (6 codes) — all I
//! | Code         | Status |
//! |--------------|--------|
//! | Success      | I |
//! | Malformed    | I |
//! | NoTrustLine  | I |
//! | CantRevoke   | I |
//! | InvalidState | I |
//! | LowReserve   | I |
//!
//! ## AccountMerge (8 codes) — all I
//! (all variants fully tested inline)
//!
//! ## Inflation (2 codes) — all I
//! (all variants fully tested inline)
//!
//! ## ManageData (5 codes) — all I
//! (all variants fully tested inline)
//!
//! ## BumpSequence (2 codes) — all I
//! (all variants fully tested inline)
//!
//! ## CreateClaimableBalance (6 codes) — 1 gap
//! | Code          | Status |
//! |---------------|--------|
//! | Success       | T |
//! | Malformed     | I |
//! | LowReserve    | I |
//! | NoTrust       | I |
//! | NotAuthorized | I |
//! | Underfunded   | I |
//!
//! ## ClaimClaimableBalance (7 codes) — 1 gap
//! | Code           | Status |
//! |----------------|--------|
//! | Success        | I |
//! | DoesNotExist   | I |
//! | CannotClaim    | T |
//! | LineFull       | I |
//! | NoTrust        | I |
//! | NotAuthorized  | I |
//! | TrustlineFrozen| I |
//!
//! ## BeginSponsoringFutureReserves (4 codes) — 1 gap
//! | Code             | Status |
//! |------------------|--------|
//! | Success          | I |
//! | Malformed        | I |
//! | AlreadySponsored | I |
//! | Recursive        | T |
//!
//! ## EndSponsoringFutureReserves (2 codes) — all I
//! (all variants fully tested inline)
//!
//! ## RevokeSponsorship (6 codes) — 4 gaps
//! | Code             | Status |
//! |------------------|--------|
//! | Success          | T |
//! | DoesNotExist     | I |
//! | NotSponsor       | T |
//! | LowReserve       | I |
//! | OnlyTransferable | T |
//! | Malformed        | T |
//!
//! ## Clawback (5 codes) — all I
//! (all variants fully tested inline)
//!
//! ## ClawbackClaimableBalance (4 codes) — 2 gaps
//! | Code               | Status |
//! |--------------------|--------|
//! | Success            | T |
//! | DoesNotExist       | I |
//! | NotIssuer          | T |
//! | NotClawbackEnabled | T |
//!
//! ## LiquidityPoolDeposit (9 codes) — 2 gaps
//! | Code            | Status |
//! |-----------------|--------|
//! | Success         | I |
//! | Malformed       | T |
//! | NoTrust         | I |
//! | NotAuthorized   | I |
//! | Underfunded     | I |
//! | LineFull        | I |
//! | BadPrice        | I |
//! | PoolFull        | T |
//! | TrustlineFrozen | I |
//!
//! ## LiquidityPoolWithdraw (7 codes) — 2 gaps
//! | Code            | Status |
//! |-----------------|--------|
//! | Success         | I |
//! | Malformed       | T |
//! | NoTrust         | I |
//! | Underfunded     | I |
//! | LineFull        | I |
//! | UnderMinimum    | I |
//! | TrustlineFrozen | T |
//!
//! ## Soroban operations (excluded)
//! InvokeHostFunction, ExtendFootprintTtl, RestoreFootprint are excluded —
//! they delegate to host functions and require SorobanContext.

mod allow_trust;
mod begin_sponsoring;
mod change_trust;
mod claim_claimable_balance;
mod clawback_claimable_balance;
mod create_claimable_balance;
mod liquidity_pool_deposit;
mod liquidity_pool_withdraw;
mod manage_buy_offer;
mod manage_sell_offer;
mod path_payment_strict_receive;
mod path_payment_strict_send;
mod payment;
mod revoke_sponsorship;

/// Helper macro to assert an operation result matches a specific result code.
///
/// Usage:
/// ```ignore
/// assert_op_result!(result, PaymentResult::Success);
/// assert_op_result!(result, CreateAccountResult::Malformed);
/// ```
macro_rules! assert_op_result {
    ($result:expr, $variant:pat) => {{
        let result = $result.expect("operation should not return Err");
        match &result {
            stellar_xdr::curr::OperationResult::OpInner(inner) => {
                assert!(
                    matches!(inner, $variant),
                    "expected {}, got {:?}",
                    stringify!($variant),
                    inner
                );
            }
            other => panic!("expected OpInner, got {:?}", other),
        }
    }};
}

pub(crate) use assert_op_result;
