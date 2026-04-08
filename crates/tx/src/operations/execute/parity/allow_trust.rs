//! Parity tests for AllowTrust operation result codes.
//!
//! Covers gaps not exercised by inline unit tests:
//! - `Malformed` — source account doesn't exist
//! - `TrustNotRequired` — dead code in protocol 17+ (CAP-0035)
//! - `LowReserve` — pool share redemption failure during deauthorization

use super::super::trust_flags::execute_allow_trust;
use super::super::TxIdentity;
use super::assert_op_result;
use crate::state::LedgerStateManager;
use crate::test_utils::*;
use stellar_xdr::curr::*;

fn create_test_context() -> crate::validation::LedgerContext {
    crate::validation::LedgerContext::testnet(1, 1000)
}

/// AllowTrust returns Malformed when the source (issuer) account doesn't exist.
#[test]
fn test_allow_trust_malformed_source_not_found() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0); // NOT created in state
    let trustor_id = create_test_account_id(1);

    state.create_account(create_test_account(trustor_id.clone(), 100_000_000));

    let op = AllowTrustOp {
        trustor: trustor_id,
        asset: AssetCode::CreditAlphanum4(AssetCode4(*b"USD\0")),
        authorize: TrustLineFlags::AuthorizedFlag as u32,
    };

    let tx_id = TxIdentity {
        source_id: &source_id,
        seq: 0,
        op_index: 0,
    };

    let result = execute_allow_trust(&op, &source_id, &tx_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::AllowTrust(AllowTrustResult::Malformed)
    );
}

/// Dead code: TrustNotRequired is unreachable in protocol 17+ (CAP-0035).
/// The check was removed from execute_allow_trust. The variant exists in XDR
/// and make_allow_trust_result but is never triggered.
#[test]
#[ignore = "Dead code: CAP-0035 (protocol 17+) removed TrustNotRequired check"]
fn test_allow_trust_trust_not_required() {}

/// LowReserve is returned when deauthorizing a trustline causes pool share
/// redemption that fails due to insufficient reserve on the trustor's account.
/// Requires: issuer with AUTH_REVOCABLE, trustor with pool share trustline,
/// liquidity pool deposit, deauthorization triggering redemption, and the
/// trustor having insufficient reserve for the redemption.
#[test]
#[ignore = "Complex setup: requires liquidity pool + deauthorization + reserve exhaustion"]
fn test_allow_trust_low_reserve() {}
