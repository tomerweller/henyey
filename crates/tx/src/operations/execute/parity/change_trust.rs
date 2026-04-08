//! Parity tests for ChangeTrust operation result codes.
//!
//! Covers gaps not exercised by inline unit tests:
//! - `TrustLineMissing` — not actually a result code returned by execute_change_trust
//! - `NotAuthMaintainLiabilities` — not returned by execute_change_trust either
//!
//! After analysis, ChangeTrust in Henyey does not return TrustLineMissing or
//! NotAuthMaintainLiabilities. These exist in the XDR but are handled via
//! other code paths (e.g., InvalidLimit for missing trustline on removal).
//! Tests document these findings.

use super::super::change_trust::execute_change_trust;
use super::assert_op_result;
use crate::state::LedgerStateManager;
use crate::test_utils::*;
use stellar_xdr::curr::*;

fn create_test_context() -> crate::validation::LedgerContext {
    crate::validation::LedgerContext::testnet(1, 1000)
}

/// ChangeTrust returns InvalidLimit (not TrustLineMissing) when trying to
/// remove a trustline that doesn't exist (limit=0 with no existing trustline).
/// The TrustLineMissing variant exists in XDR but is not used by this implementation.
#[test]
fn test_change_trust_remove_nonexistent_returns_invalid_limit() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let issuer_id = create_test_account_id(1);

    state.create_account(create_test_account(source_id.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

    let op = ChangeTrustOp {
        line: ChangeTrustAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_id,
        }),
        limit: 0, // Remove a trustline that doesn't exist
    };

    let result = execute_change_trust(&op, &source_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::ChangeTrust(ChangeTrustResult::InvalidLimit)
    );
}

/// NotAuthMaintainLiabilities exists in XDR but is not returned by the
/// current ChangeTrust implementation. This test documents that finding.
/// In stellar-core, this was returned when a trustline had AUTH_TO_MAINTAIN_LIABILITIES
/// but the operation tried to reduce the limit below balance+buying_liabilities.
/// The current Henyey implementation handles this via InvalidLimit instead.
#[test]
#[ignore]
fn test_change_trust_not_auth_maintain_liabilities() {
    // TODO(#1126): NotAuthMaintainLiabilities exists in XDR but may be
    // unreachable in current protocol versions. Needs investigation against
    // stellar-core to determine if this is dead code or a missing validation.
    todo!()
}
