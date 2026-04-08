//! Parity tests for ClawbackClaimableBalance operation result codes.
//!
//! Covers gaps not exercised by inline unit tests:
//! - `Success` — successful clawback of a claimable balance
//! - `NotIssuer` — source is not the issuer of the asset
//! - `NotClawbackEnabled` — claimable balance doesn't have clawback flag

use super::super::clawback::execute_clawback_claimable_balance;
use super::assert_op_result;
use crate::state::LedgerStateManager;
use crate::test_utils::*;
use stellar_xdr::curr::*;

fn create_test_context() -> crate::validation::LedgerContext {
    crate::validation::LedgerContext::testnet(1, 1000)
}

/// ClawbackClaimableBalance succeeds when the issuer claws back a claimable balance
/// that has the CLAWBACK_ENABLED flag set.
#[test]
fn test_clawback_claimable_balance_success() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let issuer_id = create_test_account_id(0);
    let claimant_id = create_test_account_id(1);

    state.create_account(create_test_account_with_flags(
        issuer_id.clone(),
        100_000_000,
        AccountFlags::ClawbackEnabledFlag as u32,
    ));

    let asset = create_test_asset(b"USD\0", issuer_id.clone());
    let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([42; 32]));

    let cb_entry = ClaimableBalanceEntry {
        balance_id: balance_id.clone(),
        claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: claimant_id,
            predicate: ClaimPredicate::Unconditional,
        })]
        .try_into()
        .unwrap(),
        asset,
        amount: 1_000_000,
        ext: ClaimableBalanceEntryExt::V1(ClaimableBalanceEntryExtensionV1 {
            ext: ClaimableBalanceEntryExtensionV1Ext::V0,
            flags: ClaimableBalanceFlags::ClaimableBalanceClawbackEnabledFlag as u32,
        }),
    };
    state.create_claimable_balance(cb_entry);

    let op = ClawbackClaimableBalanceOp {
        balance_id: balance_id.clone(),
    };

    let result = execute_clawback_claimable_balance(&op, &issuer_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::ClawbackClaimableBalance(ClawbackClaimableBalanceResult::Success)
    );

    // Verify the claimable balance was deleted
    assert!(state.get_claimable_balance(&balance_id).is_none());
}

/// ClawbackClaimableBalance returns NotIssuer when the source is not the issuer
/// of the asset in the claimable balance.
#[test]
fn test_clawback_claimable_balance_not_issuer() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let issuer_id = create_test_account_id(0);
    let non_issuer_id = create_test_account_id(1);
    let claimant_id = create_test_account_id(2);

    state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
    state.create_account(create_test_account(non_issuer_id.clone(), 100_000_000));

    let asset = create_test_asset(b"USD\0", issuer_id);
    let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([43; 32]));

    let cb_entry = ClaimableBalanceEntry {
        balance_id: balance_id.clone(),
        claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: claimant_id,
            predicate: ClaimPredicate::Unconditional,
        })]
        .try_into()
        .unwrap(),
        asset,
        amount: 1_000_000,
        ext: ClaimableBalanceEntryExt::V1(ClaimableBalanceEntryExtensionV1 {
            ext: ClaimableBalanceEntryExtensionV1Ext::V0,
            flags: ClaimableBalanceFlags::ClaimableBalanceClawbackEnabledFlag as u32,
        }),
    };
    state.create_claimable_balance(cb_entry);

    let op = ClawbackClaimableBalanceOp {
        balance_id: balance_id.clone(),
    };

    // non_issuer_id is not the issuer
    let result = execute_clawback_claimable_balance(&op, &non_issuer_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::ClawbackClaimableBalance(ClawbackClaimableBalanceResult::NotIssuer)
    );
}

/// ClawbackClaimableBalance returns NotClawbackEnabled when the claimable balance
/// doesn't have the CLAWBACK_ENABLED flag set.
#[test]
fn test_clawback_claimable_balance_not_clawback_enabled() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let issuer_id = create_test_account_id(0);
    let claimant_id = create_test_account_id(1);

    state.create_account(create_test_account_with_flags(
        issuer_id.clone(),
        100_000_000,
        AccountFlags::ClawbackEnabledFlag as u32,
    ));

    let asset = create_test_asset(b"USD\0", issuer_id.clone());
    let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([44; 32]));

    // Create WITHOUT the clawback flag (V0 ext = no flags)
    let cb_entry = ClaimableBalanceEntry {
        balance_id: balance_id.clone(),
        claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: claimant_id,
            predicate: ClaimPredicate::Unconditional,
        })]
        .try_into()
        .unwrap(),
        asset,
        amount: 1_000_000,
        ext: ClaimableBalanceEntryExt::V0,
    };
    state.create_claimable_balance(cb_entry);

    let op = ClawbackClaimableBalanceOp {
        balance_id: balance_id.clone(),
    };

    let result = execute_clawback_claimable_balance(&op, &issuer_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::ClawbackClaimableBalance(
            ClawbackClaimableBalanceResult::NotClawbackEnabled
        )
    );
}
