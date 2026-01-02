//! Clawback operation execution.
//!
//! This module implements the execution logic for:
//! - Clawback (clawback from a trustline)
//! - ClawbackClaimableBalance (clawback from a claimable balance)

use stellar_xdr::curr::{
    AccountId, Asset, ClawbackClaimableBalanceOp, ClawbackClaimableBalanceResult,
    ClawbackClaimableBalanceResultCode, ClawbackOp, ClawbackResult, ClawbackResultCode,
    LedgerKey, LedgerKeyClaimableBalance, OperationResult, OperationResultTr,
};

use crate::frame::muxed_to_account_id;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;

/// Account flag for clawback enabled
const AUTH_CLAWBACK_ENABLED_FLAG: u32 = 0x8;

/// Execute a Clawback operation.
///
/// This operation claws back an amount of an asset from an account's trustline.
/// The source account must be the issuer of the asset and must have
/// the AUTH_CLAWBACK_ENABLED flag set.
pub fn execute_clawback(
    op: &ClawbackOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Validate amount
    if op.amount <= 0 {
        return Ok(make_clawback_result(ClawbackResultCode::Malformed));
    }

    // Cannot clawback native asset
    if matches!(&op.asset, Asset::Native) {
        return Ok(make_clawback_result(ClawbackResultCode::Malformed));
    }

    // Check source account exists and is the issuer
    let issuer = match state.get_account(source) {
        Some(a) => a.clone(),
        None => {
            return Ok(make_clawback_result(ClawbackResultCode::Malformed));
        }
    };

    // Verify source is the issuer of the asset
    let asset_issuer = match &op.asset {
        Asset::Native => {
            return Ok(make_clawback_result(ClawbackResultCode::Malformed));
        }
        Asset::CreditAlphanum4(a) => &a.issuer,
        Asset::CreditAlphanum12(a) => &a.issuer,
    };

    if asset_issuer != source {
        return Ok(make_clawback_result(ClawbackResultCode::Malformed));
    }

    // Check issuer has AUTH_CLAWBACK_ENABLED flag
    if issuer.flags & AUTH_CLAWBACK_ENABLED_FLAG == 0 {
        return Ok(make_clawback_result(ClawbackResultCode::NotClawbackEnabled));
    }

    // Convert MuxedAccount to AccountId for trustline lookup
    let from_account_id = muxed_to_account_id(&op.from);

    // Get the trustline
    let trustline = match state.get_trustline(&from_account_id, &op.asset) {
        Some(tl) => tl.clone(),
        None => {
            return Ok(make_clawback_result(ClawbackResultCode::NoTrust));
        }
    };

    // Check trustline has sufficient balance
    if trustline.balance < op.amount {
        return Ok(make_clawback_result(ClawbackResultCode::Underfunded));
    }

    // Perform the clawback - deduct from trustline
    if let Some(tl) = state.get_trustline_mut(&from_account_id, &op.asset) {
        tl.balance -= op.amount;
    }

    Ok(make_clawback_result(ClawbackResultCode::Success))
}

/// Execute a ClawbackClaimableBalance operation.
///
/// This operation claws back an entire claimable balance.
/// The source account must be the issuer of the asset in the claimable balance
/// and must have the AUTH_CLAWBACK_ENABLED flag set.
pub fn execute_clawback_claimable_balance(
    op: &ClawbackClaimableBalanceOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Get the claimable balance entry
    let entry = match state.get_claimable_balance(&op.balance_id) {
        Some(e) => e.clone(),
        None => {
            return Ok(make_clawback_cb_result(
                ClawbackClaimableBalanceResultCode::DoesNotExist,
            ));
        }
    };

    // Cannot clawback native asset
    if matches!(&entry.asset, Asset::Native) {
        return Ok(make_clawback_cb_result(
            ClawbackClaimableBalanceResultCode::NotClawbackEnabled,
        ));
    }

    // Check source account exists and is the issuer
    let issuer = match state.get_account(source) {
        Some(a) => a.clone(),
        None => {
            return Ok(make_clawback_cb_result(
                ClawbackClaimableBalanceResultCode::NotClawbackEnabled,
            ));
        }
    };

    // Verify source is the issuer of the asset
    let asset_issuer = match &entry.asset {
        Asset::Native => {
            return Ok(make_clawback_cb_result(
                ClawbackClaimableBalanceResultCode::NotClawbackEnabled,
            ));
        }
        Asset::CreditAlphanum4(a) => &a.issuer,
        Asset::CreditAlphanum12(a) => &a.issuer,
    };

    if asset_issuer != source {
        return Ok(make_clawback_cb_result(
            ClawbackClaimableBalanceResultCode::NotClawbackEnabled,
        ));
    }

    // Check issuer has AUTH_CLAWBACK_ENABLED flag
    if issuer.flags & AUTH_CLAWBACK_ENABLED_FLAG == 0 {
        return Ok(make_clawback_cb_result(
            ClawbackClaimableBalanceResultCode::NotClawbackEnabled,
        ));
    }

    let sponsorship_multiplier = entry.claimants.len() as i64;
    let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
        balance_id: entry.balance_id.clone(),
    });
    if state.entry_sponsor(&ledger_key).is_some() {
        state.remove_entry_sponsorship_with_sponsor_counts(
            &ledger_key,
            None,
            sponsorship_multiplier,
        )?;
    }

    // Delete the claimable balance (clawed back entirely)
    state.delete_claimable_balance(&op.balance_id);

    Ok(make_clawback_cb_result(
        ClawbackClaimableBalanceResultCode::Success,
    ))
}

/// Create a Clawback result.
fn make_clawback_result(code: ClawbackResultCode) -> OperationResult {
    let result = match code {
        ClawbackResultCode::Success => ClawbackResult::Success,
        ClawbackResultCode::Malformed => ClawbackResult::Malformed,
        ClawbackResultCode::NotClawbackEnabled => ClawbackResult::NotClawbackEnabled,
        ClawbackResultCode::NoTrust => ClawbackResult::NoTrust,
        ClawbackResultCode::Underfunded => ClawbackResult::Underfunded,
    };

    OperationResult::OpInner(OperationResultTr::Clawback(result))
}

/// Create a ClawbackClaimableBalance result.
fn make_clawback_cb_result(code: ClawbackClaimableBalanceResultCode) -> OperationResult {
    let result = match code {
        ClawbackClaimableBalanceResultCode::Success => ClawbackClaimableBalanceResult::Success,
        ClawbackClaimableBalanceResultCode::DoesNotExist => {
            ClawbackClaimableBalanceResult::DoesNotExist
        }
        ClawbackClaimableBalanceResultCode::NotIssuer => ClawbackClaimableBalanceResult::NotIssuer,
        ClawbackClaimableBalanceResultCode::NotClawbackEnabled => {
            ClawbackClaimableBalanceResult::NotClawbackEnabled
        }
    };

    OperationResult::OpInner(OperationResultTr::ClawbackClaimableBalance(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    fn create_test_account(account_id: AccountId, balance: i64, flags: u32) -> AccountEntry {
        AccountEntry {
            account_id,
            balance,
            seq_num: SequenceNumber(1),
            num_sub_entries: 0,
            inflation_dest: None,
            flags,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: vec![].try_into().unwrap(),
            ext: AccountEntryExt::V0,
        }
    }

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    #[test]
    fn test_clawback_not_enabled() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(0);
        let holder_id = create_test_account_id(1);

        // Issuer without clawback enabled
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000, 0));
        state.create_account(create_test_account(holder_id.clone(), 10_000_000, 0));

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });

        // Create trustline with balance
        let trustline = TrustLineEntry {
            account_id: holder_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            balance: 1000,
            limit: i64::MAX,
            flags: 1, // Authorized
            ext: TrustLineEntryExt::V0,
        };
        state.create_trustline(trustline);

        let op = ClawbackOp {
            asset: asset.clone(),
            from: holder_id.into(),
            amount: 500,
        };

        let result = execute_clawback(&op, &issuer_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::Clawback(r)) => {
                assert!(matches!(r, ClawbackResult::NotClawbackEnabled));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_clawback_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(0);
        let holder_id = create_test_account_id(1);

        // Issuer with clawback enabled (flag 0x8)
        state.create_account(create_test_account(
            issuer_id.clone(),
            100_000_000,
            AUTH_CLAWBACK_ENABLED_FLAG,
        ));
        state.create_account(create_test_account(holder_id.clone(), 10_000_000, 0));

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });

        // Create trustline with balance
        let trustline = TrustLineEntry {
            account_id: holder_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            balance: 1000,
            limit: i64::MAX,
            flags: 1, // Authorized
            ext: TrustLineEntryExt::V0,
        };
        state.create_trustline(trustline);

        let op = ClawbackOp {
            asset: asset.clone(),
            from: holder_id.clone().into(),
            amount: 500,
        };

        let result = execute_clawback(&op, &issuer_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::Clawback(r)) => {
                assert!(matches!(r, ClawbackResult::Success));
            }
            _ => panic!("Unexpected result type"),
        }

        // Verify balance was clawed back
        let tl = state.get_trustline(&holder_id, &asset).unwrap();
        assert_eq!(tl.balance, 500);
    }

    #[test]
    fn test_clawback_claimable_balance_not_exist() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(0);
        state.create_account(create_test_account(
            issuer_id.clone(),
            100_000_000,
            AUTH_CLAWBACK_ENABLED_FLAG,
        ));

        let op = ClawbackClaimableBalanceOp {
            balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0u8; 32])),
        };

        let result = execute_clawback_claimable_balance(&op, &issuer_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ClawbackClaimableBalance(r)) => {
                assert!(matches!(r, ClawbackClaimableBalanceResult::DoesNotExist));
            }
            _ => panic!("Unexpected result type"),
        }
    }
}
