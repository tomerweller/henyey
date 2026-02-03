//! Clawback operation execution.
//!
//! This module implements the execution logic for:
//! - Clawback (clawback from a trustline)
//! - ClawbackClaimableBalance (clawback from a claimable balance)

use stellar_xdr::curr::{
    AccountId, Asset, ClawbackClaimableBalanceOp, ClawbackClaimableBalanceResult,
    ClawbackClaimableBalanceResultCode, ClawbackOp, ClawbackResult, ClawbackResultCode, LedgerKey,
    LedgerKeyClaimableBalance, OperationResult, OperationResultTr, TrustLineFlags,
};

use crate::frame::muxed_to_account_id;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;

/// Account flag for clawback enabled
const AUTH_CLAWBACK_ENABLED_FLAG: u32 = 0x8;

/// Trustline flag for clawback enabled
const TRUSTLINE_CLAWBACK_ENABLED_FLAG: u32 = TrustLineFlags::TrustlineClawbackEnabledFlag as u32;

/// Execute a Clawback operation.
///
/// This operation claws back an amount of an asset from an account's trustline.
/// The source account must be the issuer of the asset and the trustline must have
/// the TRUSTLINE_CLAWBACK_ENABLED flag set.
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

    // Convert MuxedAccount to AccountId for trustline lookup
    let from_account_id = muxed_to_account_id(&op.from);

    // Get the trustline
    let trustline = match state.get_trustline(&from_account_id, &op.asset) {
        Some(tl) => tl.clone(),
        None => {
            return Ok(make_clawback_result(ClawbackResultCode::NoTrust));
        }
    };

    // Check trustline has TRUSTLINE_CLAWBACK_ENABLED flag set
    // Per C++ stellar-core, we check the trustline flag, not the issuer account flag
    if trustline.flags & TRUSTLINE_CLAWBACK_ENABLED_FLAG == 0 {
        return Ok(make_clawback_result(ClawbackResultCode::NotClawbackEnabled));
    }

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

    // Check source account exists and is the issuer.
    // Use a mutable load to mirror C++ loadSourceAccount access patterns.
    let issuer_flags = match state.get_account_mut(source) {
        Some(a) => a.flags,
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
    if issuer_flags & AUTH_CLAWBACK_ENABLED_FLAG == 0 {
        return Ok(make_clawback_cb_result(
            ClawbackClaimableBalanceResultCode::NotClawbackEnabled,
        ));
    }

    let sponsorship_multiplier = entry.claimants.len() as i64;
    let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
        balance_id: entry.balance_id.clone(),
    });
    let sponsor = state.entry_sponsor(&ledger_key).cloned();
    // Delete the claimable balance (clawed back entirely)
    state.delete_claimable_balance(&op.balance_id);
    if let Some(sponsor) = sponsor {
        state.update_num_sponsoring(&sponsor, -sponsorship_multiplier)?;
    }

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

    const AUTHORIZED_FLAG: u32 = TrustLineFlags::AuthorizedFlag as u32;

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

    fn create_asset(issuer: &AccountId) -> Asset {
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer.clone(),
        })
    }

    fn create_test_trustline(
        account_id: AccountId,
        asset: Asset,
        balance: i64,
        limit: i64,
        flags: u32,
    ) -> TrustLineEntry {
        let tl_asset = match asset {
            Asset::CreditAlphanum4(a) => TrustLineAsset::CreditAlphanum4(a),
            Asset::CreditAlphanum12(a) => TrustLineAsset::CreditAlphanum12(a),
            Asset::Native => TrustLineAsset::Native,
        };
        TrustLineEntry {
            account_id,
            asset: tl_asset,
            balance,
            limit,
            flags,
            ext: TrustLineEntryExt::V0,
        }
    }

    #[test]
    fn test_clawback_not_enabled() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(0);
        let holder_id = create_test_account_id(1);

        // Issuer account (clawback flag on account doesn't matter for Clawback op)
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000, 0));
        state.create_account(create_test_account(holder_id.clone(), 10_000_000, 0));

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });

        // Create trustline WITHOUT clawback enabled flag (only authorized)
        let trustline = TrustLineEntry {
            account_id: holder_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            balance: 1000,
            limit: i64::MAX,
            flags: 1, // Authorized only, no clawback flag
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

        // Issuer account (clawback flag on account doesn't matter for Clawback op)
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000, 0));
        state.create_account(create_test_account(holder_id.clone(), 10_000_000, 0));

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });

        // Create trustline WITH clawback enabled flag
        let trustline = TrustLineEntry {
            account_id: holder_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            balance: 1000,
            limit: i64::MAX,
            flags: 1 | TRUSTLINE_CLAWBACK_ENABLED_FLAG, // Authorized + Clawback enabled
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

    /// Test Clawback with negative amount returns Malformed.
    ///
    /// C++ Reference: ClawbackTests.cpp - "malformed negative" test section
    #[test]
    fn test_clawback_malformed_negative_amount() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(10);
        let holder_id = create_test_account_id(11);

        state.create_account(create_test_account(
            issuer_id.clone(),
            100_000_000,
            AUTH_CLAWBACK_ENABLED_FLAG,
        ));
        state.create_account(create_test_account(holder_id.clone(), 100_000_000, 0));

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            holder_id.clone(),
            asset.clone(),
            1000,
            10_000,
            TRUSTLINE_CLAWBACK_ENABLED_FLAG,
        ));

        let op = ClawbackOp {
            asset,
            from: MuxedAccount::Ed25519(match holder_id.0 {
                PublicKey::PublicKeyTypeEd25519(k) => k,
            }),
            amount: -1, // Negative
        };

        let result = execute_clawback(&op, &issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Clawback(r)) => {
                assert!(
                    matches!(r, ClawbackResult::Malformed),
                    "Expected Malformed for negative amount, got {:?}",
                    r
                );
            }
            _ => panic!("Unexpected result type"),
        }
    }

    /// Test Clawback with zero amount returns Malformed.
    ///
    /// C++ Reference: ClawbackTests.cpp - "malformed zero" test section
    #[test]
    fn test_clawback_malformed_zero_amount() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(12);
        let holder_id = create_test_account_id(13);

        state.create_account(create_test_account(
            issuer_id.clone(),
            100_000_000,
            AUTH_CLAWBACK_ENABLED_FLAG,
        ));
        state.create_account(create_test_account(holder_id.clone(), 100_000_000, 0));

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            holder_id.clone(),
            asset.clone(),
            1000,
            10_000,
            TRUSTLINE_CLAWBACK_ENABLED_FLAG,
        ));

        let op = ClawbackOp {
            asset,
            from: MuxedAccount::Ed25519(match holder_id.0 {
                PublicKey::PublicKeyTypeEd25519(k) => k,
            }),
            amount: 0, // Zero
        };

        let result = execute_clawback(&op, &issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Clawback(r)) => {
                assert!(
                    matches!(r, ClawbackResult::Malformed),
                    "Expected Malformed for zero amount, got {:?}",
                    r
                );
            }
            _ => panic!("Unexpected result type"),
        }
    }

    /// Test Clawback on native asset returns Malformed.
    ///
    /// C++ Reference: ClawbackTests.cpp - "malformed native" test section
    #[test]
    fn test_clawback_malformed_native_asset() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(14);
        let holder_id = create_test_account_id(15);

        state.create_account(create_test_account(
            issuer_id.clone(),
            100_000_000,
            AUTH_CLAWBACK_ENABLED_FLAG,
        ));
        state.create_account(create_test_account(holder_id.clone(), 100_000_000, 0));

        let op = ClawbackOp {
            asset: Asset::Native, // Native asset
            from: MuxedAccount::Ed25519(match holder_id.0 {
                PublicKey::PublicKeyTypeEd25519(k) => k,
            }),
            amount: 100,
        };

        let result = execute_clawback(&op, &issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Clawback(r)) => {
                assert!(
                    matches!(r, ClawbackResult::Malformed),
                    "Expected Malformed for native asset, got {:?}",
                    r
                );
            }
            _ => panic!("Unexpected result type"),
        }
    }

    /// Test Clawback when source is not the issuer returns Malformed.
    ///
    /// C++ Reference: ClawbackTests.cpp - "not issuer" test section
    #[test]
    fn test_clawback_not_issuer() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(16);
        let holder_id = create_test_account_id(17);
        let non_issuer_id = create_test_account_id(18);

        state.create_account(create_test_account(
            issuer_id.clone(),
            100_000_000,
            AUTH_CLAWBACK_ENABLED_FLAG,
        ));
        state.create_account(create_test_account(holder_id.clone(), 100_000_000, 0));
        state.create_account(create_test_account(
            non_issuer_id.clone(),
            100_000_000,
            AUTH_CLAWBACK_ENABLED_FLAG,
        ));

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            holder_id.clone(),
            asset.clone(),
            1000,
            10_000,
            TRUSTLINE_CLAWBACK_ENABLED_FLAG,
        ));

        // Try to clawback from non-issuer account
        let op = ClawbackOp {
            asset,
            from: MuxedAccount::Ed25519(match holder_id.0 {
                PublicKey::PublicKeyTypeEd25519(k) => k,
            }),
            amount: 100,
        };

        let result = execute_clawback(&op, &non_issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Clawback(r)) => {
                assert!(
                    matches!(r, ClawbackResult::Malformed),
                    "Expected Malformed when not issuer, got {:?}",
                    r
                );
            }
            _ => panic!("Unexpected result type"),
        }
    }

    /// Test Clawback when trustline doesn't exist returns NoTrust.
    ///
    /// C++ Reference: ClawbackTests.cpp - "no trust" test section
    #[test]
    fn test_clawback_no_trust() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(19);
        let holder_id = create_test_account_id(20);

        state.create_account(create_test_account(
            issuer_id.clone(),
            100_000_000,
            AUTH_CLAWBACK_ENABLED_FLAG,
        ));
        state.create_account(create_test_account(holder_id.clone(), 100_000_000, 0));

        let asset = create_asset(&issuer_id);
        // No trustline created

        let op = ClawbackOp {
            asset,
            from: MuxedAccount::Ed25519(match holder_id.0 {
                PublicKey::PublicKeyTypeEd25519(k) => k,
            }),
            amount: 100,
        };

        let result = execute_clawback(&op, &issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Clawback(r)) => {
                assert!(
                    matches!(r, ClawbackResult::NoTrust),
                    "Expected NoTrust, got {:?}",
                    r
                );
            }
            _ => panic!("Unexpected result type"),
        }
    }

    /// Test Clawback underfunded - clawback amount exceeds trustline balance.
    ///
    /// C++ Reference: ClawbackTests.cpp - "underfunded" test section
    #[test]
    fn test_clawback_underfunded() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(21);
        let holder_id = create_test_account_id(22);

        state.create_account(create_test_account(
            issuer_id.clone(),
            100_000_000,
            AUTH_CLAWBACK_ENABLED_FLAG,
        ));
        state.create_account(create_test_account(holder_id.clone(), 100_000_000, 0));

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            holder_id.clone(),
            asset.clone(),
            100, // Only 100 balance
            10_000,
            TRUSTLINE_CLAWBACK_ENABLED_FLAG,
        ));

        let op = ClawbackOp {
            asset,
            from: MuxedAccount::Ed25519(match holder_id.0 {
                PublicKey::PublicKeyTypeEd25519(k) => k,
            }),
            amount: 200, // More than balance
        };

        let result = execute_clawback(&op, &issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Clawback(r)) => {
                assert!(
                    matches!(r, ClawbackResult::Underfunded),
                    "Expected Underfunded, got {:?}",
                    r
                );
            }
            _ => panic!("Unexpected result type"),
        }
    }

    /// Test Clawback partial amount succeeds and updates trustline correctly.
    ///
    /// C++ Reference: ClawbackTests.cpp - "partial amount" test section
    #[test]
    fn test_clawback_partial_amount() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(25);
        let holder_id = create_test_account_id(26);

        state.create_account(create_test_account(
            issuer_id.clone(),
            100_000_000,
            AUTH_CLAWBACK_ENABLED_FLAG,
        ));
        state.create_account(create_test_account(holder_id.clone(), 100_000_000, 0));

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            holder_id.clone(),
            asset.clone(),
            1000, // 1000 balance
            10_000,
            TRUSTLINE_CLAWBACK_ENABLED_FLAG,
        ));
        state.get_account_mut(&holder_id).unwrap().num_sub_entries += 1;

        let holder_id_clone = holder_id.clone();
        let op = ClawbackOp {
            asset: asset.clone(),
            from: MuxedAccount::Ed25519(match holder_id_clone.0 {
                PublicKey::PublicKeyTypeEd25519(k) => k,
            }),
            amount: 300, // Clawback only 300
        };

        let result = execute_clawback(&op, &issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Clawback(r)) => {
                assert!(
                    matches!(r, ClawbackResult::Success),
                    "Expected Success, got {:?}",
                    r
                );
            }
            _ => panic!("Unexpected result type"),
        }

        // Verify trustline balance was reduced
        let trustline = state.get_trustline(&holder_id, &asset).unwrap();
        assert_eq!(trustline.balance, 700, "Expected balance to be reduced to 700");
    }

    /// Test Clawback with trustline not authorized returns NotClawbackEnabled.
    /// Clawback requires the trustline to have TRUSTLINE_CLAWBACK_ENABLED_FLAG.
    ///
    /// C++ Reference: ClawbackTests.cpp - "trustline not clawback enabled"
    #[test]
    fn test_clawback_trustline_not_clawback_enabled() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(27);
        let holder_id = create_test_account_id(28);

        // Issuer has AUTH_CLAWBACK_ENABLED_FLAG
        state.create_account(create_test_account(
            issuer_id.clone(),
            100_000_000,
            AUTH_CLAWBACK_ENABLED_FLAG,
        ));
        state.create_account(create_test_account(holder_id.clone(), 100_000_000, 0));

        let asset = create_asset(&issuer_id);
        // Trustline does NOT have TRUSTLINE_CLAWBACK_ENABLED_FLAG
        state.create_trustline(create_test_trustline(
            holder_id.clone(),
            asset.clone(),
            1000,
            10_000,
            AUTHORIZED_FLAG, // Only authorized, not clawback enabled
        ));

        let op = ClawbackOp {
            asset,
            from: MuxedAccount::Ed25519(match holder_id.0 {
                PublicKey::PublicKeyTypeEd25519(k) => k,
            }),
            amount: 100,
        };

        let result = execute_clawback(&op, &issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Clawback(r)) => {
                assert!(
                    matches!(r, ClawbackResult::NotClawbackEnabled),
                    "Expected NotClawbackEnabled, got {:?}",
                    r
                );
            }
            _ => panic!("Unexpected result type"),
        }
    }

    /// Test Clawback entire balance succeeds.
    ///
    /// C++ Reference: ClawbackTests.cpp - "full amount"
    #[test]
    fn test_clawback_full_balance() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(29);
        let holder_id = create_test_account_id(30);

        state.create_account(create_test_account(
            issuer_id.clone(),
            100_000_000,
            AUTH_CLAWBACK_ENABLED_FLAG,
        ));
        state.create_account(create_test_account(holder_id.clone(), 100_000_000, 0));

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            holder_id.clone(),
            asset.clone(),
            500,
            10_000,
            TRUSTLINE_CLAWBACK_ENABLED_FLAG,
        ));
        state.get_account_mut(&holder_id).unwrap().num_sub_entries += 1;

        let holder_id_clone = holder_id.clone();
        let op = ClawbackOp {
            asset: asset.clone(),
            from: MuxedAccount::Ed25519(match holder_id_clone.0 {
                PublicKey::PublicKeyTypeEd25519(k) => k,
            }),
            amount: 500, // Clawback entire balance
        };

        let result = execute_clawback(&op, &issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Clawback(r)) => {
                assert!(
                    matches!(r, ClawbackResult::Success),
                    "Expected Success, got {:?}",
                    r
                );
            }
            _ => panic!("Unexpected result type"),
        }

        // Verify trustline balance is now zero
        let trustline = state.get_trustline(&holder_id, &asset).unwrap();
        assert_eq!(trustline.balance, 0, "Expected balance to be 0");
    }
}
