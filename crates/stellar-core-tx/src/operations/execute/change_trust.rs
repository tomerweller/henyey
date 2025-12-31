//! ChangeTrust operation execution.

use stellar_xdr::curr::{
    AccountId, Asset, ChangeTrustAsset, ChangeTrustOp, ChangeTrustResult, ChangeTrustResultCode,
    OperationResult, OperationResultTr, TrustLineEntry, TrustLineEntryExt, TrustLineFlags,
};

use crate::apply::account_id_to_key;
use crate::state::{AssetKey, LedgerStateManager};
use crate::validation::LedgerContext;
use crate::{Result, TxError};

/// Execute a ChangeTrust operation.
pub fn execute_change_trust(
    op: &ChangeTrustOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Validate limit
    if op.limit < 0 {
        return Ok(make_result(ChangeTrustResultCode::Malformed));
    }

    // Convert ChangeTrustAsset to Asset
    let asset = match &op.line {
        ChangeTrustAsset::Native => {
            return Ok(make_result(ChangeTrustResultCode::Malformed));
        }
        ChangeTrustAsset::CreditAlphanum4(a) => Asset::CreditAlphanum4(a.clone()),
        ChangeTrustAsset::CreditAlphanum12(a) => Asset::CreditAlphanum12(a.clone()),
        ChangeTrustAsset::PoolShare(_) => {
            // Pool shares handled separately, for now return success
            return Ok(make_result(ChangeTrustResultCode::Success));
        }
    };

    // Check not trusting self
    let issuer = get_asset_issuer(&asset);
    if let Some(issuer_id) = issuer {
        let source_key = account_id_to_key(source);
        let issuer_key = account_id_to_key(&issuer_id);
        if source_key == issuer_key {
            return Ok(make_result(ChangeTrustResultCode::SelfNotAllowed));
        }
    }

    // Check source account exists
    if state.get_account(source).is_none() {
        return Err(TxError::SourceAccountNotFound);
    }

    // Get existing trustline if any
    let existing = state.get_trustline(source, &asset);

    if op.limit == 0 {
        // Removing trustline
        if let Some(tl) = existing {
            if tl.balance > 0 {
                // Can't remove trustline with balance
                return Ok(make_result(ChangeTrustResultCode::InvalidLimit));
            }
            state.delete_trustline(source, &asset);

            // Decrease sub-entries
            if let Some(account) = state.get_account_mut(source) {
                if account.num_sub_entries > 0 {
                    account.num_sub_entries -= 1;
                }
            }
        }
    } else if existing.is_some() {
        // Updating existing trustline
        if let Some(tl) = state.get_trustline_mut(source, &asset) {
            tl.limit = op.limit;
        }
    } else {
        // Creating new trustline
        // Check source can afford new sub-entry
        let source_account = state
            .get_account(source)
            .ok_or(TxError::SourceAccountNotFound)?;
        let new_min_balance = state.minimum_balance(source_account.num_sub_entries + 1);
        if source_account.balance < new_min_balance {
            return Ok(make_result(ChangeTrustResultCode::LowReserve));
        }

        // Create trustline
        let trustline = TrustLineEntry {
            account_id: source.clone(),
            asset: changeTrustAssetToTrustLineAsset(&op.line),
            balance: 0,
            limit: op.limit,
            flags: 0,
            ext: TrustLineEntryExt::V0,
        };

        state.create_trustline(trustline);

        // Increase sub-entries
        if let Some(account) = state.get_account_mut(source) {
            account.num_sub_entries += 1;
        }
    }

    Ok(make_result(ChangeTrustResultCode::Success))
}

fn changeTrustAssetToTrustLineAsset(asset: &ChangeTrustAsset) -> stellar_xdr::curr::TrustLineAsset {
    use sha2::{Digest, Sha256};
    use stellar_xdr::curr::{Limits, PoolId, Hash, WriteXdr};

    match asset {
        ChangeTrustAsset::Native => stellar_xdr::curr::TrustLineAsset::Native,
        ChangeTrustAsset::CreditAlphanum4(a) => {
            stellar_xdr::curr::TrustLineAsset::CreditAlphanum4(a.clone())
        }
        ChangeTrustAsset::CreditAlphanum12(a) => {
            stellar_xdr::curr::TrustLineAsset::CreditAlphanum12(a.clone())
        }
        ChangeTrustAsset::PoolShare(params) => {
            // Compute pool ID as SHA256 hash of the liquidity pool parameters XDR
            let pool_id = if let Ok(xdr_bytes) = params.to_xdr(Limits::none()) {
                let mut hasher = Sha256::new();
                hasher.update(&xdr_bytes);
                Hash(hasher.finalize().into())
            } else {
                Hash([0u8; 32])
            };
            stellar_xdr::curr::TrustLineAsset::PoolShare(PoolId(pool_id))
        }
    }
}

fn get_asset_issuer(asset: &Asset) -> Option<AccountId> {
    match asset {
        Asset::Native => None,
        Asset::CreditAlphanum4(a) => Some(a.issuer.clone()),
        Asset::CreditAlphanum12(a) => Some(a.issuer.clone()),
    }
}

fn make_result(code: ChangeTrustResultCode) -> OperationResult {
    let result = match code {
        ChangeTrustResultCode::Success => ChangeTrustResult::Success,
        ChangeTrustResultCode::Malformed => ChangeTrustResult::Malformed,
        ChangeTrustResultCode::NoIssuer => ChangeTrustResult::NoIssuer,
        ChangeTrustResultCode::InvalidLimit => ChangeTrustResult::InvalidLimit,
        ChangeTrustResultCode::LowReserve => ChangeTrustResult::LowReserve,
        ChangeTrustResultCode::SelfNotAllowed => ChangeTrustResult::SelfNotAllowed,
        ChangeTrustResultCode::TrustLineMissing => ChangeTrustResult::TrustLineMissing,
        ChangeTrustResultCode::CannotDelete => ChangeTrustResult::CannotDelete,
        ChangeTrustResultCode::NotAuthMaintainLiabilities => {
            ChangeTrustResult::NotAuthMaintainLiabilities
        }
    };
    OperationResult::OpInner(OperationResultTr::ChangeTrust(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    fn create_test_account(account_id: AccountId, balance: i64) -> AccountEntry {
        AccountEntry {
            account_id,
            balance,
            seq_num: SequenceNumber(1),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
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
    fn test_change_trust_create() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let asset = AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_id,
        };

        let op = ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(asset),
            limit: 1_000_000_000,
        };

        let result = execute_change_trust(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        // Verify sub-entries increased
        assert_eq!(state.get_account(&source_id).unwrap().num_sub_entries, 1);
    }
}
