//! Sponsorship operation execution.
//!
//! This module implements the execution logic for sponsorship operations:
//! - BeginSponsoringFutureReserves
//! - EndSponsoringFutureReserves
//! - RevokeSponsorship

use stellar_xdr::curr::{
    AccountId, BeginSponsoringFutureReservesOp, BeginSponsoringFutureReservesResult,
    BeginSponsoringFutureReservesResultCode, EndSponsoringFutureReservesResult,
    EndSponsoringFutureReservesResultCode, OperationResult, OperationResultTr,
    RevokeSponsorshipOp, RevokeSponsorshipResult, RevokeSponsorshipResultCode,
    LedgerEntryData, LedgerKey, LedgerKeyAccount, LedgerKeyClaimableBalance, LedgerKeyData,
    LedgerKeyOffer, LedgerKeyTrustLine, TrustLineAsset, SponsorshipDescriptor,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::{Result, TxError};

/// Execute a BeginSponsoringFutureReserves operation.
///
/// This operation marks the beginning of a sponsorship relationship where
/// the source account will pay reserves for entries created by the sponsored account.
///
/// Note: The sponsored account does NOT need to exist at this point - it may be
/// created by a later operation in the same transaction (e.g., CreateAccount).
pub fn execute_begin_sponsoring_future_reserves(
    op: &BeginSponsoringFutureReservesOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Check source account exists (the sponsor must exist to pay reserves)
    if state.get_account(source).is_none() {
        return Ok(make_begin_result(
            BeginSponsoringFutureReservesResultCode::Malformed,
        ));
    }

    // Note: We do NOT check if sponsored_id exists here because:
    // 1. The account may be created by a later CreateAccount operation
    // 2. C++ stellar-core does not require the sponsored account to exist

    // Cannot sponsor yourself
    if source == &op.sponsored_id {
        return Ok(make_begin_result(
            BeginSponsoringFutureReservesResultCode::Malformed,
        ));
    }

    if state.is_sponsored(&op.sponsored_id) {
        return Ok(make_begin_result(
            BeginSponsoringFutureReservesResultCode::AlreadySponsored,
        ));
    }

    if state.is_sponsored(source) || state.is_sponsoring(&op.sponsored_id) {
        return Ok(make_begin_result(
            BeginSponsoringFutureReservesResultCode::Recursive,
        ));
    }

    state.push_sponsorship(source.clone(), op.sponsored_id.clone());

    Ok(make_begin_result(
        BeginSponsoringFutureReservesResultCode::Success,
    ))
}

/// Execute an EndSponsoringFutureReserves operation.
///
/// This operation ends a sponsorship relationship that was begun with
/// BeginSponsoringFutureReserves.
///
/// Note: In a full implementation, this would pop from the sponsorship stack.
pub fn execute_end_sponsoring_future_reserves(
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Check source account exists
    if state.get_account(source).is_none() {
        return Ok(make_end_result(
            EndSponsoringFutureReservesResultCode::NotSponsored,
        ));
    }

    if state.remove_sponsorship_for(source).is_none() {
        return Ok(make_end_result(
            EndSponsoringFutureReservesResultCode::NotSponsored,
        ));
    }

    Ok(make_end_result(EndSponsoringFutureReservesResultCode::Success))
}

/// Execute a RevokeSponsorship operation.
///
/// This operation revokes sponsorship of a ledger entry, transferring
/// the reserve responsibility back to the entry owner.
pub fn execute_revoke_sponsorship(
    op: &RevokeSponsorshipOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    use stellar_xdr::curr::RevokeSponsorshipOp as RSO;

    // Check source account exists
    if state.get_account(source).is_none() {
        return Ok(make_revoke_result(RevokeSponsorshipResultCode::NotSponsor));
    }

    match op {
        RSO::LedgerEntry(ledger_key) => {
            // Check if the entry exists
            let Some(entry) = state.get_entry(ledger_key) else {
                return Ok(make_revoke_result(RevokeSponsorshipResultCode::DoesNotExist));
            };
            let entry = entry.clone();

            let (owner_id, multiplier) = match &entry.data {
                LedgerEntryData::Account(a) => (a.account_id.clone(), 2i64),
                LedgerEntryData::Trustline(tl) => {
                    let mult = match &tl.asset {
                        TrustLineAsset::PoolShare(_) => 2i64,
                        _ => 1i64,
                    };
                    (tl.account_id.clone(), mult)
                }
                LedgerEntryData::Offer(o) => (o.seller_id.clone(), 1i64),
                LedgerEntryData::Data(d) => (d.account_id.clone(), 1i64),
                LedgerEntryData::ClaimableBalance(cb) => {
                    let Some(sponsor) = state.entry_sponsor(ledger_key) else {
                        return Ok(make_revoke_result(RevokeSponsorshipResultCode::Malformed));
                    };
                    (sponsor.clone(), cb.claimants.len() as i64)
                }
                _ => {
                    return Ok(make_revoke_result(RevokeSponsorshipResultCode::Malformed));
                }
            };

            let current_sponsor = state.entry_sponsor(ledger_key).cloned();
            let was_sponsored = current_sponsor.is_some();

            if was_sponsored {
                if current_sponsor.as_ref() != Some(source) {
                    return Ok(make_revoke_result(RevokeSponsorshipResultCode::NotSponsor));
                }
            } else if &owner_id != source {
                return Ok(make_revoke_result(RevokeSponsorshipResultCode::NotSponsor));
            }

            let new_sponsor = state.active_sponsor_for(source);
            let will_be_sponsored = new_sponsor
                .as_ref()
                .map(|sponsor| sponsor != &owner_id)
                .unwrap_or(false);

            if matches!(entry.data, LedgerEntryData::ClaimableBalance(_)) && !will_be_sponsored {
                return Ok(make_revoke_result(
                    RevokeSponsorshipResultCode::OnlyTransferable,
                ));
            }

            let mut sponsorship_changed = false;
            if was_sponsored && will_be_sponsored {
                let new_sponsor = new_sponsor.expect("sponsor must exist");
                let new_sponsor_account = state
                    .get_account(&new_sponsor)
                    .ok_or(TxError::SourceAccountNotFound)?;
                let new_min_balance = state.minimum_balance_for_account_with_deltas(
                    new_sponsor_account,
                    context.protocol_version,
                    0,
                    multiplier,
                    0,
                )?;
                if new_sponsor_account.balance < new_min_balance {
                    return Ok(make_revoke_result(RevokeSponsorshipResultCode::LowReserve));
                }

                let old_sponsor = current_sponsor.expect("old sponsor exists");
                state.update_num_sponsoring(&old_sponsor, -multiplier)?;
                state.update_num_sponsoring(&new_sponsor, multiplier)?;
                state.set_entry_sponsor(ledger_key.clone(), new_sponsor);
                sponsorship_changed = true;
            } else if was_sponsored && !will_be_sponsored {
                if let Some(owner_account) = state.get_account(&owner_id) {
                    let new_min_balance = state.minimum_balance_for_account_with_deltas(
                        owner_account,
                        context.protocol_version,
                        0,
                        0,
                        -multiplier,
                    )?;
                    if owner_account.balance < new_min_balance {
                        return Ok(make_revoke_result(RevokeSponsorshipResultCode::LowReserve));
                    }
                }

                if matches!(entry.data, LedgerEntryData::ClaimableBalance(_)) {
                    state.remove_entry_sponsorship_with_sponsor_counts(
                        ledger_key,
                        None,
                        multiplier,
                    )?;
                } else {
                    state.remove_entry_sponsorship_and_update_counts(
                        ledger_key,
                        &owner_id,
                        multiplier,
                    )?;
                }
                sponsorship_changed = true;
            } else if !was_sponsored && will_be_sponsored {
                let new_sponsor = new_sponsor.expect("sponsor must exist");
                let new_sponsor_account = state
                    .get_account(&new_sponsor)
                    .ok_or(TxError::SourceAccountNotFound)?;
                let new_min_balance = state.minimum_balance_for_account_with_deltas(
                    new_sponsor_account,
                    context.protocol_version,
                    0,
                    multiplier,
                    0,
                )?;
                if new_sponsor_account.balance < new_min_balance {
                    return Ok(make_revoke_result(RevokeSponsorshipResultCode::LowReserve));
                }

                state.apply_entry_sponsorship_with_sponsor(
                    ledger_key.clone(),
                    &new_sponsor,
                    Some(&owner_id),
                    multiplier,
                )?;
                sponsorship_changed = true;
            }

            if sponsorship_changed {
                update_entry_after_sponsorship(state, ledger_key)?;
            }

            Ok(make_revoke_result(RevokeSponsorshipResultCode::Success))
        }
        RSO::Signer(signer_key) => {
            // Check if the account exists
            let Some(account) = state.get_account(&signer_key.account_id) else {
                return Ok(make_revoke_result(RevokeSponsorshipResultCode::DoesNotExist));
            };

            let signer_pos = account
                .signers
                .iter()
                .position(|s| s.key == signer_key.signer_key);
            let Some(pos) = signer_pos else {
                return Ok(make_revoke_result(RevokeSponsorshipResultCode::DoesNotExist));
            };

            let owner_id = signer_key.account_id.clone();
            let current_sponsor = current_signer_sponsor(account, pos);
            let was_sponsored = current_sponsor.is_some();

            if was_sponsored {
                if current_sponsor.as_ref() != Some(source) {
                    return Ok(make_revoke_result(RevokeSponsorshipResultCode::NotSponsor));
                }
            } else if &owner_id != source {
                return Ok(make_revoke_result(RevokeSponsorshipResultCode::NotSponsor));
            }

            let new_sponsor = state.active_sponsor_for(source);
            let will_be_sponsored = new_sponsor
                .as_ref()
                .map(|sponsor| sponsor != &owner_id)
                .unwrap_or(false);

            if was_sponsored && will_be_sponsored {
                let new_sponsor = new_sponsor.expect("sponsor must exist");
                let new_sponsor_account = state
                    .get_account(&new_sponsor)
                    .ok_or(TxError::SourceAccountNotFound)?;
                let new_min_balance = state.minimum_balance_for_account_with_deltas(
                    new_sponsor_account,
                    context.protocol_version,
                    0,
                    1,
                    0,
                )?;
                if new_sponsor_account.balance < new_min_balance {
                    return Ok(make_revoke_result(RevokeSponsorshipResultCode::LowReserve));
                }

                let old_sponsor = current_sponsor.expect("old sponsor exists");
                state.update_num_sponsoring(&old_sponsor, -1)?;
                state.update_num_sponsoring(&new_sponsor, 1)?;
                set_signer_sponsor(state, &owner_id, pos, Some(new_sponsor))?;
            } else if was_sponsored && !will_be_sponsored {
                if let Some(owner_account) = state.get_account(&owner_id) {
                    let new_min_balance = state.minimum_balance_for_account_with_deltas(
                        owner_account,
                        context.protocol_version,
                        0,
                        0,
                        -1,
                    )?;
                    if owner_account.balance < new_min_balance {
                        return Ok(make_revoke_result(RevokeSponsorshipResultCode::LowReserve));
                    }
                }

                let old_sponsor = current_sponsor.expect("old sponsor exists");
                state.update_num_sponsoring(&old_sponsor, -1)?;
                state.update_num_sponsored(&owner_id, -1)?;
                set_signer_sponsor(state, &owner_id, pos, None)?;
            } else if !was_sponsored && will_be_sponsored {
                let new_sponsor = new_sponsor.expect("sponsor must exist");
                let new_sponsor_account = state
                    .get_account(&new_sponsor)
                    .ok_or(TxError::SourceAccountNotFound)?;
                let new_min_balance = state.minimum_balance_for_account_with_deltas(
                    new_sponsor_account,
                    context.protocol_version,
                    0,
                    1,
                    0,
                )?;
                if new_sponsor_account.balance < new_min_balance {
                    return Ok(make_revoke_result(RevokeSponsorshipResultCode::LowReserve));
                }

                state.update_num_sponsoring(&new_sponsor, 1)?;
                state.update_num_sponsored(&owner_id, 1)?;
                set_signer_sponsor(state, &owner_id, pos, Some(new_sponsor))?;
            }

            Ok(make_revoke_result(RevokeSponsorshipResultCode::Success))
        }
    }
}

/// Create a BeginSponsoringFutureReserves result.
fn make_begin_result(code: BeginSponsoringFutureReservesResultCode) -> OperationResult {
    let result = match code {
        BeginSponsoringFutureReservesResultCode::Success => {
            BeginSponsoringFutureReservesResult::Success
        }
        BeginSponsoringFutureReservesResultCode::Malformed => {
            BeginSponsoringFutureReservesResult::Malformed
        }
        BeginSponsoringFutureReservesResultCode::AlreadySponsored => {
            BeginSponsoringFutureReservesResult::AlreadySponsored
        }
        BeginSponsoringFutureReservesResultCode::Recursive => {
            BeginSponsoringFutureReservesResult::Recursive
        }
    };

    OperationResult::OpInner(OperationResultTr::BeginSponsoringFutureReserves(result))
}

/// Create an EndSponsoringFutureReserves result.
fn make_end_result(code: EndSponsoringFutureReservesResultCode) -> OperationResult {
    let result = match code {
        EndSponsoringFutureReservesResultCode::Success => EndSponsoringFutureReservesResult::Success,
        EndSponsoringFutureReservesResultCode::NotSponsored => {
            EndSponsoringFutureReservesResult::NotSponsored
        }
    };

    OperationResult::OpInner(OperationResultTr::EndSponsoringFutureReserves(result))
}

/// Create a RevokeSponsorship result.
fn make_revoke_result(code: RevokeSponsorshipResultCode) -> OperationResult {
    let result = match code {
        RevokeSponsorshipResultCode::Success => RevokeSponsorshipResult::Success,
        RevokeSponsorshipResultCode::DoesNotExist => RevokeSponsorshipResult::DoesNotExist,
        RevokeSponsorshipResultCode::NotSponsor => RevokeSponsorshipResult::NotSponsor,
        RevokeSponsorshipResultCode::LowReserve => RevokeSponsorshipResult::LowReserve,
        RevokeSponsorshipResultCode::OnlyTransferable => RevokeSponsorshipResult::OnlyTransferable,
        RevokeSponsorshipResultCode::Malformed => RevokeSponsorshipResult::Malformed,
    };

    OperationResult::OpInner(OperationResultTr::RevokeSponsorship(result))
}

fn update_entry_after_sponsorship(
    state: &mut LedgerStateManager,
    ledger_key: &LedgerKey,
) -> Result<()> {
    match ledger_key {
        LedgerKey::Account(LedgerKeyAccount { account_id }) => {
            if let Some(account) = state.get_account(account_id).cloned() {
                state.update_account(account);
            }
        }
        LedgerKey::Trustline(LedgerKeyTrustLine { account_id, asset }) => {
            if let Some(tl) = state.get_trustline_by_trustline_asset(account_id, asset).cloned() {
                state.update_trustline(tl);
            }
        }
        LedgerKey::Offer(LedgerKeyOffer { seller_id, offer_id }) => {
            if let Some(offer) = state.get_offer(seller_id, *offer_id).cloned() {
                state.update_offer(offer);
            }
        }
        LedgerKey::Data(LedgerKeyData { account_id, data_name }) => {
            let name = String::from_utf8_lossy(data_name.as_vec()).to_string();
            if let Some(data) = state.get_data(account_id, &name).cloned() {
                state.update_data(data);
            }
        }
        LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance { balance_id }) => {
            if let Some(cb) = state.get_claimable_balance(balance_id).cloned() {
                state.update_claimable_balance(cb);
            }
        }
        _ => {}
    }
    Ok(())
}

fn current_signer_sponsor(account: &stellar_xdr::curr::AccountEntry, pos: usize) -> Option<AccountId> {
    match &account.ext {
        stellar_xdr::curr::AccountEntryExt::V0 => None,
        stellar_xdr::curr::AccountEntryExt::V1(v1) => match &v1.ext {
            stellar_xdr::curr::AccountEntryExtensionV1Ext::V0 => None,
            stellar_xdr::curr::AccountEntryExtensionV1Ext::V2(v2) => v2
                .signer_sponsoring_i_ds
                .get(pos)
                .and_then(|id| match id {
                    SponsorshipDescriptor(Some(s)) => Some(s.clone()),
                    _ => None,
                }),
        },
    }
}

fn set_signer_sponsor(
    state: &mut LedgerStateManager,
    account_id: &AccountId,
    pos: usize,
    sponsor: Option<AccountId>,
) -> Result<()> {
    let entry = {
        let account = state
            .get_account_mut(account_id)
            .ok_or(TxError::SourceAccountNotFound)?;
        let ext = crate::state::ensure_account_ext_v2(account);
        let mut sponsoring_ids: Vec<SponsorshipDescriptor> =
            ext.signer_sponsoring_i_ds.iter().cloned().collect();
        if sponsoring_ids.len() <= pos {
            return Err(TxError::Internal(
                "signer sponsoring ids out of range".to_string(),
            ));
        }
        sponsoring_ids[pos] = SponsorshipDescriptor(sponsor);
        ext.signer_sponsoring_i_ds = sponsoring_ids.try_into().unwrap_or_default();
        account.clone()
    };
    state.update_account(entry);
    Ok(())
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

    fn create_data_entry(account_id: &AccountId, name: &str) -> DataEntry {
        DataEntry {
            account_id: account_id.clone(),
            data_name: String64::try_from(name.as_bytes().to_vec()).unwrap(),
            data_value: vec![1u8].try_into().unwrap(),
            ext: DataEntryExt::V0,
        }
    }

    fn create_claimable_balance_entry(
        sponsor_id: &AccountId,
        balance_id: ClaimableBalanceId,
    ) -> ClaimableBalanceEntry {
        let claimant = Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: sponsor_id.clone(),
            predicate: ClaimPredicate::Unconditional,
        });
        ClaimableBalanceEntry {
            balance_id,
            claimants: vec![claimant].try_into().unwrap(),
            asset: Asset::Native,
            amount: 10,
            ext: ClaimableBalanceEntryExt::V0,
        }
    }

    fn create_account_with_signer(
        account_id: AccountId,
        signer_key: SignerKey,
        sponsor: Option<AccountId>,
    ) -> AccountEntry {
        let signers = vec![Signer {
            key: signer_key,
            weight: 1,
        }];
        let sponsoring_ids = vec![SponsorshipDescriptor(sponsor.clone())];
        AccountEntry {
            account_id,
            balance: 100_000_000,
            seq_num: SequenceNumber(1),
            num_sub_entries: 1,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: signers.try_into().unwrap(),
            ext: AccountEntryExt::V1(AccountEntryExtensionV1 {
                liabilities: Liabilities {
                    buying: 0,
                    selling: 0,
                },
                ext: AccountEntryExtensionV1Ext::V2(AccountEntryExtensionV2 {
                    num_sponsored: if sponsor.is_some() { 1 } else { 0 },
                    num_sponsoring: 0,
                    signer_sponsoring_i_ds: sponsoring_ids.try_into().unwrap(),
                    ext: AccountEntryExtensionV2Ext::V0,
                }),
            }),
        }
    }

    #[test]
    fn test_begin_sponsoring_self() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = BeginSponsoringFutureReservesOp {
            sponsored_id: source_id.clone(), // Sponsor self
        };

        let result =
            execute_begin_sponsoring_future_reserves(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::BeginSponsoringFutureReserves(r)) => {
                assert!(matches!(r, BeginSponsoringFutureReservesResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_begin_sponsoring_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let sponsor_id = create_test_account_id(0);
        let sponsored_id = create_test_account_id(1);
        state.create_account(create_test_account(sponsor_id.clone(), 100_000_000));
        state.create_account(create_test_account(sponsored_id.clone(), 10_000_000));

        let op = BeginSponsoringFutureReservesOp {
            sponsored_id: sponsored_id.clone(),
        };

        let result =
            execute_begin_sponsoring_future_reserves(&op, &sponsor_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::BeginSponsoringFutureReserves(r)) => {
                assert!(matches!(r, BeginSponsoringFutureReservesResult::Success));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_end_sponsoring_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let sponsor_id = create_test_account_id(0);
        let sponsored_id = create_test_account_id(1);
        state.create_account(create_test_account(sponsor_id.clone(), 100_000_000));
        state.create_account(create_test_account(sponsored_id.clone(), 100_000_000));

        let begin = BeginSponsoringFutureReservesOp {
            sponsored_id: sponsored_id.clone(),
        };
        execute_begin_sponsoring_future_reserves(&begin, &sponsor_id, &mut state, &context)
            .unwrap();

        let result =
            execute_end_sponsoring_future_reserves(&sponsored_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::EndSponsoringFutureReserves(r)) => {
                assert!(matches!(r, EndSponsoringFutureReservesResult::Success));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_end_sponsoring_not_sponsored() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let account_id = create_test_account_id(0);
        state.create_account(create_test_account(account_id.clone(), 100_000_000));

        let result = execute_end_sponsoring_future_reserves(&account_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::EndSponsoringFutureReserves(r)) => {
                assert!(matches!(r, EndSponsoringFutureReservesResult::NotSponsored));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_revoke_sponsorship_not_exists() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let nonexistent_id = create_test_account_id(99);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = RevokeSponsorshipOp::LedgerEntry(LedgerKey::Account(LedgerKeyAccount {
            account_id: nonexistent_id,
        }));

        let result = execute_revoke_sponsorship(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::RevokeSponsorship(r)) => {
                assert!(matches!(r, RevokeSponsorshipResult::DoesNotExist));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_revoke_sponsorship_removes_entry_sponsorship() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let sponsor_id = create_test_account_id(1);
        let owner_id = create_test_account_id(2);

        state.create_account(create_test_account(sponsor_id.clone(), 100_000_000));
        state.create_account(create_test_account(owner_id.clone(), 100_000_000));

        let data_entry = create_data_entry(&owner_id, "test");
        state.create_data(data_entry);

        let ledger_key = LedgerKey::Data(LedgerKeyData {
            account_id: owner_id.clone(),
            data_name: String64::try_from("test".as_bytes().to_vec()).unwrap(),
        });
        state
            .apply_entry_sponsorship_with_sponsor(ledger_key.clone(), &sponsor_id, Some(&owner_id), 1)
            .unwrap();

        let op = RevokeSponsorshipOp::LedgerEntry(ledger_key.clone());
        let result = execute_revoke_sponsorship(&op, &sponsor_id, &mut state, &context);
        assert!(matches!(
            result.unwrap(),
            OperationResult::OpInner(OperationResultTr::RevokeSponsorship(
                RevokeSponsorshipResult::Success
            ))
        ));
        assert!(state.entry_sponsor(&ledger_key).is_none());
    }

    #[test]
    fn test_revoke_sponsorship_not_sponsor() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let owner_id = create_test_account_id(1);
        let other_id = create_test_account_id(2);

        state.create_account(create_test_account(owner_id.clone(), 100_000_000));
        state.create_account(create_test_account(other_id.clone(), 100_000_000));

        let data_entry = create_data_entry(&owner_id, "test");
        state.create_data(data_entry);

        let ledger_key = LedgerKey::Data(LedgerKeyData {
            account_id: owner_id.clone(),
            data_name: String64::try_from("test".as_bytes().to_vec()).unwrap(),
        });
        let op = RevokeSponsorshipOp::LedgerEntry(ledger_key);
        let result = execute_revoke_sponsorship(&op, &other_id, &mut state, &context);
        assert!(matches!(
            result.unwrap(),
            OperationResult::OpInner(OperationResultTr::RevokeSponsorship(
                RevokeSponsorshipResult::NotSponsor
            ))
        ));
    }

    #[test]
    fn test_revoke_sponsorship_transfer() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let old_sponsor = create_test_account_id(1);
        let new_sponsor = create_test_account_id(2);
        let owner_id = create_test_account_id(3);

        state.create_account(create_test_account(old_sponsor.clone(), 100_000_000));
        state.create_account(create_test_account(new_sponsor.clone(), 100_000_000));
        state.create_account(create_test_account(owner_id.clone(), 100_000_000));

        let data_entry = create_data_entry(&owner_id, "test");
        state.create_data(data_entry);

        let ledger_key = LedgerKey::Data(LedgerKeyData {
            account_id: owner_id.clone(),
            data_name: String64::try_from("test".as_bytes().to_vec()).unwrap(),
        });
        state
            .apply_entry_sponsorship_with_sponsor(ledger_key.clone(), &old_sponsor, Some(&owner_id), 1)
            .unwrap();

        let begin = BeginSponsoringFutureReservesOp {
            sponsored_id: old_sponsor.clone(),
        };
        execute_begin_sponsoring_future_reserves(&begin, &new_sponsor, &mut state, &context).unwrap();

        let op = RevokeSponsorshipOp::LedgerEntry(ledger_key.clone());
        let result = execute_revoke_sponsorship(&op, &old_sponsor, &mut state, &context);
        assert!(matches!(
            result.unwrap(),
            OperationResult::OpInner(OperationResultTr::RevokeSponsorship(
                RevokeSponsorshipResult::Success
            ))
        ));

        let sponsor = state.entry_sponsor(&ledger_key).cloned();
        assert_eq!(sponsor, Some(new_sponsor));
    }

    #[test]
    fn test_revoke_sponsorship_claimable_balance_only_transferable() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let sponsor_id = create_test_account_id(1);
        state.create_account(create_test_account(sponsor_id.clone(), 100_000_000));

        let balance_id =
            ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([1u8; 32]));
        let entry = create_claimable_balance_entry(&sponsor_id, balance_id.clone());
        state.create_claimable_balance(entry);

        let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
            balance_id: balance_id.clone(),
        });
        state
            .apply_entry_sponsorship_with_sponsor(ledger_key.clone(), &sponsor_id, None, 1)
            .unwrap();

        let op = RevokeSponsorshipOp::LedgerEntry(ledger_key);
        let result = execute_revoke_sponsorship(&op, &sponsor_id, &mut state, &context);
        assert!(matches!(
            result.unwrap(),
            OperationResult::OpInner(OperationResultTr::RevokeSponsorship(
                RevokeSponsorshipResult::OnlyTransferable
            ))
        ));
    }

    #[test]
    fn test_revoke_sponsorship_signer_removes_sponsorship() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let sponsor_id = create_test_account_id(1);
        let owner_id = create_test_account_id(2);
        let signer_key = SignerKey::Ed25519(Uint256([7u8; 32]));

        state.create_account(create_test_account(sponsor_id.clone(), 100_000_000));
        state.create_account(create_account_with_signer(
            owner_id.clone(),
            signer_key.clone(),
            Some(sponsor_id.clone()),
        ));
        if let Some(account) = state.get_account_mut(&sponsor_id) {
            let ext = crate::state::ensure_account_ext_v2(account);
            ext.num_sponsoring = 1;
        }

        let op = RevokeSponsorshipOp::Signer(RevokeSponsorshipOpSigner {
            account_id: owner_id.clone(),
            signer_key: signer_key.clone(),
        });
        let result = execute_revoke_sponsorship(&op, &sponsor_id, &mut state, &context);
        assert!(matches!(
            result.unwrap(),
            OperationResult::OpInner(OperationResultTr::RevokeSponsorship(
                RevokeSponsorshipResult::Success
            ))
        ));
    }

    #[test]
    fn test_revoke_sponsorship_signer_transfer() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let old_sponsor = create_test_account_id(1);
        let new_sponsor = create_test_account_id(2);
        let owner_id = create_test_account_id(3);
        let signer_key = SignerKey::Ed25519(Uint256([8u8; 32]));

        state.create_account(create_test_account(old_sponsor.clone(), 100_000_000));
        state.create_account(create_test_account(new_sponsor.clone(), 100_000_000));
        state.create_account(create_account_with_signer(
            owner_id.clone(),
            signer_key.clone(),
            Some(old_sponsor.clone()),
        ));
        if let Some(account) = state.get_account_mut(&old_sponsor) {
            let ext = crate::state::ensure_account_ext_v2(account);
            ext.num_sponsoring = 1;
        }

        let begin = BeginSponsoringFutureReservesOp {
            sponsored_id: old_sponsor.clone(),
        };
        execute_begin_sponsoring_future_reserves(&begin, &new_sponsor, &mut state, &context).unwrap();

        let op = RevokeSponsorshipOp::Signer(RevokeSponsorshipOpSigner {
            account_id: owner_id.clone(),
            signer_key: signer_key.clone(),
        });
        let result = execute_revoke_sponsorship(&op, &old_sponsor, &mut state, &context);
        assert!(matches!(
            result.unwrap(),
            OperationResult::OpInner(OperationResultTr::RevokeSponsorship(
                RevokeSponsorshipResult::Success
            ))
        ));
    }
}
