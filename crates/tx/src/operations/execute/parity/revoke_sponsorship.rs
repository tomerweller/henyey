//! Parity tests for RevokeSponsorship operation result codes.
//!
//! Covers gaps not exercised by inline unit tests:
//! - `Success` — sponsor successfully revokes sponsorship of a trustline
//! - `NotSponsor` — third party who is not the sponsor tries to revoke
//! - `OnlyTransferable` — ClaimableBalance sponsorship can only be transferred, not removed
//! - `Malformed` — unsupported entry type or ClaimableBalance without sponsor

use super::super::sponsorship::execute_revoke_sponsorship;
use super::assert_op_result;
use crate::state::LedgerStateManager;
use crate::test_utils::*;
use stellar_xdr::curr::*;

fn create_test_context() -> crate::validation::LedgerContext {
    crate::validation::LedgerContext::testnet(1, 1000)
}

/// RevokeSponsorship succeeds when the sponsor revokes a trustline sponsorship
/// and the owner has enough balance to cover the reserve.
#[test]
fn test_revoke_sponsorship_success() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let sponsor_id = create_test_account_id(0);
    let owner_id = create_test_account_id(1);
    let issuer_id = create_test_account_id(2);

    // Sponsor has num_sponsoring=1 (already sponsors the trustline)
    state.create_account(create_test_account_with_sponsorship(
        sponsor_id.clone(),
        100_000_000,
        0, // num_sub_entries
        0, // num_sponsored
        1, // num_sponsoring (sponsors owner's trustline)
    ));
    // Owner needs enough balance to cover the reserve when sponsorship is removed.
    // With num_sub_entries=1, num_sponsored=1: min_balance = (2+1+0-1)*5M = 10M
    // After revoke removes sponsorship: min_balance = (2+1+0-0)*5M = 15M
    state.create_account(create_test_account_with_sponsorship(
        owner_id.clone(),
        100_000_000,
        1, // num_sub_entries (the trustline)
        1, // num_sponsored (trustline is sponsored)
        0, // num_sponsoring
    ));
    state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

    let tl_asset = create_test_trustline_asset(b"USD\0", issuer_id);

    state.create_trustline(create_test_trustline(
        owner_id.clone(),
        tl_asset.clone(),
        0,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    // Mark the trustline as sponsored by sponsor_id
    let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
        account_id: owner_id.clone(),
        asset: tl_asset.clone(),
    });
    state.set_entry_sponsor(ledger_key.clone(), sponsor_id.clone());

    let op = RevokeSponsorshipOp::LedgerEntry(ledger_key);

    let result = execute_revoke_sponsorship(&op, &sponsor_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::RevokeSponsorship(RevokeSponsorshipResult::Success)
    );
}

/// RevokeSponsorship returns NotSponsor when a third party (not the sponsor or owner)
/// tries to revoke a sponsored entry.
#[test]
fn test_revoke_sponsorship_not_sponsor() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let sponsor_id = create_test_account_id(0);
    let owner_id = create_test_account_id(1);
    let third_party_id = create_test_account_id(2);
    let issuer_id = create_test_account_id(3);

    state.create_account(create_test_account(sponsor_id.clone(), 100_000_000));
    state.create_account(create_test_account_with_subentries(
        owner_id.clone(),
        100_000_000,
        1,
    ));
    state.create_account(create_test_account(third_party_id.clone(), 100_000_000));
    state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

    let tl_asset = create_test_trustline_asset(b"USD\0", issuer_id);

    state.create_trustline(create_test_trustline(
        owner_id.clone(),
        tl_asset.clone(),
        0,
        1_000_000,
        TrustLineFlags::AuthorizedFlag as u32,
    ));

    let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
        account_id: owner_id.clone(),
        asset: tl_asset.clone(),
    });
    state.set_entry_sponsor(ledger_key.clone(), sponsor_id.clone());

    let op = RevokeSponsorshipOp::LedgerEntry(ledger_key);

    // Third party is neither the sponsor nor the owner
    let result = execute_revoke_sponsorship(&op, &third_party_id, &mut state, &context);
    assert_op_result!(
        result,
        OperationResultTr::RevokeSponsorship(RevokeSponsorshipResult::NotSponsor)
    );
}

/// RevokeSponsorship returns OnlyTransferable for ClaimableBalance entries
/// when there is no new sponsor to transfer to (will_be_sponsored=false).
#[test]
#[ignore]
fn test_revoke_sponsorship_only_transferable() {
    // TODO(#1126): Requires creating a ClaimableBalance entry in the ledger
    // state with an entry sponsor, then calling revoke without a new sponsor.
    // ClaimableBalance creation requires specific state setup not yet abstracted.
    todo!()
}

/// RevokeSponsorship returns Malformed for ClaimableBalance entries that have
/// no entry sponsor set.
#[test]
#[ignore]
fn test_revoke_sponsorship_malformed() {
    // TODO(#1126): Requires creating a ClaimableBalance entry without an entry
    // sponsor. The code path: ClaimableBalance match arm checks entry_sponsor()
    // and returns Malformed if None.
    todo!()
}
