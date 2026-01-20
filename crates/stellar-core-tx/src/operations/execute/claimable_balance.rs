//! Claimable Balance operation execution.
//!
//! This module implements the execution logic for CreateClaimableBalance and
//! ClaimClaimableBalance operations.

use std::collections::HashSet;

use stellar_xdr::curr::{
    AccountFlags, AccountId, Asset, ClaimClaimableBalanceOp, ClaimClaimableBalanceResult,
    ClaimClaimableBalanceResultCode, ClaimPredicate, ClaimableBalanceEntry,
    ClaimableBalanceEntryExt, ClaimableBalanceEntryExtensionV1,
    ClaimableBalanceEntryExtensionV1Ext, ClaimableBalanceFlags, ClaimableBalanceId, Claimant,
    CreateClaimableBalanceOp, CreateClaimableBalanceResult, CreateClaimableBalanceResultCode, Hash,
    HashIdPreimage, HashIdPreimageOperationId, LedgerKey, LedgerKeyClaimableBalance,
    OperationResult, OperationResultTr, SequenceNumber,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::{Result, TxError};

/// Execute a CreateClaimableBalance operation.
///
/// This operation creates a new claimable balance entry that can be claimed
/// by one of the specified claimants.
///
/// # Arguments
///
/// * `op` - The CreateClaimableBalance operation data
/// * `source` - The source account ID
/// * `state` - The ledger state manager
/// * `context` - The ledger context
///
/// # Returns
///
/// Returns the operation result indicating success or a specific failure reason.
pub fn execute_create_claimable_balance(
    op: &CreateClaimableBalanceOp,
    source: &AccountId,
    tx_source: &AccountId,
    tx_seq: i64,
    op_index: u32,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    // Validate the operation
    if op.claimants.is_empty() {
        return Ok(make_create_result(
            CreateClaimableBalanceResultCode::Malformed,
            None,
        ));
    }

    if op.amount <= 0 {
        return Ok(make_create_result(
            CreateClaimableBalanceResultCode::Malformed,
            None,
        ));
    }

    // Check for duplicate claimants and validate predicates.
    let mut destinations = HashSet::new();
    for claimant in op.claimants.iter() {
        match claimant {
            Claimant::ClaimantTypeV0(cv0) => {
                if !destinations.insert(cv0.destination.clone()) {
                    return Ok(make_create_result(
                        CreateClaimableBalanceResultCode::Malformed,
                        None,
                    ));
                }
                if !validate_claim_predicate(&cv0.predicate, 1) {
                    return Ok(make_create_result(
                        CreateClaimableBalanceResultCode::Malformed,
                        None,
                    ));
                }
            }
        }
    }

    // Check source account exists
    let account = match state.get_account(source) {
        Some(a) => a.clone(),
        None => {
            return Ok(make_create_result(
                CreateClaimableBalanceResultCode::Underfunded,
                None,
            ));
        }
    };

    let issuer = asset_issuer(&op.asset);
    let mut source_trustline_flags = None;
    let sponsor = state
        .active_sponsor_for(source)
        .unwrap_or_else(|| source.clone());
    let sponsor_is_source = sponsor == *source;
    let sponsorship_multiplier = op.claimants.len() as i64;

    let sponsor_account = state
        .get_account(&sponsor)
        .ok_or(TxError::SourceAccountNotFound)?;
    let sponsor_min_balance = state.minimum_balance_for_account_with_deltas(
        sponsor_account,
        context.protocol_version,
        0,
        sponsorship_multiplier,
        0,
    )?;
    if sponsor_account.balance < sponsor_min_balance {
        return Ok(make_create_result(
            CreateClaimableBalanceResultCode::LowReserve,
            None,
        ));
    }

    // Check source has sufficient balance
    match &op.asset {
        Asset::Native => {
            let min_balance = if sponsor_is_source {
                state.minimum_balance_for_account_with_deltas(
                    &account,
                    context.protocol_version,
                    0,
                    sponsorship_multiplier,
                    0,
                )?
            } else {
                state.minimum_balance_for_account(&account, context.protocol_version, 0)?
            };
            let available = account.balance - min_balance;
            if available < op.amount {
                return Ok(make_create_result(
                    CreateClaimableBalanceResultCode::Underfunded,
                    None,
                ));
            }
        }
        _ => {
            if issuer.as_ref() != Some(source) {
                // For non-native assets, check trustline when not issuer
                match state.get_trustline(source, &op.asset) {
                    Some(tl) => {
                        source_trustline_flags = Some(tl.flags);
                        if !is_trustline_authorized(tl.flags) {
                            return Ok(make_create_result(
                                CreateClaimableBalanceResultCode::NotAuthorized,
                                None,
                            ));
                        }
                        if tl.balance < op.amount {
                            return Ok(make_create_result(
                                CreateClaimableBalanceResultCode::Underfunded,
                                None,
                            ));
                        }
                    }
                    None => {
                        return Ok(make_create_result(
                            CreateClaimableBalanceResultCode::NoTrust,
                            None,
                        ));
                    }
                }
            }
        }
    }

    // Generate the claimable balance ID
    let balance_id = generate_claimable_balance_id(tx_source, tx_seq, op_index)?;

    // Deduct balance from source
    match &op.asset {
        Asset::Native => {
            if let Some(account) = state.get_account_mut(source) {
                account.balance -= op.amount;
            }
        }
        _ => {
            if issuer.as_ref() != Some(source) {
                if let Some(tl) = state.get_trustline_mut(source, &op.asset) {
                    tl.balance -= op.amount;
                }
            }
        }
    }

    let mut claimable_flags = 0u32;
    if context.protocol_version >= 17 {
        if let Some(issuer_id) = issuer.as_ref() {
            let clawback_enabled = if issuer_id == source {
                account.flags & (AccountFlags::ClawbackEnabledFlag as u32) != 0
            } else {
                source_trustline_flags
                    .map(|flags| flags & TRUSTLINE_CLAWBACK_ENABLED_FLAG != 0)
                    .unwrap_or(false)
            };
            if clawback_enabled {
                claimable_flags |=
                    ClaimableBalanceFlags::ClaimableBalanceClawbackEnabledFlag as u32;
            }
        }
    }

    // Convert any relative time predicates into absolute times.
    let mut claimants: Vec<Claimant> = op.claimants.iter().cloned().collect();
    for claimant in &mut claimants {
        let Claimant::ClaimantTypeV0(cv0) = claimant;
        update_predicate_for_apply(&mut cv0.predicate, context.close_time);
    }
    let claimants = claimants
        .try_into()
        .map_err(|_| TxError::Internal("claimants size overflow".to_string()))?;

    // Create the claimable balance entry
    let entry = ClaimableBalanceEntry {
        balance_id: balance_id.clone(),
        claimants,
        asset: op.asset.clone(),
        amount: op.amount,
        ext: if claimable_flags > 0 {
            ClaimableBalanceEntryExt::V1(ClaimableBalanceEntryExtensionV1 {
                ext: ClaimableBalanceEntryExtensionV1Ext::V0,
                flags: claimable_flags,
            })
        } else {
            ClaimableBalanceEntryExt::V0
        },
    };

    let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
        balance_id: balance_id.clone(),
    });
    state.apply_entry_sponsorship_with_sponsor(
        ledger_key,
        &sponsor,
        None,
        sponsorship_multiplier,
    )?;
    state.create_claimable_balance(entry);

    Ok(make_create_result(
        CreateClaimableBalanceResultCode::Success,
        Some(balance_id),
    ))
}

/// Execute a ClaimClaimableBalance operation.
///
/// This operation claims an existing claimable balance, transferring the
/// balance to the claiming account.
///
/// # Arguments
///
/// * `op` - The ClaimClaimableBalance operation data
/// * `source` - The source account ID (the claimant)
/// * `state` - The ledger state manager
/// * `context` - The ledger context
///
/// # Returns
///
/// Returns the operation result indicating success or a specific failure reason.
pub fn execute_claim_claimable_balance(
    op: &ClaimClaimableBalanceOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    // Get the claimable balance entry
    let entry = match state.get_claimable_balance(&op.balance_id) {
        Some(e) => e.clone(),
        None => {
            return Ok(make_claim_result(
                ClaimClaimableBalanceResultCode::DoesNotExist,
            ));
        }
    };

    // Check if source is a valid claimant
    let is_valid_claimant = entry.claimants.iter().any(|c| match c {
        stellar_xdr::curr::Claimant::ClaimantTypeV0(cv0) => {
            &cv0.destination == source && check_predicate(&cv0.predicate, context)
        }
    });

    if !is_valid_claimant {
        return Ok(make_claim_result(
            ClaimClaimableBalanceResultCode::CannotClaim,
        ));
    }

    // Check source account exists (use mutable access to mirror C++ loadSourceAccount)
    if state.get_account_mut(source).is_none() {
        return Ok(make_claim_result(
            ClaimClaimableBalanceResultCode::CannotClaim,
        ));
    }

    // Transfer the balance
    match &entry.asset {
        Asset::Native => {
            if let Some(account) = state.get_account_mut(source) {
                let max_receive = i64::MAX - account.balance;
                if entry.amount > max_receive {
                    return Ok(make_claim_result(ClaimClaimableBalanceResultCode::LineFull));
                }
                account.balance += entry.amount;
            }
        }
        _ => {
            // Get the issuer of the asset
            let issuer = match &entry.asset {
                Asset::CreditAlphanum4(a) => &a.issuer,
                Asset::CreditAlphanum12(a) => &a.issuer,
                Asset::Native => unreachable!(),
            };

            // If source is the issuer, they don't need a trustline (C++ IssuerImpl behavior).
            // Issuers have unlimited trust for their own assets - just skip the trustline check.
            if source == issuer {
                // Issuer claiming their own asset: no trustline update needed
                // (the tokens are effectively burned/returned to issuer)
            } else {
                // Non-issuer: check trustline exists
                match state.get_trustline_mut(source, &entry.asset) {
                    Some(tl) => {
                        if !is_trustline_authorized(tl.flags) {
                            return Ok(make_claim_result(
                                ClaimClaimableBalanceResultCode::NotAuthorized,
                            ));
                        }
                        // Check trustline limit
                        if tl.balance + entry.amount > tl.limit {
                            return Ok(make_claim_result(
                                ClaimClaimableBalanceResultCode::LineFull,
                            ));
                        }
                        tl.balance += entry.amount;
                    }
                    None => {
                        return Ok(make_claim_result(ClaimClaimableBalanceResultCode::NoTrust));
                    }
                }
            }
        }
    }

    let sponsorship_multiplier = entry.claimants.len() as i64;
    let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
        balance_id: entry.balance_id.clone(),
    });
    let sponsor = state.entry_sponsor(&ledger_key).cloned();
    // Delete the claimable balance entry
    state.delete_claimable_balance(&op.balance_id);
    if let Some(sponsor) = sponsor {
        state.update_num_sponsoring(&sponsor, -sponsorship_multiplier)?;
    }

    Ok(make_claim_result(ClaimClaimableBalanceResultCode::Success))
}

/// Generate a claimable balance ID.
fn generate_claimable_balance_id(
    tx_source: &AccountId,
    tx_seq: i64,
    op_index: u32,
) -> Result<ClaimableBalanceId> {
    let preimage = HashIdPreimage::OpId(HashIdPreimageOperationId {
        source_account: tx_source.clone(),
        seq_num: SequenceNumber(tx_seq),
        op_num: op_index,
    });
    let hash = stellar_core_common::Hash256::hash_xdr(&preimage)
        .map_err(|e| TxError::Internal(format!("claimable balance id hash error: {}", e)))?;
    Ok(ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(hash.0)))
}

const AUTHORIZED_FLAG: u32 = stellar_xdr::curr::TrustLineFlags::AuthorizedFlag as u32;
const TRUSTLINE_CLAWBACK_ENABLED_FLAG: u32 =
    stellar_xdr::curr::TrustLineFlags::TrustlineClawbackEnabledFlag as u32;

fn is_trustline_authorized(flags: u32) -> bool {
    flags & AUTHORIZED_FLAG != 0
}

fn asset_issuer(asset: &Asset) -> Option<AccountId> {
    match asset {
        Asset::Native => None,
        Asset::CreditAlphanum4(a) => Some(a.issuer.clone()),
        Asset::CreditAlphanum12(a) => Some(a.issuer.clone()),
    }
}

/// Check if a claim predicate is satisfied.
fn check_predicate(predicate: &stellar_xdr::curr::ClaimPredicate, context: &LedgerContext) -> bool {
    match predicate {
        ClaimPredicate::Unconditional => true,
        ClaimPredicate::And(predicates) => {
            predicates.len() == 2 && predicates.iter().all(|p| check_predicate(p, context))
        }
        ClaimPredicate::Or(predicates) => {
            predicates.len() == 2 && predicates.iter().any(|p| check_predicate(p, context))
        }
        ClaimPredicate::Not(p) => p
            .as_ref()
            .map(|inner| !check_predicate(inner, context))
            .unwrap_or(false),
        ClaimPredicate::BeforeAbsoluteTime(time) => (context.close_time as i64) < *time,
        ClaimPredicate::BeforeRelativeTime(_) => false,
    }
}

fn validate_claim_predicate(predicate: &ClaimPredicate, depth: u32) -> bool {
    if depth > 4 {
        return false;
    }
    match predicate {
        ClaimPredicate::Unconditional => true,
        ClaimPredicate::And(predicates) => {
            predicates.len() == 2
                && validate_claim_predicate(&predicates[0], depth + 1)
                && validate_claim_predicate(&predicates[1], depth + 1)
        }
        ClaimPredicate::Or(predicates) => {
            predicates.len() == 2
                && validate_claim_predicate(&predicates[0], depth + 1)
                && validate_claim_predicate(&predicates[1], depth + 1)
        }
        ClaimPredicate::Not(predicate) => predicate
            .as_ref()
            .map(|inner| validate_claim_predicate(inner, depth + 1))
            .unwrap_or(false),
        ClaimPredicate::BeforeAbsoluteTime(time) => *time >= 0,
        ClaimPredicate::BeforeRelativeTime(time) => *time >= 0,
    }
}

fn update_predicate_for_apply(predicate: &mut ClaimPredicate, close_time: u64) {
    match predicate {
        ClaimPredicate::And(predicates) => {
            if predicates.len() == 2 {
                let mut left = predicates[0].clone();
                let mut right = predicates[1].clone();
                update_predicate_for_apply(&mut left, close_time);
                update_predicate_for_apply(&mut right, close_time);
                *predicate = ClaimPredicate::And(vec![left, right].try_into().unwrap());
            }
        }
        ClaimPredicate::Or(predicates) => {
            if predicates.len() == 2 {
                let mut left = predicates[0].clone();
                let mut right = predicates[1].clone();
                update_predicate_for_apply(&mut left, close_time);
                update_predicate_for_apply(&mut right, close_time);
                *predicate = ClaimPredicate::Or(vec![left, right].try_into().unwrap());
            }
        }
        ClaimPredicate::Not(predicate) => {
            if let Some(inner) = predicate.as_mut() {
                update_predicate_for_apply(inner, close_time);
            }
        }
        ClaimPredicate::BeforeRelativeTime(relative) => {
            let close_time_i64 = if close_time > i64::MAX as u64 {
                i64::MAX
            } else {
                close_time as i64
            };
            let absolute = if close_time_i64 > i64::MAX - *relative {
                i64::MAX
            } else {
                close_time_i64 + *relative
            };
            *predicate = ClaimPredicate::BeforeAbsoluteTime(absolute);
        }
        ClaimPredicate::BeforeAbsoluteTime(_) | ClaimPredicate::Unconditional => {}
    }
}

/// Create a CreateClaimableBalance result.
fn make_create_result(
    code: CreateClaimableBalanceResultCode,
    balance_id: Option<ClaimableBalanceId>,
) -> OperationResult {
    let result = match code {
        CreateClaimableBalanceResultCode::Success => {
            CreateClaimableBalanceResult::Success(balance_id.unwrap())
        }
        CreateClaimableBalanceResultCode::Malformed => CreateClaimableBalanceResult::Malformed,
        CreateClaimableBalanceResultCode::LowReserve => CreateClaimableBalanceResult::LowReserve,
        CreateClaimableBalanceResultCode::NoTrust => CreateClaimableBalanceResult::NoTrust,
        CreateClaimableBalanceResultCode::NotAuthorized => {
            CreateClaimableBalanceResult::NotAuthorized
        }
        CreateClaimableBalanceResultCode::Underfunded => CreateClaimableBalanceResult::Underfunded,
    };

    OperationResult::OpInner(OperationResultTr::CreateClaimableBalance(result))
}

/// Create a ClaimClaimableBalance result.
fn make_claim_result(code: ClaimClaimableBalanceResultCode) -> OperationResult {
    let result = match code {
        ClaimClaimableBalanceResultCode::Success => ClaimClaimableBalanceResult::Success,
        ClaimClaimableBalanceResultCode::DoesNotExist => ClaimClaimableBalanceResult::DoesNotExist,
        ClaimClaimableBalanceResultCode::CannotClaim => ClaimClaimableBalanceResult::CannotClaim,
        ClaimClaimableBalanceResultCode::LineFull => ClaimClaimableBalanceResult::LineFull,
        ClaimClaimableBalanceResultCode::NoTrust => ClaimClaimableBalanceResult::NoTrust,
        ClaimClaimableBalanceResultCode::NotAuthorized => {
            ClaimClaimableBalanceResult::NotAuthorized
        }
    };

    OperationResult::OpInner(OperationResultTr::ClaimClaimableBalance(result))
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

    fn create_test_trustline(
        account_id: AccountId,
        issuer: AccountId,
        authorized: bool,
        clawback_enabled: bool,
        balance: i64,
    ) -> TrustLineEntry {
        let mut flags = 0;
        if authorized {
            flags |= AUTHORIZED_FLAG;
        }
        if clawback_enabled {
            flags |= TRUSTLINE_CLAWBACK_ENABLED_FLAG;
        }
        TrustLineEntry {
            account_id,
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"USD\0"),
                issuer,
            }),
            balance,
            limit: 100_000_000,
            flags,
            ext: TrustLineEntryExt::V0,
        }
    }

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    #[test]
    fn test_create_claimable_balance_malformed_no_claimants() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = CreateClaimableBalanceOp {
            asset: Asset::Native,
            amount: 10_000_000,
            claimants: vec![].try_into().unwrap(), // No claimants
        };

        let result = execute_create_claimable_balance(
            &op, &source_id, &source_id, 123, 0, &mut state, &context,
        );
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::CreateClaimableBalance(r)) => {
                assert!(matches!(r, CreateClaimableBalanceResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_create_claimable_balance_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let claimant_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(claimant_id.clone(), 10_000_000));

        let claimant = Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: claimant_id.clone(),
            predicate: ClaimPredicate::Unconditional,
        });

        let op = CreateClaimableBalanceOp {
            asset: Asset::Native,
            amount: 10_000_000,
            claimants: vec![claimant].try_into().unwrap(),
        };

        let result = execute_create_claimable_balance(
            &op, &source_id, &source_id, 123, 0, &mut state, &context,
        );
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::CreateClaimableBalance(r)) => {
                if let CreateClaimableBalanceResult::Success(balance_id) = r {
                    let expected = generate_claimable_balance_id(&source_id, 123, 0).unwrap();
                    assert_eq!(balance_id, expected);
                } else {
                    panic!("unexpected result: {:?}", r);
                }
            }
            _ => panic!("Unexpected result type"),
        }

        // Check source balance was deducted
        let source = state.get_account(&source_id).unwrap();
        assert_eq!(source.balance, 90_000_000);
    }

    #[test]
    fn test_create_claimable_balance_duplicate_claimants_malformed() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let claimant_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let claimant = Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: claimant_id.clone(),
            predicate: ClaimPredicate::Unconditional,
        });

        let op = CreateClaimableBalanceOp {
            asset: Asset::Native,
            amount: 10_000_000,
            claimants: vec![claimant.clone(), claimant].try_into().unwrap(),
        };

        let result = execute_create_claimable_balance(
            &op, &source_id, &source_id, 123, 0, &mut state, &context,
        )
        .expect("create claimable balance");

        match result {
            OperationResult::OpInner(OperationResultTr::CreateClaimableBalance(r)) => {
                assert!(matches!(r, CreateClaimableBalanceResult::Malformed));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_create_claimable_balance_invalid_predicate_malformed() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let claimant_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let bad_predicate = ClaimPredicate::Not(None);
        let claimant = Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: claimant_id.clone(),
            predicate: bad_predicate,
        });

        let op = CreateClaimableBalanceOp {
            asset: Asset::Native,
            amount: 10_000_000,
            claimants: vec![claimant].try_into().unwrap(),
        };

        let result = execute_create_claimable_balance(
            &op, &source_id, &source_id, 123, 0, &mut state, &context,
        )
        .expect("create claimable balance");

        match result {
            OperationResult::OpInner(OperationResultTr::CreateClaimableBalance(r)) => {
                assert!(matches!(r, CreateClaimableBalanceResult::Malformed));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_create_claimable_balance_relative_time_converted() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let claimant_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(claimant_id.clone(), 10_000_000));

        let predicate = ClaimPredicate::BeforeRelativeTime(50);
        let claimant = Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: claimant_id.clone(),
            predicate,
        });

        let op = CreateClaimableBalanceOp {
            asset: Asset::Native,
            amount: 10_000_000,
            claimants: vec![claimant].try_into().unwrap(),
        };

        let result = execute_create_claimable_balance(
            &op, &source_id, &source_id, 123, 0, &mut state, &context,
        )
        .expect("create claimable balance");

        let balance_id = match result {
            OperationResult::OpInner(OperationResultTr::CreateClaimableBalance(
                CreateClaimableBalanceResult::Success(balance_id),
            )) => balance_id,
            other => panic!("unexpected result: {:?}", other),
        };

        let entry = state
            .get_claimable_balance(&balance_id)
            .expect("claimable balance exists");
        let stored_predicate = match entry.claimants[0] {
            Claimant::ClaimantTypeV0(ref cv0) => &cv0.predicate,
        };
        match stored_predicate {
            ClaimPredicate::BeforeAbsoluteTime(time) => {
                assert_eq!(*time, context.close_time as i64 + 50);
            }
            other => panic!("unexpected predicate: {:?}", other),
        }
    }

    #[test]
    fn test_create_claimable_balance_no_trust() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(2);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let claimant = Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: create_test_account_id(3),
            predicate: ClaimPredicate::Unconditional,
        });

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_id,
        });

        let op = CreateClaimableBalanceOp {
            asset,
            amount: 10_000_000,
            claimants: vec![claimant].try_into().unwrap(),
        };

        let result = execute_create_claimable_balance(
            &op, &source_id, &source_id, 123, 0, &mut state, &context,
        )
        .expect("create claimable balance");

        match result {
            OperationResult::OpInner(OperationResultTr::CreateClaimableBalance(r)) => {
                assert!(matches!(r, CreateClaimableBalanceResult::NoTrust));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_create_claimable_balance_not_authorized() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(2);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let trustline = create_test_trustline(
            source_id.clone(),
            issuer_id.clone(),
            false,
            false,
            50_000_000,
        );
        state.create_trustline(trustline);

        let claimant = Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: create_test_account_id(3),
            predicate: ClaimPredicate::Unconditional,
        });

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_id,
        });

        let op = CreateClaimableBalanceOp {
            asset,
            amount: 10_000_000,
            claimants: vec![claimant].try_into().unwrap(),
        };

        let result = execute_create_claimable_balance(
            &op, &source_id, &source_id, 123, 0, &mut state, &context,
        )
        .expect("create claimable balance");

        match result {
            OperationResult::OpInner(OperationResultTr::CreateClaimableBalance(r)) => {
                assert!(matches!(r, CreateClaimableBalanceResult::NotAuthorized));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_create_claimable_balance_issuer_clawback_flag() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let mut context = create_test_context();
        context.protocol_version = 21;

        let issuer_id = create_test_account_id(9);
        let mut issuer = create_test_account(issuer_id.clone(), 100_000_000);
        issuer.flags |= AccountFlags::ClawbackEnabledFlag as u32;
        state.create_account(issuer);

        let claimant = Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: create_test_account_id(3),
            predicate: ClaimPredicate::Unconditional,
        });

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_id.clone(),
        });

        let op = CreateClaimableBalanceOp {
            asset,
            amount: 10_000_000,
            claimants: vec![claimant].try_into().unwrap(),
        };

        let result = execute_create_claimable_balance(
            &op, &issuer_id, &issuer_id, 123, 0, &mut state, &context,
        )
        .expect("create claimable balance");

        match result {
            OperationResult::OpInner(OperationResultTr::CreateClaimableBalance(
                CreateClaimableBalanceResult::Success(balance_id),
            )) => {
                let entry = state
                    .get_claimable_balance(&balance_id)
                    .expect("claimable balance exists");
                match &entry.ext {
                    ClaimableBalanceEntryExt::V1(v1) => {
                        assert_eq!(
                            v1.flags,
                            ClaimableBalanceFlags::ClaimableBalanceClawbackEnabledFlag as u32
                        );
                    }
                    other => panic!("unexpected ext: {:?}", other),
                }
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_create_claimable_balance_trustline_clawback_flag() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let mut context = create_test_context();
        context.protocol_version = 21;

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(2);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let trustline =
            create_test_trustline(source_id.clone(), issuer_id.clone(), true, true, 50_000_000);
        state.create_trustline(trustline);

        let claimant = Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: create_test_account_id(3),
            predicate: ClaimPredicate::Unconditional,
        });

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_id,
        });

        let op = CreateClaimableBalanceOp {
            asset,
            amount: 10_000_000,
            claimants: vec![claimant].try_into().unwrap(),
        };

        let result = execute_create_claimable_balance(
            &op, &source_id, &source_id, 123, 0, &mut state, &context,
        )
        .expect("create claimable balance");

        match result {
            OperationResult::OpInner(OperationResultTr::CreateClaimableBalance(
                CreateClaimableBalanceResult::Success(balance_id),
            )) => {
                let entry = state
                    .get_claimable_balance(&balance_id)
                    .expect("claimable balance exists");
                match &entry.ext {
                    ClaimableBalanceEntryExt::V1(v1) => {
                        assert_eq!(
                            v1.flags,
                            ClaimableBalanceFlags::ClaimableBalanceClawbackEnabledFlag as u32
                        );
                    }
                    other => panic!("unexpected ext: {:?}", other),
                }
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_claim_claimable_balance_not_exists() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let claimant_id = create_test_account_id(1);
        state.create_account(create_test_account(claimant_id.clone(), 10_000_000));

        let op = ClaimClaimableBalanceOp {
            balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0u8; 32])),
        };

        let result = execute_claim_claimable_balance(&op, &claimant_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ClaimClaimableBalance(r)) => {
                assert!(matches!(r, ClaimClaimableBalanceResult::DoesNotExist));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_claim_claimable_balance_no_trust() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(0);
        let claimant_id = create_test_account_id(1);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state.create_account(create_test_account(claimant_id.clone(), 100_000_000));

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });

        let claimants = vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: claimant_id.clone(),
            predicate: ClaimPredicate::Unconditional,
        })];
        let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([2u8; 32]));
        let entry = ClaimableBalanceEntry {
            balance_id: balance_id.clone(),
            claimants: claimants.try_into().unwrap(),
            asset,
            amount: 100,
            ext: ClaimableBalanceEntryExt::V0,
        };
        state.create_claimable_balance(entry);

        let op = ClaimClaimableBalanceOp { balance_id };
        let result =
            execute_claim_claimable_balance(&op, &claimant_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ClaimClaimableBalance(r)) => {
                assert!(matches!(r, ClaimClaimableBalanceResult::NoTrust));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_claim_claimable_balance_issuer_success() {
        // Test that an issuer can claim their own claimable balance without a trustline.
        // This matches C++ TrustLineWrapper::IssuerImpl behavior where issuers have
        // unlimited trust for their own assets.
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        // Issuer is both the asset issuer AND the claimant
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        // Note: Issuer does NOT have a trustline for their own asset

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });

        // Create claimable balance where the issuer is the claimant
        let claimants = vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: issuer_id.clone(), // Issuer is the claimant
            predicate: ClaimPredicate::Unconditional,
        })];
        let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([99u8; 32]));
        let entry = ClaimableBalanceEntry {
            balance_id: balance_id.clone(),
            claimants: claimants.try_into().unwrap(),
            asset,
            amount: 100_000_000,
            ext: ClaimableBalanceEntryExt::V0,
        };
        state.create_claimable_balance(entry);

        // Issuer claims their own claimable balance
        let op = ClaimClaimableBalanceOp { balance_id };
        let result =
            execute_claim_claimable_balance(&op, &issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ClaimClaimableBalance(r)) => {
                // Should succeed - issuer doesn't need trustline
                assert!(matches!(r, ClaimClaimableBalanceResult::Success));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_claim_claimable_balance_native_line_full() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let claimant_id = create_test_account_id(1);
        state.create_account(create_test_account(claimant_id.clone(), i64::MAX - 50));

        let claimants = vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: claimant_id.clone(),
            predicate: ClaimPredicate::Unconditional,
        })];
        let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([5u8; 32]));
        let entry = ClaimableBalanceEntry {
            balance_id: balance_id.clone(),
            claimants: claimants.try_into().unwrap(),
            asset: Asset::Native,
            amount: 100,
            ext: ClaimableBalanceEntryExt::V0,
        };
        state.create_claimable_balance(entry);

        let op = ClaimClaimableBalanceOp { balance_id };
        let result =
            execute_claim_claimable_balance(&op, &claimant_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ClaimClaimableBalance(r)) => {
                assert!(matches!(r, ClaimClaimableBalanceResult::LineFull));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_claim_claimable_balance_not_authorized() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(0);
        let claimant_id = create_test_account_id(1);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state.create_account(create_test_account(claimant_id.clone(), 100_000_000));

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });

        let trustline = TrustLineEntry {
            account_id: claimant_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            balance: 0,
            limit: 1_000,
            flags: 0,
            ext: TrustLineEntryExt::V0,
        };
        state.create_trustline(trustline);
        state.get_account_mut(&claimant_id).unwrap().num_sub_entries += 1;

        let claimants = vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: claimant_id.clone(),
            predicate: ClaimPredicate::Unconditional,
        })];
        let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([3u8; 32]));
        let entry = ClaimableBalanceEntry {
            balance_id: balance_id.clone(),
            claimants: claimants.try_into().unwrap(),
            asset,
            amount: 100,
            ext: ClaimableBalanceEntryExt::V0,
        };
        state.create_claimable_balance(entry);

        let op = ClaimClaimableBalanceOp { balance_id };
        let result =
            execute_claim_claimable_balance(&op, &claimant_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ClaimClaimableBalance(r)) => {
                assert!(matches!(r, ClaimClaimableBalanceResult::NotAuthorized));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_claim_claimable_balance_line_full() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(0);
        let claimant_id = create_test_account_id(1);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state.create_account(create_test_account(claimant_id.clone(), 100_000_000));

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });

        let trustline = TrustLineEntry {
            account_id: claimant_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            balance: 901,
            limit: 1_000,
            flags: AUTHORIZED_FLAG,
            ext: TrustLineEntryExt::V0,
        };
        state.create_trustline(trustline);
        state.get_account_mut(&claimant_id).unwrap().num_sub_entries += 1;

        let claimants = vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: claimant_id.clone(),
            predicate: ClaimPredicate::Unconditional,
        })];
        let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([4u8; 32]));
        let entry = ClaimableBalanceEntry {
            balance_id: balance_id.clone(),
            claimants: claimants.try_into().unwrap(),
            asset,
            amount: 100,
            ext: ClaimableBalanceEntryExt::V0,
        };
        state.create_claimable_balance(entry);

        let op = ClaimClaimableBalanceOp { balance_id };
        let result =
            execute_claim_claimable_balance(&op, &claimant_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ClaimClaimableBalance(r)) => {
                assert!(matches!(r, ClaimClaimableBalanceResult::LineFull));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }
}
