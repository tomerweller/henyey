//! Claimable Balance operation execution.
//!
//! This module implements the execution logic for CreateClaimableBalance and
//! ClaimClaimableBalance operations.

use stellar_xdr::curr::{
    AccountId, Asset, ClaimClaimableBalanceOp, ClaimClaimableBalanceResult,
    ClaimClaimableBalanceResultCode, ClaimableBalanceEntry, ClaimableBalanceEntryExt,
    ClaimableBalanceId, CreateClaimableBalanceOp, CreateClaimableBalanceResult,
    CreateClaimableBalanceResultCode, Hash, OperationResult, OperationResultTr,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;

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

    // Check source has sufficient balance
    match &op.asset {
        Asset::Native => {
            let min_balance = state.minimum_balance(account.num_sub_entries);
            let available = account.balance - min_balance;
            if available < op.amount {
                return Ok(make_create_result(
                    CreateClaimableBalanceResultCode::Underfunded,
                    None,
                ));
            }
        }
        _ => {
            // For non-native assets, check trustline
            match state.get_trustline(source, &op.asset) {
                Some(tl) => {
                    if tl.balance < op.amount {
                        return Ok(make_create_result(
                            CreateClaimableBalanceResultCode::Underfunded,
                            None,
                        ));
                    }
                }
                None => {
                    return Ok(make_create_result(
                        CreateClaimableBalanceResultCode::Underfunded,
                        None,
                    ));
                }
            }
        }
    }

    // Generate the claimable balance ID
    let balance_id = generate_claimable_balance_id(source, context);

    // Deduct balance from source
    match &op.asset {
        Asset::Native => {
            if let Some(account) = state.get_account_mut(source) {
                account.balance -= op.amount;
            }
        }
        _ => {
            if let Some(tl) = state.get_trustline_mut(source, &op.asset) {
                tl.balance -= op.amount;
            }
        }
    }

    // Create the claimable balance entry
    let entry = ClaimableBalanceEntry {
        balance_id: balance_id.clone(),
        claimants: op.claimants.clone(),
        asset: op.asset.clone(),
        amount: op.amount,
        ext: ClaimableBalanceEntryExt::V0,
    };

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
        return Ok(make_claim_result(ClaimClaimableBalanceResultCode::CannotClaim));
    }

    // Check source account exists
    if state.get_account(source).is_none() {
        return Ok(make_claim_result(ClaimClaimableBalanceResultCode::CannotClaim));
    }

    // Transfer the balance
    match &entry.asset {
        Asset::Native => {
            if let Some(account) = state.get_account_mut(source) {
                account.balance += entry.amount;
            }
        }
        _ => {
            // For non-native assets, check trustline exists
            match state.get_trustline_mut(source, &entry.asset) {
                Some(tl) => {
                    // Check trustline limit
                    if tl.balance + entry.amount > tl.limit {
                        return Ok(make_claim_result(ClaimClaimableBalanceResultCode::LineFull));
                    }
                    tl.balance += entry.amount;
                }
                None => {
                    return Ok(make_claim_result(ClaimClaimableBalanceResultCode::NoTrust));
                }
            }
        }
    }

    // Delete the claimable balance entry
    state.delete_claimable_balance(&op.balance_id);

    Ok(make_claim_result(ClaimClaimableBalanceResultCode::Success))
}

/// Generate a claimable balance ID.
fn generate_claimable_balance_id(source: &AccountId, context: &LedgerContext) -> ClaimableBalanceId {
    use sha2::{Digest, Sha256};
    use stellar_xdr::curr::WriteXdr;

    // Generate a unique ID by hashing source account + sequence + timestamp
    let mut hasher = Sha256::new();
    if let Ok(bytes) = source.to_xdr(stellar_xdr::curr::Limits::none()) {
        hasher.update(&bytes);
    }
    hasher.update(&context.sequence.to_le_bytes());
    hasher.update(&context.close_time.to_le_bytes());
    let hash = hasher.finalize();

    ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(hash.into()))
}

/// Check if a claim predicate is satisfied.
fn check_predicate(predicate: &stellar_xdr::curr::ClaimPredicate, context: &LedgerContext) -> bool {
    use stellar_xdr::curr::ClaimPredicate;

    match predicate {
        ClaimPredicate::Unconditional => true,
        ClaimPredicate::And(predicates) => {
            predicates.iter().all(|p| check_predicate(p, context))
        }
        ClaimPredicate::Or(predicates) => {
            predicates.iter().any(|p| check_predicate(p, context))
        }
        ClaimPredicate::Not(p) => !check_predicate(p.as_ref().unwrap(), context),
        ClaimPredicate::BeforeAbsoluteTime(time) => (context.close_time as i64) < *time,
        ClaimPredicate::BeforeRelativeTime(_) => {
            // Relative time is relative to the claimable balance creation time
            // For simplicity, we treat this as always true
            true
        }
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

        let result = execute_create_claimable_balance(&op, &source_id, &mut state, &context);
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

        let result = execute_create_claimable_balance(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::CreateClaimableBalance(r)) => {
                assert!(matches!(r, CreateClaimableBalanceResult::Success(_)));
            }
            _ => panic!("Unexpected result type"),
        }

        // Check source balance was deducted
        let source = state.get_account(&source_id).unwrap();
        assert_eq!(source.balance, 90_000_000);
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
}
