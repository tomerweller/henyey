//! SetOptions operation execution.
//!
//! This module implements the execution logic for the SetOptions operation,
//! which modifies various account settings.

use stellar_xdr::curr::{
    AccountId, OperationResult, OperationResultTr, SetOptionsOp, SetOptionsResult,
    SetOptionsResultCode, Signer, SignerKey,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::{Result, TxError};

/// Maximum number of signers allowed on an account.
const MAX_SIGNERS: usize = 20;

/// Execute a SetOptions operation.
///
/// This operation modifies account settings including:
/// - Inflation destination
/// - Account flags (auth required, revocable, immutable, clawback enabled)
/// - Master key weight
/// - Threshold levels (low, medium, high)
/// - Home domain
/// - Signers
///
/// # Arguments
///
/// * `op` - The SetOptions operation data
/// * `source` - The source account ID
/// * `state` - The ledger state manager
/// * `context` - The ledger context
///
/// # Returns
///
/// Returns the operation result indicating success or a specific failure reason.
pub fn execute_set_options(
    op: &SetOptionsOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Validate operation parameters
    if let Some(weight) = op.master_weight {
        if weight > 255 {
            return Ok(make_result(SetOptionsResultCode::ThresholdOutOfRange));
        }
    }

    if let Some(t) = op.low_threshold {
        if t > 255 {
            return Ok(make_result(SetOptionsResultCode::ThresholdOutOfRange));
        }
    }

    if let Some(t) = op.med_threshold {
        if t > 255 {
            return Ok(make_result(SetOptionsResultCode::ThresholdOutOfRange));
        }
    }

    if let Some(t) = op.high_threshold {
        if t > 255 {
            return Ok(make_result(SetOptionsResultCode::ThresholdOutOfRange));
        }
    }

    // Get source account
    let source_account = match state.get_account(source) {
        Some(account) => account,
        None => return Err(TxError::SourceAccountNotFound),
    };

    // Check flag consistency
    const AUTH_REQUIRED_FLAG: u32 = 0x1;
    const AUTH_REVOCABLE_FLAG: u32 = 0x2;
    const AUTH_IMMUTABLE_FLAG: u32 = 0x4;
    const AUTH_CLAWBACK_FLAG: u32 = 0x8;

    let current_flags = source_account.flags;

    // If account is immutable, can only clear flags (not set new ones)
    if current_flags & AUTH_IMMUTABLE_FLAG != 0 {
        if let Some(set_flags) = op.set_flags {
            if set_flags != 0 {
                return Ok(make_result(SetOptionsResultCode::CantChange));
            }
        }
    }

    // Clawback requires auth revocable
    if let Some(set_flags) = op.set_flags {
        if set_flags & AUTH_CLAWBACK_FLAG != 0 {
            let new_flags = current_flags | set_flags;
            if new_flags & AUTH_REVOCABLE_FLAG == 0 {
                return Ok(make_result(SetOptionsResultCode::AuthRevocableRequired));
            }
        }
    }

    // Can't clear revocable if clawback is set
    if let Some(clear_flags) = op.clear_flags {
        if clear_flags & AUTH_REVOCABLE_FLAG != 0 {
            if current_flags & AUTH_CLAWBACK_FLAG != 0 {
                return Ok(make_result(SetOptionsResultCode::AuthRevocableRequired));
            }
        }
    }

    // Get current signer count for sub-entry calculations
    let current_signer_count = source_account.signers.len();
    let current_num_sub_entries = source_account.num_sub_entries;
    let base_reserve = state.base_reserve();

    // Now apply changes to the account
    let source_account_mut = state
        .get_account_mut(source)
        .ok_or(TxError::SourceAccountNotFound)?;

    // Update inflation destination
    if let Some(ref inflation_dest) = op.inflation_dest {
        source_account_mut.inflation_dest = Some(inflation_dest.clone());
    }

    // Update flags
    if let Some(clear_flags) = op.clear_flags {
        source_account_mut.flags &= !clear_flags;
    }
    if let Some(set_flags) = op.set_flags {
        source_account_mut.flags |= set_flags;
    }

    // Update master weight
    if let Some(master_weight) = op.master_weight {
        source_account_mut.thresholds.0[0] = master_weight as u8;
    }

    // Update thresholds
    if let Some(low_threshold) = op.low_threshold {
        source_account_mut.thresholds.0[1] = low_threshold as u8;
    }
    if let Some(med_threshold) = op.med_threshold {
        source_account_mut.thresholds.0[2] = med_threshold as u8;
    }
    if let Some(high_threshold) = op.high_threshold {
        source_account_mut.thresholds.0[3] = high_threshold as u8;
    }

    // Update home domain
    if let Some(ref home_domain) = op.home_domain {
        source_account_mut.home_domain = home_domain.clone();
    }

    // Update signers
    if let Some(ref signer) = op.signer {
        let signer_key = &signer.key;
        let weight = signer.weight;

        // Find existing signer or position to insert
        let existing_pos = source_account_mut
            .signers
            .iter()
            .position(|s| &s.key == signer_key);

        if weight == 0 {
            // Remove signer
            if let Some(pos) = existing_pos {
                let mut signers_vec: Vec<_> = source_account_mut.signers.iter().cloned().collect();
                signers_vec.remove(pos);
                source_account_mut.signers = signers_vec.try_into().unwrap_or_default();

                // Decrease sub-entry count
                if source_account_mut.num_sub_entries > 0 {
                    source_account_mut.num_sub_entries -= 1;
                }
            }
            // If signer doesn't exist and weight is 0, that's fine - no-op
        } else {
            // Add or update signer
            if let Some(pos) = existing_pos {
                // Update existing signer weight
                let mut signers_vec: Vec<_> = source_account_mut.signers.iter().cloned().collect();
                signers_vec[pos].weight = weight;
                source_account_mut.signers = signers_vec.try_into().unwrap_or_default();
            } else {
                // Check we haven't exceeded max signers
                if current_signer_count >= MAX_SIGNERS {
                    return Ok(make_result(SetOptionsResultCode::TooManySigners));
                }

                // Check source can afford new sub-entry
                // We calculate with the saved values since we can't borrow state here
                let new_min_balance = (2 + current_num_sub_entries + 1) as i64 * base_reserve;
                if source_account_mut.balance < new_min_balance {
                    return Ok(make_result(SetOptionsResultCode::LowReserve));
                }

                // Add new signer
                let new_signer = Signer {
                    key: signer_key.clone(),
                    weight,
                };
                let mut signers_vec: Vec<_> = source_account_mut.signers.iter().cloned().collect();
                signers_vec.push(new_signer);
                // Sort signers by key for deterministic ordering
                signers_vec.sort_by(|a, b| compare_signer_keys(&a.key, &b.key));
                source_account_mut.signers = signers_vec.try_into().unwrap_or_default();

                // Increase sub-entry count
                source_account_mut.num_sub_entries += 1;
            }
        }
    }

    Ok(make_result(SetOptionsResultCode::Success))
}

/// Compare signer keys for sorting.
fn compare_signer_keys(a: &SignerKey, b: &SignerKey) -> std::cmp::Ordering {
    // Compare based on key type first, then content
    match (a, b) {
        (SignerKey::Ed25519(a_key), SignerKey::Ed25519(b_key)) => a_key.0.cmp(&b_key.0),
        (SignerKey::PreAuthTx(a_key), SignerKey::PreAuthTx(b_key)) => a_key.0.cmp(&b_key.0),
        (SignerKey::HashX(a_key), SignerKey::HashX(b_key)) => a_key.0.cmp(&b_key.0),
        (SignerKey::Ed25519SignedPayload(a_key), SignerKey::Ed25519SignedPayload(b_key)) => {
            a_key.ed25519.0.cmp(&b_key.ed25519.0)
        }
        // Different types: order by discriminant
        (a, b) => {
            let a_disc = signer_key_discriminant(a);
            let b_disc = signer_key_discriminant(b);
            a_disc.cmp(&b_disc)
        }
    }
}

/// Get discriminant for signer key type ordering.
fn signer_key_discriminant(key: &SignerKey) -> u8 {
    match key {
        SignerKey::Ed25519(_) => 0,
        SignerKey::PreAuthTx(_) => 1,
        SignerKey::HashX(_) => 2,
        SignerKey::Ed25519SignedPayload(_) => 3,
    }
}

/// Create an OperationResult from a SetOptionsResultCode.
fn make_result(code: SetOptionsResultCode) -> OperationResult {
    let result = match code {
        SetOptionsResultCode::Success => SetOptionsResult::Success,
        SetOptionsResultCode::LowReserve => SetOptionsResult::LowReserve,
        SetOptionsResultCode::TooManySigners => SetOptionsResult::TooManySigners,
        SetOptionsResultCode::BadFlags => SetOptionsResult::BadFlags,
        SetOptionsResultCode::InvalidInflation => SetOptionsResult::InvalidInflation,
        SetOptionsResultCode::CantChange => SetOptionsResult::CantChange,
        SetOptionsResultCode::UnknownFlag => SetOptionsResult::UnknownFlag,
        SetOptionsResultCode::ThresholdOutOfRange => SetOptionsResult::ThresholdOutOfRange,
        SetOptionsResultCode::BadSigner => SetOptionsResult::BadSigner,
        SetOptionsResultCode::InvalidHomeDomain => SetOptionsResult::InvalidHomeDomain,
        SetOptionsResultCode::AuthRevocableRequired => SetOptionsResult::AuthRevocableRequired,
    };

    OperationResult::OpInner(OperationResultTr::SetOptions(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn make_string32(s: &str) -> String32 {
        String32::try_from(s.as_bytes().to_vec()).unwrap()
    }

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
    fn test_set_options_update_thresholds() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: Some(10),
            low_threshold: Some(1),
            med_threshold: Some(2),
            high_threshold: Some(3),
            home_domain: None,
            signer: None,
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        let account = state.get_account(&source_id).unwrap();
        assert_eq!(account.thresholds.0[0], 10); // master weight
        assert_eq!(account.thresholds.0[1], 1);  // low
        assert_eq!(account.thresholds.0[2], 2);  // med
        assert_eq!(account.thresholds.0[3], 3);  // high
    }

    #[test]
    fn test_set_options_set_flags() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: Some(0x3), // AUTH_REQUIRED | AUTH_REVOCABLE
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: None,
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        let account = state.get_account(&source_id).unwrap();
        assert_eq!(account.flags, 0x3);
    }

    #[test]
    fn test_set_options_threshold_out_of_range() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: Some(256), // Out of range
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: None,
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::SetOptions(r)) => {
                assert!(matches!(r, SetOptionsResult::ThresholdOutOfRange));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_set_options_immutable_cant_change() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let mut account = create_test_account(source_id.clone(), 100_000_000);
        account.flags = 0x4; // AUTH_IMMUTABLE
        state.create_account(account);

        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: Some(0x1), // Try to set AUTH_REQUIRED
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: None,
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::SetOptions(r)) => {
                assert!(matches!(r, SetOptionsResult::CantChange));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_set_options_add_signer() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let signer_key = SignerKey::Ed25519(Uint256([1u8; 32]));
        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: Some(Signer {
                key: signer_key.clone(),
                weight: 5,
            }),
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        let account = state.get_account(&source_id).unwrap();
        assert_eq!(account.signers.len(), 1);
        assert_eq!(account.num_sub_entries, 1);
    }

    #[test]
    fn test_set_options_home_domain() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: Some(make_string32("stellar.org")),
            signer: None,
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        let account = state.get_account(&source_id).unwrap();
        assert_eq!(account.home_domain.to_string(), "stellar.org");
    }
}
