//! RestoreFootprint operation execution.
//!
//! This module implements the execution logic for the RestoreFootprint operation,
//! which restores archived Soroban contract data entries.

use stellar_xdr::curr::{
    AccountId, Hash, LedgerKey, OperationResult, OperationResultTr, RestoreFootprintOp,
    RestoreFootprintResult, RestoreFootprintResultCode, SorobanTransactionData, TtlEntry,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;

/// Default TTL extension for restored entries (in ledgers).
const DEFAULT_RESTORE_TTL: u32 = 518400; // ~30 days at 5-second ledger close

/// Execute a RestoreFootprint operation.
///
/// This operation restores archived entries that have expired TTLs,
/// making them live again with a new TTL.
///
/// # Arguments
///
/// * `op` - The RestoreFootprint operation data
/// * `source` - The source account ID
/// * `state` - The ledger state manager
/// * `context` - The ledger context
/// * `soroban_data` - The Soroban transaction data containing the footprint
///
/// # Returns
///
/// Returns the operation result indicating success or a specific failure reason.
pub fn execute_restore_footprint(
    _op: &RestoreFootprintOp,
    _source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
    soroban_data: Option<&SorobanTransactionData>,
) -> Result<OperationResult> {
    // Get the footprint from Soroban transaction data
    let footprint = match soroban_data {
        Some(data) => &data.resources.footprint,
        None => {
            return Ok(make_result(RestoreFootprintResultCode::Malformed));
        }
    };

    // Calculate the new TTL for restored entries
    let current_ledger = context.sequence;
    let new_ttl = current_ledger.saturating_add(DEFAULT_RESTORE_TTL);

    // Restore all entries in the read-write footprint
    // (RestoreFootprint only restores entries that are in read-write)
    for key in footprint.read_write.iter() {
        if let Err(_) = restore_entry(key, new_ttl, state, current_ledger) {
            return Ok(make_result(RestoreFootprintResultCode::ResourceLimitExceeded));
        }
    }

    Ok(make_result(RestoreFootprintResultCode::Success))
}

/// Restore a single ledger entry.
fn restore_entry(
    key: &LedgerKey,
    new_ttl: u32,
    state: &mut LedgerStateManager,
    current_ledger: u32,
) -> std::result::Result<(), &'static str> {
    // Only contract data and contract code can be restored
    match key {
        LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {}
        _ => return Ok(()), // Non-contract entries don't need restoration
    }

    // Compute the key hash for TTL lookup
    let key_hash = compute_ledger_key_hash(key);

    // Check the current TTL status
    let current_ttl = state.get_ttl(&key_hash).map(|t| t.live_until_ledger_seq);

    match current_ttl {
        Some(ttl) if ttl >= current_ledger => {
            // Entry is still live, no restoration needed
            // But we can still extend the TTL if requested
            state.extend_ttl(&key_hash, new_ttl);
            Ok(())
        }
        Some(_) | None => {
            // Entry is archived or has no TTL entry
            // We need to check if the entry itself exists in state
            if state.get_entry(key).is_none() {
                // Entry doesn't exist at all - cannot restore
                // In a real implementation, we'd look for it in archive storage
                return Err("Entry not found in archive");
            }

            // Create or update the TTL entry to restore the entry
            let ttl_entry = TtlEntry {
                key_hash: key_hash.clone(),
                live_until_ledger_seq: new_ttl,
            };

            if state.get_ttl(&key_hash).is_some() {
                state.update_ttl(ttl_entry);
            } else {
                state.create_ttl(ttl_entry);
            }

            Ok(())
        }
    }
}

/// Compute the hash of a ledger key for TTL lookup.
fn compute_ledger_key_hash(key: &LedgerKey) -> Hash {
    use sha2::{Digest, Sha256};
    use stellar_xdr::curr::WriteXdr;

    let mut hasher = Sha256::new();
    if let Ok(bytes) = key.to_xdr(stellar_xdr::curr::Limits::none()) {
        hasher.update(&bytes);
    }
    let result = hasher.finalize();
    Hash(result.into())
}

/// Create an OperationResult from a RestoreFootprintResultCode.
fn make_result(code: RestoreFootprintResultCode) -> OperationResult {
    let result = match code {
        RestoreFootprintResultCode::Success => RestoreFootprintResult::Success,
        RestoreFootprintResultCode::Malformed => RestoreFootprintResult::Malformed,
        RestoreFootprintResultCode::ResourceLimitExceeded => {
            RestoreFootprintResult::ResourceLimitExceeded
        }
        RestoreFootprintResultCode::InsufficientRefundableFee => {
            RestoreFootprintResult::InsufficientRefundableFee
        }
    };

    OperationResult::OpInner(OperationResultTr::RestoreFootprint(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    #[test]
    fn test_restore_footprint_no_soroban_data() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        let op = RestoreFootprintOp {
            ext: ExtensionPoint::V0,
        };

        let result = execute_restore_footprint(&op, &source, &mut state, &context, None);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::RestoreFootprint(r)) => {
                assert!(matches!(r, RestoreFootprintResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_restore_footprint_empty_footprint() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        let op = RestoreFootprintOp {
            ext: ExtensionPoint::V0,
        };

        let soroban_data = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: vec![].try_into().unwrap(),
                    read_write: vec![].try_into().unwrap(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        };

        let result =
            execute_restore_footprint(&op, &source, &mut state, &context, Some(&soroban_data));
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::RestoreFootprint(r)) => {
                assert!(matches!(r, RestoreFootprintResult::Success));
            }
            _ => panic!("Unexpected result type"),
        }
    }
}
