//! RestoreFootprint operation execution.
//!
//! This module implements the execution logic for the RestoreFootprint operation,
//! which restores archived Soroban contract data entries.

use stellar_xdr::curr::{
    AccountId, Hash, LedgerEntry, LedgerEntryData, LedgerKey, OperationResult, OperationResultTr,
    RestoreFootprintOp, RestoreFootprintResult, RestoreFootprintResultCode, SorobanTransactionData,
    TtlEntry,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;

/// Entry to restore from the hot archive.
pub struct HotArchiveRestoreEntry {
    /// The key of the entry to restore.
    pub key: LedgerKey,
    /// The entry value from the hot archive.
    pub entry: LedgerEntry,
}

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
/// * `min_persistent_entry_ttl` - Minimum persistent entry TTL from Soroban config
/// * `hot_archive_restores` - Entries to restore from the hot archive
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
    min_persistent_entry_ttl: u32,
    hot_archive_restores: &[HotArchiveRestoreEntry],
) -> Result<OperationResult> {
    // Get the footprint from Soroban transaction data
    let footprint = match soroban_data {
        Some(data) => &data.resources.footprint,
        None => {
            return Ok(make_result(RestoreFootprintResultCode::Malformed));
        }
    };

    if !footprint.read_only.is_empty() {
        return Ok(make_result(RestoreFootprintResultCode::Malformed));
    }

    for key in footprint.read_write.iter() {
        if !is_persistent_entry(key) {
            return Ok(make_result(RestoreFootprintResultCode::Malformed));
        }
    }

    // Calculate the new TTL for restored entries
    // Per C++ RestoreFootprintOpFrame.cpp line 115-116:
    //   restoredLiveUntilLedger = ledgerSeq + archivalSettings.minPersistentTTL - 1
    let current_ledger = context.sequence;
    let new_ttl = current_ledger
        .saturating_add(min_persistent_entry_ttl)
        .saturating_sub(1);

    // First, restore hot archive entries to state.
    // These entries don't exist in the live bucket list, so we need to add them.
    for restore in hot_archive_restores {
        tracing::debug!(
            ?restore.key,
            new_ttl,
            "RestoreFootprint: restoring entry from hot archive to state"
        );
        // Add the entry to state based on type
        match &restore.entry.data {
            LedgerEntryData::ContractCode(code) => {
                state.create_contract_code(code.clone());
            }
            LedgerEntryData::ContractData(data) => {
                state.create_contract_data(data.clone());
            }
            _ => {
                // Hot archive should only contain ContractCode and ContractData
                tracing::warn!(
                    ?restore.key,
                    "RestoreFootprint: unexpected entry type in hot archive"
                );
            }
        }

        // Create the TTL entry for the restored entry
        let key_hash = compute_ledger_key_hash(&restore.key);
        let ttl_entry = TtlEntry {
            key_hash,
            live_until_ledger_seq: new_ttl,
        };
        state.create_ttl(ttl_entry);
    }

    // Restore all entries in the read-write footprint that exist in live state
    // (these have expired TTLs but the entry still exists)
    for key in footprint.read_write.iter() {
        // Skip entries that were restored from hot archive - they're already handled
        if hot_archive_restores.iter().any(|r| &r.key == key) {
            continue;
        }

        if restore_entry(key, new_ttl, state, current_ledger).is_err() {
            return Ok(make_result(
                RestoreFootprintResultCode::ResourceLimitExceeded,
            ));
        }
    }

    Ok(make_result(RestoreFootprintResultCode::Success))
}

fn is_persistent_entry(key: &LedgerKey) -> bool {
    match key {
        LedgerKey::ContractCode(_) => true,
        LedgerKey::ContractData(cd) => matches!(
            cd.durability,
            stellar_xdr::curr::ContractDataDurability::Persistent
        ),
        _ => false,
    }
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
            // Entry is still live, no restoration needed.
            Ok(())
        }
        Some(_) | None => {
            // Entry is archived or has no TTL entry
            // We need to check if the entry itself exists in state
            if state.get_entry(key).is_none() {
                // Neither live nor archived entry exists; skip per upstream behavior.
                return Ok(());
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

    /// Default min persistent TTL for tests (matches testnet config)
    const TEST_MIN_PERSISTENT_TTL: u32 = 120960;

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

        let result = execute_restore_footprint(
            &op,
            &source,
            &mut state,
            &context,
            None,
            TEST_MIN_PERSISTENT_TTL,
            &[], // No hot archive restores
        );
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

        let result = execute_restore_footprint(
            &op,
            &source,
            &mut state,
            &context,
            Some(&soroban_data),
            TEST_MIN_PERSISTENT_TTL,
            &[], // No hot archive restores
        );
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::RestoreFootprint(r)) => {
                assert!(matches!(r, RestoreFootprintResult::Success));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_restore_footprint_rejects_read_only() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        let op = RestoreFootprintOp {
            ext: ExtensionPoint::V0,
        };

        let contract_key = LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: Hash([1u8; 32]),
        });

        let soroban_data = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: vec![contract_key].try_into().unwrap(),
                    read_write: vec![].try_into().unwrap(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        };

        let result = execute_restore_footprint(
            &op,
            &source,
            &mut state,
            &context,
            Some(&soroban_data),
            TEST_MIN_PERSISTENT_TTL,
            &[], // No hot archive restores
        );
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::RestoreFootprint(r)) => {
                assert!(matches!(r, RestoreFootprintResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_restore_footprint_rejects_non_persistent_entry() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        let op = RestoreFootprintOp {
            ext: ExtensionPoint::V0,
        };

        let temp_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([2u8; 32]))),
            key: ScVal::U32(1),
            durability: ContractDataDurability::Temporary,
        });

        let soroban_data = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: vec![].try_into().unwrap(),
                    read_write: vec![temp_key].try_into().unwrap(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        };

        let result = execute_restore_footprint(
            &op,
            &source,
            &mut state,
            &context,
            Some(&soroban_data),
            TEST_MIN_PERSISTENT_TTL,
            &[], // No hot archive restores
        );
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::RestoreFootprint(r)) => {
                assert!(matches!(r, RestoreFootprintResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }
}
