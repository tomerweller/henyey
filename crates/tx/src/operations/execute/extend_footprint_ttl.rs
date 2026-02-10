//! ExtendFootprintTtl operation execution.
//!
//! This module implements the execution logic for the ExtendFootprintTtl operation,
//! which extends the time-to-live for Soroban contract data entries.

use stellar_xdr::curr::{
    AccountId, ExtendFootprintTtlOp, ExtendFootprintTtlResult, ExtendFootprintTtlResultCode, Hash,
    LedgerKey, OperationResult, OperationResultTr, SorobanTransactionData, WriteXdr,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;

/// Max TTL extension for entries (in ledgers).
const MAX_ENTRY_TTL: u32 = 6_312_000; // ~1 year at 5-second ledger close

/// Execute an ExtendFootprintTtl operation.
///
/// This operation extends the TTL of all entries in the transaction's footprint
/// to at least the specified ledger sequence.
///
/// Matches C++ ExtendFootprintTTLApplyHelper::apply() behavior:
/// - Skips missing entries (not found in state)
/// - Skips archived/non-live entries (TTL < current_ledger)
/// - Skips entries whose TTL already meets or exceeds the target
/// - Tracks accumulated read bytes and fails with ResourceLimitExceeded
///   if disk_read_bytes limit is exceeded
pub fn execute_extend_footprint_ttl(
    op: &ExtendFootprintTtlOp,
    _source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
    soroban_data: Option<&SorobanTransactionData>,
) -> Result<OperationResult> {
    // Validate extend_to is positive
    if op.extend_to == 0 {
        return Ok(make_result(ExtendFootprintTtlResultCode::Malformed));
    }

    if op.extend_to > MAX_ENTRY_TTL.saturating_sub(1) {
        return Ok(make_result(ExtendFootprintTtlResultCode::Malformed));
    }

    // Get the footprint from Soroban transaction data
    let soroban_data = match soroban_data {
        Some(data) => data,
        None => {
            return Ok(make_result(ExtendFootprintTtlResultCode::Malformed));
        }
    };
    let footprint = &soroban_data.resources.footprint;

    if !footprint.read_write.is_empty() {
        return Ok(make_result(ExtendFootprintTtlResultCode::Malformed));
    }

    for key in footprint.read_only.iter() {
        if !is_ttl_entry(key) {
            return Ok(make_result(ExtendFootprintTtlResultCode::Malformed));
        }
    }

    // Calculate the target TTL ledger sequence
    // C++: newLiveUntilLedgerSeq = getLedgerSeq() + mOpFrame.mExtendFootprintTTLOp.extendTo
    let current_ledger = context.sequence;
    let new_live_until = current_ledger.saturating_add(op.extend_to);
    let disk_read_bytes_limit = soroban_data.resources.disk_read_bytes;
    let mut accumulated_read_bytes: u32 = 0;

    // Extend TTL for all entries in the read-only footprint.
    // Matches C++ ExtendFootprintTTLApplyHelper::apply():
    // - Look up TTL key first; skip missing/non-live entries
    // - Skip entries whose TTL already meets target
    // - Check read bytes resource limit
    for key in footprint.read_only.iter() {
        let key_hash = compute_ledger_key_hash(key);

        // Look up the TTL entry for this key
        let ttl_entry = state.get_ttl(&key_hash).cloned();
        match ttl_entry {
            None => {
                // TTL entry not found - skip (C++: !ttlLeOpt -> continue)
                continue;
            }
            Some(ttl) => {
                if ttl.live_until_ledger_seq < current_ledger {
                    // Entry is not live (archived/expired) - skip
                    // C++: !isLive(*ttlLeOpt, getLedgerSeq()) -> continue
                    continue;
                }
                if ttl.live_until_ledger_seq >= new_live_until {
                    // TTL already sufficient - skip
                    // C++: currLiveUntilLedgerSeq >= newLiveUntilLedgerSeq -> continue
                    continue;
                }
            }
        }

        // The main entry must exist (TTL exists and is live => entry exists)
        // C++: releaseAssertOrThrow(entryOpt)
        let entry = state.get_entry(key);
        if entry.is_none() {
            // Should not happen if TTL is live, but be safe
            continue;
        }

        // Track read bytes and check limit
        // C++: checkReadBytesResourceLimit(entrySize)
        let entry_size = entry
            .and_then(|e| e.to_xdr(stellar_xdr::curr::Limits::none()).ok())
            .map(|bytes| bytes.len() as u32)
            .unwrap_or(0);
        accumulated_read_bytes = accumulated_read_bytes.saturating_add(entry_size);
        if disk_read_bytes_limit > 0 && accumulated_read_bytes > disk_read_bytes_limit {
            return Ok(make_result(
                ExtendFootprintTtlResultCode::ResourceLimitExceeded,
            ));
        }

        // Extend the TTL
        state.extend_ttl(&key_hash, new_live_until);
    }

    Ok(make_result(ExtendFootprintTtlResultCode::Success))
}

fn is_ttl_entry(key: &LedgerKey) -> bool {
    matches!(key, LedgerKey::ContractData(_) | LedgerKey::ContractCode(_))
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

/// Create an OperationResult from an ExtendFootprintTtlResultCode.
fn make_result(code: ExtendFootprintTtlResultCode) -> OperationResult {
    let result = match code {
        ExtendFootprintTtlResultCode::Success => ExtendFootprintTtlResult::Success,
        ExtendFootprintTtlResultCode::Malformed => ExtendFootprintTtlResult::Malformed,
        ExtendFootprintTtlResultCode::ResourceLimitExceeded => {
            ExtendFootprintTtlResult::ResourceLimitExceeded
        }
        ExtendFootprintTtlResultCode::InsufficientRefundableFee => {
            ExtendFootprintTtlResult::InsufficientRefundableFee
        }
    };

    OperationResult::OpInner(OperationResultTr::ExtendFootprintTtl(result))
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
    fn test_extend_footprint_ttl_malformed() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        let op = ExtendFootprintTtlOp {
            ext: ExtensionPoint::V0,
            extend_to: 0, // Invalid - must be positive
        };

        let result = execute_extend_footprint_ttl(&op, &source, &mut state, &context, None);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ExtendFootprintTtl(r)) => {
                assert!(matches!(r, ExtendFootprintTtlResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_extend_footprint_ttl_no_soroban_data() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        let op = ExtendFootprintTtlOp {
            ext: ExtensionPoint::V0,
            extend_to: 1000,
        };

        // No Soroban data provided
        let result = execute_extend_footprint_ttl(&op, &source, &mut state, &context, None);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ExtendFootprintTtl(r)) => {
                assert!(matches!(r, ExtendFootprintTtlResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_extend_footprint_ttl_rejects_read_write() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        let op = ExtendFootprintTtlOp {
            ext: ExtensionPoint::V0,
            extend_to: 1000,
        };

        let contract_key = LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: Hash([1u8; 32]),
        });

        let soroban_data = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: vec![].try_into().unwrap(),
                    read_write: vec![contract_key].try_into().unwrap(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        };

        let result =
            execute_extend_footprint_ttl(&op, &source, &mut state, &context, Some(&soroban_data));
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ExtendFootprintTtl(r)) => {
                assert!(matches!(r, ExtendFootprintTtlResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_extend_footprint_ttl_rejects_non_ttl_entry() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        let op = ExtendFootprintTtlOp {
            ext: ExtensionPoint::V0,
            extend_to: 1000,
        };

        let account_key = LedgerKey::Account(LedgerKeyAccount {
            account_id: create_test_account_id(1),
        });

        let soroban_data = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: vec![account_key].try_into().unwrap(),
                    read_write: vec![].try_into().unwrap(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        };

        let result =
            execute_extend_footprint_ttl(&op, &source, &mut state, &context, Some(&soroban_data));
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ExtendFootprintTtl(r)) => {
                assert!(matches!(r, ExtendFootprintTtlResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_extend_footprint_ttl_rejects_large_extend_to() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        let op = ExtendFootprintTtlOp {
            ext: ExtensionPoint::V0,
            extend_to: MAX_ENTRY_TTL,
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
            execute_extend_footprint_ttl(&op, &source, &mut state, &context, Some(&soroban_data));
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ExtendFootprintTtl(r)) => {
                assert!(matches!(r, ExtendFootprintTtlResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    /// Test ExtendFootprintTtl succeeds with empty footprint (no-op).
    ///
    /// C++ Reference: SorobanTest.cpp - "extend ttl empty footprint" test section
    #[test]
    fn test_extend_footprint_ttl_success_empty_footprint() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        let op = ExtendFootprintTtlOp {
            ext: ExtensionPoint::V0,
            extend_to: 1000, // Valid extend_to value
        };

        // Empty footprint is valid
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
            execute_extend_footprint_ttl(&op, &source, &mut state, &context, Some(&soroban_data));
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ExtendFootprintTtl(r)) => {
                assert!(
                    matches!(r, ExtendFootprintTtlResult::Success),
                    "Empty footprint should succeed, got {:?}",
                    r
                );
            }
            _ => panic!("Unexpected result type"),
        }
    }

    /// Test ExtendFootprintTtl at max valid extend_to (MAX_ENTRY_TTL - 1).
    ///
    /// C++ Reference: SorobanTest.cpp - "extend ttl boundary" test section
    #[test]
    fn test_extend_footprint_ttl_at_max_boundary() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        // MAX_ENTRY_TTL - 1 is the highest valid value
        let op = ExtendFootprintTtlOp {
            ext: ExtensionPoint::V0,
            extend_to: MAX_ENTRY_TTL - 1,
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
            execute_extend_footprint_ttl(&op, &source, &mut state, &context, Some(&soroban_data));
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ExtendFootprintTtl(r)) => {
                assert!(
                    matches!(r, ExtendFootprintTtlResult::Success),
                    "Max boundary should succeed, got {:?}",
                    r
                );
            }
            _ => panic!("Unexpected result type"),
        }
    }

    /// Test ExtendFootprintTtl with missing ContractCode entry succeeds (skips).
    ///
    /// C++ Reference: ExtendFootprintTTLOpFrame.cpp lines 121-131 -
    /// missing entries are skipped with `continue`, not failed.
    /// Testnet ledger 197881: ExtendFootprintTtl with archived entries must succeed.
    #[test]
    fn test_extend_footprint_ttl_skips_missing_contract_code() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        let op = ExtendFootprintTtlOp {
            ext: ExtensionPoint::V0,
            extend_to: 1000,
        };

        // ContractCode key - valid for TTL but entry doesn't exist in state
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

        let result =
            execute_extend_footprint_ttl(&op, &source, &mut state, &context, Some(&soroban_data));
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ExtendFootprintTtl(r)) => {
                assert!(
                    matches!(r, ExtendFootprintTtlResult::Success),
                    "Missing entry should be skipped (success), got {:?}",
                    r
                );
            }
            _ => panic!("Unexpected result type"),
        }
    }

    /// Test ExtendFootprintTtl with missing ContractData entry succeeds (skips).
    ///
    /// C++ Reference: ExtendFootprintTTLOpFrame.cpp lines 121-131 -
    /// missing entries are skipped with `continue`, not failed.
    #[test]
    fn test_extend_footprint_ttl_skips_missing_contract_data() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        let op = ExtendFootprintTtlOp {
            ext: ExtensionPoint::V0,
            extend_to: 1000,
        };

        // ContractData key - valid for TTL but entry doesn't exist in state
        let contract_data_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Account(create_test_account_id(1)),
            key: ScVal::I32(42),
            durability: ContractDataDurability::Persistent,
        });

        let soroban_data = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: vec![contract_data_key].try_into().unwrap(),
                    read_write: vec![].try_into().unwrap(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        };

        let result =
            execute_extend_footprint_ttl(&op, &source, &mut state, &context, Some(&soroban_data));
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ExtendFootprintTtl(r)) => {
                assert!(
                    matches!(r, ExtendFootprintTtlResult::Success),
                    "Missing entry should be skipped (success), got {:?}",
                    r
                );
            }
            _ => panic!("Unexpected result type"),
        }
    }
}
