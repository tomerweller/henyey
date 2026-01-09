//! ExtendFootprintTtl operation execution.
//!
//! This module implements the execution logic for the ExtendFootprintTtl operation,
//! which extends the time-to-live for Soroban contract data entries.

use stellar_xdr::curr::{
    AccountId, ExtendFootprintTtlOp, ExtendFootprintTtlResult, ExtendFootprintTtlResultCode,
    Hash, LedgerKey, OperationResult, OperationResultTr, SorobanTransactionData,
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
/// # Arguments
///
/// * `op` - The ExtendFootprintTtl operation data
/// * `source` - The source account ID
/// * `state` - The ledger state manager
/// * `context` - The ledger context
/// * `soroban_data` - The Soroban transaction data containing the footprint
///
/// # Returns
///
/// Returns the operation result indicating success or a specific failure reason.
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
    let footprint = match soroban_data {
        Some(data) => &data.resources.footprint,
        None => {
            return Ok(make_result(ExtendFootprintTtlResultCode::Malformed));
        }
    };

    if !footprint.read_write.is_empty() {
        return Ok(make_result(ExtendFootprintTtlResultCode::Malformed));
    }

    for key in footprint.read_only.iter() {
        if !is_ttl_entry(key) {
            return Ok(make_result(ExtendFootprintTtlResultCode::Malformed));
        }
    }

    // Calculate the target TTL ledger sequence
    let current_ledger = context.sequence;
    let target_ttl = current_ledger.saturating_add(op.extend_to);

    // Extend TTL for all entries in the read-only footprint
    for key in footprint.read_only.iter() {
        if extend_entry_ttl(key, target_ttl, state).is_err() {
            // Entry not found or cannot extend - this is a resource issue
            return Ok(make_result(ExtendFootprintTtlResultCode::ResourceLimitExceeded));
        }
    }

    // Extend TTL for all entries in the read-write footprint
    for key in footprint.read_write.iter() {
        if extend_entry_ttl(key, target_ttl, state).is_err() {
            return Ok(make_result(ExtendFootprintTtlResultCode::ResourceLimitExceeded));
        }
    }

    Ok(make_result(ExtendFootprintTtlResultCode::Success))
}

fn is_ttl_entry(key: &LedgerKey) -> bool {
    matches!(key, LedgerKey::ContractData(_) | LedgerKey::ContractCode(_))
}

/// Extend the TTL of a single ledger entry.
fn extend_entry_ttl(
    key: &LedgerKey,
    target_ttl: u32,
    state: &mut LedgerStateManager,
) -> std::result::Result<(), &'static str> {
    // Compute the key hash for TTL lookup
    let key_hash = compute_ledger_key_hash(key);

    // Check if the entry exists
    if state.get_entry(key).is_none() {
        return Err("Entry not found");
    }

    // Try to extend the TTL
    state.extend_ttl(&key_hash, target_ttl);
    Ok(())
}

/// Compute the hash of a ledger key for TTL lookup.
fn compute_ledger_key_hash(key: &LedgerKey) -> Hash {
    use sha2::{Sha256, Digest};
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
}
