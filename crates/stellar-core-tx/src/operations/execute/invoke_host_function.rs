//! InvokeHostFunction operation execution.
//!
//! This module implements the execution logic for the InvokeHostFunction operation,
//! which executes Soroban smart contract functions.

use stellar_xdr::curr::{
    AccountId, ContractCodeEntry, ContractCodeEntryExt, ContractDataDurability, Hash,
    HostFunction, InvokeHostFunctionOp, InvokeHostFunctionResult, InvokeHostFunctionResultCode,
    LedgerKey, LedgerKeyContractCode, LedgerKeyContractData, Limits, OperationResult,
    OperationResultTr, ScAddress, ScVal, SorobanTransactionData, TtlEntry, WriteXdr,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;

/// Default TTL for newly created contract entries (in ledgers).
const DEFAULT_CONTRACT_TTL: u32 = 518400; // ~30 days at 5-second ledger close

/// Execute an InvokeHostFunction operation.
///
/// This operation invokes a Soroban smart contract function, which can:
/// - Call an existing contract
/// - Create a new contract
/// - Upload contract code
///
/// # Arguments
///
/// * `op` - The InvokeHostFunction operation data
/// * `source` - The source account ID
/// * `state` - The ledger state manager
/// * `context` - The ledger context
/// * `soroban_data` - The Soroban transaction data
///
/// # Returns
///
/// Returns the operation result with the function's return value on success,
/// or a specific failure reason.
pub fn execute_invoke_host_function(
    op: &InvokeHostFunctionOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
    soroban_data: Option<&SorobanTransactionData>,
) -> Result<OperationResult> {
    // Validate we have Soroban data for footprint
    let soroban_data = match soroban_data {
        Some(data) => data,
        None => {
            return Ok(make_result(
                InvokeHostFunctionResultCode::Malformed,
                Hash([0u8; 32]),
            ));
        }
    };

    // Dispatch based on host function type
    match &op.host_function {
        HostFunction::InvokeContract(_)
        | HostFunction::CreateContract(_)
        | HostFunction::CreateContractV2(_) => {
            // For contract operations, use soroban-env-host
            execute_contract_invocation(op, source, state, context, soroban_data)
        }
        HostFunction::UploadContractWasm(wasm) => {
            // WASM upload can be handled locally without full host
            execute_upload_wasm(wasm, source, state, context)
        }
    }
}

/// Execute a contract invocation using soroban-env-host.
fn execute_contract_invocation(
    op: &InvokeHostFunctionOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
    soroban_data: &SorobanTransactionData,
) -> Result<OperationResult> {
    use crate::soroban::execute_host_function;
    use sha2::{Digest, Sha256};

    // Convert auth entries to a slice
    let auth_entries: Vec<_> = op.auth.iter().cloned().collect();

    // Execute via soroban-env-host
    match execute_host_function(
        &op.host_function,
        &auth_entries,
        source,
        state,
        context,
        soroban_data,
    ) {
        Ok(result) => {
            // Apply storage changes back to our state
            for change in result.storage_changes {
                if let Some(entry) = change.new_entry {
                    // Apply the entry based on its type
                    match &entry.data {
                        stellar_xdr::curr::LedgerEntryData::ContractData(cd) => {
                            state.create_contract_data(cd.clone());
                        }
                        stellar_xdr::curr::LedgerEntryData::ContractCode(cc) => {
                            state.create_contract_code(cc.clone());
                        }
                        stellar_xdr::curr::LedgerEntryData::Ttl(ttl) => {
                            state.create_ttl(ttl.clone());
                        }
                        _ => {}
                    }

                    // Apply TTL if present for contract entries
                    if let Some(live_until) = change.live_until {
                        let key_hash = compute_key_hash(&change.key);
                        let ttl = TtlEntry {
                            key_hash,
                            live_until_ledger_seq: live_until,
                        };
                        state.create_ttl(ttl);
                    }
                }
                // For deleted entries, we would remove from state (not yet implemented)
            }

            // Compute result hash from return value
            let result_hash = compute_return_value_hash(&result.return_value);

            tracing::info!(
                cpu_insns = result.cpu_insns,
                mem_bytes = result.mem_bytes,
                "Soroban contract executed successfully"
            );

            Ok(make_result(InvokeHostFunctionResultCode::Success, result_hash))
        }
        Err(host_error) => {
            tracing::warn!(
                error = %host_error,
                "Soroban contract execution failed"
            );

            // Map host error to appropriate result code
            Ok(make_result(
                InvokeHostFunctionResultCode::Trapped,
                Hash([0u8; 32]),
            ))
        }
    }
}

/// Execute WASM upload.
fn execute_upload_wasm(
    wasm: &stellar_xdr::curr::BytesM,
    _source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    use sha2::{Digest, Sha256};

    // Hash the WASM code
    let mut hasher = Sha256::new();
    hasher.update(wasm.as_slice());
    let code_hash = Hash(hasher.finalize().into());

    // Check if this code already exists
    if state.get_contract_code(&code_hash).is_some() {
        // Code already exists, just return success with the hash
        return Ok(make_result(InvokeHostFunctionResultCode::Success, code_hash));
    }

    // Create the contract code entry
    let code_entry = ContractCodeEntry {
        ext: ContractCodeEntryExt::V0,
        hash: code_hash.clone(),
        code: wasm.clone(),
    };
    state.create_contract_code(code_entry);

    // Create TTL for the code
    let code_key_hash = compute_contract_code_key_hash(&code_hash);
    let ttl_entry = TtlEntry {
        key_hash: code_key_hash,
        live_until_ledger_seq: context.sequence + DEFAULT_CONTRACT_TTL,
    };
    state.create_ttl(ttl_entry);

    // Return success with the code hash
    Ok(make_result(InvokeHostFunctionResultCode::Success, code_hash))
}

/// Compute the hash of a ledger key for TTL lookup.
fn compute_key_hash(key: &LedgerKey) -> Hash {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    if let Ok(bytes) = key.to_xdr(Limits::none()) {
        hasher.update(&bytes);
    }
    Hash(hasher.finalize().into())
}

/// Compute the hash of a return value.
fn compute_return_value_hash(value: &ScVal) -> Hash {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    if let Ok(bytes) = value.to_xdr(Limits::none()) {
        hasher.update(&bytes);
    }
    Hash(hasher.finalize().into())
}

/// Compute the hash of a contract code key for TTL lookup.
fn compute_contract_code_key_hash(code_hash: &Hash) -> Hash {
    use sha2::{Digest, Sha256};

    let ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: code_hash.clone(),
    });

    let mut hasher = Sha256::new();
    if let Ok(bytes) = ledger_key.to_xdr(Limits::none()) {
        hasher.update(&bytes);
    }
    Hash(hasher.finalize().into())
}

/// Create an OperationResult from an InvokeHostFunctionResultCode.
fn make_result(code: InvokeHostFunctionResultCode, success_hash: Hash) -> OperationResult {
    let result = match code {
        InvokeHostFunctionResultCode::Success => InvokeHostFunctionResult::Success(success_hash),
        InvokeHostFunctionResultCode::Malformed => InvokeHostFunctionResult::Malformed,
        InvokeHostFunctionResultCode::Trapped => InvokeHostFunctionResult::Trapped,
        InvokeHostFunctionResultCode::ResourceLimitExceeded => {
            InvokeHostFunctionResult::ResourceLimitExceeded
        }
        InvokeHostFunctionResultCode::EntryArchived => InvokeHostFunctionResult::EntryArchived,
        InvokeHostFunctionResultCode::InsufficientRefundableFee => {
            InvokeHostFunctionResult::InsufficientRefundableFee
        }
    };

    OperationResult::OpInner(OperationResultTr::InvokeHostFunction(result))
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
    fn test_invoke_host_function_no_soroban_data() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        let op = InvokeHostFunctionOp {
            host_function: HostFunction::UploadContractWasm(vec![0u8; 100].try_into().unwrap()),
            auth: vec![].try_into().unwrap(),
        };

        let result = execute_invoke_host_function(&op, &source, &mut state, &context, None);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::InvokeHostFunction(r)) => {
                assert!(matches!(r, InvokeHostFunctionResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_upload_wasm_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);

        // Create minimal valid WASM
        let wasm_bytes: Vec<u8> = vec![
            0x00, 0x61, 0x73, 0x6d, // WASM magic number
            0x01, 0x00, 0x00, 0x00, // WASM version
        ];

        let op = InvokeHostFunctionOp {
            host_function: HostFunction::UploadContractWasm(wasm_bytes.try_into().unwrap()),
            auth: vec![].try_into().unwrap(),
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
            execute_invoke_host_function(&op, &source, &mut state, &context, Some(&soroban_data));
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::InvokeHostFunction(r)) => {
                assert!(matches!(r, InvokeHostFunctionResult::Success(_)));
            }
            _ => panic!("Unexpected result type"),
        }
    }
}
