//! Soroban Host execution integration.
//!
//! This module provides the integration between our ledger state and the
//! soroban-env-host crate for executing Soroban smart contracts.

use std::rc::Rc;

use sha2::{Digest, Sha256};

// Use soroban-env-host types for Host interaction
use soroban_env_host::{
    budget::Budget,
    events::Events,
    storage::{AccessType, EntryWithLiveUntil, Footprint, FootprintMap, SnapshotSource, Storage, StorageMap},
    DiagnosticLevel, Host, HostError, LedgerInfo,
};

// Both soroban-env-host v25 and our code use stellar-xdr v25, so we can use types directly
use stellar_xdr::curr::{
    AccountId, ContractDataDurability, Hash, HostFunction, LedgerEntry, LedgerEntryData,
    LedgerEntryExt, LedgerFootprint, LedgerKey, Limits, ReadXdr, ScAddress, ScVal,
    SorobanAuthorizationEntry, SorobanTransactionData, WriteXdr,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use super::SorobanConfig;

/// Result of Soroban host function execution.
pub struct SorobanExecutionResult {
    /// The return value of the function.
    pub return_value: ScVal,
    /// Storage changes made during execution.
    pub storage_changes: Vec<StorageChange>,
    /// Events emitted during execution.
    pub events: Events,
    /// CPU instructions consumed.
    pub cpu_insns: u64,
    /// Memory bytes consumed.
    pub mem_bytes: u64,
}

/// A single storage change from Soroban execution.
pub struct StorageChange {
    /// The ledger key.
    pub key: LedgerKey,
    /// The new entry (None if deleted).
    pub new_entry: Option<LedgerEntry>,
    /// The new live_until ledger (for TTL).
    pub live_until: Option<u32>,
}

/// Adapter that provides snapshot access to our ledger state for Soroban.
pub struct LedgerSnapshotAdapter<'a> {
    state: &'a LedgerStateManager,
    current_ledger: u32,
}

impl<'a> LedgerSnapshotAdapter<'a> {
    pub fn new(state: &'a LedgerStateManager, current_ledger: u32) -> Self {
        Self {
            state,
            current_ledger,
        }
    }
}

impl<'a> SnapshotSource for LedgerSnapshotAdapter<'a> {
    fn get(&self, key: &Rc<LedgerKey>) -> Result<Option<EntryWithLiveUntil>, HostError> {
        // Look up the entry in our state
        let entry = match key.as_ref() {
            LedgerKey::Account(account_key) => {
                self.state.get_account(&account_key.account_id).map(|acc| {
                    LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::Account(acc.clone()),
                        ext: LedgerEntryExt::V0,
                    }
                })
            }
            LedgerKey::Trustline(tl_key) => {
                self.state
                    .get_trustline_by_trustline_asset(&tl_key.account_id, &tl_key.asset)
                    .map(|tl| LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::Trustline(tl.clone()),
                        ext: LedgerEntryExt::V0,
                    })
            }
            LedgerKey::ContractData(cd_key) => {
                self.state
                    .get_contract_data(&cd_key.contract, &cd_key.key, cd_key.durability.clone())
                    .map(|cd| LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::ContractData(cd.clone()),
                        ext: LedgerEntryExt::V0,
                    })
            }
            LedgerKey::ContractCode(cc_key) => {
                self.state.get_contract_code(&cc_key.hash).map(|code| {
                    LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::ContractCode(code.clone()),
                        ext: LedgerEntryExt::V0,
                    }
                })
            }
            LedgerKey::Ttl(ttl_key) => {
                self.state.get_ttl(&ttl_key.key_hash).map(|ttl| {
                    LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::Ttl(ttl.clone()),
                        ext: LedgerEntryExt::V0,
                    }
                })
            }
            _ => None,
        };

        match entry {
            Some(e) => {
                // Get TTL for contract entries
                let live_until = get_entry_ttl(self.state, key.as_ref(), self.current_ledger);
                Ok(Some((Rc::new(e), live_until)))
            }
            None => Ok(None),
        }
    }
}

/// Get the TTL for a ledger entry.
fn get_entry_ttl(state: &LedgerStateManager, key: &LedgerKey, _current_ledger: u32) -> Option<u32> {
    match key {
        LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {
            // Compute key hash for TTL lookup
            let key_hash = compute_key_hash(key);
            state.get_ttl(&key_hash).map(|ttl| ttl.live_until_ledger_seq)
        }
        _ => None,
    }
}

/// Compute the hash of a ledger key for TTL lookup.
fn compute_key_hash(key: &LedgerKey) -> Hash {
    let mut hasher = Sha256::new();
    if let Ok(bytes) = key.to_xdr(Limits::none()) {
        hasher.update(&bytes);
    }
    Hash(hasher.finalize().into())
}

/// Build a Soroban storage footprint from transaction resources.
pub fn build_footprint(
    budget: &Budget,
    ledger_footprint: &LedgerFootprint,
) -> Result<Footprint, HostError> {
    let mut footprint_map = FootprintMap::new();

    // Add read-only entries
    for key in ledger_footprint.read_only.iter() {
        footprint_map = footprint_map.insert(Rc::new(key.clone()), AccessType::ReadOnly, budget)?;
    }

    // Add read-write entries
    for key in ledger_footprint.read_write.iter() {
        footprint_map = footprint_map.insert(Rc::new(key.clone()), AccessType::ReadWrite, budget)?;
    }

    Ok(Footprint(footprint_map))
}

/// Build a storage map from the ledger state using the footprint.
pub fn build_storage_map(
    budget: &Budget,
    footprint: &Footprint,
    snapshot: &impl SnapshotSource,
) -> Result<StorageMap, HostError> {
    let mut storage_map = StorageMap::new();

    for (key, _access_type) in footprint.0.iter(budget)? {
        let entry = snapshot.get(key)?;
        storage_map = storage_map.insert(key.clone(), entry, budget)?;
    }

    Ok(storage_map)
}

/// Execute a Soroban host function using soroban-env-host.
///
/// # Arguments
///
/// * `host_function` - The host function to execute
/// * `auth_entries` - Authorization entries for the invocation
/// * `source` - Source account for the transaction
/// * `state` - Ledger state manager for reading entries
/// * `context` - Ledger context with sequence, close time, etc.
/// * `soroban_data` - Soroban transaction data with footprint and resources
/// * `soroban_config` - Network configuration with cost parameters
///
/// # Returns
///
/// Returns the execution result including return value, storage changes, and events.
/// Returns an error if the host function fails or budget is exceeded.
pub fn execute_host_function(
    host_function: &HostFunction,
    auth_entries: &[SorobanAuthorizationEntry],
    source: &AccountId,
    state: &LedgerStateManager,
    context: &LedgerContext,
    soroban_data: &SorobanTransactionData,
    soroban_config: &SorobanConfig,
) -> Result<SorobanExecutionResult, HostError> {
    // Create budget with network cost parameters
    // Use transaction-specified instruction limit, capped by network limit
    let instruction_limit = std::cmp::min(
        soroban_data.resources.instructions as u64,
        soroban_config.tx_max_instructions,
    );

    // SorobanResources does not include a per-transaction memory cap; enforce network limit.
    let memory_limit = soroban_config.tx_max_memory_bytes;

    let budget = if soroban_config.has_valid_cost_params() {
        // Use network cost parameters for accurate metering
        Budget::try_from_configs(
            instruction_limit,
            memory_limit,
            soroban_config.cpu_cost_params.clone(),
            soroban_config.mem_cost_params.clone(),
        )?
    } else {
        // Fallback to default budget if no cost params available
        // This will produce incorrect results but allows basic testing
        tracing::warn!(
            "Using default Soroban budget - cost parameters not loaded from network. \
             Transaction results may not match network."
        );
        Budget::default()
    };

    // Build footprint from transaction resources
    let footprint = build_footprint(&budget, &soroban_data.resources.footprint)?;

    // Create snapshot adapter
    let snapshot = LedgerSnapshotAdapter::new(state, context.sequence);

    // Build storage map from footprint
    let storage_map = build_storage_map(&budget, &footprint, &snapshot)?;

    // Create storage with enforcing footprint
    let storage = Storage::with_enforcing_footprint_and_map(footprint, storage_map);

    // Create host
    let host = Host::with_storage_and_budget(storage, budget.clone());

    // Set ledger info with TTL values from network config
    let ledger_info = LedgerInfo {
        protocol_version: context.protocol_version,
        sequence_number: context.sequence,
        timestamp: context.close_time,
        network_id: context.network_id.0.0,
        base_reserve: context.base_reserve,
        min_temp_entry_ttl: soroban_config.min_temp_entry_ttl,
        min_persistent_entry_ttl: soroban_config.min_persistent_entry_ttl,
        max_entry_ttl: soroban_config.max_entry_ttl,
    };
    host.set_ledger_info(ledger_info)?;

    // Set source account
    host.set_source_account(source.clone())?;

    // Set authorization entries
    host.set_authorization_entries(auth_entries.to_vec())?;

    // Generate PRNG seed from ledger info
    let mut seed = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(&context.network_id.0.0);
    hasher.update(&context.sequence.to_le_bytes());
    hasher.update(&context.close_time.to_le_bytes());
    seed.copy_from_slice(&hasher.finalize());
    host.set_base_prng_seed(seed)?;

    // Enable diagnostics for debugging
    host.set_diagnostic_level(DiagnosticLevel::Debug)?;

    // Execute the host function
    let result = host.invoke_function(host_function.clone())?;

    // Get final storage and events
    let (final_storage, events) = host.try_finish()?;

    // Extract storage changes
    let mut storage_changes = Vec::new();
    for (key, entry_with_live_until) in final_storage.map.iter(&budget)? {
        match entry_with_live_until {
            Some((entry, live_until)) => {
                storage_changes.push(StorageChange {
                    key: key.as_ref().clone(),
                    new_entry: Some(entry.as_ref().clone()),
                    live_until: *live_until,
                });
            }
            None => {
                // Entry was deleted
                storage_changes.push(StorageChange {
                    key: key.as_ref().clone(),
                    new_entry: None,
                    live_until: None,
                });
            }
        }
    }

    // Get budget consumption
    let cpu_insns = budget.get_cpu_insns_consumed().unwrap_or(0);
    let mem_bytes = budget.get_mem_bytes_consumed().unwrap_or(0);

    Ok(SorobanExecutionResult {
        return_value: result,
        storage_changes,
        events,
        cpu_insns,
        mem_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_key_hash() {
        let key = LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
            hash: Hash([1u8; 32]),
        });
        let hash = compute_key_hash(&key);
        assert_ne!(hash.0, [0u8; 32]);
    }
}
