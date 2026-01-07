//! Soroban Host execution integration.
//!
//! This module provides the integration between our ledger state and the
//! soroban-env-host crate for executing Soroban smart contracts.

use std::rc::Rc;

use sha2::{Digest, Sha256};

// Use soroban-env-host types for Host interaction
use soroban_env_host_p24 as soroban_env_host24;
use soroban_env_host24::{
    budget::Budget,
    e2e_invoke::{self},
    fees::{compute_rent_fee, LedgerEntryRentChange},
    storage::{AccessType, EntryWithLiveUntil, Footprint, FootprintMap, SnapshotSource, StorageMap},
    HostError as HostErrorP24, LedgerInfo as LedgerInfoP24,
};
use soroban_env_host24::xdr::{ReadXdr as ReadXdrP24, WriteXdr as WriteXdrP24};
use soroban_env_host_p25 as soroban_env_host25;
use soroban_env_host25::HostError as HostErrorP25;

// Both soroban-env-host v25 and our code use stellar-xdr v25, so we can use types directly
use stellar_xdr::curr::{
    AccountId, DiagnosticEvent, Hash, HostFunction, LedgerEntry, LedgerEntryData, LedgerEntryExt,
    LedgerFootprint, LedgerKey, Limits, ReadXdr, ScVal, SorobanAuthorizationEntry,
    SorobanTransactionData, SorobanTransactionDataExt, WriteXdr,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use super::SorobanConfig;
use super::error::convert_host_error_p24_to_p25;

/// Result of Soroban host function execution.
pub struct SorobanExecutionResult {
    /// The return value of the function.
    pub return_value: ScVal,
    /// Storage changes made during execution.
    pub storage_changes: Vec<StorageChange>,
    /// Contract and system events emitted during execution.
    pub contract_events: Vec<stellar_xdr::curr::ContractEvent>,
    /// Diagnostic events emitted during execution.
    pub diagnostic_events: Vec<DiagnosticEvent>,
    /// CPU instructions consumed.
    pub cpu_insns: u64,
    /// Memory bytes consumed.
    pub mem_bytes: u64,
    /// Contract events + return value size in bytes.
    pub contract_events_and_return_value_size: u32,
    /// Rent fee charged for storage changes.
    pub rent_fee: i64,
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

    /// Get an archived entry without checking TTL.
    /// Used for entries that are being restored from the hot archive.
    pub fn get_archived(
        &self,
        key: &Rc<soroban_env_host24::xdr::LedgerKey>,
    ) -> Result<Option<EntryWithLiveUntil>, HostErrorP24> {
        let current_key = convert_ledger_key_from_p24(key.as_ref()).ok_or_else(|| {
            HostErrorP24::from(soroban_env_host24::Error::from_type_and_code(
                soroban_env_host24::xdr::ScErrorType::Context,
                soroban_env_host24::xdr::ScErrorCode::InternalError,
            ))
        })?;

        // Get TTL but don't check if it's expired - this is for archived entries
        let live_until = get_entry_ttl(self.state, &current_key, self.current_ledger);

        // Get entry without TTL check (entry might be archived with expired TTL)
        let entry = match &current_key {
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
                // No TTL check for archived entries
                self.state
                    .get_contract_data(&cd_key.contract, &cd_key.key, cd_key.durability.clone())
                    .map(|cd| LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::ContractData(cd.clone()),
                        ext: LedgerEntryExt::V0,
                    })
            }
            LedgerKey::ContractCode(cc_key) => {
                // No TTL check for archived entries
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
                let entry = convert_ledger_entry_to_p24(&e).ok_or_else(|| {
                    HostErrorP24::from(soroban_env_host24::Error::from_type_and_code(
                        soroban_env_host24::xdr::ScErrorType::Context,
                        soroban_env_host24::xdr::ScErrorCode::InternalError,
                    ))
                })?;
                Ok(Some((Rc::new(entry), live_until)))
            }
            None => Ok(None),
        }
    }
}

impl<'a> SnapshotSource for LedgerSnapshotAdapter<'a> {
    fn get(
        &self,
        key: &Rc<soroban_env_host24::xdr::LedgerKey>,
    ) -> Result<Option<EntryWithLiveUntil>, HostErrorP24> {
        let current_key = convert_ledger_key_from_p24(key.as_ref()).ok_or_else(|| {
            HostErrorP24::from(soroban_env_host24::Error::from_type_and_code(
                soroban_env_host24::xdr::ScErrorType::Context,
                soroban_env_host24::xdr::ScErrorCode::InternalError,
            ))
        })?;

        // For ContractData and ContractCode, check TTL first.
        // If TTL has expired, the entry is considered to be in the hot archive
        // and not accessible. This mimics C++ stellar-core behavior.
        let live_until = get_entry_ttl(self.state, &current_key, self.current_ledger);

        let entry = match &current_key {
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
                // Check if entry has expired TTL - if so, it's archived and not accessible
                if let Some(ttl) = live_until {
                    if ttl < self.current_ledger {
                        return Ok(None);
                    }
                }
                self.state
                    .get_contract_data(&cd_key.contract, &cd_key.key, cd_key.durability.clone())
                    .map(|cd| LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::ContractData(cd.clone()),
                        ext: LedgerEntryExt::V0,
                    })
            }
            LedgerKey::ContractCode(cc_key) => {
                // Check if entry has expired TTL - if so, it's archived and not accessible
                if let Some(ttl) = live_until {
                    if ttl < self.current_ledger {
                        return Ok(None);
                    }
                }
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
                let entry = convert_ledger_entry_to_p24(&e).ok_or_else(|| {
                    HostErrorP24::from(soroban_env_host24::Error::from_type_and_code(
                        soroban_env_host24::xdr::ScErrorType::Context,
                        soroban_env_host24::xdr::ScErrorCode::InternalError,
                    ))
                })?;
                Ok(Some((Rc::new(entry), live_until)))
            }
            None => Ok(None),
        }
    }
}

/// Adapter that provides snapshot access to our ledger state for Soroban (p25 host).
pub struct LedgerSnapshotAdapterP25<'a> {
    state: &'a LedgerStateManager,
    current_ledger: u32,
}

impl<'a> LedgerSnapshotAdapterP25<'a> {
    pub fn new(state: &'a LedgerStateManager, current_ledger: u32) -> Self {
        Self {
            state,
            current_ledger,
        }
    }

    /// Get an archived entry without checking TTL.
    /// Used for entries that are being restored from the hot archive.
    pub fn get_archived(
        &self,
        key: &Rc<LedgerKey>,
    ) -> Result<Option<soroban_env_host25::storage::EntryWithLiveUntil>, HostErrorP25> {
        // Get TTL but don't check if it's expired - this is for archived entries
        let live_until = get_entry_ttl(self.state, key.as_ref(), self.current_ledger);

        // Get entry without TTL check (entry might be archived with expired TTL)
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
                // No TTL check for archived entries
                self.state
                    .get_contract_data(&cd_key.contract, &cd_key.key, cd_key.durability.clone())
                    .map(|cd| LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::ContractData(cd.clone()),
                        ext: LedgerEntryExt::V0,
                    })
            }
            LedgerKey::ContractCode(cc_key) => {
                // No TTL check for archived entries
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
            Some(e) => Ok(Some((Rc::new(e), live_until))),
            None => Ok(None),
        }
    }
}

impl<'a> soroban_env_host25::storage::SnapshotSource for LedgerSnapshotAdapterP25<'a> {
    fn get(
        &self,
        key: &Rc<LedgerKey>,
    ) -> Result<Option<soroban_env_host25::storage::EntryWithLiveUntil>, HostErrorP25> {
        // For ContractData and ContractCode, check TTL first.
        // If TTL has expired, the entry is considered to be in the hot archive
        // and not accessible. This mimics C++ stellar-core behavior.
        let live_until = get_entry_ttl(self.state, key.as_ref(), self.current_ledger);

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
                // Check if entry has expired TTL - if so, it's archived and not accessible
                if let Some(ttl) = live_until {
                    if ttl < self.current_ledger {
                        return Ok(None);
                    }
                }
                self.state
                    .get_contract_data(&cd_key.contract, &cd_key.key, cd_key.durability.clone())
                    .map(|cd| LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::ContractData(cd.clone()),
                        ext: LedgerEntryExt::V0,
                    })
            }
            LedgerKey::ContractCode(cc_key) => {
                // Check if entry has expired TTL - if so, it's archived and not accessible
                if let Some(ttl) = live_until {
                    if ttl < self.current_ledger {
                        return Ok(None);
                    }
                }
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
                Ok(Some((Rc::new(e), live_until)))
            }
            None => Ok(None),
        }
    }
}

/// Get the TTL for a ledger entry.
fn get_entry_ttl(state: &LedgerStateManager, key: &LedgerKey, current_ledger: u32) -> Option<u32> {
    match key {
        LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {
            // Compute key hash for TTL lookup
            let key_hash = compute_key_hash(key);
            let ttl = state.get_ttl(&key_hash).map(|ttl| ttl.live_until_ledger_seq);
            if let Some(live_until) = ttl {
                if live_until < current_ledger {
                    tracing::warn!(
                        current_ledger,
                        live_until,
                        key_type = if matches!(key, LedgerKey::ContractCode(_)) { "ContractCode" } else { "ContractData" },
                        "Soroban entry TTL is EXPIRED"
                    );
                }
            } else {
                // TTL entries may not be present in older bucket lists or for newly created entries
                // that haven't been checkpointed yet. This is not an error condition.
                tracing::debug!(
                    key_type = if matches!(key, LedgerKey::ContractCode(_)) { "ContractCode" } else { "ContractData" },
                    "Soroban entry has no TTL record in bucket list"
                );
            }
            ttl
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

fn convert_ledger_key_to_p24(
    key: &LedgerKey,
) -> Option<soroban_env_host24::xdr::LedgerKey> {
    let bytes = key.to_xdr(Limits::none()).ok()?;
    soroban_env_host24::xdr::LedgerKey::from_xdr(
        &bytes,
        soroban_env_host24::xdr::Limits::none(),
    )
    .ok()
}

fn convert_ledger_key_from_p24(
    key: &soroban_env_host24::xdr::LedgerKey,
) -> Option<LedgerKey> {
    let bytes = soroban_env_host24::xdr::WriteXdr::to_xdr(
        key,
        soroban_env_host24::xdr::Limits::none(),
    )
    .ok()?;
    LedgerKey::from_xdr(&bytes, Limits::none()).ok()
}

fn convert_ledger_entry_to_p24(
    entry: &LedgerEntry,
) -> Option<soroban_env_host24::xdr::LedgerEntry> {
    let bytes = entry.to_xdr(Limits::none()).ok()?;
    soroban_env_host24::xdr::LedgerEntry::from_xdr(
        &bytes,
        soroban_env_host24::xdr::Limits::none(),
    )
    .ok()
}

fn convert_contract_cost_params_to_p24(
    params: &stellar_xdr::curr::ContractCostParams,
) -> Option<soroban_env_host24::xdr::ContractCostParams> {
    let bytes = params.to_xdr(Limits::none()).ok()?;
    soroban_env_host24::xdr::ContractCostParams::from_xdr(
        &bytes,
        soroban_env_host24::xdr::Limits::none(),
    )
    .ok()
}

/// Build a Soroban storage footprint from transaction resources.
#[allow(dead_code)]
pub fn build_footprint(
    budget: &Budget,
    ledger_footprint: &LedgerFootprint,
) -> Result<Footprint, HostErrorP24> {
    let mut footprint_map = FootprintMap::new();

    // Add read-only entries
    for key in ledger_footprint.read_only.iter() {
        let key = convert_ledger_key_to_p24(key).ok_or_else(|| {
            HostErrorP24::from(soroban_env_host24::Error::from_type_and_code(
                soroban_env_host24::xdr::ScErrorType::Context,
                soroban_env_host24::xdr::ScErrorCode::InternalError,
            ))
        })?;
        footprint_map = footprint_map.insert(Rc::new(key), AccessType::ReadOnly, budget)?;
    }

    // Add read-write entries
    for key in ledger_footprint.read_write.iter() {
        let key = convert_ledger_key_to_p24(key).ok_or_else(|| {
            HostErrorP24::from(soroban_env_host24::Error::from_type_and_code(
                soroban_env_host24::xdr::ScErrorType::Context,
                soroban_env_host24::xdr::ScErrorCode::InternalError,
            ))
        })?;
        footprint_map = footprint_map.insert(Rc::new(key), AccessType::ReadWrite, budget)?;
    }

    Ok(Footprint(footprint_map))
}

/// Build a storage map from the ledger state using the footprint.
#[allow(dead_code)]
pub fn build_storage_map(
    budget: &Budget,
    footprint: &Footprint,
    snapshot: &impl SnapshotSource,
) -> Result<StorageMap, HostErrorP24> {
    let mut storage_map = StorageMap::new();
    let mut found_count = 0;
    let mut missing_count = 0;

    for (key, access_type) in footprint.0.iter(budget)? {
        let entry = snapshot.get(key)?;
        let key_type = match key.as_ref() {
            soroban_env_host24::xdr::LedgerKey::Account(_) => "Account",
            soroban_env_host24::xdr::LedgerKey::Trustline(_) => "Trustline",
            soroban_env_host24::xdr::LedgerKey::ContractData(_) => "ContractData",
            soroban_env_host24::xdr::LedgerKey::ContractCode(_) => "ContractCode",
            soroban_env_host24::xdr::LedgerKey::Ttl(_) => "Ttl",
            _ => "Other",
        };

        if let Some((ref e, ref ttl)) = entry {
            found_count += 1;
            let has_ext = !matches!(e.ext, soroban_env_host24::xdr::LedgerEntryExt::V0);
            tracing::trace!(
                key_type,
                access = ?access_type,
                last_modified = e.last_modified_ledger_seq,
                has_ext,
                live_until = ?ttl,
                "Soroban footprint entry found"
            );
        } else {
            missing_count += 1;
            tracing::warn!(
                key_type,
                access = ?access_type,
                "Soroban footprint entry MISSING from storage"
            );
        }
        storage_map = storage_map.insert(key.clone(), entry, budget)?;
    }

    tracing::debug!(
        found_count,
        missing_count,
        total = found_count + missing_count,
        "Soroban storage map built from footprint"
    );

    Ok(storage_map)
}

/// Execute a Soroban host function using soroban-env-host's e2e_invoke API.
///
/// This uses the same high-level API that C++ stellar-core uses, which handles
/// all the internal setup correctly.
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
) -> Result<SorobanExecutionResult, HostErrorP25> {
    if context.protocol_version >= 25 {
        return execute_host_function_p25(
            host_function,
            auth_entries,
            source,
            state,
            context,
            soroban_data,
            soroban_config,
        );
    }
    execute_host_function_p24(
        host_function,
        auth_entries,
        source,
        state,
        context,
        soroban_data,
        soroban_config,
    )
}

fn execute_host_function_p24(
    host_function: &HostFunction,
    auth_entries: &[SorobanAuthorizationEntry],
    source: &AccountId,
    state: &LedgerStateManager,
    context: &LedgerContext,
    soroban_data: &SorobanTransactionData,
    soroban_config: &SorobanConfig,
) -> Result<SorobanExecutionResult, HostErrorP25> {
    // Create budget with network cost parameters
    // Use a larger budget for the e2e_invoke call which includes XDR parsing overhead
    // The transaction's instruction limit is for contract execution only, but e2e_invoke
    // also meters the setup operations (XDR parsing, storage map building, etc.)
    let instruction_limit = soroban_config.tx_max_instructions * 2; // Double for setup overhead
    let memory_limit = soroban_config.tx_max_memory_bytes * 2; // Double for setup overhead

    let budget = if soroban_config.has_valid_cost_params() {
        let cpu_cost_params = convert_contract_cost_params_to_p24(&soroban_config.cpu_cost_params)
            .ok_or_else(|| {
                HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
                    soroban_env_host25::xdr::ScErrorType::Context,
                    soroban_env_host25::xdr::ScErrorCode::InternalError,
                ))
            })?;
        let mem_cost_params = convert_contract_cost_params_to_p24(&soroban_config.mem_cost_params)
            .ok_or_else(|| {
                HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
                    soroban_env_host25::xdr::ScErrorType::Context,
                    soroban_env_host25::xdr::ScErrorCode::InternalError,
                ))
            })?;
        Budget::try_from_configs(
            instruction_limit,
            memory_limit,
            cpu_cost_params,
            mem_cost_params,
        )
        .map_err(convert_host_error_p24_to_p25)?
    } else {
        tracing::warn!(
            "Using default Soroban budget - cost parameters not loaded from network."
        );
        Budget::default()
    };

    // Build ledger info
    let ledger_info = LedgerInfoP24 {
        protocol_version: context.protocol_version,
        sequence_number: context.sequence,
        timestamp: context.close_time,
        network_id: context.network_id.0.0,
        base_reserve: context.base_reserve,
        min_temp_entry_ttl: soroban_config.min_temp_entry_ttl,
        min_persistent_entry_ttl: soroban_config.min_persistent_entry_ttl,
        max_entry_ttl: soroban_config.max_entry_ttl,
    };
    tracing::debug!(
        protocol_version = context.protocol_version,
        sequence_number = context.sequence,
        timestamp = context.close_time,
        instruction_limit,
        memory_limit,
        has_cost_params = soroban_config.has_valid_cost_params(),
        "Soroban host ledger info configured"
    );

    // Use PRNG seed from context if provided (computed as subSha256(txSetHash, txIndex)),
    // otherwise fall back to a deterministic but incorrect seed based on ledger info.
    let seed: Vec<u8> = if let Some(prng_seed) = context.soroban_prng_seed {
        prng_seed.to_vec()
    } else {
        // Fallback: use ledger info to generate a deterministic but incorrect seed.
        // This will cause Soroban contract results to differ from C++ stellar-core.
        tracing::warn!(
            "Using fallback PRNG seed - results may differ from C++ stellar-core"
        );
        let mut hasher = Sha256::new();
        hasher.update(&context.network_id.0.0);
        hasher.update(&context.sequence.to_le_bytes());
        hasher.update(&context.close_time.to_le_bytes());
        hasher.finalize().to_vec()
    };

    // Encode all data to XDR bytes for e2e_invoke
    let encoded_host_fn = host_function
        .to_xdr(Limits::none())
        .map_err(|_e| {
            HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
                soroban_env_host25::xdr::ScErrorType::Context,
                soroban_env_host25::xdr::ScErrorCode::InternalError,
            ))
        })?;

    let encoded_resources = soroban_data
        .resources
        .to_xdr(Limits::none())
        .map_err(|_e| {
            HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
                soroban_env_host25::xdr::ScErrorType::Context,
                soroban_env_host25::xdr::ScErrorCode::InternalError,
            ))
        })?;

    let encoded_source = source.to_xdr(Limits::none()).map_err(|_e| {
        HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
            soroban_env_host25::xdr::ScErrorType::Context,
            soroban_env_host25::xdr::ScErrorCode::InternalError,
        ))
    })?;

    // Encode auth entries
    let encoded_auth_entries: Vec<Vec<u8>> = auth_entries
        .iter()
        .map(|e| e.to_xdr(Limits::none()))
        .collect::<Result<_, _>>()
        .map_err(|_e| {
            HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
                soroban_env_host25::xdr::ScErrorType::Context,
                soroban_env_host25::xdr::ScErrorCode::InternalError,
            ))
        })?;

    // Extract archived entry indices from soroban_data.ext for TTL restoration FIRST
    // These are indices into the read_write footprint entries that need their TTL restored
    // We need this before building entries so we can include archived entries
    let restored_rw_entry_indices: Vec<u32> = match &soroban_data.ext {
        SorobanTransactionDataExt::V1(ext) => {
            ext.archived_soroban_entries.iter().copied().collect()
        }
        SorobanTransactionDataExt::V0 => Vec::new(),
    };
    let restored_indices_set: std::collections::HashSet<u32> = restored_rw_entry_indices.iter().copied().collect();

    // Create snapshot adapter to get ledger entries
    let snapshot = LedgerSnapshotAdapter::new(state, context.sequence);

    // Collect and encode ledger entries from the footprint
    // IMPORTANT: e2e_invoke expects exactly one TTL entry for each ledger entry (they are zipped)
    // For non-contract entries (Account, etc), we pass empty bytes for TTL
    let mut encoded_ledger_entries = Vec::new();
    let mut encoded_ttl_entries = Vec::new();

    // Helper to encode an entry and its TTL
    let mut add_entry = |key: &LedgerKey,
                         entry: &soroban_env_host24::xdr::LedgerEntry,
                         live_until: Option<u32>|
     -> Result<(), HostErrorP25> {
        encoded_ledger_entries.push(
            entry
                .to_xdr(soroban_env_host24::xdr::Limits::none())
                .map_err(|_| {
                    HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
                        soroban_env_host25::xdr::ScErrorType::Context,
                        soroban_env_host25::xdr::ScErrorCode::InternalError,
                    ))
                })?,
        );

        // Encode TTL entry if present, otherwise push empty bytes
        // e2e_invoke zips entries with TTLs, so we need exactly one TTL per entry
        // For contract entries (ContractData, ContractCode), we always need TTL
        let needs_ttl = matches!(key, LedgerKey::ContractData(_) | LedgerKey::ContractCode(_));
        let ttl_bytes = if let Some(lu) = live_until {
            let key_hash = compute_key_hash(key);
            let ttl_entry = soroban_env_host24::xdr::TtlEntry {
                key_hash: soroban_env_host24::xdr::Hash(key_hash.0),
                live_until_ledger_seq: lu,
            };
            ttl_entry
                .to_xdr(soroban_env_host24::xdr::Limits::none())
                .map_err(|_| {
                HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
                    soroban_env_host25::xdr::ScErrorType::Context,
                    soroban_env_host25::xdr::ScErrorCode::InternalError,
                ))
            })?
        } else if needs_ttl {
            // For archived entries being restored, provide expired TTL (0)
            // The host will extend this TTL as part of restoration
            let key_hash = compute_key_hash(key);
            let ttl_entry = soroban_env_host24::xdr::TtlEntry {
                key_hash: soroban_env_host24::xdr::Hash(key_hash.0),
                live_until_ledger_seq: 0, // Expired/archived
            };
            ttl_entry
                .to_xdr(soroban_env_host24::xdr::Limits::none())
                .map_err(|_| {
                HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
                    soroban_env_host25::xdr::ScErrorType::Context,
                    soroban_env_host25::xdr::ScErrorCode::InternalError,
                ))
            })?
        } else {
            // Empty bytes for entries that don't need TTL (non-contract entries)
            Vec::new()
        };
        encoded_ttl_entries.push(ttl_bytes);
        Ok(())
    };

    for key in soroban_data.resources.footprint.read_only.iter() {
        let key_p24 = convert_ledger_key_to_p24(key).ok_or_else(|| {
            HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
                soroban_env_host25::xdr::ScErrorType::Context,
                soroban_env_host25::xdr::ScErrorCode::InternalError,
            ))
        })?;
        if let Some((entry, live_until)) =
            snapshot.get(&Rc::new(key_p24)).map_err(convert_host_error_p24_to_p25)?
        {
            add_entry(key, &entry, live_until)?;
        }
    }

    if !restored_indices_set.is_empty() {
        tracing::warn!(
            restored_count = restored_rw_entry_indices.len(),
            restored_indices = ?restored_rw_entry_indices,
            "P24: Transaction has archived entries to restore"
        );
    }

    for (idx, key) in soroban_data.resources.footprint.read_write.iter().enumerate() {
        let key_p24 = convert_ledger_key_to_p24(key).ok_or_else(|| {
            HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
                soroban_env_host25::xdr::ScErrorType::Context,
                soroban_env_host25::xdr::ScErrorCode::InternalError,
            ))
        })?;

        // For archived entries being restored, use get_archived which doesn't check TTL
        let is_being_restored = restored_indices_set.contains(&(idx as u32));
        let entry_result = if is_being_restored {
            let result = snapshot.get_archived(&Rc::new(key_p24)).map_err(convert_host_error_p24_to_p25)?;
            if let Some((ref entry, live_until)) = result {
                tracing::warn!(
                    idx = idx,
                    key_type = ?std::mem::discriminant(key),
                    live_until = ?live_until,
                    current_ledger = context.sequence,
                    "P24: Archived entry found for restoration"
                );
            } else {
                tracing::warn!(
                    idx = idx,
                    key_type = ?std::mem::discriminant(key),
                    "P24: Archived entry being restored but NOT FOUND in state"
                );
            }
            result
        } else {
            snapshot.get(&Rc::new(key_p24)).map_err(convert_host_error_p24_to_p25)?
        };

        if let Some((entry, live_until)) = entry_result {
            add_entry(key, &entry, live_until)?;
        }
    }

    tracing::debug!(
        ledger_entries_count = encoded_ledger_entries.len(),
        ttl_entries_count = encoded_ttl_entries.len(),
        restored_count = restored_rw_entry_indices.len(),
        "Prepared entries for e2e_invoke"
    );

    // Call e2e_invoke - iterator yields &Vec<u8> which implements AsRef<[u8]>
    let mut diagnostic_events: Vec<soroban_env_host24::xdr::DiagnosticEvent> = Vec::new();
    let result = match e2e_invoke::invoke_host_function(
        &budget,
        true, // enable_diagnostics
        &encoded_host_fn,
        &encoded_resources,
        &restored_rw_entry_indices,
        &encoded_source,
        encoded_auth_entries.iter(),
        ledger_info,
        encoded_ledger_entries.iter(),
        encoded_ttl_entries.iter(),
        &seed,
        &mut diagnostic_events,
        None, // trace_hook
        None, // module_cache - let host load from storage
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(
                cpu_consumed = budget.get_cpu_insns_consumed().unwrap_or(0),
                mem_consumed = budget.get_mem_bytes_consumed().unwrap_or(0),
                diagnostic_events = diagnostic_events.len(),
                "Soroban e2e_invoke failed"
            );
            return Err(convert_host_error_p24_to_p25(e));
        }
    };

    // Parse the result
    let (return_value, return_value_size) = match result.encoded_invoke_result {
        Ok(ref bytes) => {
            let val = ScVal::from_xdr(bytes, Limits::none()).unwrap_or(ScVal::Void);
            (val, bytes.len() as u32)
        }
        Err(ref e) => {
            return Err(convert_host_error_p24_to_p25(e.clone()));
        }
    };

    let mut contract_events = Vec::new();
    let mut contract_events_size = 0u32;
    for buf in result.encoded_contract_events.iter() {
        contract_events_size = contract_events_size.saturating_add(buf.len() as u32);
        if let Ok(event) = stellar_xdr::curr::ContractEvent::from_xdr(buf, Limits::none()) {
            contract_events.push(event);
        }
    }

    let rent_changes: Vec<LedgerEntryRentChange> = e2e_invoke::extract_rent_changes(&result.ledger_changes);

    // Convert ledger changes to our format
    let storage_changes = result.ledger_changes
        .into_iter()
        .filter_map(|change| {
            // Include entries that:
            // 1. Have a new value (were created or modified), OR
            // 2. Are NOT read-only and have no new value (were deleted)
            // Skip read-only entries that weren't modified (just reads, not deletions).
            let is_deletion = !change.read_only && change.encoded_new_value.is_none();
            let is_modification = change.encoded_new_value.is_some();

            if is_modification || is_deletion {
                let key = LedgerKey::from_xdr(&change.encoded_key, Limits::none()).ok()?;
                let new_entry = change.encoded_new_value.and_then(|bytes| {
                    LedgerEntry::from_xdr(&bytes, Limits::none()).ok()
                });
                // Get TTL from ttl_change if present
                let live_until = change.ttl_change.map(|ttl| ttl.new_live_until_ledger);
                Some(StorageChange {
                    key,
                    new_entry,
                    live_until,
                })
            } else {
                None
            }
        })
        .collect();

    // Get budget consumption
    let cpu_insns = budget.get_cpu_insns_consumed().unwrap_or(0);
    let mem_bytes = budget.get_mem_bytes_consumed().unwrap_or(0);
    let contract_events_and_return_value_size = contract_events_size.saturating_add(return_value_size);
    let rent_fee_config = rent_fee_config_p25_to_p24(&soroban_config.rent_fee_config);
    let rent_fee = compute_rent_fee(&rent_changes, &rent_fee_config, context.sequence);
    let diagnostic_events = convert_diagnostic_events_p24(diagnostic_events);

    Ok(SorobanExecutionResult {
        return_value,
        storage_changes,
        contract_events,
        diagnostic_events,
        cpu_insns,
        mem_bytes,
        contract_events_and_return_value_size,
        rent_fee,
    })
}

fn execute_host_function_p25(
    host_function: &HostFunction,
    auth_entries: &[SorobanAuthorizationEntry],
    source: &AccountId,
    state: &LedgerStateManager,
    context: &LedgerContext,
    soroban_data: &SorobanTransactionData,
    soroban_config: &SorobanConfig,
) -> Result<SorobanExecutionResult, HostErrorP25> {
    use soroban_env_host25::{
        budget::Budget,
        e2e_invoke,
        fees::{compute_rent_fee, LedgerEntryRentChange},
        storage::SnapshotSource,
    };

    let instruction_limit = soroban_config.tx_max_instructions * 2;
    let memory_limit = soroban_config.tx_max_memory_bytes * 2;

    let budget = if soroban_config.has_valid_cost_params() {
        Budget::try_from_configs(
            instruction_limit,
            memory_limit,
            soroban_config.cpu_cost_params.clone(),
            soroban_config.mem_cost_params.clone(),
        )?
    } else {
        tracing::warn!(
            "Using default Soroban budget - cost parameters not loaded from network."
        );
        Budget::default()
    };

    let ledger_info = soroban_env_host25::LedgerInfo {
        protocol_version: context.protocol_version,
        sequence_number: context.sequence,
        timestamp: context.close_time,
        network_id: context.network_id.0.0,
        base_reserve: context.base_reserve,
        min_temp_entry_ttl: soroban_config.min_temp_entry_ttl,
        min_persistent_entry_ttl: soroban_config.min_persistent_entry_ttl,
        max_entry_ttl: soroban_config.max_entry_ttl,
    };

    tracing::debug!(
        protocol_version = context.protocol_version,
        sequence_number = context.sequence,
        timestamp = context.close_time,
        instruction_limit,
        memory_limit,
        has_cost_params = soroban_config.has_valid_cost_params(),
        "P25: Soroban host ledger info configured"
    );

    let seed: Vec<u8> = if let Some(prng_seed) = context.soroban_prng_seed {
        prng_seed.to_vec()
    } else {
        tracing::warn!(
            "P25: Using fallback PRNG seed - results may differ from C++ stellar-core"
        );
        let mut hasher = Sha256::new();
        hasher.update(&context.network_id.0.0);
        hasher.update(&context.sequence.to_le_bytes());
        hasher.update(&context.close_time.to_le_bytes());
        hasher.finalize().to_vec()
    };

    let encoded_host_fn = host_function.to_xdr(Limits::none())
        .map_err(|_e| HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
            soroban_env_host25::xdr::ScErrorType::Context,
            soroban_env_host25::xdr::ScErrorCode::InternalError,
        )))?;

    let encoded_resources = soroban_data.resources.to_xdr(Limits::none())
        .map_err(|_e| HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
            soroban_env_host25::xdr::ScErrorType::Context,
            soroban_env_host25::xdr::ScErrorCode::InternalError,
        )))?;

    let encoded_source = source.to_xdr(Limits::none())
        .map_err(|_e| HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
            soroban_env_host25::xdr::ScErrorType::Context,
            soroban_env_host25::xdr::ScErrorCode::InternalError,
        )))?;

    let encoded_auth_entries: Vec<Vec<u8>> = auth_entries
        .iter()
        .map(|e| e.to_xdr(Limits::none()))
        .collect::<Result<_, _>>()
        .map_err(|_| HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
            soroban_env_host25::xdr::ScErrorType::Context,
            soroban_env_host25::xdr::ScErrorCode::InternalError,
        )))?;

    // Extract archived entry indices from soroban_data.ext for TTL restoration FIRST
    // These are indices into the read_write footprint entries that need their TTL restored
    // We need this before building entries so we can include archived entries
    let restored_rw_entry_indices: Vec<u32> = match &soroban_data.ext {
        SorobanTransactionDataExt::V1(ext) => {
            ext.archived_soroban_entries.iter().copied().collect()
        }
        SorobanTransactionDataExt::V0 => Vec::new(),
    };
    let restored_indices_set: std::collections::HashSet<u32> = restored_rw_entry_indices.iter().copied().collect();

    let snapshot = LedgerSnapshotAdapterP25::new(state, context.sequence);

    let mut encoded_ledger_entries = Vec::new();
    let mut encoded_ttl_entries = Vec::new();

    let mut add_entry =
        |key: &LedgerKey, entry: &LedgerEntry, live_until: Option<u32>| -> Result<(), HostErrorP25> {
        encoded_ledger_entries.push(entry.to_xdr(Limits::none())
            .map_err(|_| HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
                soroban_env_host25::xdr::ScErrorType::Context,
                soroban_env_host25::xdr::ScErrorCode::InternalError,
            )))?);

        // For contract entries (ContractData, ContractCode), we always need TTL
        let needs_ttl = matches!(key, LedgerKey::ContractData(_) | LedgerKey::ContractCode(_));
        let ttl_bytes = if let Some(lu) = live_until {
            let key_hash = compute_key_hash(key);
            let ttl_entry = stellar_xdr::curr::TtlEntry {
                key_hash,
                live_until_ledger_seq: lu,
            };
            ttl_entry.to_xdr(Limits::none())
                .map_err(|_| HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
                    soroban_env_host25::xdr::ScErrorType::Context,
                    soroban_env_host25::xdr::ScErrorCode::InternalError,
                )))?
        } else if needs_ttl {
            // For archived entries being restored, provide expired TTL (0)
            // The host will extend this TTL as part of restoration
            let key_hash = compute_key_hash(key);
            let ttl_entry = stellar_xdr::curr::TtlEntry {
                key_hash,
                live_until_ledger_seq: 0, // Expired/archived
            };
            ttl_entry.to_xdr(Limits::none())
                .map_err(|_| HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
                    soroban_env_host25::xdr::ScErrorType::Context,
                    soroban_env_host25::xdr::ScErrorCode::InternalError,
                )))?
        } else {
            Vec::new()
        };
        encoded_ttl_entries.push(ttl_bytes);
        Ok(())
    };

    for key in soroban_data.resources.footprint.read_only.iter() {
        if let Some((entry, live_until)) = snapshot.get(&Rc::new(key.clone()))? {
            add_entry(key, &entry, live_until)?;
        }
    }

    if !restored_indices_set.is_empty() {
        tracing::warn!(
            restored_count = restored_rw_entry_indices.len(),
            restored_indices = ?restored_rw_entry_indices,
            "P25: Transaction has archived entries to restore"
        );
    }

    for (idx, key) in soroban_data.resources.footprint.read_write.iter().enumerate() {
        // For archived entries being restored, use get_archived which doesn't check TTL
        let is_being_restored = restored_indices_set.contains(&(idx as u32));
        let entry_result = if is_being_restored {
            let result = snapshot.get_archived(&Rc::new(key.clone()))?;
            if result.is_none() {
                tracing::warn!(
                    idx = idx,
                    key_type = ?std::mem::discriminant(key),
                    "P25: Archived entry being restored but NOT FOUND in state"
                );
            } else {
                tracing::info!(
                    idx = idx,
                    key_type = ?std::mem::discriminant(key),
                    "P25: Archived entry found for restoration"
                );
            }
            result
        } else {
            snapshot.get(&Rc::new(key.clone()))?
        };

        if let Some((entry, live_until)) = entry_result {
            add_entry(key, &entry, live_until)?;
        }
    }

    tracing::debug!(
        ledger_entries_count = encoded_ledger_entries.len(),
        ttl_entries_count = encoded_ttl_entries.len(),
        restored_count = restored_rw_entry_indices.len(),
        "P25: Prepared entries for e2e_invoke"
    );

    let mut diagnostic_events: Vec<soroban_env_host25::xdr::DiagnosticEvent> = Vec::new();

    let result = match e2e_invoke::invoke_host_function(
        &budget,
        true,
        &encoded_host_fn,
        &encoded_resources,
        &restored_rw_entry_indices,
        &encoded_source,
        encoded_auth_entries.iter(),
        ledger_info,
        encoded_ledger_entries.iter(),
        encoded_ttl_entries.iter(),
        &seed,
        &mut diagnostic_events,
        None,
        None,
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(
                cpu_consumed = budget.get_cpu_insns_consumed().unwrap_or(0),
                mem_consumed = budget.get_mem_bytes_consumed().unwrap_or(0),
                diagnostic_events = diagnostic_events.len(),
                "P25: Soroban e2e_invoke failed"
            );
            return Err(e);
        }
    };

    let (return_value, return_value_size) = match result.encoded_invoke_result {
        Ok(ref bytes) => {
            let val = ScVal::from_xdr(bytes, Limits::none()).unwrap_or(ScVal::Void);
            (val, bytes.len() as u32)
        }
        Err(ref e) => {
            return Err(e.clone());
        }
    };

    let mut contract_events = Vec::new();
    let mut contract_events_size = 0u32;
    for buf in result.encoded_contract_events.iter() {
        contract_events_size = contract_events_size.saturating_add(buf.len() as u32);
        if let Ok(event) = stellar_xdr::curr::ContractEvent::from_xdr(buf, Limits::none()) {
            contract_events.push(event);
        }
    }

    let rent_changes: Vec<LedgerEntryRentChange> = e2e_invoke::extract_rent_changes(&result.ledger_changes);

    let storage_changes = result.ledger_changes
        .into_iter()
        .filter_map(|change| {
            // Include entries that:
            // 1. Have a new value (were created or modified), OR
            // 2. Are NOT read-only and have no new value (were deleted)
            // Skip read-only entries that weren't modified (just reads, not deletions).
            let is_deletion = !change.read_only && change.encoded_new_value.is_none();
            let is_modification = change.encoded_new_value.is_some();

            if is_modification || is_deletion {
                let key = LedgerKey::from_xdr(&change.encoded_key, Limits::none()).ok()?;
                let new_entry = change.encoded_new_value.and_then(|bytes| {
                    LedgerEntry::from_xdr(&bytes, Limits::none()).ok()
                });
                let live_until = change.ttl_change.map(|ttl| ttl.new_live_until_ledger);
                Some(StorageChange {
                    key,
                    new_entry,
                    live_until,
                })
            } else {
                None
            }
        })
        .collect();

    let cpu_insns = budget.get_cpu_insns_consumed().unwrap_or(0);
    let mem_bytes = budget.get_mem_bytes_consumed().unwrap_or(0);
    let contract_events_and_return_value_size = contract_events_size.saturating_add(return_value_size);
    let rent_fee = compute_rent_fee(
        &rent_changes,
        &soroban_config.rent_fee_config,
        context.sequence,
    );
    let diagnostic_events = convert_diagnostic_events_p25(diagnostic_events);

    Ok(SorobanExecutionResult {
        return_value,
        storage_changes,
        contract_events,
        diagnostic_events,
        cpu_insns,
        mem_bytes,
        contract_events_and_return_value_size,
        rent_fee,
    })
}

fn convert_diagnostic_events_p24(
    events: Vec<soroban_env_host24::xdr::DiagnosticEvent>,
) -> Vec<DiagnosticEvent> {
    events
        .into_iter()
        .filter_map(|event| {
            let bytes = soroban_env_host24::xdr::WriteXdr::to_xdr(
                &event,
                soroban_env_host24::xdr::Limits::none(),
            )
            .ok()?;
            DiagnosticEvent::from_xdr(&bytes, Limits::none()).ok()
        })
        .collect()
}

fn rent_fee_config_p25_to_p24(
    config: &soroban_env_host25::fees::RentFeeConfiguration,
) -> soroban_env_host24::fees::RentFeeConfiguration {
    soroban_env_host24::fees::RentFeeConfiguration {
        fee_per_write_1kb: config.fee_per_write_1kb,
        fee_per_rent_1kb: config.fee_per_rent_1kb,
        fee_per_write_entry: config.fee_per_write_entry,
        persistent_rent_rate_denominator: config.persistent_rent_rate_denominator,
        temporary_rent_rate_denominator: config.temporary_rent_rate_denominator,
    }
}

fn convert_diagnostic_events_p25(
    events: Vec<soroban_env_host25::xdr::DiagnosticEvent>,
) -> Vec<DiagnosticEvent> {
    events
        .into_iter()
        .filter_map(|event| {
            let bytes = soroban_env_host25::xdr::WriteXdr::to_xdr(
                &event,
                soroban_env_host25::xdr::Limits::none(),
            )
            .ok()?;
            DiagnosticEvent::from_xdr(&bytes, Limits::none()).ok()
        })
        .collect()
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
