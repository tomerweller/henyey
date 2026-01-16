//! Protocol 25 Soroban host implementation.
//!
//! This module provides Soroban execution for protocol version 25.
//! It uses soroban-env-host-p25 which is pinned to the exact git revision
//! used by C++ stellar-core for protocol 25.

use std::rc::Rc;

use sha2::{Digest, Sha256};

use soroban_env_host_p25::{
    budget::Budget, e2e_invoke, storage::SnapshotSource, xdr::DiagnosticEvent, HostError,
    LedgerInfo,
};

use stellar_xdr::curr::{
    AccountId, ContractEvent, ContractEventType, Hash, HostFunction, LedgerEntry, LedgerEntryData,
    LedgerEntryExt, LedgerKey, Limits, ReadXdr, ScVal, SorobanAuthorizationEntry,
    SorobanTransactionData, SorobanTransactionDataExt, WriteXdr,
};

use super::{
    EncodedContractEvent, InvokeHostFunctionOutput, LedgerEntryChange, LiveBucketListRestore,
    TtlChange,
};
use crate::soroban::SorobanConfig;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;

// Type alias for entry with TTL from the snapshot source
type EntryWithLiveUntil = (Rc<LedgerEntry>, Option<u32>);

/// Adapter that provides snapshot access to our ledger state for Soroban.
struct LedgerSnapshotAdapter<'a> {
    state: &'a LedgerStateManager,
    current_ledger: u32,
}

impl<'a> LedgerSnapshotAdapter<'a> {
    fn new(state: &'a LedgerStateManager, current_ledger: u32) -> Self {
        Self {
            state,
            current_ledger,
        }
    }
}

impl<'a> SnapshotSource for LedgerSnapshotAdapter<'a> {
    fn get(&self, key: &Rc<LedgerKey>) -> Result<Option<EntryWithLiveUntil>, HostError> {
        // For ContractData and ContractCode, check TTL first.
        // If TTL has expired, the entry is considered to be in the hot archive
        // and not accessible (unless being explicitly restored).
        // This mimics C++ stellar-core behavior where archived entries are not
        // in the live bucket list.
        let live_until = get_entry_ttl(self.state, key.as_ref(), self.current_ledger);

        let entry = match key.as_ref() {
            LedgerKey::Account(account_key) => {
                self.state
                    .get_account(&account_key.account_id)
                    .map(|acc| LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::Account(acc.clone()),
                        ext: LedgerEntryExt::V0,
                    })
            }
            LedgerKey::Trustline(tl_key) => self
                .state
                .get_trustline_by_trustline_asset(&tl_key.account_id, &tl_key.asset)
                .map(|tl| LedgerEntry {
                    last_modified_ledger_seq: self.current_ledger,
                    data: LedgerEntryData::Trustline(tl.clone()),
                    ext: LedgerEntryExt::V0,
                }),
            LedgerKey::ContractData(cd_key) => {
                // NOTE: In production, entries with expired TTL would be evicted to
                // hot archive. But in verification mode we don't run eviction, so
                // we pass all entries to Soroban and let it handle TTL checking.
                // The live_until value is still included for Soroban to use.
                self.state
                    .get_contract_data(&cd_key.contract, &cd_key.key, cd_key.durability.clone())
                    .map(|cd| LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::ContractData(cd.clone()),
                        ext: LedgerEntryExt::V0,
                    })
            }
            LedgerKey::ContractCode(cc_key) => {
                // NOTE: Same as ContractData - let Soroban handle TTL checking.
                self.state
                    .get_contract_code(&cc_key.hash)
                    .map(|code| LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::ContractCode(code.clone()),
                        ext: LedgerEntryExt::V0,
                    })
            }
            LedgerKey::Ttl(ttl_key) => {
                self.state
                    .get_ttl(&ttl_key.key_hash)
                    .map(|ttl| LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::Ttl(ttl.clone()),
                        ext: LedgerEntryExt::V0,
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

/// Get the TTL for a ledger entry.
fn get_entry_ttl(state: &LedgerStateManager, key: &LedgerKey, current_ledger: u32) -> Option<u32> {
    match key {
        LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {
            let key_hash = compute_key_hash(key);
            let ttl = state
                .get_ttl(&key_hash)
                .map(|ttl| ttl.live_until_ledger_seq);
            if let Some(live_until) = ttl {
                if live_until < current_ledger {
                    tracing::warn!(
                        current_ledger,
                        live_until,
                        key_type = if matches!(key, LedgerKey::ContractCode(_)) {
                            "ContractCode"
                        } else {
                            "ContractData"
                        },
                        "Soroban entry TTL is EXPIRED"
                    );
                }
            } else {
                tracing::warn!(
                    key_type = if matches!(key, LedgerKey::ContractCode(_)) {
                        "ContractCode"
                    } else {
                        "ContractData"
                    },
                    "Soroban entry has NO TTL record"
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

/// Result of fetching an entry for restoration.
struct RestorationInfo {
    /// The data/code entry being restored.
    entry: LedgerEntry,
    /// The live_until ledger for TTL.
    live_until: Option<u32>,
    /// If this is a live BL restore (entry exists with expired TTL), contains
    /// the full restore info needed for RESTORED ledger entry changes.
    live_bl_restore: Option<LiveBucketListRestore>,
}

/// Get an entry for restoration from the hot archive or live BucketList.
///
/// This is used when an entry is being explicitly restored - we need to fetch
/// the entry even though its TTL has expired.
///
/// If the entry exists in the live BucketList with an expired TTL, this is a
/// "live BL restore" and we return the complete LiveBucketListRestore info
/// needed to emit RESTORED ledger entry changes.
fn get_entry_for_restoration(
    state: &LedgerStateManager,
    key: &LedgerKey,
    current_ledger: u32,
) -> Result<Option<RestorationInfo>, HostError> {
    // Get TTL and check if it's expired (live BL restore)
    let (live_until, ttl_entry_opt) = match key {
        LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {
            let key_hash = compute_key_hash(key);
            if let Some(ttl) = state.get_ttl(&key_hash) {
                let live_until = ttl.live_until_ledger_seq;
                // Build the TTL ledger entry
                let ttl_ledger_entry = LedgerEntry {
                    last_modified_ledger_seq: current_ledger,
                    data: LedgerEntryData::Ttl(ttl.clone()),
                    ext: LedgerEntryExt::V0,
                };
                let ttl_key = LedgerKey::Ttl(stellar_xdr::curr::LedgerKeyTtl { key_hash });
                (Some(live_until), Some((ttl_key, ttl_ledger_entry)))
            } else {
                (None, None)
            }
        }
        _ => (None, None),
    };

    // Fetch entry from state WITHOUT filtering by TTL
    let entry = match key {
        LedgerKey::ContractData(cd_key) => state
            .get_contract_data(&cd_key.contract, &cd_key.key, cd_key.durability.clone())
            .map(|cd| LedgerEntry {
                last_modified_ledger_seq: current_ledger,
                data: LedgerEntryData::ContractData(cd.clone()),
                ext: LedgerEntryExt::V0,
            }),
        LedgerKey::ContractCode(cc_key) => {
            state
                .get_contract_code(&cc_key.hash)
                .map(|code| LedgerEntry {
                    last_modified_ledger_seq: current_ledger,
                    data: LedgerEntryData::ContractCode(code.clone()),
                    ext: LedgerEntryExt::V0,
                })
        }
        _ => {
            // Restoration only applies to ContractData and ContractCode
            return Ok(None);
        }
    };

    match entry {
        Some(e) => {
            // Check if this is a live BL restore: entry exists AND TTL is expired
            let live_bl_restore =
                if let (Some(lu), Some((ttl_key, ttl_entry))) = (live_until, ttl_entry_opt) {
                    if lu < current_ledger {
                        // TTL is expired, this is a live BL restore
                        tracing::debug!(
                            live_until = lu,
                            current_ledger,
                            "Entry is being restored from live BucketList (expired TTL)"
                        );
                        Some(LiveBucketListRestore {
                            key: key.clone(),
                            entry: e.clone(),
                            ttl_key,
                            ttl_entry,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };

            Ok(Some(RestorationInfo {
                entry: e,
                live_until,
                live_bl_restore,
            }))
        }
        None => Ok(None),
    }
}

/// Invoke a host function using the protocol 25 soroban-env-host.
pub fn invoke_host_function(
    host_function: &HostFunction,
    auth_entries: &[SorobanAuthorizationEntry],
    source: &AccountId,
    state: &LedgerStateManager,
    context: &LedgerContext,
    soroban_data: &SorobanTransactionData,
    soroban_config: &SorobanConfig,
) -> Result<InvokeHostFunctionOutput, HostError> {
    // Create budget with network cost parameters
    let instruction_limit = soroban_config.tx_max_instructions * 2; // Double for setup overhead
    let memory_limit = soroban_config.tx_max_memory_bytes * 2;

    let budget = if soroban_config.has_valid_cost_params() {
        Budget::try_from_configs(
            instruction_limit,
            memory_limit,
            soroban_config.cpu_cost_params.clone(),
            soroban_config.mem_cost_params.clone(),
        )?
    } else {
        tracing::warn!("Using default Soroban budget - cost parameters not loaded from network.");
        Budget::default()
    };

    // Build ledger info
    let ledger_info = LedgerInfo {
        protocol_version: context.protocol_version,
        sequence_number: context.sequence,
        timestamp: context.close_time,
        network_id: context.network_id.0 .0,
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

    // Use PRNG seed from context if provided
    let seed: Vec<u8> = if let Some(prng_seed) = context.soroban_prng_seed {
        prng_seed.to_vec()
    } else {
        tracing::warn!("P25: Using fallback PRNG seed - results may differ from C++ stellar-core");
        let mut hasher = Sha256::new();
        hasher.update(&context.network_id.0 .0);
        hasher.update(&context.sequence.to_le_bytes());
        hasher.update(&context.close_time.to_le_bytes());
        hasher.finalize().to_vec()
    };

    // Encode all data to XDR bytes for e2e_invoke
    let encoded_host_fn = host_function.to_xdr(Limits::none()).map_err(|_| {
        HostError::from(soroban_env_host_p25::Error::from_type_and_code(
            soroban_env_host_p25::xdr::ScErrorType::Context,
            soroban_env_host_p25::xdr::ScErrorCode::InternalError,
        ))
    })?;

    let encoded_resources = soroban_data.resources.to_xdr(Limits::none()).map_err(|_| {
        HostError::from(soroban_env_host_p25::Error::from_type_and_code(
            soroban_env_host_p25::xdr::ScErrorType::Context,
            soroban_env_host_p25::xdr::ScErrorCode::InternalError,
        ))
    })?;

    let encoded_source = source.to_xdr(Limits::none()).map_err(|_| {
        HostError::from(soroban_env_host_p25::Error::from_type_and_code(
            soroban_env_host_p25::xdr::ScErrorType::Context,
            soroban_env_host_p25::xdr::ScErrorCode::InternalError,
        ))
    })?;

    // Encode auth entries
    let encoded_auth_entries: Vec<Vec<u8>> = auth_entries
        .iter()
        .map(|e| e.to_xdr(Limits::none()))
        .collect::<Result<_, _>>()
        .map_err(|_| {
            HostError::from(soroban_env_host_p25::Error::from_type_and_code(
                soroban_env_host_p25::xdr::ScErrorType::Context,
                soroban_env_host_p25::xdr::ScErrorCode::InternalError,
            ))
        })?;

    // Create snapshot adapter
    let snapshot = LedgerSnapshotAdapter::new(state, context.sequence);

    // Extract archived entry indices for TTL restoration BEFORE collecting entries
    // These indices point into the read_write footprint and indicate entries being restored
    let restored_rw_entry_indices: Vec<u32> = match &soroban_data.ext {
        SorobanTransactionDataExt::V1(ext) => {
            let indices: Vec<u32> = ext.archived_soroban_entries.iter().copied().collect();
            if !indices.is_empty() {
                tracing::info!(
                    indices = ?indices,
                    rw_footprint_len = soroban_data.resources.footprint.read_write.len(),
                    "P25: Found archived entry indices for restoration"
                );
            }
            indices
        }
        SorobanTransactionDataExt::V0 => Vec::new(),
    };
    let restored_indices_set: std::collections::HashSet<u32> =
        restored_rw_entry_indices.iter().copied().collect();

    // Collect and encode ledger entries from the footprint
    let mut encoded_ledger_entries = Vec::new();
    let mut encoded_ttl_entries = Vec::new();

    let mut add_entry =
        |key: &LedgerKey, entry: &LedgerEntry, live_until: Option<u32>| -> Result<(), HostError> {
            encoded_ledger_entries.push(entry.to_xdr(Limits::none()).map_err(|_| {
                HostError::from(soroban_env_host_p25::Error::from_type_and_code(
                    soroban_env_host_p25::xdr::ScErrorType::Context,
                    soroban_env_host_p25::xdr::ScErrorCode::InternalError,
                ))
            })?);

            let ttl_bytes = if let Some(lu) = live_until {
                let key_hash = compute_key_hash(key);
                let ttl_entry = stellar_xdr::curr::TtlEntry {
                    key_hash,
                    live_until_ledger_seq: lu,
                };
                ttl_entry.to_xdr(Limits::none()).map_err(|_| {
                    HostError::from(soroban_env_host_p25::Error::from_type_and_code(
                        soroban_env_host_p25::xdr::ScErrorType::Context,
                        soroban_env_host_p25::xdr::ScErrorCode::InternalError,
                    ))
                })?
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

    // Track entries restored from live BucketList (expired TTL but not yet evicted)
    let mut live_bl_restores: Vec<LiveBucketListRestore> = Vec::new();

    // For read_write entries, check if they're being restored from archive
    for (idx, key) in soroban_data
        .resources
        .footprint
        .read_write
        .iter()
        .enumerate()
    {
        let is_being_restored = restored_indices_set.contains(&(idx as u32));

        if is_being_restored {
            // Entry is being restored - fetch without TTL filtering
            if let Some(restore_info) = get_entry_for_restoration(state, key, context.sequence)? {
                tracing::debug!(
                    idx,
                    live_until = restore_info.live_until,
                    current_ledger = context.sequence,
                    is_live_bl_restore = restore_info.live_bl_restore.is_some(),
                    "Fetching archived entry for restoration"
                );
                add_entry(key, &restore_info.entry, restore_info.live_until)?;

                // Track live BL restorations
                if let Some(live_bl_restore) = restore_info.live_bl_restore {
                    live_bl_restores.push(live_bl_restore);
                }
            }
        } else {
            // Normal entry - use standard TTL-filtered lookup
            if let Some((entry, live_until)) = snapshot.get(&Rc::new(key.clone()))? {
                add_entry(key, &entry, live_until)?;
            }
        }
    }

    tracing::debug!(
        ledger_entries_count = encoded_ledger_entries.len(),
        ttl_entries_count = encoded_ttl_entries.len(),
        restored_count = restored_rw_entry_indices.len(),
        live_bl_restore_count = live_bl_restores.len(),
        "P25: Prepared entries for e2e_invoke"
    );

    // Call e2e_invoke
    let mut diagnostic_events: Vec<DiagnosticEvent> = Vec::new();

    let result = e2e_invoke::invoke_host_function(
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
        None, // module_cache
    )?;

    // Parse the return value
    let return_value = match result.encoded_invoke_result {
        Ok(ref bytes) => ScVal::from_xdr(bytes, Limits::none()).unwrap_or(ScVal::Void),
        Err(ref e) => {
            return Err(e.clone());
        }
    };

    // Convert ledger changes
    // Include entries that:
    // - Had their content modified (encoded_new_value.is_some())
    // - Are involved in rent calculations (old_entry_size_bytes_for_rent > 0)
    // - Had their TTL extended (ttl_change.is_some())
    let ledger_changes = result
        .ledger_changes
        .into_iter()
        .filter_map(|change| {
            if change.encoded_new_value.is_some()
                || change.old_entry_size_bytes_for_rent > 0
                || change.ttl_change.is_some()
            {
                let key = LedgerKey::from_xdr(&change.encoded_key, Limits::none()).ok()?;
                let new_entry = change
                    .encoded_new_value
                    .and_then(|bytes| LedgerEntry::from_xdr(&bytes, Limits::none()).ok());
                let ttl_change = change.ttl_change.map(|ttl| TtlChange {
                    new_live_until_ledger: ttl.new_live_until_ledger,
                });
                Some(LedgerEntryChange {
                    key,
                    new_entry,
                    ttl_change,
                    old_entry_size_bytes: change.old_entry_size_bytes_for_rent,
                })
            } else {
                None
            }
        })
        .collect();

    // Decode and filter contract events
    // Only Contract and System events go into the success preimage hash
    let mut contract_events = Vec::new();
    let mut encoded_contract_events = Vec::new();

    for encoded_event in result.encoded_contract_events {
        // Store the encoded version for diagnostics
        encoded_contract_events.push(EncodedContractEvent {
            encoded_event: encoded_event.clone(),
            in_successful_call: true,
        });

        // Decode and filter for hash computation
        if let Ok(event) = ContractEvent::from_xdr(&encoded_event, Limits::none()) {
            // Only include Contract and System events (not Diagnostic)
            if matches!(
                event.type_,
                ContractEventType::Contract | ContractEventType::System
            ) {
                contract_events.push(event);
            }
        }
    }

    let cpu_insns = budget.get_cpu_insns_consumed().unwrap_or(0);
    let mem_bytes = budget.get_mem_bytes_consumed().unwrap_or(0);

    Ok(InvokeHostFunctionOutput {
        return_value,
        ledger_changes,
        contract_events,
        encoded_contract_events,
        cpu_insns,
        mem_bytes,
        live_bucket_list_restores: live_bl_restores,
    })
}
