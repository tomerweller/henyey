//! Protocol 24 Soroban host implementation.
//!
//! This module provides Soroban execution for protocol versions 20-24.
//! It uses soroban-env-host-p24 which is pinned to the exact git revision
//! used by stellar-core for protocol 24.

use std::rc::Rc;

use sha2::{Digest, Sha256};

use soroban_env_host_p24::xdr::{ReadXdr as ReadXdrP24, WriteXdr as WriteXdrP24};
use soroban_env_host_p24::{
    budget::Budget, e2e_invoke, storage::SnapshotSource,
    xdr::DiagnosticEvent as DiagnosticEventP24, HostError as HostErrorP24,
    LedgerInfo as LedgerInfoP24,
};
use soroban_env_host_p25::HostError as HostErrorP25;

use stellar_xdr::curr::{
    AccountId, ContractEvent, ContractEventType, Hash, HostFunction, LedgerEntry, LedgerEntryData,
    LedgerEntryExt, LedgerKey, Limits, ReadXdr, ScVal, SorobanAuthorizationEntry,
    SorobanTransactionData, SorobanTransactionDataExt, WriteXdr,
};

use super::{EncodedContractEvent, InvokeHostFunctionOutput, LedgerEntryChange, TtlChange};
use crate::soroban::error::convert_host_error_p24_to_p25;
use crate::soroban::SorobanConfig;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;

// Type alias for entry with TTL from the snapshot source
type EntryWithLiveUntil = (Rc<soroban_env_host_p24::xdr::LedgerEntry>, Option<u32>);

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
    fn get(
        &self,
        key: &Rc<soroban_env_host_p24::xdr::LedgerKey>,
    ) -> Result<Option<EntryWithLiveUntil>, HostErrorP24> {
        let current_key = convert_ledger_key_from_p24(key.as_ref()).ok_or_else(|| {
            HostErrorP24::from(soroban_env_host_p24::Error::from_type_and_code(
                soroban_env_host_p24::xdr::ScErrorType::Context,
                soroban_env_host_p24::xdr::ScErrorCode::InternalError,
            ))
        })?;

        // For ContractData and ContractCode, check TTL first.
        // If TTL has expired, the entry is considered to be in the hot archive
        // and not accessible (unless being explicitly restored).
        // This mimics stellar-core behavior where archived entries are not
        // in the live bucket list.
        let live_until = get_entry_ttl(self.state, &current_key, self.current_ledger);

        let entry = match &current_key {
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
                // Check if entry has expired TTL - if so, it's archived and not accessible
                if let Some(ttl) = live_until {
                    if ttl < self.current_ledger {
                        // Entry is archived, not in live bucket list
                        return Ok(None);
                    }
                }
                self.state
                    .get_contract_data(&cd_key.contract, &cd_key.key, cd_key.durability)
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
                        // Entry is archived, not in live bucket list
                        return Ok(None);
                    }
                }
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
            Some(e) => {
                let entry = convert_ledger_entry_to_p24(&e).ok_or_else(|| {
                    HostErrorP24::from(soroban_env_host_p24::Error::from_type_and_code(
                        soroban_env_host_p24::xdr::ScErrorType::Context,
                        soroban_env_host_p24::xdr::ScErrorCode::InternalError,
                    ))
                })?;
                Ok(Some((Rc::new(entry), live_until)))
            }
            None => Ok(None),
        }
    }
}

/// Get the TTL for a ledger entry.
///
/// Uses `get_ttl_at_ledger_start()` to return the TTL value from the bucket
/// list snapshot at ledger start. This matches stellar-core behavior for
/// parallel Soroban execution (V1 phases): transactions in different clusters
/// should NOT see each other's TTL changes.
fn get_entry_ttl(state: &LedgerStateManager, key: &LedgerKey, current_ledger: u32) -> Option<u32> {
    match key {
        LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {
            let key_hash = compute_key_hash(key);
            let ttl = state.get_ttl_at_ledger_start(&key_hash);
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

/// Get an entry for restoration from the hot archive or live BucketList.
///
/// This is used when an entry is being explicitly restored - we need to fetch
/// the entry even though its TTL has expired or doesn't exist.
fn get_entry_for_restoration(
    state: &LedgerStateManager,
    key: &LedgerKey,
    current_ledger: u32,
) -> Result<(Option<LedgerEntry>, Option<u32>), HostErrorP25> {
    // Get TTL if it exists
    let live_until = match key {
        LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {
            let key_hash = compute_key_hash(key);
            state
                .get_ttl(&key_hash)
                .map(|ttl| ttl.live_until_ledger_seq)
        }
        _ => None,
    };

    // Fetch entry from state WITHOUT filtering by TTL
    let entry = match key {
        LedgerKey::ContractData(cd_key) => state
            .get_contract_data(&cd_key.contract, &cd_key.key, cd_key.durability)
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
            return Ok((None, None));
        }
    };

    Ok((entry, live_until))
}

fn convert_ledger_key_to_p24(key: &LedgerKey) -> Option<soroban_env_host_p24::xdr::LedgerKey> {
    let bytes = key.to_xdr(Limits::none()).ok()?;
    soroban_env_host_p24::xdr::LedgerKey::from_xdr(
        &bytes,
        soroban_env_host_p24::xdr::Limits::none(),
    )
    .ok()
}

fn convert_ledger_key_from_p24(key: &soroban_env_host_p24::xdr::LedgerKey) -> Option<LedgerKey> {
    let bytes =
        soroban_env_host_p24::xdr::WriteXdr::to_xdr(key, soroban_env_host_p24::xdr::Limits::none())
            .ok()?;
    LedgerKey::from_xdr(&bytes, Limits::none()).ok()
}

fn convert_ledger_entry_to_p24(
    entry: &LedgerEntry,
) -> Option<soroban_env_host_p24::xdr::LedgerEntry> {
    let bytes = entry.to_xdr(Limits::none()).ok()?;
    soroban_env_host_p24::xdr::LedgerEntry::from_xdr(
        &bytes,
        soroban_env_host_p24::xdr::Limits::none(),
    )
    .ok()
}

fn convert_contract_cost_params_to_p24(
    params: &stellar_xdr::curr::ContractCostParams,
) -> Option<soroban_env_host_p24::xdr::ContractCostParams> {
    let bytes = params.to_xdr(Limits::none()).ok()?;
    soroban_env_host_p24::xdr::ContractCostParams::from_xdr(
        &bytes,
        soroban_env_host_p24::xdr::Limits::none(),
    )
    .ok()
}

/// Invoke a host function using the protocol 24 soroban-env-host.
pub fn invoke_host_function(
    host_function: &HostFunction,
    auth_entries: &[SorobanAuthorizationEntry],
    source: &AccountId,
    state: &LedgerStateManager,
    context: &LedgerContext,
    soroban_data: &SorobanTransactionData,
    soroban_config: &SorobanConfig,
) -> Result<InvokeHostFunctionOutput, HostErrorP25> {
    // Create budget with network cost parameters
    let instruction_limit = soroban_config.tx_max_instructions * 2; // Double for setup overhead
    let memory_limit = soroban_config.tx_max_memory_bytes * 2;

    let budget = if soroban_config.has_valid_cost_params() {
        let cpu_cost_params = convert_contract_cost_params_to_p24(&soroban_config.cpu_cost_params)
            .ok_or_else(|| {
                HostErrorP25::from(soroban_env_host_p25::Error::from_type_and_code(
                    soroban_env_host_p25::xdr::ScErrorType::Context,
                    soroban_env_host_p25::xdr::ScErrorCode::InternalError,
                ))
            })?;
        let mem_cost_params = convert_contract_cost_params_to_p24(&soroban_config.mem_cost_params)
            .ok_or_else(|| {
                HostErrorP25::from(soroban_env_host_p25::Error::from_type_and_code(
                    soroban_env_host_p25::xdr::ScErrorType::Context,
                    soroban_env_host_p25::xdr::ScErrorCode::InternalError,
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
        tracing::warn!("Using default Soroban budget - cost parameters not loaded from network.");
        Budget::default()
    };

    // Build ledger info
    let ledger_info = LedgerInfoP24 {
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
        "P24: Soroban host ledger info configured"
    );

    // Use PRNG seed from context if provided
    let seed: Vec<u8> = if let Some(prng_seed) = context.soroban_prng_seed {
        prng_seed.to_vec()
    } else {
        tracing::warn!("P24: Using fallback PRNG seed - results may differ from stellar-core");
        let mut hasher = Sha256::new();
        hasher.update(context.network_id.0 .0);
        hasher.update(context.sequence.to_le_bytes());
        hasher.update(context.close_time.to_le_bytes());
        hasher.finalize().to_vec()
    };

    // Encode all data to XDR bytes for e2e_invoke
    let encoded_host_fn = host_function.to_xdr(Limits::none()).map_err(|_| {
        HostErrorP25::from(soroban_env_host_p25::Error::from_type_and_code(
            soroban_env_host_p25::xdr::ScErrorType::Context,
            soroban_env_host_p25::xdr::ScErrorCode::InternalError,
        ))
    })?;

    let encoded_resources = soroban_data.resources.to_xdr(Limits::none()).map_err(|_| {
        HostErrorP25::from(soroban_env_host_p25::Error::from_type_and_code(
            soroban_env_host_p25::xdr::ScErrorType::Context,
            soroban_env_host_p25::xdr::ScErrorCode::InternalError,
        ))
    })?;

    let encoded_source = source.to_xdr(Limits::none()).map_err(|_| {
        HostErrorP25::from(soroban_env_host_p25::Error::from_type_and_code(
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
            HostErrorP25::from(soroban_env_host_p25::Error::from_type_and_code(
                soroban_env_host_p25::xdr::ScErrorType::Context,
                soroban_env_host_p25::xdr::ScErrorCode::InternalError,
            ))
        })?;

    // Create snapshot adapter
    let snapshot = LedgerSnapshotAdapter::new(state, context.sequence);

    // Collect and encode ledger entries from the footprint
    let mut encoded_ledger_entries = Vec::new();
    let mut encoded_ttl_entries = Vec::new();
    let current_ledger = context.sequence; // Capture for use in closure

    // Helper to encode an entry and its TTL, returning the encoded bytes.
    let encode_entry = |key: &LedgerKey,
                        entry: &soroban_env_host_p24::xdr::LedgerEntry,
                        live_until: Option<u32>|
     -> Result<(Vec<u8>, Vec<u8>), HostErrorP25> {
        let entry_bytes = entry
            .to_xdr(soroban_env_host_p24::xdr::Limits::none())
            .map_err(|_| {
                HostErrorP25::from(soroban_env_host_p25::Error::from_type_and_code(
                    soroban_env_host_p25::xdr::ScErrorType::Context,
                    soroban_env_host_p25::xdr::ScErrorCode::InternalError,
                ))
            })?;

        let needs_ttl = matches!(key, LedgerKey::ContractData(_) | LedgerKey::ContractCode(_));
        let ttl_bytes = if let Some(lu) = live_until {
            let key_hash = compute_key_hash(key);
            let ttl_entry = soroban_env_host_p24::xdr::TtlEntry {
                key_hash: soroban_env_host_p24::xdr::Hash(key_hash.0),
                live_until_ledger_seq: lu,
            };
            ttl_entry
                .to_xdr(soroban_env_host_p24::xdr::Limits::none())
                .map_err(|_| {
                    HostErrorP25::from(soroban_env_host_p25::Error::from_type_and_code(
                        soroban_env_host_p25::xdr::ScErrorType::Context,
                        soroban_env_host_p25::xdr::ScErrorCode::InternalError,
                    ))
                })?
        } else if needs_ttl {
            let key_hash = compute_key_hash(key);
            let ttl_entry = soroban_env_host_p24::xdr::TtlEntry {
                key_hash: soroban_env_host_p24::xdr::Hash(key_hash.0),
                live_until_ledger_seq: current_ledger,
            };
            ttl_entry
                .to_xdr(soroban_env_host_p24::xdr::Limits::none())
                .map_err(|_| {
                    HostErrorP25::from(soroban_env_host_p25::Error::from_type_and_code(
                        soroban_env_host_p25::xdr::ScErrorType::Context,
                        soroban_env_host_p25::xdr::ScErrorCode::InternalError,
                    ))
                })?
        } else {
            Vec::new()
        };
        Ok((entry_bytes, ttl_bytes))
    };

    // Extract archived entry indices for TTL restoration BEFORE collecting entries
    // These indices point into the read_write footprint and indicate entries being restored
    let restored_rw_entry_indices: Vec<u32> = match &soroban_data.ext {
        SorobanTransactionDataExt::V1(ext) => {
            let indices: Vec<u32> = ext.archived_soroban_entries.iter().copied().collect();
            if !indices.is_empty() {
                tracing::warn!(
                    indices = ?indices,
                    rw_footprint_len = soroban_data.resources.footprint.read_write.len(),
                    "P24: Transaction has archived entries to restore"
                );
            }
            indices
        }
        SorobanTransactionDataExt::V0 => Vec::new(),
    };
    let restored_indices_set: std::collections::HashSet<u32> =
        restored_rw_entry_indices.iter().copied().collect();

    // Collect read_only entries
    for key in soroban_data.resources.footprint.read_only.iter() {
        let key_p24 = convert_ledger_key_to_p24(key).ok_or_else(|| {
            HostErrorP25::from(soroban_env_host_p25::Error::from_type_and_code(
                soroban_env_host_p25::xdr::ScErrorType::Context,
                soroban_env_host_p25::xdr::ScErrorCode::InternalError,
            ))
        })?;
        if let Some((entry, live_until)) = snapshot
            .get(&Rc::new(key_p24))
            .map_err(convert_host_error_p24_to_p25)?
        {
            let (le, ttl) = encode_entry(key, &entry, live_until)?;
            encoded_ledger_entries.push(le);
            encoded_ttl_entries.push(ttl);
        }
        // If entry not found, skip it — e2e_invoke's footprint loop will
        // add it to the storage map as None (entry doesn't exist yet).
    }

    // Collect read_write entries, handling archived entries specially
    for (idx, key) in soroban_data
        .resources
        .footprint
        .read_write
        .iter()
        .enumerate()
    {
        let is_being_restored = restored_indices_set.contains(&(idx as u32));

        if is_being_restored {
            // Entry is being restored from archive - fetch WITHOUT TTL filtering
            let (entry, live_until) = get_entry_for_restoration(state, key, context.sequence)?;
            if let Some(e) = entry {
                let entry_p24 = convert_ledger_entry_to_p24(&e).ok_or_else(|| {
                    HostErrorP25::from(soroban_env_host_p25::Error::from_type_and_code(
                        soroban_env_host_p25::xdr::ScErrorType::Context,
                        soroban_env_host_p25::xdr::ScErrorCode::InternalError,
                    ))
                })?;
                tracing::info!(
                    idx,
                    key_type = ?std::mem::discriminant(key),
                    live_until,
                    current_ledger = context.sequence,
                    is_live_bl_restore = live_until.map(|lu| lu < context.sequence).unwrap_or(false),
                    "P24: Archived entry found for restoration"
                );
                let (le, ttl) = encode_entry(key, &entry_p24, live_until)?;
                encoded_ledger_entries.push(le);
                encoded_ttl_entries.push(ttl);
            }
            // If restored entry not found, skip it — e2e_invoke's footprint
            // loop will add it to the storage map as None.
        } else {
            // Normal entry - use standard TTL-filtered lookup
            let key_p24 = convert_ledger_key_to_p24(key).ok_or_else(|| {
                HostErrorP25::from(soroban_env_host_p25::Error::from_type_and_code(
                    soroban_env_host_p25::xdr::ScErrorType::Context,
                    soroban_env_host_p25::xdr::ScErrorCode::InternalError,
                ))
            })?;
            if let Some((entry, live_until)) = snapshot
                .get(&Rc::new(key_p24))
                .map_err(convert_host_error_p24_to_p25)?
            {
                let (le, ttl) = encode_entry(key, &entry, live_until)?;
                encoded_ledger_entries.push(le);
                encoded_ttl_entries.push(ttl);
            }
            // If entry not found, skip it — e2e_invoke's footprint loop will
            // add it to the storage map as None (entry doesn't exist yet).
        }
    }

    tracing::debug!(
        ledger_entries_count = encoded_ledger_entries.len(),
        ttl_entries_count = encoded_ttl_entries.len(),
        restored_count = restored_rw_entry_indices.len(),
        "P24: Prepared entries for e2e_invoke"
    );

    // Call e2e_invoke
    let mut diagnostic_events: Vec<DiagnosticEventP24> = Vec::new();

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
        None, // module_cache
    ) {
        Ok(result) => result,
        Err(err) => return Err(convert_host_error_p24_to_p25(err)),
    };

    // Parse the return value
    let return_value = match result.encoded_invoke_result {
        Ok(ref bytes) => ScVal::from_xdr(bytes, Limits::none()).unwrap_or(ScVal::Void),
        Err(ref e) => {
            return Err(convert_host_error_p24_to_p25(e.clone()));
        }
    };

    // Convert ledger changes
    // Include entries that:
    // - Had their content modified (encoded_new_value.is_some())
    // - Are involved in rent calculations (old_entry_size_bytes_for_rent > 0)
    // - Had their TTL actually extended (new > old)
    // Note: stellar-core only includes TTL changes when TTL is extended, not just
    // when ttl_change is present. See extract_ledger_effects in soroban_proto_any.rs.
    let ledger_changes = result
        .ledger_changes
        .into_iter()
        .filter_map(|change| {
            // Check if TTL was actually extended
            let ttl_extended = change
                .ttl_change
                .as_ref()
                .map(|ttl| ttl.new_live_until_ledger > ttl.old_live_until_ledger)
                .unwrap_or(false);

            if change.encoded_new_value.is_some()
                || change.old_entry_size_bytes_for_rent > 0
                || ttl_extended
            {
                let key = LedgerKey::from_xdr(&change.encoded_key, Limits::none()).ok()?;
                let new_entry = change
                    .encoded_new_value
                    .and_then(|bytes| LedgerEntry::from_xdr(&bytes, Limits::none()).ok());
                let ttl_change = change.ttl_change.map(|ttl| TtlChange {
                    old_live_until_ledger: ttl.old_live_until_ledger,
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
        // P24 doesn't have auto-restore, so no live BL restorations
        live_bucket_list_restores: Vec::new(),
    })
}
