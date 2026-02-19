//! Protocol 25 Soroban host implementation.
//!
//! This module provides Soroban execution for protocol version 25.
//! It uses soroban-env-host-p25 which is pinned to the exact git revision
//! used by stellar-core for protocol 25.
//!
//! Note: soroban-env-host v25.0.0 uses stellar-xdr 25.0.0 from crates.io,
//! while our workspace uses a git revision of stellar-xdr. We convert between
//! the two via XDR serialization when crossing the boundary.

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
use crate::soroban::host::EntryWithTtl;
use crate::soroban::SorobanConfig;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;

// Type aliases for soroban-env-host P25's XDR types (from stellar-xdr 25.0.0)
type P25LedgerKey = soroban_env_host_p25::xdr::LedgerKey;
type P25LedgerEntry = soroban_env_host_p25::xdr::LedgerEntry;

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

    /// Get an entry using our workspace XDR types (for internal use).
    /// This is separate from the `SnapshotSource::get()` trait impl which uses
    /// soroban-env-host's XDR types.
    ///
    /// IMPORTANT: This function filters out expired Soroban entries (ContractData, ContractCode)
    /// to match stellar-core behavior. In stellar-core, entries with expired TTL are not passed to
    /// the host during invoke_host_function - expired temporary entries are skipped entirely,
    /// and expired persistent entries are treated as archived (requiring restoration).
    fn get_local(
        &self,
        key: &LedgerKey,
    ) -> Result<Option<EntryWithTtl>, HostError> {
        let live_until = get_entry_ttl(self.state, key, self.current_ledger);

        let entry = match key {
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
                // Check TTL: In stellar-core, ContractData entries are only passed to
                // the host if they have a valid (non-expired) TTL entry. Entries without
                // a TTL entry or with expired TTL are not passed to the host.
                // - If TTL exists and is live (live_until >= current_ledger): pass to host
                // - If TTL exists and is expired (live_until < current_ledger): skip
                // - If TTL doesn't exist: skip (entry is not properly initialized or was deleted)
                match live_until {
                    Some(lu) if lu >= self.current_ledger => {
                        // TTL exists and is live - return the entry
                        self.state
                            .get_contract_data(&cd_key.contract, &cd_key.key, cd_key.durability)
                            .map(|cd| LedgerEntry {
                                last_modified_ledger_seq: self.current_ledger,
                                data: LedgerEntryData::ContractData(cd.clone()),
                                ext: LedgerEntryExt::V0,
                            })
                    }
                    Some(lu) => {
                        // TTL exists but is expired
                        tracing::debug!(
                            current_ledger = self.current_ledger,
                            live_until = lu,
                            "get_local: ContractData entry has expired TTL, not passing to host"
                        );
                        None
                    }
                    None => {
                        // No TTL entry found - in stellar-core this means the entry is not live
                        tracing::debug!(
                            current_ledger = self.current_ledger,
                            "get_local: ContractData entry has no TTL, not passing to host"
                        );
                        None
                    }
                }
            }
            LedgerKey::ContractCode(cc_key) => {
                // Same as ContractData - require valid TTL to pass to host
                match live_until {
                    Some(lu) if lu >= self.current_ledger => {
                        // TTL exists and is live - return the entry
                        self.state
                            .get_contract_code(&cc_key.hash)
                            .map(|code| LedgerEntry {
                                last_modified_ledger_seq: self.current_ledger,
                                data: LedgerEntryData::ContractCode(code.clone()),
                                ext: LedgerEntryExt::V0,
                            })
                    }
                    Some(lu) => {
                        // TTL exists but is expired
                        tracing::debug!(
                            current_ledger = self.current_ledger,
                            live_until = lu,
                            "get_local: ContractCode entry has expired TTL, not passing to host"
                        );
                        None
                    }
                    None => {
                        // No TTL entry found
                        tracing::debug!(
                            current_ledger = self.current_ledger,
                            "get_local: ContractCode entry has no TTL, not passing to host"
                        );
                        None
                    }
                }
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

impl<'a> SnapshotSource for LedgerSnapshotAdapter<'a> {
    fn get(
        &self,
        key: &Rc<P25LedgerKey>,
    ) -> Result<Option<soroban_env_host_p25::storage::EntryWithLiveUntil>, HostError> {
        // Convert P25 key to our workspace XDR type
        let Some(local_key) = convert_ledger_key_from_p25(key.as_ref()) else {
            return Ok(None);
        };

        // For ContractData and ContractCode, check TTL first.
        // If TTL has expired, the entry is considered to be in the hot archive
        // and not accessible (unless being explicitly restored).
        // This mimics stellar-core behavior where archived entries are not
        // in the live bucket list.
        let live_until = get_entry_ttl(self.state, &local_key, self.current_ledger);

        let entry = match &local_key {
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
                // Check TTL: In stellar-core, ContractData entries are only accessible
                // if they have a valid (non-expired) TTL entry. Entries without a TTL entry
                // or with expired TTL are treated as archived and not accessible.
                match live_until {
                    Some(lu) if lu >= self.current_ledger => {
                        // TTL exists and is live - return the entry
                        self.state
                            .get_contract_data(&cd_key.contract, &cd_key.key, cd_key.durability)
                            .map(|cd| LedgerEntry {
                                last_modified_ledger_seq: self.current_ledger,
                                data: LedgerEntryData::ContractData(cd.clone()),
                                ext: LedgerEntryExt::V0,
                            })
                    }
                    Some(lu) => {
                        // TTL exists but is expired
                        tracing::debug!(
                            current_ledger = self.current_ledger,
                            live_until = lu,
                            "ContractData entry has expired TTL, treating as archived"
                        );
                        return Ok(None);
                    }
                    None => {
                        // No TTL entry found - entry is not properly initialized
                        tracing::debug!(
                            current_ledger = self.current_ledger,
                            "ContractData entry has no TTL, treating as not live"
                        );
                        return Ok(None);
                    }
                }
            }
            LedgerKey::ContractCode(cc_key) => {
                // Same as ContractData - require valid TTL
                match live_until {
                    Some(lu) if lu >= self.current_ledger => {
                        // TTL exists and is live - return the entry
                        self.state
                            .get_contract_code(&cc_key.hash)
                            .map(|code| LedgerEntry {
                                last_modified_ledger_seq: self.current_ledger,
                                data: LedgerEntryData::ContractCode(code.clone()),
                                ext: LedgerEntryExt::V0,
                            })
                    }
                    Some(lu) => {
                        // TTL exists but is expired
                        tracing::debug!(
                            current_ledger = self.current_ledger,
                            live_until = lu,
                            "ContractCode entry has expired TTL, treating as archived"
                        );
                        return Ok(None);
                    }
                    None => {
                        // No TTL entry found
                        tracing::debug!(
                            current_ledger = self.current_ledger,
                            "ContractCode entry has no TTL, treating as not live"
                        );
                        return Ok(None);
                    }
                }
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

        // Convert the entry to P25 XDR type
        match entry {
            Some(e) => {
                let p25_entry = convert_ledger_entry_to_p25(&e).ok_or_else(|| {
                    HostError::from(soroban_env_host_p25::Error::from_type_and_code(
                        soroban_env_host_p25::xdr::ScErrorType::Context,
                        soroban_env_host_p25::xdr::ScErrorCode::InternalError,
                    ))
                })?;
                Ok(Some((Rc::new(p25_entry), live_until)))
            }
            None => Ok(None),
        }
    }
}

/// Get the TTL for a ledger entry.
///
/// IMPORTANT: This function uses `get_ttl_at_ledger_start()` to return the TTL
/// value from the bucket list snapshot at ledger start. This is critical for
/// matching stellar-core behavior in parallel Soroban execution (V1 phases):
///
/// - Transactions in different clusters of the same stage should NOT see each
///   other's changes (including newly created TTL entries)
/// - Only entries that existed at ledger start should be passed to the host
/// - Entries created by earlier transactions in the same ledger are filtered out
///
/// This ensures that if TX 4 creates a new entry with TTL, TX 5 (in a different
/// cluster of the same stage) will NOT see that entry when loading its footprint.
fn get_entry_ttl(state: &LedgerStateManager, key: &LedgerKey, current_ledger: u32) -> Option<u32> {
    match key {
        LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {
            let key_hash = compute_key_hash(key);
            // Use get_ttl_at_ledger_start() to match stellar-core behavior for parallel Soroban.
            // This returns the TTL from the bucket list snapshot at ledger start,
            // NOT the current TTL (which might include entries created by earlier TXs).
            let ttl = state.get_ttl_at_ledger_start(&key_hash);
            if let Some(live_until) = ttl {
                if live_until < current_ledger {
                    tracing::debug!(
                        current_ledger,
                        live_until,
                        key_type = if matches!(key, LedgerKey::ContractCode(_)) {
                            "ContractCode"
                        } else {
                            "ContractData"
                        },
                        "Soroban entry TTL is EXPIRED (from bucket list snapshot)"
                    );
                }
            } else {
                // Check if the entry has a current TTL (created within this ledger)
                let has_current_ttl = state.get_ttl(&key_hash).is_some();
                if has_current_ttl {
                    tracing::debug!(
                        key_type = if matches!(key, LedgerKey::ContractCode(_)) {
                            "ContractCode"
                        } else {
                            "ContractData"
                        },
                        "Soroban entry has TTL but not in bucket list snapshot (created within ledger)"
                    );
                } else {
                    tracing::debug!(
                        key_type = if matches!(key, LedgerKey::ContractCode(_)) {
                            "ContractCode"
                        } else {
                            "ContractData"
                        },
                        "Soroban entry has NO TTL record"
                    );
                }
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

// P25 XDR conversion functions (soroban-env-host v25.0.0 uses stellar-xdr 25.0.0)
fn convert_ledger_key_from_p25(key: &P25LedgerKey) -> Option<LedgerKey> {
    let bytes =
        soroban_env_host_p25::xdr::WriteXdr::to_xdr(key, soroban_env_host_p25::xdr::Limits::none())
            .ok()?;
    LedgerKey::from_xdr(&bytes, Limits::none()).ok()
}

fn convert_ledger_entry_to_p25(entry: &LedgerEntry) -> Option<P25LedgerEntry> {
    use soroban_env_host_p25::xdr::ReadXdr as _;
    let bytes = entry.to_xdr(Limits::none()).ok()?;
    soroban_env_host_p25::xdr::LedgerEntry::from_xdr(
        &bytes,
        soroban_env_host_p25::xdr::Limits::none(),
    )
    .ok()
}

fn convert_contract_cost_params_to_p25(
    params: &stellar_xdr::curr::ContractCostParams,
) -> Option<soroban_env_host_p25::xdr::ContractCostParams> {
    use soroban_env_host_p25::xdr::ReadXdr as _;
    let bytes = params.to_xdr(Limits::none()).ok()?;
    soroban_env_host_p25::xdr::ContractCostParams::from_xdr(
        &bytes,
        soroban_env_host_p25::xdr::Limits::none(),
    )
    .ok()
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
        let cpu_params = convert_contract_cost_params_to_p25(&soroban_config.cpu_cost_params)
            .ok_or_else(|| {
                HostError::from(soroban_env_host_p25::Error::from_type_and_code(
                    soroban_env_host_p25::xdr::ScErrorType::Context,
                    soroban_env_host_p25::xdr::ScErrorCode::InternalError,
                ))
            })?;
        let mem_params = convert_contract_cost_params_to_p25(&soroban_config.mem_cost_params)
            .ok_or_else(|| {
                HostError::from(soroban_env_host_p25::Error::from_type_and_code(
                    soroban_env_host_p25::xdr::ScErrorType::Context,
                    soroban_env_host_p25::xdr::ScErrorCode::InternalError,
                ))
            })?;
        Budget::try_from_configs(instruction_limit, memory_limit, cpu_params, mem_params)?
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
        tracing::warn!("P25: Using fallback PRNG seed - results may differ from stellar-core");
        let mut hasher = Sha256::new();
        hasher.update(context.network_id.0 .0);
        hasher.update(context.sequence.to_le_bytes());
        hasher.update(context.close_time.to_le_bytes());
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

    // Helper to encode an entry and its TTL, returning the encoded bytes.
    let encode_entry =
        |key: &LedgerKey, entry: &LedgerEntry, live_until: Option<u32>| -> Result<(Vec<u8>, Vec<u8>), HostError> {
            let entry_bytes = entry.to_xdr(Limits::none()).map_err(|_| {
                HostError::from(soroban_env_host_p25::Error::from_type_and_code(
                    soroban_env_host_p25::xdr::ScErrorType::Context,
                    soroban_env_host_p25::xdr::ScErrorCode::InternalError,
                ))
            })?;

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
            Ok((entry_bytes, ttl_bytes))
        };

    for key in soroban_data.resources.footprint.read_only.iter() {
        if let Some((entry, live_until)) = snapshot.get_local(key)? {
            let (le, ttl) = encode_entry(key, entry.as_ref(), live_until)?;
            encoded_ledger_entries.push(le);
            encoded_ttl_entries.push(ttl);
        }
        // If entry not found, skip it — e2e_invoke's footprint loop will
        // add it to the storage map as None (entry doesn't exist yet).
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
                let (le, ttl) = encode_entry(key, &restore_info.entry, restore_info.live_until)?;
                encoded_ledger_entries.push(le);
                encoded_ttl_entries.push(ttl);

                // Track live BL restorations
                if let Some(live_bl_restore) = restore_info.live_bl_restore {
                    live_bl_restores.push(live_bl_restore);
                }
            }
            // If restored entry not found, skip it — e2e_invoke's footprint
            // loop will add it to the storage map as None.
        } else {
            // Normal entry - use standard TTL-filtered lookup
            if let Some((entry, live_until)) = snapshot.get_local(key)? {
                let (le, ttl) = encode_entry(key, entry.as_ref(), live_until)?;
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
        live_bucket_list_restores: live_bl_restores,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        ContractDataDurability, ContractDataEntry, ContractId, LedgerKeyContractData, ScAddress,
        ScVal, TtlEntry,
    };

    /// Helper to create a test contract data key.
    fn make_contract_data_key(contract_hash: [u8; 32], key_val: i32) -> LedgerKey {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash(contract_hash))),
            key: ScVal::I32(key_val),
            durability: ContractDataDurability::Persistent,
        })
    }

    /// Helper to create a test contract data entry.
    fn make_contract_data_entry(contract_hash: [u8; 32], key_val: i32, val: i32) -> ContractDataEntry {
        ContractDataEntry {
            ext: stellar_xdr::curr::ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash(contract_hash))),
            key: ScVal::I32(key_val),
            durability: ContractDataDurability::Persistent,
            val: ScVal::I32(val),
        }
    }

    /// Test that get_local returns entry when TTL is valid (live_until >= current_ledger).
    ///
    /// This is a regression test for the fix where entries without valid TTL should
    /// not be passed to the Soroban host. Previously, entries were returned even when
    /// TTL was missing or expired.
    ///
    /// Note: We call capture_ttl_bucket_list_snapshot() to simulate entries that
    /// existed at ledger start (i.e., in the bucket list). This is required because
    /// get_entry_ttl() uses get_ttl_at_ledger_start() for parallel Soroban isolation.
    #[test]
    fn test_get_local_with_valid_ttl() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let current_ledger = 1000u32;

        let contract_hash = [1u8; 32];
        let key = make_contract_data_key(contract_hash, 42);
        let entry = make_contract_data_entry(contract_hash, 42, 100);

        // Create the contract data entry
        state.create_contract_data(entry);

        // Create TTL entry with live_until >= current_ledger (valid)
        let key_hash = compute_key_hash(&key);
        let ttl = TtlEntry {
            key_hash: key_hash.clone(),
            live_until_ledger_seq: current_ledger + 100, // Valid: 1100 >= 1000
        };
        state.create_ttl(ttl);

        // Capture the TTL snapshot to simulate entries existing at ledger start.
        // This is necessary because get_entry_ttl() uses get_ttl_at_ledger_start()
        // for parallel Soroban execution isolation.
        state.capture_ttl_bucket_list_snapshot();

        // Test get_local returns the entry
        let snapshot = LedgerSnapshotAdapter::new(&state, current_ledger);
        let result = snapshot.get_local(&key).expect("get_local should succeed");

        assert!(result.is_some(), "Entry with valid TTL should be returned");
        let (entry, live_until) = result.unwrap();
        assert_eq!(live_until, Some(current_ledger + 100));
        assert!(matches!(entry.data, LedgerEntryData::ContractData(_)));
    }

    /// Test that get_local returns None when TTL is expired (live_until < current_ledger).
    ///
    /// This matches stellar-core behavior where entries with expired TTL are not
    /// passed to the Soroban host during invoke_host_function.
    ///
    /// Note: We call capture_ttl_bucket_list_snapshot() to simulate entries that
    /// existed at ledger start (i.e., in the bucket list). This is required because
    /// get_entry_ttl() uses get_ttl_at_ledger_start() for parallel Soroban isolation.
    #[test]
    fn test_get_local_with_expired_ttl() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let current_ledger = 1000u32;

        let contract_hash = [2u8; 32];
        let key = make_contract_data_key(contract_hash, 42);
        let entry = make_contract_data_entry(contract_hash, 42, 100);

        // Create the contract data entry
        state.create_contract_data(entry);

        // Create TTL entry with live_until < current_ledger (expired)
        let key_hash = compute_key_hash(&key);
        let ttl = TtlEntry {
            key_hash: key_hash.clone(),
            live_until_ledger_seq: current_ledger - 1, // Expired: 999 < 1000
        };
        state.create_ttl(ttl);

        // Capture the TTL snapshot to simulate entries existing at ledger start.
        state.capture_ttl_bucket_list_snapshot();

        // Test get_local returns None for expired entry
        let snapshot = LedgerSnapshotAdapter::new(&state, current_ledger);
        let result = snapshot.get_local(&key).expect("get_local should succeed");

        assert!(
            result.is_none(),
            "Entry with expired TTL should not be returned"
        );
    }

    /// Test that get_local returns None when TTL entry doesn't exist.
    ///
    /// This matches stellar-core behavior where entries without a TTL entry
    /// are not considered live and are not passed to the Soroban host.
    #[test]
    fn test_get_local_without_ttl() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let current_ledger = 1000u32;

        let contract_hash = [3u8; 32];
        let key = make_contract_data_key(contract_hash, 42);
        let entry = make_contract_data_entry(contract_hash, 42, 100);

        // Create the contract data entry but NO TTL entry
        state.create_contract_data(entry);

        // Test get_local returns None when TTL doesn't exist
        let snapshot = LedgerSnapshotAdapter::new(&state, current_ledger);
        let result = snapshot.get_local(&key).expect("get_local should succeed");

        assert!(
            result.is_none(),
            "Entry without TTL should not be returned"
        );
    }

    /// Test that get_local returns entry when TTL equals current_ledger (boundary case).
    ///
    /// An entry with live_until == current_ledger is still live (it lives through
    /// the current ledger).
    ///
    /// Note: We call capture_ttl_bucket_list_snapshot() to simulate entries that
    /// existed at ledger start (i.e., in the bucket list). This is required because
    /// get_entry_ttl() uses get_ttl_at_ledger_start() for parallel Soroban isolation.
    #[test]
    fn test_get_local_with_ttl_at_boundary() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let current_ledger = 1000u32;

        let contract_hash = [4u8; 32];
        let key = make_contract_data_key(contract_hash, 42);
        let entry = make_contract_data_entry(contract_hash, 42, 100);

        // Create the contract data entry
        state.create_contract_data(entry);

        // Create TTL entry with live_until == current_ledger (boundary - still live)
        let key_hash = compute_key_hash(&key);
        let ttl = TtlEntry {
            key_hash: key_hash.clone(),
            live_until_ledger_seq: current_ledger, // Boundary: 1000 >= 1000
        };
        state.create_ttl(ttl);

        // Capture the TTL snapshot to simulate entries existing at ledger start.
        state.capture_ttl_bucket_list_snapshot();

        // Test get_local returns the entry (boundary is still live)
        let snapshot = LedgerSnapshotAdapter::new(&state, current_ledger);
        let result = snapshot.get_local(&key).expect("get_local should succeed");

        assert!(
            result.is_some(),
            "Entry with TTL at boundary should be returned (still live)"
        );
    }

    /// Test that non-Soroban entries (Account, Trustline) are returned without TTL check.
    #[test]
    fn test_get_local_account_no_ttl_required() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let current_ledger = 1000u32;

        // Create an account
        let account_id = AccountId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::curr::Uint256([5u8; 32]),
        ));
        let account = stellar_xdr::curr::AccountEntry {
            account_id: account_id.clone(),
            balance: 1_000_000_000,
            seq_num: stellar_xdr::curr::SequenceNumber(1),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: stellar_xdr::curr::String32::default(),
            thresholds: stellar_xdr::curr::Thresholds([1, 0, 0, 0]),
            signers: stellar_xdr::curr::VecM::default(),
            ext: stellar_xdr::curr::AccountEntryExt::V0,
        };
        state.create_account(account);

        let key = LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
            account_id: account_id.clone(),
        });

        // Test get_local returns the account (no TTL required for classic entries)
        let snapshot = LedgerSnapshotAdapter::new(&state, current_ledger);
        let result = snapshot.get_local(&key).expect("get_local should succeed");

        assert!(
            result.is_some(),
            "Account entry should be returned without TTL"
        );
        let (entry, live_until) = result.unwrap();
        assert!(live_until.is_none(), "Account should have no TTL");
        assert!(matches!(entry.data, LedgerEntryData::Account(_)));
    }

    /// Test that entries created WITHIN the current ledger are NOT visible to Soroban.
    ///
    /// This is a critical regression test for parallel Soroban execution (V1 phases).
    /// In stellar-core, transactions in different clusters of the same stage
    /// should NOT see each other's changes. This is achieved by using the bucket list
    /// snapshot at ledger start for TTL lookups.
    ///
    /// Scenario:
    /// 1. Ledger starts, bucket list snapshot is captured (empty TTL snapshot)
    /// 2. TX 4 creates a new ContractData entry with TTL
    /// 3. TX 5 tries to read that entry
    /// 4. TX 5 should NOT see the entry (TTL not in bucket list snapshot)
    ///
    /// This test verifies the fix for ledger 842789 TX 5 mismatch where our code
    /// incorrectly showed the entry as visible, causing TX 5 to succeed when it
    /// should have trapped.
    #[test]
    fn test_get_local_entry_created_within_ledger_not_visible() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let current_ledger = 1000u32;

        // Step 1: Capture the bucket list snapshot BEFORE any entries are created.
        // This simulates the start of the ledger before any transactions run.
        state.capture_ttl_bucket_list_snapshot();

        // Step 2: TX 4 creates a new ContractData entry with TTL.
        // This simulates an earlier transaction creating an entry within the ledger.
        let contract_hash = [6u8; 32];
        let key = make_contract_data_key(contract_hash, 42);
        let entry = make_contract_data_entry(contract_hash, 42, 100);
        state.create_contract_data(entry);

        let key_hash = compute_key_hash(&key);
        let ttl = TtlEntry {
            key_hash: key_hash.clone(),
            live_until_ledger_seq: current_ledger + 100, // Valid TTL
        };
        state.create_ttl(ttl);

        // Verify the entry exists in current state
        assert!(
            state.get_ttl(&key_hash).is_some(),
            "TTL should exist in current state"
        );

        // Step 3: TX 5 tries to read the entry via LedgerSnapshotAdapter.
        // Since the TTL was created AFTER the bucket list snapshot was captured,
        // get_ttl_at_ledger_start() should return None.
        let snapshot = LedgerSnapshotAdapter::new(&state, current_ledger);
        let result = snapshot.get_local(&key).expect("get_local should succeed");

        // Step 4: The entry should NOT be visible because its TTL is not in the
        // bucket list snapshot (it was created within the ledger).
        assert!(
            result.is_none(),
            "Entry created within ledger should NOT be visible to subsequent Soroban TXs"
        );
    }
}
