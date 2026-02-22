//! Soroban Host execution integration.
//!
//! This module provides the integration between our ledger state and the
//! soroban-env-host crate for executing Soroban smart contracts.

use std::rc::Rc;

use sha2::{Digest, Sha256};

// Use soroban-env-host types for Host interaction
use soroban_env_host24::xdr::ReadXdr as ReadXdrP24;
use soroban_env_host24::{
    budget::{AsBudget, Budget},
    e2e_invoke::{self},
    fees::{compute_rent_fee, LedgerEntryRentChange},
    storage::{EntryWithLiveUntil, SnapshotSource},
    vm::VersionedContractCodeCostInputs,
    CompilationContext, ErrorHandler, HostError as HostErrorP24, LedgerInfo as LedgerInfoP24,
    ModuleCache,
};
use soroban_env_host25::HostError as HostErrorP25;
use soroban_env_host_p24 as soroban_env_host24;
use soroban_env_host_p25 as soroban_env_host25;

// P25 module cache types
use soroban_env_host25::{
    budget::AsBudget as AsBudgetP25,
    vm::VersionedContractCodeCostInputs as VersionedContractCodeCostInputsP25,
    CompilationContext as CompilationContextP25, ErrorHandler as ErrorHandlerP25,
    ModuleCache as ModuleCacheP25,
};

// Note: soroban-env-host v25.0.0 uses stellar-xdr 25.0.0 from crates.io,
// while our workspace uses a git revision of stellar-xdr. We need to convert
// between the two via XDR serialization when crossing the boundary.
use stellar_xdr::curr::{
    AccountId, DiagnosticEvent, Hash, HostFunction, LedgerEntry, LedgerKey, Limits, ReadXdr, ScVal,
    SorobanAuthorizationEntry, SorobanTransactionData, SorobanTransactionDataExt, WriteXdr,
};

// Type aliases for soroban-env-host P25's XDR types (from stellar-xdr 25.0.0)
type P25LedgerKey = soroban_env_host25::xdr::LedgerKey;
type P25LedgerEntry = soroban_env_host25::xdr::LedgerEntry;

use super::error::convert_host_error_p24_to_p25;
use super::SorobanConfig;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;

/// Return type for `get_archived_with_restore_info` (p24 version).
/// Contains: (entry, live_until, live_bl_restore_info)
type ArchivedWithRestoreInfoP24 = Option<(
    Rc<soroban_env_host24::xdr::LedgerEntry>,
    Option<u32>,
    Option<super::protocol::LiveBucketListRestore>,
)>;

/// Return type for `get_archived_with_restore_info` (p25 version).
/// Contains: (entry, live_until, live_bl_restore_info)
type ArchivedWithRestoreInfoP25 = Option<(
    Rc<LedgerEntry>,
    Option<u32>,
    Option<super::protocol::LiveBucketListRestore>,
)>;

/// A ledger entry paired with its optional TTL (live_until ledger sequence).
pub type EntryWithTtl = (Rc<LedgerEntry>, Option<u32>);

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
    /// Entries restored from the live BucketList (expired TTL but not yet evicted).
    pub live_bucket_list_restores: Vec<super::protocol::LiveBucketListRestore>,
    /// Indices of entries ACTUALLY restored from hot archive in THIS transaction.
    /// This is a subset of the transaction envelope's archived_soroban_entries,
    /// excluding entries that were already restored by a previous transaction
    /// in the same ledger. Used to determine whether to emit INIT vs LIVE changes.
    pub actual_restored_indices: Vec<u32>,
    /// Entries restored from hot archive that the host did NOT emit storage changes for
    /// (i.e., the host only read them without modifying them or extending their TTL).
    ///
    /// These must still be recorded in the ledger delta so that subsequent stages/clusters
    /// can see the restoration. This mirrors stellar-core's handleArchivedEntry which
    /// unconditionally calls mOpState.upsertEntry(lk, le, ...) regardless of host access.
    ///
    /// Key → (entry, restored_live_until).
    pub hot_archive_read_only_restored_entries: std::collections::HashMap<LedgerKey, (LedgerEntry, u32)>,
}

/// Error from Soroban execution that includes consumed resources.
/// This is needed to properly determine TRAPPED vs RESOURCE_LIMIT_EXCEEDED
/// based on whether actual consumption exceeded specified limits.
pub struct SorobanExecutionError {
    /// The underlying host error.
    pub host_error: HostErrorP25,
    /// CPU instructions consumed before failure.
    pub cpu_insns_consumed: u64,
    /// Memory bytes consumed before failure.
    pub mem_bytes_consumed: u64,
}

/// A single storage change from Soroban execution.
pub struct StorageChange {
    /// The ledger key.
    pub key: LedgerKey,
    /// The new entry (None if deleted or read-only).
    pub new_entry: Option<LedgerEntry>,
    /// The new live_until ledger (for TTL).
    pub live_until: Option<u32>,
    /// Whether the TTL was extended (new > old).
    pub ttl_extended: bool,
    /// Whether the entry was included due to rent calculations (old_entry_size_bytes_for_rent > 0).
    /// Rent-related read-only entries should still emit TTL updates.
    pub is_rent_related: bool,
    /// Whether this is a read-only entry with only a TTL change (no data modification).
    /// Such changes should be applied to state (bucket list) but NOT included in transaction meta.
    /// This matches stellar-core's behavior per CAP-0063: read-only TTL bumps are accumulated
    /// separately and flushed at write barriers, not in individual transaction meta.
    pub is_read_only_ttl_bump: bool,
}

/// Persistent module cache that can be reused across transactions.
///
/// This enum wraps either a P24 or P25 module cache, allowing it to be
/// passed through the execution layer without knowing the protocol version
/// upfront. The cache is populated once at ledger start and reused for all
/// transactions in that ledger, matching stellar-core's SharedModuleCacheCompiler.
#[derive(Clone)]
pub enum PersistentModuleCache {
    /// Protocol 24 module cache
    P24(ModuleCache),
    /// Protocol 25+ module cache
    P25(ModuleCacheP25),
}

impl PersistentModuleCache {
    /// Create a new empty P24 cache.
    pub fn new_p24() -> Option<Self> {
        let ctx = WasmCompilationContext::new();
        ModuleCache::new(&ctx).ok().map(PersistentModuleCache::P24)
    }

    /// Create a new empty P25 cache.
    pub fn new_p25() -> Option<Self> {
        let ctx = WasmCompilationContextP25::new();
        ModuleCacheP25::new(&ctx)
            .ok()
            .map(PersistentModuleCache::P25)
    }

    /// Create a new cache for the given protocol version.
    pub fn new_for_protocol(protocol_version: u32) -> Option<Self> {
        if protocol_version >= 25 {
            Self::new_p25()
        } else {
            Self::new_p24()
        }
    }

    /// Add a contract code entry to the cache.
    /// Returns true if compilation succeeded, false otherwise.
    pub fn add_contract(&self, code: &[u8], protocol_version: u32) -> bool {
        match self {
            PersistentModuleCache::P24(cache) => {
                let ctx = WasmCompilationContext::new();
                let contract_id =
                    soroban_env_host24::xdr::Hash(<Sha256 as Digest>::digest(code).into());
                let cost_inputs = VersionedContractCodeCostInputs::V0 {
                    wasm_bytes: code.len(),
                };
                cache
                    .parse_and_cache_module(&ctx, protocol_version, &contract_id, code, cost_inputs)
                    .is_ok()
            }
            PersistentModuleCache::P25(cache) => {
                let ctx = WasmCompilationContextP25::new();
                let contract_id =
                    soroban_env_host25::xdr::Hash(<Sha256 as Digest>::digest(code).into());
                let cost_inputs = VersionedContractCodeCostInputsP25::V0 {
                    wasm_bytes: code.len(),
                };
                cache
                    .parse_and_cache_module(&ctx, protocol_version, &contract_id, code, cost_inputs)
                    .is_ok()
            }
        }
    }

    /// Remove a contract code entry from the cache by its hash.
    ///
    /// This should be called when contract code is evicted (TTL expired) to
    /// prevent unbounded growth of the module cache.
    ///
    /// Returns true if the module was found and removed, false otherwise.
    pub fn remove_contract(&self, hash: &[u8; 32]) -> bool {
        match self {
            PersistentModuleCache::P24(cache) => {
                let contract_id = soroban_env_host24::xdr::Hash(*hash);
                cache.remove_module(&contract_id).ok().flatten().is_some()
            }
            PersistentModuleCache::P25(cache) => {
                let contract_id = soroban_env_host25::xdr::Hash(*hash);
                cache.remove_module(&contract_id).ok().flatten().is_some()
            }
        }
    }

    /// Get the P24 cache if this is a P24 cache.
    pub fn as_p24(&self) -> Option<&ModuleCache> {
        match self {
            PersistentModuleCache::P24(cache) => Some(cache),
            PersistentModuleCache::P25(_) => None,
        }
    }

    /// Get the P25 cache if this is a P25 cache.
    pub fn as_p25(&self) -> Option<&ModuleCacheP25> {
        match self {
            PersistentModuleCache::P24(_) => None,
            PersistentModuleCache::P25(cache) => Some(cache),
        }
    }
}

/// Adapter that provides snapshot access to our ledger state for Soroban (P24).
pub struct LedgerSnapshotAdapter<'a> {
    state: &'a LedgerStateManager,
    current_ledger: u32,
    hot_archive: Option<&'a dyn super::HotArchiveLookup>,
}

impl<'a> LedgerSnapshotAdapter<'a> {
    /// Create a new snapshot adapter without hot archive lookup.
    #[allow(dead_code)]
    pub fn new(state: &'a LedgerStateManager, current_ledger: u32) -> Self {
        Self {
            state,
            current_ledger,
            hot_archive: None,
        }
    }

    /// Create a new snapshot adapter with hot archive lookup capability.
    pub fn with_hot_archive(
        state: &'a LedgerStateManager,
        current_ledger: u32,
        hot_archive: Option<&'a dyn super::HotArchiveLookup>,
    ) -> Self {
        Self {
            state,
            current_ledger,
            hot_archive,
        }
    }

    /// Get an archived entry without checking TTL.
    /// Used for entries that are being restored from the hot archive.
    ///
    /// This method first checks the live state (for entries with expired TTL but not yet evicted),
    /// then falls back to the hot archive bucket list (for truly evicted entries).
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

        // Use get_entry() to reconstruct the full LedgerEntry with correct
        // last_modified_ledger_seq and ext (sponsorship) metadata.
        // No TTL check - entry might be archived with expired TTL.
        let entry = self.state.get_entry(&current_key);

        // If entry found in live state, return it
        if let Some(e) = entry {
            let entry = convert_ledger_entry_to_p24(&e).ok_or_else(|| {
                HostErrorP24::from(soroban_env_host24::Error::from_type_and_code(
                    soroban_env_host24::xdr::ScErrorType::Context,
                    soroban_env_host24::xdr::ScErrorCode::InternalError,
                ))
            })?;
            return Ok(Some((Rc::new(entry), live_until)));
        }

        // Entry not found in live state - try the hot archive bucket list.
        // This handles the case where the entry was evicted from the live bucket list
        // and is now in the hot archive, waiting to be restored.
        if let Some(hot_archive) = self.hot_archive {
            if let Some(archived_entry) = hot_archive.get(&current_key) {
                tracing::debug!(
                    key_type = ?std::mem::discriminant(&current_key),
                    "P24: Found archived entry in hot archive bucket list"
                );
                // Convert to P24 format
                let entry = convert_ledger_entry_to_p24(&archived_entry).ok_or_else(|| {
                    HostErrorP24::from(soroban_env_host24::Error::from_type_and_code(
                        soroban_env_host24::xdr::ScErrorType::Context,
                        soroban_env_host24::xdr::ScErrorCode::InternalError,
                    ))
                })?;
                // Hot archive entries have no TTL (they are archived/expired)
                return Ok(Some((Rc::new(entry), None)));
            }
        }

        Ok(None)
    }

    /// Get an archived entry in curr (stellar_xdr) format, without P24 conversion.
    ///
    /// This is used to capture the entry data for hot archive restorations so
    /// that read-only restorations (where the host doesn't modify the entry) can
    /// still be recorded in the ledger delta.
    ///
    /// Parity: stellar-core InvokeHostFunctionOpFrame::handleArchivedEntry unconditionally
    /// calls mOpState.upsertEntry(lk, le, ...) regardless of whether the host modifies the
    /// entry. This method enables henyey to replicate that behavior.
    pub fn get_curr_archived(
        &self,
        key: &LedgerKey,
    ) -> Option<(LedgerEntry, Option<u32>)> {
        // Get TTL but don't check if it's expired - this is for archived entries
        let live_until = get_entry_ttl(self.state, key, self.current_ledger);

        // Check live state first (entry may be in live BL with expired TTL)
        if let Some(e) = self.state.get_entry(key) {
            return Some((e, live_until));
        }

        // Fall back to hot archive
        if let Some(hot_archive) = self.hot_archive {
            if let Some(archived_entry) = hot_archive.get(key) {
                // Hot archive entries have no TTL (they are archived/expired)
                return Some((archived_entry, None));
            }
        }

        None
    }

    /// Get an archived entry and check if it's a live BL restore.
    /// Returns (p24 entry, live_until, live_bl_restore info if applicable).
    pub fn get_archived_with_restore_info(
        &self,
        key: &Rc<soroban_env_host24::xdr::LedgerKey>,
        current_key: &LedgerKey,
    ) -> Result<ArchivedWithRestoreInfoP24, HostErrorP24> {
        let result = self.get_archived(key)?;

        match result {
            Some((entry, live_until)) => {
                // Check if this is a live BL restore: entry exists AND TTL is expired
                let live_bl_restore = if let Some(lu) = live_until {
                    if lu < self.current_ledger {
                        // Get the entry with correct metadata
                        let current_entry = self.state.get_entry(current_key);

                        if let Some(e) = current_entry {
                            // Get the TTL entry for the restore info
                            let key_hash = compute_key_hash(current_key);
                            let ttl_key = LedgerKey::Ttl(stellar_xdr::curr::LedgerKeyTtl {
                                key_hash: key_hash.clone(),
                            });
                            let ttl_entry = self.state.get_entry(&ttl_key);

                            ttl_entry.map(|te| super::protocol::LiveBucketListRestore {
                                key: current_key.clone(),
                                entry: e,
                                ttl_key,
                                ttl_entry: te,
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                Ok(Some((entry, live_until, live_bl_restore)))
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
        // and not accessible. This mimics stellar-core behavior.
        let live_until = get_entry_ttl(self.state, &current_key, self.current_ledger);

        // Check TTL expiration for contract entries before looking up the entry.
        if matches!(
            current_key,
            LedgerKey::ContractData(_) | LedgerKey::ContractCode(_)
        ) {
            if let Some(ttl) = live_until {
                if ttl < self.current_ledger {
                    tracing::debug!(
                        current_ledger = self.current_ledger,
                        live_until = ttl,
                        "P24 SnapshotSource: Filtering out entry with expired TTL"
                    );
                    return Ok(None);
                }
            } else {
                // No TTL means entry doesn't exist in Soroban state yet
                // (will be created by the contract invocation).
            }
        }

        // Use get_entry() to reconstruct the full LedgerEntry with correct
        // last_modified_ledger_seq and ext (sponsorship) metadata.
        // stellar-core preserves original entry metadata in its InMemorySorobanState.
        let entry = self.state.get_entry(&current_key);

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
    hot_archive: Option<&'a dyn super::HotArchiveLookup>,
}

impl<'a> LedgerSnapshotAdapterP25<'a> {
    /// Create a new snapshot adapter with hot archive lookup capability.
    pub fn with_hot_archive(
        state: &'a LedgerStateManager,
        current_ledger: u32,
        hot_archive: Option<&'a dyn super::HotArchiveLookup>,
    ) -> Self {
        Self {
            state,
            current_ledger,
            hot_archive,
        }
    }

    /// Get an entry using our workspace XDR types (for internal use).
    /// This is separate from the `SnapshotSource::get()` trait impl which uses
    /// soroban-env-host's XDR types.
    pub fn get_local(&self, key: &LedgerKey) -> Result<Option<EntryWithTtl>, HostErrorP25> {
        // For ContractData and ContractCode, check TTL from bucket list snapshot.
        // This matches stellar-core behavior for parallel Soroban execution:
        // - Entries with valid TTL (live_until >= current_ledger): pass to host
        // - Entries with expired TTL (live_until < current_ledger): archived, not accessible
        // - Entries without TTL in bucket list snapshot: created within ledger, not visible
        let live_until = get_entry_ttl(self.state, key, self.current_ledger);

        // Check TTL expiration for contract entries before looking up the entry.
        if matches!(key, LedgerKey::ContractData(_) | LedgerKey::ContractCode(_)) {
            match live_until {
                Some(ttl) if ttl >= self.current_ledger => {} // live, proceed
                _ => return Ok(None),                         // expired or no TTL
            }
        }

        // Use get_entry() to reconstruct the full LedgerEntry with correct
        // last_modified_ledger_seq and ext (sponsorship) metadata.
        let entry = self.state.get_entry(key);

        match entry {
            Some(e) => Ok(Some((Rc::new(e), live_until))),
            None => Ok(None),
        }
    }

    /// Get an archived entry without checking TTL.
    /// Used for entries that are being restored from the hot archive.
    ///
    /// This method first checks the live state (for entries with expired TTL but not yet evicted),
    /// then falls back to the hot archive bucket list (for truly evicted entries).
    ///
    /// Returns entries in our workspace XDR types (not soroban-env-host's types).
    pub fn get_archived(&self, key: &Rc<LedgerKey>) -> Result<Option<EntryWithTtl>, HostErrorP25> {
        // Get TTL but don't check if it's expired - this is for archived entries
        let live_until = get_entry_ttl(self.state, key.as_ref(), self.current_ledger);

        // Use get_entry() to reconstruct the full LedgerEntry with correct
        // last_modified_ledger_seq and ext (sponsorship) metadata.
        let entry = self.state.get_entry(key.as_ref());

        // If entry found in live state, return it
        if let Some(e) = entry {
            return Ok(Some((Rc::new(e), live_until)));
        }

        // Entry not found in live state - try the hot archive bucket list.
        // This handles the case where the entry was evicted from the live bucket list
        // and is now in the hot archive, waiting to be restored.
        if let Some(hot_archive) = self.hot_archive {
            if let Some(archived_entry) = hot_archive.get(key.as_ref()) {
                tracing::debug!(
                    key_type = ?std::mem::discriminant(key.as_ref()),
                    "P25: Found archived entry in hot archive bucket list"
                );
                // Hot archive entries have no TTL (they are archived/expired)
                return Ok(Some((Rc::new(archived_entry), None)));
            }
        }

        Ok(None)
    }

    /// Get an archived entry and check if it's a live BL restore.
    /// Returns (entry, live_until, live_bl_restore_info).
    ///
    /// Returns entries in our workspace XDR types (not soroban-env-host's types).
    pub fn get_archived_with_restore_info(
        &self,
        key: &Rc<LedgerKey>,
    ) -> Result<ArchivedWithRestoreInfoP25, HostErrorP25> {
        let result = self.get_archived(key)?;

        match result {
            Some((entry, live_until)) => {
                // Check if this is a live BL restore: entry exists AND TTL is expired
                let live_bl_restore = if let Some(lu) = live_until {
                    if lu < self.current_ledger {
                        // Get the TTL entry for the restore info
                        let key_hash = compute_key_hash(key.as_ref());
                        let ttl_key = LedgerKey::Ttl(stellar_xdr::curr::LedgerKeyTtl {
                            key_hash: key_hash.clone(),
                        });
                        let ttl_entry = self.state.get_entry(&ttl_key);

                        ttl_entry.map(|te| super::protocol::LiveBucketListRestore {
                            key: key.as_ref().clone(),
                            entry: entry.as_ref().clone(),
                            ttl_key,
                            ttl_entry: te,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };

                Ok(Some((entry, live_until, live_bl_restore)))
            }
            None => Ok(None),
        }
    }
}

impl<'a> soroban_env_host25::storage::SnapshotSource for LedgerSnapshotAdapterP25<'a> {
    fn get(
        &self,
        key: &Rc<P25LedgerKey>,
    ) -> Result<Option<soroban_env_host25::storage::EntryWithLiveUntil>, HostErrorP25> {
        // Convert P25 key to our workspace XDR type
        let Some(local_key) = convert_ledger_key_from_p25(key.as_ref()) else {
            return Ok(None);
        };

        // For ContractData and ContractCode, check TTL first.
        // If TTL has expired, the entry is considered to be in the hot archive
        // and not accessible. This mimics stellar-core behavior.
        let live_until = get_entry_ttl(self.state, &local_key, self.current_ledger);

        // Check TTL expiration for contract entries before looking up the entry.
        if matches!(
            &local_key,
            LedgerKey::ContractData(_) | LedgerKey::ContractCode(_)
        ) {
            match live_until {
                Some(ttl) if ttl >= self.current_ledger => {} // live, proceed
                _ => return Ok(None),                         // expired or no TTL
            }
        }

        // Use get_entry() to reconstruct the full LedgerEntry with correct
        // last_modified_ledger_seq and ext (sponsorship) metadata.
        let entry = self.state.get_entry(&local_key);

        // Convert the entry to P25 XDR type
        match entry {
            Some(e) => {
                let p25_entry = convert_ledger_entry_to_p25(&e).ok_or_else(|| {
                    HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
                        soroban_env_host25::xdr::ScErrorType::Context,
                        soroban_env_host25::xdr::ScErrorCode::InternalError,
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
/// This function returns the CURRENT TTL value (after any modifications by earlier
/// transactions in this ledger), not the ledger-start TTL. This matches stellar-core
/// behavior where the Soroban host computes rent fees based on the current state.
///
/// If TX 6 extends an entry's TTL from 682237 → 700457, TX 7 accessing the same entry
/// will see old_live_until=700457 (the post-TX-6 value) and NOT pay rent for the extension.
/// This is the correct behavior because only one transaction should pay rent for a TTL
/// extension in a given ledger.
///
/// Note: TTL emission determination (whether to emit TTL to bucket list) still
/// needs to compare against ledger-start TTL, which is handled separately in
/// the storage_changes filter.
fn get_entry_ttl(state: &LedgerStateManager, key: &LedgerKey, current_ledger: u32) -> Option<u32> {
    match key {
        LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {
            let key_hash = compute_key_hash(key);
            // Use current state TTL which includes updates from earlier TXs in this ledger.
            // This matches stellar-core sequential execution where LedgerTxn reflects all prior
            // changes, including TTL bumps from earlier transactions.
            let ttl = state
                .get_ttl(&key_hash)
                .map(|ttl| ttl.live_until_ledger_seq);
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
                        "Soroban entry TTL is EXPIRED"
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

fn convert_ledger_key_to_p24(key: &LedgerKey) -> Option<soroban_env_host24::xdr::LedgerKey> {
    let bytes = key.to_xdr(Limits::none()).ok()?;
    soroban_env_host24::xdr::LedgerKey::from_xdr(&bytes, soroban_env_host24::xdr::Limits::none())
        .ok()
}

fn convert_ledger_key_from_p24(key: &soroban_env_host24::xdr::LedgerKey) -> Option<LedgerKey> {
    let bytes =
        soroban_env_host24::xdr::WriteXdr::to_xdr(key, soroban_env_host24::xdr::Limits::none())
            .ok()?;
    LedgerKey::from_xdr(&bytes, Limits::none()).ok()
}

fn convert_ledger_entry_to_p24(
    entry: &LedgerEntry,
) -> Option<soroban_env_host24::xdr::LedgerEntry> {
    let bytes = entry.to_xdr(Limits::none()).ok()?;
    soroban_env_host24::xdr::LedgerEntry::from_xdr(&bytes, soroban_env_host24::xdr::Limits::none())
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

// P25 XDR conversion functions (soroban-env-host v25.0.0 uses stellar-xdr 25.0.0)
fn convert_ledger_key_from_p25(key: &P25LedgerKey) -> Option<LedgerKey> {
    let bytes =
        soroban_env_host25::xdr::WriteXdr::to_xdr(key, soroban_env_host25::xdr::Limits::none())
            .ok()?;
    LedgerKey::from_xdr(&bytes, Limits::none()).ok()
}

fn convert_ledger_entry_to_p25(entry: &LedgerEntry) -> Option<P25LedgerEntry> {
    use soroban_env_host25::xdr::ReadXdr as _;
    let bytes = entry.to_xdr(Limits::none()).ok()?;
    soroban_env_host25::xdr::LedgerEntry::from_xdr(&bytes, soroban_env_host25::xdr::Limits::none())
        .ok()
}

fn convert_contract_cost_params_to_p25(
    params: &stellar_xdr::curr::ContractCostParams,
) -> Option<soroban_env_host25::xdr::ContractCostParams> {
    use soroban_env_host25::xdr::ReadXdr as _;
    let bytes = params.to_xdr(Limits::none()).ok()?;
    soroban_env_host25::xdr::ContractCostParams::from_xdr(
        &bytes,
        soroban_env_host25::xdr::Limits::none(),
    )
    .ok()
}

/// Context for pre-compiling WASM modules outside of transaction execution.
/// This mimics how stellar-core pre-compiles all contracts with an unlimited budget.
/// We use very high budget limits (10B CPU, 1GB memory) to ensure compilation never fails
/// due to budget constraints. stellar-core's SharedModuleCacheCompiler compiles
/// without any budget metering.
#[derive(Clone)]
struct WasmCompilationContext(Budget);

impl WasmCompilationContext {
    /// Create a new compilation context with very high budget limits.
    /// We use 10 billion CPU instructions and 1GB memory to ensure compilation
    /// never fails due to budget constraints. The actual compilation cost is
    /// typically much lower, but we want to match stellar-core behavior which doesn't
    /// meter compilation at all.
    fn new() -> Self {
        // Use a budget with very high limits to avoid ExceededLimit errors during pre-compilation.
        // stellar-core compiles without metering, so we use 10B instructions / 1GB memory.
        let budget = Budget::try_from_configs(
            10_000_000_000,     // 10 billion CPU instructions
            1_000_000_000,      // 1 GB memory
            Default::default(), // Default CPU cost params
            Default::default(), // Default memory cost params
        )
        .unwrap_or_else(|_| Budget::default());
        Self(budget)
    }
}

impl ErrorHandler for WasmCompilationContext {
    fn map_err<T, E>(&self, res: Result<T, E>) -> Result<T, HostErrorP24>
    where
        soroban_env_host24::Error: From<E>,
        E: std::fmt::Debug,
    {
        res.map_err(HostErrorP24::from)
    }

    fn error(
        &self,
        error: soroban_env_host24::Error,
        _msg: &str,
        _args: &[soroban_env_host24::Val],
    ) -> HostErrorP24 {
        HostErrorP24::from(error)
    }
}

impl AsBudget for WasmCompilationContext {
    fn as_budget(&self) -> &Budget {
        &self.0
    }
}

impl CompilationContext for WasmCompilationContext {}

/// Context for pre-compiling WASM modules outside of transaction execution (P25 version).
/// This mimics how stellar-core pre-compiles all contracts with an unlimited budget.
/// We use very high budget limits (10B CPU, 1GB memory) to ensure compilation never fails
/// due to budget constraints. stellar-core's SharedModuleCacheCompiler compiles
/// without any budget metering.
#[derive(Clone)]
struct WasmCompilationContextP25(soroban_env_host25::budget::Budget);

impl WasmCompilationContextP25 {
    /// Create a new compilation context with very high budget limits.
    /// We use 10 billion CPU instructions and 1GB memory to ensure compilation
    /// never fails due to budget constraints. The actual compilation cost is
    /// typically much lower, but we want to match stellar-core behavior which doesn't
    /// meter compilation at all.
    fn new() -> Self {
        // Use a budget with very high limits to avoid ExceededLimit errors during pre-compilation.
        // stellar-core compiles without metering, so we use 10B instructions / 1GB memory.
        let budget = soroban_env_host25::budget::Budget::try_from_configs(
            10_000_000_000,     // 10 billion CPU instructions
            1_000_000_000,      // 1 GB memory
            Default::default(), // Default CPU cost params
            Default::default(), // Default memory cost params
        )
        .unwrap_or_else(|_| soroban_env_host25::budget::Budget::default());
        Self(budget)
    }
}

impl ErrorHandlerP25 for WasmCompilationContextP25 {
    fn map_err<T, E>(&self, res: Result<T, E>) -> Result<T, HostErrorP25>
    where
        soroban_env_host25::Error: From<E>,
        E: std::fmt::Debug,
    {
        res.map_err(HostErrorP25::from)
    }

    fn error(
        &self,
        error: soroban_env_host25::Error,
        _msg: &str,
        _args: &[soroban_env_host25::Val],
    ) -> HostErrorP25 {
        HostErrorP25::from(error)
    }
}

impl AsBudgetP25 for WasmCompilationContextP25 {
    fn as_budget(&self) -> &soroban_env_host25::budget::Budget {
        &self.0
    }
}

impl CompilationContextP25 for WasmCompilationContextP25 {}

/// Compute rent_fee for a newly created Soroban entry.
///
/// This is used by `execute_upload_wasm` to compute the rent fee for the new
/// ContractCode entry being created, matching how stellar-core computes
/// rent fees via soroban-env-host.
///
/// # Arguments
///
/// * `entry_size_bytes` - The XDR size of the LedgerEntry being created
/// * `live_until` - The live_until ledger sequence for the entry
/// * `is_persistent` - Whether this is a persistent entry (true) or temporary (false)
/// * `is_code_entry` - Whether this is a ContractCode entry (affects P25 rent calculation)
/// * `current_ledger` - The current ledger sequence
/// * `soroban_config` - Network configuration with rent fee parameters
/// * `protocol_version` - The protocol version
///
/// # Returns
///
/// Returns the computed rent fee in stroops.
pub fn compute_rent_fee_for_new_entry(
    entry_size_bytes: u32,
    live_until: u32,
    is_persistent: bool,
    is_code_entry: bool,
    current_ledger: u32,
    soroban_config: &SorobanConfig,
    protocol_version: u32,
) -> i64 {
    // Create a rent change for a newly created entry:
    // - old_size_bytes = 0 (new entry)
    // - old_live_until_ledger = 0 (new entry)
    // - new_size_bytes = entry XDR size
    // - new_live_until_ledger = live_until

    if protocol_version >= 25 {
        use soroban_env_host25::fees::{
            compute_rent_fee as compute_rent_fee_p25,
            LedgerEntryRentChange as LedgerEntryRentChangeP25,
        };

        let rent_change = LedgerEntryRentChangeP25 {
            is_persistent,
            is_code_entry,
            old_size_bytes: 0,
            new_size_bytes: entry_size_bytes,
            old_live_until_ledger: 0,
            new_live_until_ledger: live_until,
        };

        // Use the P25 rent_fee_config directly from soroban_config
        compute_rent_fee_p25(
            &[rent_change],
            &soroban_config.rent_fee_config,
            current_ledger,
        )
    } else {
        let rent_change = LedgerEntryRentChange {
            is_persistent,
            is_code_entry,
            old_size_bytes: 0,
            new_size_bytes: entry_size_bytes,
            old_live_until_ledger: 0,
            new_live_until_ledger: live_until,
        };

        let rent_fee_config = rent_fee_config_p25_to_p24(&soroban_config.rent_fee_config);
        compute_rent_fee(&[rent_change], &rent_fee_config, current_ledger)
    }
}

/// Execute a Soroban host function using soroban-env-host's e2e_invoke API.
///
/// This uses the same high-level API that stellar-core uses, which handles
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
/// Returns an error if the host function fails or budget is exceeded, along with
/// the consumed resources which are needed to distinguish TRAPPED from RESOURCE_LIMIT_EXCEEDED.
pub fn execute_host_function(
    host_function: &HostFunction,
    auth_entries: &[SorobanAuthorizationEntry],
    source: &AccountId,
    state: &LedgerStateManager,
    context: &LedgerContext,
    soroban_data: &SorobanTransactionData,
    soroban_config: &SorobanConfig,
) -> Result<SorobanExecutionResult, SorobanExecutionError> {
    execute_host_function_with_cache(
        host_function,
        auth_entries,
        source,
        state,
        context,
        soroban_data,
        soroban_config,
        None,
        None,
    )
}

/// Execute a Soroban host function with an optional pre-populated module cache.
///
/// This is the same as `execute_host_function` but accepts an optional persistent
/// module cache. When provided, the cache is reused across transactions, avoiding
/// repeated WASM compilation. This matches stellar-core's SharedModuleCacheCompiler.
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
/// * `module_cache` - Optional pre-populated module cache for WASM reuse
/// * `hot_archive` - Optional hot archive lookup for Protocol 23+ entry restoration
#[allow(clippy::too_many_arguments)]
pub fn execute_host_function_with_cache(
    host_function: &HostFunction,
    auth_entries: &[SorobanAuthorizationEntry],
    source: &AccountId,
    state: &LedgerStateManager,
    context: &LedgerContext,
    soroban_data: &SorobanTransactionData,
    soroban_config: &SorobanConfig,
    module_cache: Option<&PersistentModuleCache>,
    hot_archive: Option<&dyn super::HotArchiveLookup>,
) -> Result<SorobanExecutionResult, SorobanExecutionError> {
    if context.protocol_version >= 25 {
        let cache = module_cache
            .unwrap_or_else(|| panic!("Module cache must be provided for Soroban TX execution"));
        let p25_cache = cache.as_p25().unwrap_or_else(|| {
            panic!(
                "Module cache is not P25 but protocol version is {}",
                context.protocol_version
            )
        });
        return execute_host_function_p25(
            host_function,
            auth_entries,
            source,
            state,
            context,
            soroban_data,
            soroban_config,
            Some(p25_cache),
            hot_archive,
        );
    }
    let cache = module_cache
        .unwrap_or_else(|| panic!("Module cache must be provided for Soroban TX execution"));
    let p24_cache = cache.as_p24().unwrap_or_else(|| {
        panic!(
            "Module cache is not P24 but protocol version is {}",
            context.protocol_version
        )
    });
    tracing::info!("Dispatching to P24 path");
    execute_host_function_p24(
        host_function,
        auth_entries,
        source,
        state,
        context,
        soroban_data,
        soroban_config,
        Some(p24_cache),
        hot_archive,
    )
}

/// Create a setup error with zero consumed resources (for errors before budget exists).
fn make_xdr_setup_error() -> SorobanExecutionError {
    SorobanExecutionError {
        host_error: HostErrorP25::from(soroban_env_host25::Error::from_type_and_code(
            soroban_env_host25::xdr::ScErrorType::Context,
            soroban_env_host25::xdr::ScErrorCode::InternalError,
        )),
        cpu_insns_consumed: 0,
        mem_bytes_consumed: 0,
    }
}

/// Encode a value to XDR, mapping errors to a setup error.
fn xdr_encode_setup<T: stellar_xdr::curr::WriteXdr>(
    val: &T,
) -> Result<Vec<u8>, SorobanExecutionError> {
    val.to_xdr(Limits::none())
        .map_err(|_| make_xdr_setup_error())
}

/// Encode a p24 XDR value, mapping errors to a setup error.
fn xdr_encode_p24_setup<T: soroban_env_host24::xdr::WriteXdr>(
    val: &T,
) -> Result<Vec<u8>, SorobanExecutionError> {
    val.to_xdr(soroban_env_host24::xdr::Limits::none())
        .map_err(|_| make_xdr_setup_error())
}

/// Result of collecting and encoding footprint entries for the Soroban host.
struct EncodedFootprint {
    ledger_entries: Vec<Vec<u8>>,
    ttl_entries: Vec<Vec<u8>>,
    actual_restored_indices: Vec<u32>,
    live_bl_restores: Vec<super::protocol::LiveBucketListRestore>,
    /// Entries actually restored from hot archive, in curr format.
    /// Key → (entry, restored_live_until). Used to record read-only
    /// restorations (where the host doesn't emit a storage change) in the delta.
    restored_entries: std::collections::HashMap<LedgerKey, (LedgerEntry, u32)>,
}

/// Collect and encode ledger entries from the transaction footprint.
///
/// Encodes each entry and its TTL for consumption by `e2e_invoke`. Handles
/// archived entry restoration for Protocol 23+ by checking hot archive state
/// and tracking which entries are actually being restored.
fn encode_footprint_entries(
    soroban_data: &SorobanTransactionData,
    snapshot: &LedgerSnapshotAdapter<'_>,
    context: &LedgerContext,
    soroban_config: &SorobanConfig,
) -> Result<EncodedFootprint, SorobanExecutionError> {
    let make_setup_error = make_xdr_setup_error;
    let current_ledger = context.sequence;

    // Extract archived entry indices from soroban_data.ext for TTL restoration
    let restored_rw_entry_indices: Vec<u32> = match &soroban_data.ext {
        SorobanTransactionDataExt::V1(ext) => {
            ext.archived_soroban_entries.iter().copied().collect()
        }
        SorobanTransactionDataExt::V0 => Vec::new(),
    };
    let restored_indices_set: std::collections::HashSet<u32> =
        restored_rw_entry_indices.iter().copied().collect();

    let mut encoded_ledger_entries = Vec::new();
    let mut encoded_ttl_entries = Vec::new();

    // Helper to encode an entry and its TTL, returning the encoded bytes.
    let encode_entry = |key: &LedgerKey,
                        entry: &soroban_env_host24::xdr::LedgerEntry,
                        live_until: Option<u32>|
     -> Result<(Vec<u8>, Vec<u8>), SorobanExecutionError> {
        let entry_bytes = xdr_encode_p24_setup(entry)?;

        let needs_ttl = matches!(key, LedgerKey::ContractData(_) | LedgerKey::ContractCode(_));
        let ttl_bytes = if let Some(lu) = live_until {
            let key_hash = compute_key_hash(key);
            xdr_encode_p24_setup(&soroban_env_host24::xdr::TtlEntry {
                key_hash: soroban_env_host24::xdr::Hash(key_hash.0),
                live_until_ledger_seq: lu,
            })?
        } else if needs_ttl {
            let key_hash = compute_key_hash(key);
            xdr_encode_p24_setup(&soroban_env_host24::xdr::TtlEntry {
                key_hash: soroban_env_host24::xdr::Hash(key_hash.0),
                live_until_ledger_seq: current_ledger,
            })?
        } else {
            Vec::new()
        };

        Ok((entry_bytes, ttl_bytes))
    };

    // Read-only footprint entries
    for key in soroban_data.resources.footprint.read_only.iter() {
        let key_p24 = convert_ledger_key_to_p24(key).ok_or_else(make_setup_error)?;
        if let Some((entry, live_until)) =
            snapshot
                .get(&Rc::new(key_p24))
                .map_err(|e| SorobanExecutionError {
                    host_error: convert_host_error_p24_to_p25(e),
                    cpu_insns_consumed: 0,
                    mem_bytes_consumed: 0,
                })?
        {
            let (le, ttl) = encode_entry(key, &entry, live_until)?;
            encoded_ledger_entries.push(le);
            encoded_ttl_entries.push(ttl);
        }
        // If entry not found, skip it — e2e_invoke's footprint loop will
        // add it to the storage map as None (entry doesn't exist yet).
    }

    if !restored_indices_set.is_empty() {
        tracing::debug!(
            restored_count = restored_rw_entry_indices.len(),
            restored_indices = ?restored_rw_entry_indices,
            "P24: Transaction has archived entries to restore"
        );
    }

    let mut live_bl_restores: Vec<super::protocol::LiveBucketListRestore> = Vec::new();
    let mut actual_restored_indices: Vec<u32> = Vec::new();
    let mut restored_entries: std::collections::HashMap<LedgerKey, (LedgerEntry, u32)> =
        std::collections::HashMap::new();

    // Read-write footprint entries (with archived entry restoration)
    for (idx, key) in soroban_data
        .resources
        .footprint
        .read_write
        .iter()
        .enumerate()
    {
        let key_p24 = convert_ledger_key_to_p24(key).ok_or_else(make_setup_error)?;

        let is_being_restored = restored_indices_set.contains(&(idx as u32));
        if is_being_restored {
            let result = snapshot
                .get_archived_with_restore_info(&Rc::new(key_p24), key)
                .map_err(|e| SorobanExecutionError {
                    host_error: convert_host_error_p24_to_p25(e),
                    cpu_insns_consumed: 0,
                    mem_bytes_consumed: 0,
                })?;
            if let Some((entry, live_until, live_bl_restore)) = result {
                let is_actually_archived = match live_until {
                    None => true,
                    Some(lu) => lu < context.sequence,
                };

                if is_actually_archived {
                    let restored_live_until =
                        Some(context.sequence + soroban_config.min_persistent_entry_ttl - 1);
                    tracing::info!(
                        idx = idx,
                        key_type = ?std::mem::discriminant(key),
                        old_live_until = ?live_until,
                        restored_live_until = ?restored_live_until,
                        current_ledger = context.sequence,
                        is_live_bl_restore = live_bl_restore.is_some(),
                        "P24: Archived entry found for restoration"
                    );
                    let (le, ttl) = encode_entry(key, &entry, restored_live_until)?;
                    encoded_ledger_entries.push(le);
                    encoded_ttl_entries.push(ttl);
                    actual_restored_indices.push(idx as u32);
                    if let Some(restore) = live_bl_restore {
                        live_bl_restores.push(restore);
                    }
                    // Capture the curr-format entry for read-only restoration tracking.
                    // Even if the host only reads this entry (no storage change emitted),
                    // we need to record it in the delta. See parity note in get_curr_archived.
                    if let Some((curr_entry, _)) = snapshot.get_curr_archived(key) {
                        if let Some(lu) = restored_live_until {
                            restored_entries.insert(key.clone(), (curr_entry, lu));
                        }
                    }
                } else {
                    tracing::debug!(
                        idx = idx,
                        key_type = ?std::mem::discriminant(key),
                        live_until = ?live_until,
                        "P24: Entry marked for restore but already live (restored by earlier TX)"
                    );
                    let (le, ttl) = encode_entry(key, &entry, live_until)?;
                    encoded_ledger_entries.push(le);
                    encoded_ttl_entries.push(ttl);
                }
            }
            // If archived entry not found, skip it — e2e_invoke's footprint
            // loop will add it to the storage map as None.
        } else {
            if let Some((entry, live_until)) =
                snapshot
                    .get(&Rc::new(key_p24))
                    .map_err(|e| SorobanExecutionError {
                        host_error: convert_host_error_p24_to_p25(e),
                        cpu_insns_consumed: 0,
                        mem_bytes_consumed: 0,
                    })?
            {
                let (le, ttl) = encode_entry(key, &entry, live_until)?;
                encoded_ledger_entries.push(le);
                encoded_ttl_entries.push(ttl);
            }
            // If entry not found, skip it — e2e_invoke's footprint loop will
            // add it to the storage map as None (entry doesn't exist yet).
        }
    }

    Ok(EncodedFootprint {
        ledger_entries: encoded_ledger_entries,
        ttl_entries: encoded_ttl_entries,
        actual_restored_indices,
        live_bl_restores,
        restored_entries,
    })
}

#[allow(clippy::too_many_arguments)]
fn execute_host_function_p24(
    host_function: &HostFunction,
    auth_entries: &[SorobanAuthorizationEntry],
    source: &AccountId,
    state: &LedgerStateManager,
    context: &LedgerContext,
    soroban_data: &SorobanTransactionData,
    soroban_config: &SorobanConfig,
    existing_cache: Option<&ModuleCache>,
    hot_archive: Option<&dyn super::HotArchiveLookup>,
) -> Result<SorobanExecutionResult, SorobanExecutionError> {
    // Create budget with network cost parameters.
    // stellar-core passes the per-transaction specified instruction limit directly
    // to the host (mResources.instructions in InvokeHostFunctionOpFrame.cpp line 547).
    // The memory limit comes from the network config (ledger_info.memory_limit).
    let instruction_limit = soroban_data.resources.instructions as u64;
    let memory_limit = soroban_config.tx_max_memory_bytes;

    let budget = if soroban_config.has_valid_cost_params() {
        let cpu_cost_params = convert_contract_cost_params_to_p24(&soroban_config.cpu_cost_params)
            .ok_or_else(make_xdr_setup_error)?;
        let mem_cost_params = convert_contract_cost_params_to_p24(&soroban_config.mem_cost_params)
            .ok_or_else(make_xdr_setup_error)?;
        Budget::try_from_configs(
            instruction_limit,
            memory_limit,
            cpu_cost_params,
            mem_cost_params,
        )
        .map_err(|e| SorobanExecutionError {
            host_error: convert_host_error_p24_to_p25(e),
            cpu_insns_consumed: 0,
            mem_bytes_consumed: 0,
        })?
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
        "Soroban host ledger info configured"
    );

    // Use PRNG seed from context if provided (computed as subSha256(txSetHash, txIndex)),
    // otherwise fall back to a deterministic but incorrect seed based on ledger info.
    let seed: Vec<u8> = if let Some(prng_seed) = context.soroban_prng_seed {
        prng_seed.to_vec()
    } else {
        // Fallback: use ledger info to generate a deterministic but incorrect seed.
        // This will cause Soroban contract results to differ from stellar-core.
        tracing::warn!("Using fallback PRNG seed - results may differ from stellar-core");
        let mut hasher = Sha256::new();
        hasher.update(context.network_id.0 .0);
        hasher.update(context.sequence.to_le_bytes());
        hasher.update(context.close_time.to_le_bytes());
        hasher.finalize().to_vec()
    };

    // Encode all data to XDR bytes for e2e_invoke
    let encoded_host_fn = xdr_encode_setup(host_function)?;
    let encoded_resources = xdr_encode_setup(&soroban_data.resources)?;
    let encoded_source = xdr_encode_setup(source)?;
    let encoded_auth_entries: Vec<Vec<u8>> = auth_entries
        .iter()
        .map(|e| xdr_encode_setup(e))
        .collect::<Result<_, _>>()?;

    // Create snapshot adapter with hot archive access for Protocol 23+ entry restoration
    let snapshot = LedgerSnapshotAdapter::with_hot_archive(state, context.sequence, hot_archive);

    // Collect and encode ledger entries from the footprint
    let EncodedFootprint {
        ledger_entries: encoded_ledger_entries,
        ttl_entries: encoded_ttl_entries,
        actual_restored_indices,
        live_bl_restores,
        restored_entries: footprint_restored_entries,
    } = encode_footprint_entries(soroban_data, &snapshot, context, soroban_config)?;

    // Use existing module cache — it must always be provided.
    let cache_start = std::time::Instant::now();
    let module_cache = existing_cache.unwrap_or_else(|| {
        panic!(
            "P24: Module cache is not available — this is a bug. \
            The persistent module cache should always be initialized before TX execution."
        )
    });
    let module_cache = Some(module_cache.clone());
    let cache_elapsed = cache_start.elapsed();
    tracing::info!(
        cache_ms = cache_elapsed.as_millis() as u64,
        "P24: Module cache ready"
    );

    // Call e2e_invoke - iterator yields &Vec<u8> which implements AsRef<[u8]>
    let invoke_start = std::time::Instant::now();
    tracing::debug!(
        instruction_limit,
        memory_limit,
        ledger_entries_count = encoded_ledger_entries.len(),
        ttl_entries_count = encoded_ttl_entries.len(),
        "P24: About to call e2e_invoke"
    );
    let mut diagnostic_events: Vec<soroban_env_host24::xdr::DiagnosticEvent> = Vec::new();
    let result = match e2e_invoke::invoke_host_function(
        &budget,
        true, // enable_diagnostics
        &encoded_host_fn,
        &encoded_resources,
        &actual_restored_indices,
        &encoded_source,
        encoded_auth_entries.iter(),
        ledger_info,
        encoded_ledger_entries.iter(),
        encoded_ttl_entries.iter(),
        &seed,
        &mut diagnostic_events,
        None, // trace_hook
        module_cache,
    ) {
        Ok(r) => {
            let invoke_elapsed = invoke_start.elapsed();
            tracing::info!(
                invoke_ms = invoke_elapsed.as_millis() as u64,
                cpu_consumed = budget.get_cpu_insns_consumed().unwrap_or(0),
                mem_consumed = budget.get_mem_bytes_consumed().unwrap_or(0),
                "P24: e2e_invoke completed successfully"
            );
            r
        }
        Err(e) => {
            tracing::debug!(
                error = %e,
                cpu_consumed = budget.get_cpu_insns_consumed().unwrap_or(0),
                mem_consumed = budget.get_mem_bytes_consumed().unwrap_or(0),
                "P24: e2e_invoke returned error"
            );
            return Err(SorobanExecutionError {
                host_error: convert_host_error_p24_to_p25(e),
                cpu_insns_consumed: budget.get_cpu_insns_consumed().unwrap_or(0),
                mem_bytes_consumed: budget.get_mem_bytes_consumed().unwrap_or(0),
            });
        }
    };

    // Parse the result
    let (return_value, return_value_size) = match result.encoded_invoke_result {
        Ok(ref bytes) => {
            let val = ScVal::from_xdr(bytes, Limits::none()).unwrap_or(ScVal::Void);
            (val, bytes.len() as u32)
        }
        Err(ref e) => {
            tracing::debug!(
                error = %e,
                "P24: e2e_invoke result contained error"
            );
            return Err(SorobanExecutionError {
                host_error: convert_host_error_p24_to_p25(e.clone()),
                cpu_insns_consumed: budget.get_cpu_insns_consumed().unwrap_or(0),
                mem_bytes_consumed: budget.get_mem_bytes_consumed().unwrap_or(0),
            });
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

    let rent_changes: Vec<LedgerEntryRentChange> =
        e2e_invoke::extract_rent_changes(&result.ledger_changes);

    // Debug: print rent_changes for P24
    if !rent_changes.is_empty() {
        tracing::debug!(
            rent_changes_count = rent_changes.len(),
            "P24: Extracted rent changes"
        );
        for (i, rc) in rent_changes.iter().enumerate() {
            tracing::debug!(
                idx = i,
                is_persistent = rc.is_persistent,
                old_size = rc.old_size_bytes,
                new_size = rc.new_size_bytes,
                old_live_until = rc.old_live_until_ledger,
                new_live_until = rc.new_live_until_ledger,
                "P24: Rent change details"
            );
        }
    }

    // Convert ledger changes to our format
    let storage_changes: Vec<crate::soroban::StorageChange> = result.ledger_changes
        .into_iter()
        .filter_map(|change| {
            // stellar-core behavior for transaction meta and state updates:
            //
            // 1. Transaction meta (setLedgerChangesFromSuccessfulOp): Uses raw res.getModifiedEntryMap()
            //    which includes ALL entries, including RO TTL bumps. RO TTL bumps ARE in transaction meta.
            // 2. State updates (commitChangesFromSuccessfulOp): Filters RO TTL bumps to mRoTTLBumps
            //    (not the entry map) and flushes them at write barriers. This is for visibility ordering.
            //
            // We track read-only TTL bumps with is_read_only_ttl_bump flag so they can be:
            // - Included in transaction meta (per stellar-core behavior)
            // - Deferred for state visibility (so subsequent TXs don't see the bump)
            
            let is_deletion = !change.read_only && change.encoded_new_value.is_none();
            let is_modification = change.encoded_new_value.is_some();
            
            // Determine if TTL was extended from the LEDGER-START perspective.
            // We pass current TTL to the host for rent calculation, but for emission
            // determination we need to compare against ledger-start TTL.
            let ttl_extended = change
                .ttl_change
                .as_ref()
                .map(|ttl| {
                    // Compare new TTL against ledger-start TTL, not host's old_live_until
                    let key = LedgerKey::from_xdr(&change.encoded_key, Limits::none()).ok();
                    if let Some(ref key) = key {
                        let key_hash = compute_key_hash(key);
                        let ledger_start_ttl = state.get_ttl_at_ledger_start(&key_hash).unwrap_or(0);
                        ttl.new_live_until_ledger > ledger_start_ttl
                    } else {
                        // Fallback to host's comparison if we can't decode the key
                        ttl.new_live_until_ledger > ttl.old_live_until_ledger
                    }
                })
                .unwrap_or(false);
            
            // A read-only TTL bump is when:
            // - Entry is read-only
            // - Entry wasn't modified (no encoded_new_value)
            // - TTL was extended
            // These should be applied to state but NOT included in transaction meta.
            let is_read_only_ttl_bump = change.read_only && !is_modification && ttl_extended;
            
            // Include entries that:
            // 1. Have a new value (were created or modified), OR
            // 2. Are NOT read-only and have no new value (were deleted), OR
            // 3. Have a TTL that was extended (for bucket list updates)
            // Note: read-only TTL bumps ARE included (for state/bucket list) but marked
            // so they can be filtered from transaction meta.
            let should_include = is_modification || is_deletion || ttl_extended;

            if should_include {
                let key = LedgerKey::from_xdr(&change.encoded_key, Limits::none()).ok()?;
                let new_entry = change.encoded_new_value.and_then(|bytes| {
                    LedgerEntry::from_xdr(&bytes, Limits::none()).ok()
                });
                // Get TTL from ttl_change if present
                let live_until = change.ttl_change.map(|ttl| ttl.new_live_until_ledger);
                let is_rent_related = change.old_entry_size_bytes_for_rent > 0;
                Some(StorageChange {
                    key,
                    new_entry,
                    live_until,
                    ttl_extended,
                    is_rent_related,
                    is_read_only_ttl_bump,
                })
            } else {
                tracing::info!(
                    key_type = ?LedgerKey::from_xdr(&change.encoded_key, Limits::none()).ok().map(|k| std::mem::discriminant(&k)),
                    read_only = change.read_only,
                    "P24: Skipping ledger change (not modified/deleted/rent-related/ttl-extended)"
                );
                None
            }
        })
        .collect();

    // Compute hot_archive_read_only_restored_entries: entries restored from hot archive
    // that the host did NOT emit storage changes for (read-only access).
    // These must be recorded in the delta to match stellar-core's behavior where
    // handleArchivedEntry unconditionally calls mOpState.upsertEntry(lk, le, ...).
    let hot_archive_read_only_restored_entries = {
        let emitted_keys: std::collections::HashSet<&LedgerKey> = storage_changes
            .iter()
            .filter(|c| c.new_entry.is_some())
            .map(|c| &c.key)
            .collect();
        footprint_restored_entries
            .into_iter()
            .filter(|(k, _)| !emitted_keys.contains(k))
            .collect::<std::collections::HashMap<_, _>>()
    };

    // Get budget consumption
    let cpu_insns = budget.get_cpu_insns_consumed().unwrap_or(0);
    let mem_bytes = budget.get_mem_bytes_consumed().unwrap_or(0);
    let contract_events_and_return_value_size =
        contract_events_size.saturating_add(return_value_size);
    let rent_fee_config = rent_fee_config_p25_to_p24(&soroban_config.rent_fee_config);
    let rent_fee = compute_rent_fee(&rent_changes, &rent_fee_config, context.sequence);
    tracing::debug!(
        computed_rent_fee = rent_fee,
        rent_changes_count = rent_changes.len(),
        ledger_seq = context.sequence,
        "P24: Computed rent fee"
    );
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
        live_bucket_list_restores: live_bl_restores,
        actual_restored_indices,
        hot_archive_read_only_restored_entries,
    })
}

#[allow(clippy::too_many_arguments)]
fn execute_host_function_p25(
    host_function: &HostFunction,
    auth_entries: &[SorobanAuthorizationEntry],
    source: &AccountId,
    state: &LedgerStateManager,
    context: &LedgerContext,
    soroban_data: &SorobanTransactionData,
    soroban_config: &SorobanConfig,
    existing_cache: Option<&ModuleCacheP25>,
    hot_archive: Option<&dyn super::HotArchiveLookup>,
) -> Result<SorobanExecutionResult, SorobanExecutionError> {
    use soroban_env_host25::{budget::Budget, e2e_invoke, fees::compute_rent_fee};

    // Helper to create error with zero consumed resources (for setup errors before budget exists)
    let make_setup_error = |e: HostErrorP25| SorobanExecutionError {
        host_error: e,
        cpu_insns_consumed: 0,
        mem_bytes_consumed: 0,
    };

    // stellar-core passes the per-transaction specified instruction limit directly
    // to the host (mResources.instructions in InvokeHostFunctionOpFrame.cpp line 547).
    // The memory limit comes from the network config (ledger_info.memory_limit).
    let instruction_limit = soroban_data.resources.instructions as u64;
    let memory_limit = soroban_config.tx_max_memory_bytes;

    let budget = if soroban_config.has_valid_cost_params() {
        let cpu_params = convert_contract_cost_params_to_p25(&soroban_config.cpu_cost_params)
            .ok_or_else(|| {
                make_setup_error(HostErrorP25::from(
                    soroban_env_host25::Error::from_type_and_code(
                        soroban_env_host25::xdr::ScErrorType::Context,
                        soroban_env_host25::xdr::ScErrorCode::InternalError,
                    ),
                ))
            })?;
        let mem_params = convert_contract_cost_params_to_p25(&soroban_config.mem_cost_params)
            .ok_or_else(|| {
                make_setup_error(HostErrorP25::from(
                    soroban_env_host25::Error::from_type_and_code(
                        soroban_env_host25::xdr::ScErrorType::Context,
                        soroban_env_host25::xdr::ScErrorCode::InternalError,
                    ),
                ))
            })?;
        Budget::try_from_configs(instruction_limit, memory_limit, cpu_params, mem_params)
            .map_err(make_setup_error)?
    } else {
        tracing::warn!("Using default Soroban budget - cost parameters not loaded from network.");
        Budget::default()
    };

    let ledger_info = soroban_env_host25::LedgerInfo {
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

    let encoded_host_fn = host_function.to_xdr(Limits::none()).map_err(|_e| {
        make_setup_error(HostErrorP25::from(
            soroban_env_host25::Error::from_type_and_code(
                soroban_env_host25::xdr::ScErrorType::Context,
                soroban_env_host25::xdr::ScErrorCode::InternalError,
            ),
        ))
    })?;

    let encoded_resources = soroban_data
        .resources
        .to_xdr(Limits::none())
        .map_err(|_e| {
            make_setup_error(HostErrorP25::from(
                soroban_env_host25::Error::from_type_and_code(
                    soroban_env_host25::xdr::ScErrorType::Context,
                    soroban_env_host25::xdr::ScErrorCode::InternalError,
                ),
            ))
        })?;

    let encoded_source = source.to_xdr(Limits::none()).map_err(|_e| {
        make_setup_error(HostErrorP25::from(
            soroban_env_host25::Error::from_type_and_code(
                soroban_env_host25::xdr::ScErrorType::Context,
                soroban_env_host25::xdr::ScErrorCode::InternalError,
            ),
        ))
    })?;

    let encoded_auth_entries: Vec<Vec<u8>> = auth_entries
        .iter()
        .map(|e| e.to_xdr(Limits::none()))
        .collect::<Result<_, _>>()
        .map_err(|_| {
            make_setup_error(HostErrorP25::from(
                soroban_env_host25::Error::from_type_and_code(
                    soroban_env_host25::xdr::ScErrorType::Context,
                    soroban_env_host25::xdr::ScErrorCode::InternalError,
                ),
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
    let restored_indices_set: std::collections::HashSet<u32> =
        restored_rw_entry_indices.iter().copied().collect();

    // Create snapshot with hot archive access for Protocol 23+ entry restoration
    let snapshot = LedgerSnapshotAdapterP25::with_hot_archive(state, context.sequence, hot_archive);

    let mut encoded_ledger_entries = Vec::new();
    let mut encoded_ttl_entries = Vec::new();
    let current_ledger_p25 = context.sequence;

    // Helper to encode an entry and its TTL, returning the encoded bytes.
    let encode_entry_p25 = |key: &LedgerKey,
                            entry: &LedgerEntry,
                            live_until: Option<u32>|
     -> Result<(Vec<u8>, Vec<u8>), SorobanExecutionError> {
        let entry_bytes = entry.to_xdr(Limits::none()).map_err(|_| {
            make_setup_error(HostErrorP25::from(
                soroban_env_host25::Error::from_type_and_code(
                    soroban_env_host25::xdr::ScErrorType::Context,
                    soroban_env_host25::xdr::ScErrorCode::InternalError,
                ),
            ))
        })?;

        let needs_ttl = matches!(key, LedgerKey::ContractData(_) | LedgerKey::ContractCode(_));
        let ttl_bytes = if let Some(lu) = live_until {
            let key_hash = compute_key_hash(key);
            let ttl_entry = stellar_xdr::curr::TtlEntry {
                key_hash,
                live_until_ledger_seq: lu,
            };
            ttl_entry.to_xdr(Limits::none()).map_err(|_| {
                make_setup_error(HostErrorP25::from(
                    soroban_env_host25::Error::from_type_and_code(
                        soroban_env_host25::xdr::ScErrorType::Context,
                        soroban_env_host25::xdr::ScErrorCode::InternalError,
                    ),
                ))
            })?
        } else if needs_ttl {
            let key_hash = compute_key_hash(key);
            let ttl_entry = stellar_xdr::curr::TtlEntry {
                key_hash,
                live_until_ledger_seq: current_ledger_p25,
            };
            ttl_entry.to_xdr(Limits::none()).map_err(|_| {
                make_setup_error(HostErrorP25::from(
                    soroban_env_host25::Error::from_type_and_code(
                        soroban_env_host25::xdr::ScErrorType::Context,
                        soroban_env_host25::xdr::ScErrorCode::InternalError,
                    ),
                ))
            })?
        } else {
            Vec::new()
        };

        Ok((entry_bytes, ttl_bytes))
    };

    for key in soroban_data.resources.footprint.read_only.iter() {
        if let Some((entry, live_until)) = snapshot.get_local(key).map_err(make_setup_error)? {
            let (le, ttl) = encode_entry_p25(key, entry.as_ref(), live_until)?;
            encoded_ledger_entries.push(le);
            encoded_ttl_entries.push(ttl);
        }
        // If entry not found, skip it — e2e_invoke's footprint loop will
        // add it to the storage map as None (entry doesn't exist yet).
    }

    if !restored_indices_set.is_empty() {
        tracing::debug!(
            restored_count = restored_rw_entry_indices.len(),
            restored_indices = ?restored_rw_entry_indices,
            "P25: Transaction has archived entries to restore"
        );
    }

    // Track entries restored from live BucketList (expired TTL but not yet evicted)
    let mut live_bl_restores: Vec<super::protocol::LiveBucketListRestore> = Vec::new();

    // Track entries restored from hot archive in curr format for read-only restoration handling.
    let mut p25_restored_entries: std::collections::HashMap<LedgerKey, (LedgerEntry, u32)> =
        std::collections::HashMap::new();

    // Build the ACTUAL list of indices being restored in THIS transaction.
    // The transaction envelope's archived_soroban_entries may list indices that were
    // already restored by a previous transaction in the same ledger. We only want to
    // tell the host about entries that are ACTUALLY being restored now.
    // This matches stellar-core's previouslyRestoredFromHotArchive() check.
    let mut actual_restored_indices: Vec<u32> = Vec::new();

    for (idx, key) in soroban_data
        .resources
        .footprint
        .read_write
        .iter()
        .enumerate()
    {
        // For archived entries being restored, use get_archived_with_restore_info
        let is_being_restored = restored_indices_set.contains(&(idx as u32));
        if is_being_restored {
            let result = snapshot
                .get_archived_with_restore_info(&Rc::new(key.clone()))
                .map_err(make_setup_error)?;
            if let Some((entry, live_until, live_bl_restore)) = result {
                // Check if this entry is ACTUALLY archived (needs restoration).
                // An entry is considered archived if:
                // 1. It has no TTL (live_until is None) - from hot archive
                // 2. Its TTL is expired (live_until < current_ledger) - live BL restore
                //
                // If the entry has a valid TTL >= current_ledger, it was already restored
                // by a previous transaction in this ledger and should be treated as live.
                let is_actually_archived = match live_until {
                    None => true,                      // From hot archive
                    Some(lu) => lu < context.sequence, // Live BL with expired TTL
                };

                if is_actually_archived {
                    // Entry is actually being restored - use restored TTL
                    let restored_live_until =
                        Some(context.sequence + soroban_config.min_persistent_entry_ttl - 1);
                    tracing::info!(
                        idx = idx,
                        key_type = ?std::mem::discriminant(key),
                        old_live_until = ?live_until,
                        restored_live_until = ?restored_live_until,
                        is_live_bl_restore = live_bl_restore.is_some(),
                        "P25: Archived entry found for restoration"
                    );
                    let (le, ttl) = encode_entry_p25(key, entry.as_ref(), restored_live_until)?;
                    encoded_ledger_entries.push(le);
                    encoded_ttl_entries.push(ttl);

                    // Track this index as actually being restored
                    actual_restored_indices.push(idx as u32);

                    // Track live BL restorations
                    if let Some(restore) = live_bl_restore {
                        live_bl_restores.push(restore);
                    }

                    // Capture the curr-format entry for read-only restoration tracking.
                    // Even if the host only reads this entry (no storage change emitted),
                    // we need to record it in the delta (parity with stellar-core handleArchivedEntry).
                    if let Some(lu) = restored_live_until {
                        if let Ok(Some((curr_entry, _))) = snapshot.get_archived(&Rc::new(key.clone())) {
                            p25_restored_entries.insert(key.clone(), ((*curr_entry).clone(), lu));
                        }
                    }
                } else {
                    // Entry is already live (restored by previous TX in this ledger).
                    // Treat it as a normal live entry, don't add to restored indices.
                    tracing::debug!(
                        idx = idx,
                        key_type = ?std::mem::discriminant(key),
                        live_until = ?live_until,
                        "P25: Entry marked for restore but already live (restored by earlier TX)"
                    );
                    let (le, ttl) = encode_entry_p25(key, entry.as_ref(), live_until)?;
                    encoded_ledger_entries.push(le);
                    encoded_ttl_entries.push(ttl);
                }
            }
            // If archived entry not found, skip it — e2e_invoke's footprint
            // loop will add it to the storage map as None.
        } else {
            // Normal entry - use standard TTL-filtered lookup
            if let Some((entry, live_until)) = snapshot.get_local(key).map_err(make_setup_error)? {
                let (le, ttl) = encode_entry_p25(key, entry.as_ref(), live_until)?;
                encoded_ledger_entries.push(le);
                encoded_ttl_entries.push(ttl);
            }
            // If entry not found, skip it — e2e_invoke's footprint loop will
            // add it to the storage map as None (entry doesn't exist yet).
        }
    }

    // Use existing module cache — it must always be provided.
    let module_cache = existing_cache.unwrap_or_else(|| {
        panic!(
            "P25: Module cache is not available — this is a bug. \
            The persistent module cache should always be initialized before TX execution."
        )
    });
    let module_cache = Some(module_cache.clone());

    let mut diagnostic_events: Vec<soroban_env_host25::xdr::DiagnosticEvent> = Vec::new();

    let result = match e2e_invoke::invoke_host_function(
        &budget,
        true,
        &encoded_host_fn,
        &encoded_resources,
        &actual_restored_indices,
        &encoded_source,
        encoded_auth_entries.iter(),
        ledger_info,
        encoded_ledger_entries.iter(),
        encoded_ttl_entries.iter(),
        &seed,
        &mut diagnostic_events,
        None,
        module_cache,
    ) {
        Ok(r) => r,
        Err(e) => {
            let cpu_insns_consumed = budget.get_cpu_insns_consumed().unwrap_or(0);
            let mem_bytes_consumed = budget.get_mem_bytes_consumed().unwrap_or(0);
            tracing::warn!(
                cpu_consumed = cpu_insns_consumed,
                mem_consumed = mem_bytes_consumed,
                error = %e,
                "P25: e2e_invoke failed"
            );
            for (i, event) in diagnostic_events.iter().enumerate() {
                use soroban_env_host25::xdr::WriteXdr as _;
                if let Ok(encoded) = event.to_xdr(soroban_env_host25::xdr::Limits::none()) {
                    tracing::warn!(
                        event_idx = i,
                        event_hex = hex::encode(&encoded),
                        "P25: Diagnostic event"
                    );
                }
            }
            return Err(SorobanExecutionError {
                host_error: e,
                cpu_insns_consumed,
                mem_bytes_consumed,
            });
        }
    };

    let (return_value, return_value_size) = match result.encoded_invoke_result {
        Ok(ref bytes) => {
            let val = ScVal::from_xdr(bytes, Limits::none()).unwrap_or(ScVal::Void);
            (val, bytes.len() as u32)
        }
        Err(ref e) => {
            let cpu_insns_consumed = budget.get_cpu_insns_consumed().unwrap_or(0);
            let mem_bytes_consumed = budget.get_mem_bytes_consumed().unwrap_or(0);
            tracing::debug!(
                cpu_consumed = cpu_insns_consumed,
                mem_consumed = mem_bytes_consumed,
                diagnostic_events = diagnostic_events.len(),
                error = %e,
                "P25: Soroban invoke_result error"
            );
            // Log diagnostic events for debugging crypto errors
            for (i, event) in diagnostic_events.iter().enumerate() {
                use soroban_env_host25::xdr::WriteXdr as _;
                if let Ok(encoded) = event.to_xdr(soroban_env_host25::xdr::Limits::none()) {
                    tracing::debug!(
                        event_idx = i,
                        event_hex = hex::encode(&encoded),
                        "P25: Diagnostic event from invoke_result error"
                    );
                }
            }
            return Err(SorobanExecutionError {
                host_error: e.clone(),
                cpu_insns_consumed,
                mem_bytes_consumed,
            });
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

    let rent_changes: Vec<soroban_env_host25::fees::LedgerEntryRentChange> =
        e2e_invoke::extract_rent_changes(&result.ledger_changes);

    let storage_changes: Vec<crate::soroban::StorageChange> = result
        .ledger_changes
        .into_iter()
        .filter_map(|change| {
            // stellar-core behavior: RO TTL bumps ARE included in transaction meta.
            // State updates defer them to mRoTTLBumps for visibility ordering, but that's
            // separate from meta. See setLedgerChangesFromSuccessfulOp vs commitChangesFromSuccessfulOp.
            let is_deletion = !change.read_only && change.encoded_new_value.is_none();
            let is_modification = change.encoded_new_value.is_some();
            let is_rent_related = change.old_entry_size_bytes_for_rent > 0;

            // Determine if TTL was extended from the LEDGER-START perspective.
            let ttl_extended = change
                .ttl_change
                .as_ref()
                .map(|ttl| {
                    // Compare new TTL against ledger-start TTL, not host's old_live_until
                    let key = LedgerKey::from_xdr(&change.encoded_key, Limits::none()).ok();
                    if let Some(ref key) = key {
                        let key_hash = compute_key_hash(key);
                        let ledger_start_ttl =
                            state.get_ttl_at_ledger_start(&key_hash).unwrap_or(0);
                        ttl.new_live_until_ledger > ledger_start_ttl
                    } else {
                        // Fallback to host's comparison if we can't decode the key
                        ttl.new_live_until_ledger > ttl.old_live_until_ledger
                    }
                })
                .unwrap_or(false);

            // A read-only TTL bump is when entry is read-only, wasn't modified, but TTL extended.
            // These should be applied to state but NOT included in transaction meta.
            let is_read_only_ttl_bump = change.read_only && !is_modification && ttl_extended;

            if is_modification || is_deletion || ttl_extended {
                let key = LedgerKey::from_xdr(&change.encoded_key, Limits::none()).ok()?;
                let new_entry = change
                    .encoded_new_value
                    .and_then(|bytes| LedgerEntry::from_xdr(&bytes, Limits::none()).ok());
                let live_until = change.ttl_change.map(|ttl| ttl.new_live_until_ledger);
                Some(StorageChange {
                    key,
                    new_entry,
                    live_until,
                    ttl_extended,
                    is_rent_related,
                    is_read_only_ttl_bump,
                })
            } else {
                None
            }
        })
        .collect();

    // Compute hot_archive_read_only_restored_entries for P25 (same logic as P24).
    let hot_archive_read_only_restored_entries = {
        let emitted_keys: std::collections::HashSet<&LedgerKey> = storage_changes
            .iter()
            .filter(|c| c.new_entry.is_some())
            .map(|c| &c.key)
            .collect();
        p25_restored_entries
            .into_iter()
            .filter(|(k, _)| !emitted_keys.contains(k))
            .collect::<std::collections::HashMap<_, _>>()
    };

    let cpu_insns = budget.get_cpu_insns_consumed().unwrap_or(0);
    let mem_bytes = budget.get_mem_bytes_consumed().unwrap_or(0);
    let contract_events_and_return_value_size =
        contract_events_size.saturating_add(return_value_size);
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
        live_bucket_list_restores: live_bl_restores,
        actual_restored_indices,
        hot_archive_read_only_restored_entries,
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
    use stellar_xdr::curr::LedgerEntryData;

    #[test]
    fn test_compute_key_hash() {
        let key = LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
            hash: Hash([1u8; 32]),
        });
        let hash = compute_key_hash(&key);
        assert_ne!(hash.0, [0u8; 32]);
    }

    /// Test compute_key_hash produces different hashes for different keys.
    #[test]
    fn test_compute_key_hash_different_keys() {
        let key1 = LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
            hash: Hash([1u8; 32]),
        });
        let key2 = LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
            hash: Hash([2u8; 32]),
        });

        let hash1 = compute_key_hash(&key1);
        let hash2 = compute_key_hash(&key2);

        assert_ne!(hash1, hash2);
    }

    /// Test compute_key_hash is deterministic.
    #[test]
    fn test_compute_key_hash_deterministic() {
        let key = LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
            hash: Hash([42u8; 32]),
        });

        let hash1 = compute_key_hash(&key);
        let hash2 = compute_key_hash(&key);

        assert_eq!(hash1, hash2);
    }

    /// Test compute_key_hash with ContractData key.
    #[test]
    fn test_compute_key_hash_contract_data() {
        use stellar_xdr::curr::{ContractDataDurability, LedgerKeyContractData, ScAddress};

        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(stellar_xdr::curr::ContractId(Hash([3u8; 32]))),
            key: ScVal::U32(100),
            durability: ContractDataDurability::Persistent,
        });

        let hash = compute_key_hash(&key);
        assert_ne!(hash.0, [0u8; 32]);
    }

    /// Test StorageChange struct with new entry (create/update).
    #[test]
    fn test_storage_change_with_new_entry() {
        let change = StorageChange {
            key: LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
                hash: Hash([4u8; 32]),
            }),
            new_entry: Some(LedgerEntry {
                last_modified_ledger_seq: 100,
                data: LedgerEntryData::ContractCode(stellar_xdr::curr::ContractCodeEntry {
                    ext: stellar_xdr::curr::ContractCodeEntryExt::V0,
                    hash: Hash([4u8; 32]),
                    code: vec![0xDE, 0xAD].try_into().unwrap(),
                }),
                ext: stellar_xdr::curr::LedgerEntryExt::V0,
            }),
            live_until: Some(1000),
            ttl_extended: false,
            is_rent_related: false,
            is_read_only_ttl_bump: false,
        };

        assert!(change.new_entry.is_some());
        assert_eq!(change.live_until, Some(1000));
    }

    /// Test StorageChange struct with TTL extension.
    #[test]
    fn test_storage_change_ttl_extended() {
        let change = StorageChange {
            key: LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
                hash: Hash([5u8; 32]),
            }),
            new_entry: None,
            live_until: Some(2000),
            ttl_extended: true,
            is_rent_related: true,
            is_read_only_ttl_bump: true,
        };

        assert!(change.ttl_extended);
        assert!(change.is_rent_related);
        assert!(change.is_read_only_ttl_bump);
    }

    /// Test StorageChange struct representing a delete (new_entry = None).
    #[test]
    fn test_storage_change_delete() {
        let change = StorageChange {
            key: LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
                hash: Hash([6u8; 32]),
            }),
            new_entry: None,
            live_until: None,
            ttl_extended: false,
            is_rent_related: false,
            is_read_only_ttl_bump: false,
        };

        assert!(change.new_entry.is_none());
        assert!(change.live_until.is_none());
        assert!(matches!(change.key, LedgerKey::ContractCode(_)));
    }
}
