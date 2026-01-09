//! In-memory Soroban state management for fast contract data access.
//!
//! This module provides an efficient in-memory cache for Soroban contract data
//! and code entries, with co-located TTL information to avoid redundant lookups.
//!
//! # Design Overview
//!
//! The [`InMemorySorobanState`] struct maintains three storage structures:
//!
//! - **Contract data entries**: Maps key hash -> (entry, TTL)
//! - **Contract code entries**: Maps key hash -> (entry, TTL, size)
//! - **Pending TTLs**: Temporary buffer for TTLs that arrive before their entries
//!
//! # TTL Co-location
//!
//! Unlike the bucket list where TTL entries are stored separately, this cache
//! embeds TTL data directly with each entry. This:
//!
//! - Reduces memory footprint (no duplicate key storage)
//! - Enables single-lookup operations (get entry + TTL together)
//! - Simplifies rent calculations during transaction execution
//!
//! # Size Tracking
//!
//! For Protocol 23+ rent calculations, the cache tracks:
//!
//! - **Contract data state size**: Sum of XDR sizes for all data entries
//! - **Contract code state size**: Sum of in-memory compiled module sizes
//!
//! # Initialization
//!
//! The cache is initialized from a bucket list snapshot during catchup or
//! restart. Entries may arrive in any order during this process, so the
//! `pending_ttls` map temporarily holds TTLs until their corresponding
//! data/code entries arrive.
//!
//! # Thread Safety
//!
//! The state is wrapped in `RwLock` at the manager level, allowing:
//!
//! - Concurrent reads during transaction execution
//! - Exclusive writes during ledger close/commit

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use stellar_core_common::Hash256;
use stellar_xdr::curr::{
    LedgerEntry, LedgerEntryData, LedgerKey, LedgerKeyContractCode, LedgerKeyContractData,
    LedgerKeyTtl, Limits, TtlEntry, WriteXdr,
};
use tracing::{debug, trace, warn};

use crate::{LedgerError, Result};

/// TTL data co-located with contract entries.
///
/// This structure stores the essential TTL information alongside
/// contract data/code entries, avoiding the need to store separate
/// TTL entries.
#[derive(Debug, Clone, Copy, Default)]
pub struct TtlData {
    /// The ledger sequence number when this entry expires.
    pub live_until_ledger_seq: u32,
    /// The ledger sequence number when this entry was last modified.
    pub last_modified_ledger_seq: u32,
}

impl TtlData {
    /// Create new TTL data.
    pub fn new(live_until: u32, last_modified: u32) -> Self {
        Self {
            live_until_ledger_seq: live_until,
            last_modified_ledger_seq: last_modified,
        }
    }

    /// Check if the entry has expired at the given ledger sequence.
    pub fn is_expired(&self, current_ledger_seq: u32) -> bool {
        self.live_until_ledger_seq < current_ledger_seq
    }

    /// Check if TTL data is initialized (non-default).
    pub fn is_initialized(&self) -> bool {
        self.live_until_ledger_seq > 0
    }
}

/// A contract data entry with co-located TTL.
#[derive(Debug, Clone)]
pub struct ContractDataMapEntry {
    /// The contract data ledger entry (immutable).
    pub ledger_entry: Arc<LedgerEntry>,
    /// TTL data co-located with the entry.
    pub ttl_data: TtlData,
}

impl ContractDataMapEntry {
    /// Get the XDR size of this entry.
    pub fn xdr_size(&self) -> u32 {
        self.ledger_entry
            .to_xdr(Limits::none())
            .map(|v| v.len() as u32)
            .unwrap_or(0)
    }
}

/// A contract code entry with co-located TTL and size tracking.
#[derive(Debug, Clone)]
pub struct ContractCodeMapEntry {
    /// The contract code ledger entry (immutable).
    pub ledger_entry: Arc<LedgerEntry>,
    /// TTL data co-located with the entry.
    pub ttl_data: TtlData,
    /// In-memory size of the compiled module (for rent calculations).
    ///
    /// Protocol 23+ uses this for rent fees, which may differ from XDR size
    /// due to compilation overhead.
    pub size_bytes: u32,
}

impl ContractCodeMapEntry {
    /// Get the XDR size of this entry.
    pub fn xdr_size(&self) -> u32 {
        self.ledger_entry
            .to_xdr(Limits::none())
            .map(|v| v.len() as u32)
            .unwrap_or(0)
    }
}

/// In-memory cache for Soroban contract state.
///
/// This cache provides fast access to contract data and code entries with
/// co-located TTL information. It's used during transaction execution to
/// avoid repeated bucket list lookups.
///
/// # Invariants
///
/// - `pending_ttls` must be empty after initialization and after each update
/// - `last_closed_ledger_seq` must match the ledger manager's tracking
/// - Size counters must match the sum of individual entry sizes
pub struct InMemorySorobanState {
    /// Contract data entries indexed by TTL key hash.
    ///
    /// Uses the TTL key hash as index to enable lookup by either
    /// CONTRACT_DATA key or TTL key without key duplication.
    contract_data_entries: HashMap<[u8; 32], ContractDataMapEntry>,

    /// Contract code entries indexed by TTL key hash.
    contract_code_entries: HashMap<[u8; 32], ContractCodeMapEntry>,

    /// Pending TTLs waiting for their entries.
    ///
    /// During initialization, TTL entries may arrive before their corresponding
    /// data/code entries. They're stored here temporarily until adopted.
    pending_ttls: HashMap<[u8; 32], TtlData>,

    /// Last closed ledger sequence number.
    last_closed_ledger_seq: u32,

    /// Cumulative XDR size of all contract data entries.
    contract_data_state_size: i64,

    /// Cumulative in-memory size of all contract code entries.
    contract_code_state_size: i64,
}

impl Default for InMemorySorobanState {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemorySorobanState {
    /// Create a new empty in-memory Soroban state.
    pub fn new() -> Self {
        Self {
            contract_data_entries: HashMap::new(),
            contract_code_entries: HashMap::new(),
            pending_ttls: HashMap::new(),
            last_closed_ledger_seq: 0,
            contract_data_state_size: 0,
            contract_code_state_size: 0,
        }
    }

    /// Check if the state is empty.
    pub fn is_empty(&self) -> bool {
        self.contract_data_entries.is_empty()
            && self.contract_code_entries.is_empty()
            && self.pending_ttls.is_empty()
    }

    /// Get the last closed ledger sequence number.
    pub fn ledger_seq(&self) -> u32 {
        self.last_closed_ledger_seq
    }

    /// Get the total state size (data + code).
    pub fn total_size(&self) -> u64 {
        (self.contract_data_state_size + self.contract_code_state_size) as u64
    }

    /// Get the number of contract data entries.
    pub fn contract_data_count(&self) -> usize {
        self.contract_data_entries.len()
    }

    /// Get the number of contract code entries.
    pub fn contract_code_count(&self) -> usize {
        self.contract_code_entries.len()
    }

    /// Get the total contract data state size in bytes.
    pub fn contract_data_state_size(&self) -> i64 {
        self.contract_data_state_size
    }

    /// Get the total contract code state size in bytes.
    pub fn contract_code_state_size(&self) -> i64 {
        self.contract_code_state_size
    }

    /// Check if a key type should be stored in memory.
    pub fn is_in_memory_type(key: &LedgerKey) -> bool {
        matches!(
            key,
            LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) | LedgerKey::Ttl(_)
        )
    }

    /// Compute the TTL key hash for a CONTRACT_DATA key.
    pub fn contract_data_key_hash(key: &LedgerKeyContractData) -> [u8; 32] {
        // Create a TTL key from the contract data key
        let ttl_key = LedgerKey::Ttl(LedgerKeyTtl {
            key_hash: Hash256::hash_xdr(&LedgerKey::ContractData(key.clone()))
                .map(|h| stellar_xdr::curr::Hash(*h.as_bytes()))
                .unwrap_or_else(|_| stellar_xdr::curr::Hash([0u8; 32])),
        });

        // Hash the TTL key itself as the map key
        Hash256::hash_xdr(&ttl_key)
            .map(|h| *h.as_bytes())
            .unwrap_or([0u8; 32])
    }

    /// Compute the TTL key hash for a CONTRACT_CODE key.
    pub fn contract_code_key_hash(key: &LedgerKeyContractCode) -> [u8; 32] {
        // Create a TTL key from the contract code key
        let ttl_key = LedgerKey::Ttl(LedgerKeyTtl {
            key_hash: Hash256::hash_xdr(&LedgerKey::ContractCode(key.clone()))
                .map(|h| stellar_xdr::curr::Hash(*h.as_bytes()))
                .unwrap_or_else(|_| stellar_xdr::curr::Hash([0u8; 32])),
        });

        // Hash the TTL key itself as the map key
        Hash256::hash_xdr(&ttl_key)
            .map(|h| *h.as_bytes())
            .unwrap_or([0u8; 32])
    }

    /// Compute the map key from a TTL key.
    pub fn ttl_key_to_map_key(key: &LedgerKeyTtl) -> [u8; 32] {
        key.key_hash.0
    }

    /// Get a contract data entry by key.
    pub fn get_contract_data(&self, key: &LedgerKeyContractData) -> Option<&ContractDataMapEntry> {
        let key_hash = Self::contract_data_key_hash(key);
        self.contract_data_entries.get(&key_hash)
    }

    /// Get a contract code entry by key.
    pub fn get_contract_code(&self, key: &LedgerKeyContractCode) -> Option<&ContractCodeMapEntry> {
        let key_hash = Self::contract_code_key_hash(key);
        self.contract_code_entries.get(&key_hash)
    }

    /// Get a ledger entry by key.
    ///
    /// Returns the entry if found, along with synthesized TTL data.
    pub fn get(&self, key: &LedgerKey) -> Option<Arc<LedgerEntry>> {
        match key {
            LedgerKey::ContractData(cd) => {
                self.get_contract_data(cd).map(|e| e.ledger_entry.clone())
            }
            LedgerKey::ContractCode(cc) => {
                self.get_contract_code(cc).map(|e| e.ledger_entry.clone())
            }
            LedgerKey::Ttl(ttl) => self.get_ttl_entry(ttl),
            _ => None,
        }
    }

    /// Get TTL data for a key.
    pub fn get_ttl(&self, key: &LedgerKey) -> Option<TtlData> {
        match key {
            LedgerKey::ContractData(cd) => self.get_contract_data(cd).map(|e| e.ttl_data),
            LedgerKey::ContractCode(cc) => self.get_contract_code(cc).map(|e| e.ttl_data),
            LedgerKey::Ttl(ttl) => {
                let key_hash = ttl.key_hash.0;
                self.contract_data_entries
                    .get(&key_hash)
                    .map(|e| e.ttl_data)
                    .or_else(|| {
                        self.contract_code_entries
                            .get(&key_hash)
                            .map(|e| e.ttl_data)
                    })
            }
            _ => None,
        }
    }

    /// Synthesize a TTL entry from stored TTL data.
    fn get_ttl_entry(&self, key: &LedgerKeyTtl) -> Option<Arc<LedgerEntry>> {
        // Look up in both maps
        let key_hash = key.key_hash.0;

        let ttl_data = self
            .contract_data_entries
            .get(&key_hash)
            .map(|e| e.ttl_data)
            .or_else(|| {
                self.contract_code_entries
                    .get(&key_hash)
                    .map(|e| e.ttl_data)
            })?;

        // Synthesize the TTL entry
        let entry = LedgerEntry {
            last_modified_ledger_seq: ttl_data.last_modified_ledger_seq,
            data: LedgerEntryData::Ttl(TtlEntry {
                key_hash: key.key_hash.clone(),
                live_until_ledger_seq: ttl_data.live_until_ledger_seq,
            }),
            ext: stellar_xdr::curr::LedgerEntryExt::V0,
        };

        Some(Arc::new(entry))
    }

    /// Check if a TTL exists for a key.
    pub fn has_ttl(&self, key: &LedgerKeyTtl) -> bool {
        let key_hash = key.key_hash.0;
        self.contract_data_entries.contains_key(&key_hash)
            || self.contract_code_entries.contains_key(&key_hash)
    }

    /// Create a new contract data entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry already exists.
    pub fn create_contract_data(&mut self, entry: LedgerEntry) -> Result<()> {
        let key = match &entry.data {
            LedgerEntryData::ContractData(cd) => LedgerKeyContractData {
                contract: cd.contract.clone(),
                key: cd.key.clone(),
                durability: cd.durability.clone(),
            },
            _ => {
                return Err(LedgerError::InvalidEntry(
                    "not a contract data entry".into(),
                ))
            }
        };

        let key_hash = Self::contract_data_key_hash(&key);

        if self.contract_data_entries.contains_key(&key_hash) {
            return Err(LedgerError::InvalidEntry(
                "contract data already exists".into(),
            ));
        }

        // Check for pending TTL
        let ttl_data = self.pending_ttls.remove(&key_hash).unwrap_or_default();

        let map_entry = ContractDataMapEntry {
            ledger_entry: Arc::new(entry),
            ttl_data,
        };

        self.contract_data_state_size += map_entry.xdr_size() as i64;
        self.contract_data_entries.insert(key_hash, map_entry);

        trace!("Created contract data entry");
        Ok(())
    }

    /// Update an existing contract data entry.
    ///
    /// Preserves the existing TTL while updating the data.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry doesn't exist.
    pub fn update_contract_data(&mut self, entry: LedgerEntry) -> Result<()> {
        let key = match &entry.data {
            LedgerEntryData::ContractData(cd) => LedgerKeyContractData {
                contract: cd.contract.clone(),
                key: cd.key.clone(),
                durability: cd.durability.clone(),
            },
            _ => {
                return Err(LedgerError::InvalidEntry(
                    "not a contract data entry".into(),
                ))
            }
        };

        let key_hash = Self::contract_data_key_hash(&key);

        let old_entry = self
            .contract_data_entries
            .remove(&key_hash)
            .ok_or_else(|| LedgerError::InvalidEntry("contract data does not exist".into()))?;

        // Update size tracking
        let old_size = old_entry.xdr_size();
        let new_entry = ContractDataMapEntry {
            ledger_entry: Arc::new(entry),
            ttl_data: old_entry.ttl_data, // Preserve TTL
        };
        let new_size = new_entry.xdr_size();

        self.contract_data_state_size += (new_size as i64) - (old_size as i64);
        self.contract_data_entries.insert(key_hash, new_entry);

        trace!("Updated contract data entry");
        Ok(())
    }

    /// Delete a contract data entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry doesn't exist.
    pub fn delete_contract_data(&mut self, key: &LedgerKeyContractData) -> Result<()> {
        let key_hash = Self::contract_data_key_hash(key);

        let old_entry = self
            .contract_data_entries
            .remove(&key_hash)
            .ok_or_else(|| LedgerError::InvalidEntry("contract data does not exist".into()))?;

        self.contract_data_state_size -= old_entry.xdr_size() as i64;

        trace!("Deleted contract data entry");
        Ok(())
    }

    /// Create a new contract code entry.
    ///
    /// # Arguments
    ///
    /// * `entry` - The contract code ledger entry
    /// * `protocol_version` - Current protocol version for size calculation
    ///
    /// # Errors
    ///
    /// Returns an error if the entry already exists.
    pub fn create_contract_code(
        &mut self,
        entry: LedgerEntry,
        protocol_version: u32,
    ) -> Result<()> {
        let key = match &entry.data {
            LedgerEntryData::ContractCode(cc) => LedgerKeyContractCode {
                hash: cc.hash.clone(),
            },
            _ => {
                return Err(LedgerError::InvalidEntry(
                    "not a contract code entry".into(),
                ))
            }
        };

        let key_hash = Self::contract_code_key_hash(&key);

        if self.contract_code_entries.contains_key(&key_hash) {
            return Err(LedgerError::InvalidEntry(
                "contract code already exists".into(),
            ));
        }

        // Check for pending TTL
        let ttl_data = self.pending_ttls.remove(&key_hash).unwrap_or_default();

        // Calculate size for rent
        let size_bytes = self.calculate_code_size(&entry, protocol_version);

        let map_entry = ContractCodeMapEntry {
            ledger_entry: Arc::new(entry),
            ttl_data,
            size_bytes,
        };

        self.contract_code_state_size += map_entry.size_bytes as i64;
        self.contract_code_entries.insert(key_hash, map_entry);

        trace!("Created contract code entry");
        Ok(())
    }

    /// Update an existing contract code entry.
    ///
    /// Preserves the existing TTL while updating the code.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry doesn't exist.
    pub fn update_contract_code(
        &mut self,
        entry: LedgerEntry,
        protocol_version: u32,
    ) -> Result<()> {
        let key = match &entry.data {
            LedgerEntryData::ContractCode(cc) => LedgerKeyContractCode {
                hash: cc.hash.clone(),
            },
            _ => {
                return Err(LedgerError::InvalidEntry(
                    "not a contract code entry".into(),
                ))
            }
        };

        let key_hash = Self::contract_code_key_hash(&key);

        let old_entry = self
            .contract_code_entries
            .remove(&key_hash)
            .ok_or_else(|| LedgerError::InvalidEntry("contract code does not exist".into()))?;

        // Calculate new size for rent
        let new_size = self.calculate_code_size(&entry, protocol_version);

        let new_entry = ContractCodeMapEntry {
            ledger_entry: Arc::new(entry),
            ttl_data: old_entry.ttl_data, // Preserve TTL
            size_bytes: new_size,
        };

        // Update size tracking
        self.contract_code_state_size += (new_size as i64) - (old_entry.size_bytes as i64);
        self.contract_code_entries.insert(key_hash, new_entry);

        trace!("Updated contract code entry");
        Ok(())
    }

    /// Delete a contract code entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry doesn't exist.
    pub fn delete_contract_code(&mut self, key: &LedgerKeyContractCode) -> Result<()> {
        let key_hash = Self::contract_code_key_hash(key);

        let old_entry = self
            .contract_code_entries
            .remove(&key_hash)
            .ok_or_else(|| LedgerError::InvalidEntry("contract code does not exist".into()))?;

        self.contract_code_state_size -= old_entry.size_bytes as i64;

        trace!("Deleted contract code entry");
        Ok(())
    }

    /// Update or create TTL for an entry.
    ///
    /// If the corresponding data/code entry exists, updates its TTL inline.
    /// Otherwise, stores in pending_ttls to be adopted later.
    pub fn update_ttl(&mut self, key: &LedgerKeyTtl, ttl_data: TtlData) {
        let key_hash = key.key_hash.0;

        // Try to update inline in contract data
        if let Some(entry) = self.contract_data_entries.get_mut(&key_hash) {
            entry.ttl_data = ttl_data;
            trace!("Updated TTL inline for contract data");
            return;
        }

        // Try to update inline in contract code
        if let Some(entry) = self.contract_code_entries.get_mut(&key_hash) {
            entry.ttl_data = ttl_data;
            trace!("Updated TTL inline for contract code");
            return;
        }

        // No entry found, store as pending
        self.pending_ttls.insert(key_hash, ttl_data);
        trace!("Stored pending TTL");
    }

    /// Process a TTL entry (extract data and update).
    pub fn process_ttl_entry(&mut self, entry: &LedgerEntry) -> Result<()> {
        let (key_hash, ttl_data) = match &entry.data {
            LedgerEntryData::Ttl(ttl) => {
                let _key = LedgerKeyTtl {
                    key_hash: ttl.key_hash.clone(),
                };
                (
                    ttl.key_hash.0,
                    TtlData::new(ttl.live_until_ledger_seq, entry.last_modified_ledger_seq),
                )
            }
            _ => return Err(LedgerError::InvalidEntry("not a TTL entry".into())),
        };

        let key = LedgerKeyTtl {
            key_hash: stellar_xdr::curr::Hash(key_hash),
        };
        self.update_ttl(&key, ttl_data);
        Ok(())
    }

    /// Calculate the in-memory size for a contract code entry.
    ///
    /// For Protocol 23+, this includes the compiled module overhead.
    /// For earlier protocols, uses XDR size only.
    fn calculate_code_size(&self, entry: &LedgerEntry, protocol_version: u32) -> u32 {
        // Get base XDR size
        let xdr_size = entry
            .to_xdr(Limits::none())
            .map(|v| v.len() as u32)
            .unwrap_or(0);

        // Protocol 23+ may include compiled module overhead
        // For now, use XDR size as a baseline
        // TODO: Integrate with Soroban host for accurate compiled module sizing
        if protocol_version >= 23 {
            // Estimate compiled module overhead as ~2x XDR size
            // This is a placeholder until proper Soroban host integration
            xdr_size * 2
        } else {
            xdr_size
        }
    }

    /// Update state with new entries from a ledger close.
    ///
    /// # Arguments
    ///
    /// * `ledger_seq` - The new ledger sequence number
    /// * `init_entries` - Newly created entries
    /// * `live_entries` - Updated entries
    /// * `dead_entries` - Deleted entry keys
    /// * `protocol_version` - Current protocol version
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ledger sequence is not exactly one more than the current
    /// - Entry operations fail
    pub fn update_state(
        &mut self,
        ledger_seq: u32,
        init_entries: &[LedgerEntry],
        live_entries: &[LedgerEntry],
        dead_entries: &[LedgerKey],
        protocol_version: u32,
    ) -> Result<()> {
        // Validate sequence progression
        if self.last_closed_ledger_seq > 0 && ledger_seq != self.last_closed_ledger_seq + 1 {
            return Err(LedgerError::InvalidLedgerSequence {
                expected: self.last_closed_ledger_seq + 1,
                actual: ledger_seq,
            });
        }

        // Process init entries (creates)
        for entry in init_entries {
            self.process_entry_create(entry, protocol_version)?;
        }

        // Process live entries (updates)
        for entry in live_entries {
            self.process_entry_update(entry, protocol_version)?;
        }

        // Process dead entries (deletes)
        for key in dead_entries {
            self.process_entry_delete(key)?;
        }

        self.last_closed_ledger_seq = ledger_seq;

        // Check invariant: pending_ttls should be empty after each update
        if !self.pending_ttls.is_empty() {
            warn!(
                "Pending TTLs not empty after update: {} remaining",
                self.pending_ttls.len()
            );
        }

        debug!(
            "Updated Soroban state to ledger {}: {} data, {} code entries",
            ledger_seq,
            self.contract_data_entries.len(),
            self.contract_code_entries.len()
        );

        Ok(())
    }

    /// Process a single entry creation.
    fn process_entry_create(&mut self, entry: &LedgerEntry, protocol_version: u32) -> Result<()> {
        match &entry.data {
            LedgerEntryData::ContractData(_) => self.create_contract_data(entry.clone()),
            LedgerEntryData::ContractCode(_) => {
                self.create_contract_code(entry.clone(), protocol_version)
            }
            LedgerEntryData::Ttl(_) => self.process_ttl_entry(entry),
            _ => Ok(()), // Ignore non-Soroban entries
        }
    }

    /// Process a single entry update.
    fn process_entry_update(&mut self, entry: &LedgerEntry, protocol_version: u32) -> Result<()> {
        match &entry.data {
            LedgerEntryData::ContractData(_) => {
                // Check if this is actually an update or a create
                let key = match &entry.data {
                    LedgerEntryData::ContractData(cd) => LedgerKeyContractData {
                        contract: cd.contract.clone(),
                        key: cd.key.clone(),
                        durability: cd.durability.clone(),
                    },
                    _ => unreachable!(),
                };
                let key_hash = Self::contract_data_key_hash(&key);
                if self.contract_data_entries.contains_key(&key_hash) {
                    self.update_contract_data(entry.clone())
                } else {
                    self.create_contract_data(entry.clone())
                }
            }
            LedgerEntryData::ContractCode(_) => {
                let key = match &entry.data {
                    LedgerEntryData::ContractCode(cc) => LedgerKeyContractCode {
                        hash: cc.hash.clone(),
                    },
                    _ => unreachable!(),
                };
                let key_hash = Self::contract_code_key_hash(&key);
                if self.contract_code_entries.contains_key(&key_hash) {
                    self.update_contract_code(entry.clone(), protocol_version)
                } else {
                    self.create_contract_code(entry.clone(), protocol_version)
                }
            }
            LedgerEntryData::Ttl(_) => self.process_ttl_entry(entry),
            _ => Ok(()), // Ignore non-Soroban entries
        }
    }

    /// Process a single entry deletion.
    fn process_entry_delete(&mut self, key: &LedgerKey) -> Result<()> {
        match key {
            LedgerKey::ContractData(cd) => {
                // Ignore error if entry doesn't exist
                let _ = self.delete_contract_data(cd);
                Ok(())
            }
            LedgerKey::ContractCode(cc) => {
                // Ignore error if entry doesn't exist
                let _ = self.delete_contract_code(cc);
                Ok(())
            }
            LedgerKey::Ttl(ttl) => {
                // TTL deletion is handled implicitly when data/code is deleted
                let key_hash = ttl.key_hash.0;
                self.pending_ttls.remove(&key_hash);
                Ok(())
            }
            _ => Ok(()), // Ignore non-Soroban entries
        }
    }

    /// Recompute all contract code sizes.
    ///
    /// Called after a protocol upgrade or config change that affects
    /// compiled module sizing.
    pub fn recompute_contract_code_sizes(&mut self, protocol_version: u32) {
        let mut total_size: i64 = 0;

        for entry in self.contract_code_entries.values_mut() {
            let new_size = entry
                .ledger_entry
                .to_xdr(Limits::none())
                .map(|v| v.len() as u32)
                .unwrap_or(0);

            // Apply protocol-specific sizing
            let adjusted_size = if protocol_version >= 23 {
                new_size * 2 // Placeholder for compiled module overhead
            } else {
                new_size
            };

            entry.size_bytes = adjusted_size;
            total_size += adjusted_size as i64;
        }

        self.contract_code_state_size = total_size;

        debug!(
            "Recomputed contract code sizes for {} entries: {} bytes",
            self.contract_code_entries.len(),
            total_size
        );
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.contract_data_entries.clear();
        self.contract_code_entries.clear();
        self.pending_ttls.clear();
        self.last_closed_ledger_seq = 0;
        self.contract_data_state_size = 0;
        self.contract_code_state_size = 0;
    }

    /// Get statistics about the current state.
    pub fn stats(&self) -> SorobanStateStats {
        SorobanStateStats {
            ledger_seq: self.last_closed_ledger_seq,
            contract_data_count: self.contract_data_entries.len(),
            contract_code_count: self.contract_code_entries.len(),
            contract_data_size: self.contract_data_state_size,
            contract_code_size: self.contract_code_state_size,
            pending_ttl_count: self.pending_ttls.len(),
        }
    }
}

/// Statistics about the Soroban state cache.
#[derive(Debug, Clone, Default)]
pub struct SorobanStateStats {
    /// Current ledger sequence.
    pub ledger_seq: u32,
    /// Number of contract data entries.
    pub contract_data_count: usize,
    /// Number of contract code entries.
    pub contract_code_count: usize,
    /// Total contract data size in bytes.
    pub contract_data_size: i64,
    /// Total contract code size in bytes.
    pub contract_code_size: i64,
    /// Number of pending TTL entries (should be 0 after init).
    pub pending_ttl_count: usize,
}

/// Thread-safe wrapper for in-memory Soroban state.
///
/// Provides concurrent read access during transaction execution
/// and exclusive write access during ledger close.
pub struct SharedSorobanState {
    inner: RwLock<InMemorySorobanState>,
}

impl Default for SharedSorobanState {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedSorobanState {
    /// Create a new shared Soroban state.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(InMemorySorobanState::new()),
        }
    }

    /// Get a read lock for concurrent access.
    pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, InMemorySorobanState> {
        self.inner.read()
    }

    /// Get a write lock for exclusive access.
    pub fn write(&self) -> parking_lot::RwLockWriteGuard<'_, InMemorySorobanState> {
        self.inner.write()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        ContractCodeEntry, ContractCodeEntryExt, ContractDataDurability, ContractDataEntry,
        ContractId, ExtensionPoint, Hash, ScAddress, ScVal,
    };

    fn make_contract_address() -> ScAddress {
        ScAddress::Contract(ContractId(Hash([1u8; 32])))
    }

    fn make_contract_data_entry(key_bytes: [u8; 32]) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 100,
            data: LedgerEntryData::ContractData(ContractDataEntry {
                ext: ExtensionPoint::V0,
                contract: make_contract_address(),
                key: ScVal::Bytes(stellar_xdr::curr::ScBytes(
                    key_bytes.to_vec().try_into().unwrap(),
                )),
                durability: ContractDataDurability::Persistent,
                val: ScVal::I32(42),
            }),
            ext: stellar_xdr::curr::LedgerEntryExt::V0,
        }
    }

    fn make_contract_code_entry(hash: [u8; 32]) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 100,
            data: LedgerEntryData::ContractCode(ContractCodeEntry {
                ext: ContractCodeEntryExt::V0,
                hash: Hash(hash),
                code: vec![0u8; 100].try_into().unwrap(),
            }),
            ext: stellar_xdr::curr::LedgerEntryExt::V0,
        }
    }

    #[test]
    fn test_empty_state() {
        let state = InMemorySorobanState::new();
        assert!(state.is_empty());
        assert_eq!(state.ledger_seq(), 0);
        assert_eq!(state.total_size(), 0);
    }

    #[test]
    fn test_create_contract_data() {
        let mut state = InMemorySorobanState::new();
        let entry = make_contract_data_entry([1u8; 32]);

        state.create_contract_data(entry.clone()).unwrap();

        assert_eq!(state.contract_data_count(), 1);
        assert!(!state.is_empty());
        assert!(state.contract_data_state_size > 0);
    }

    #[test]
    fn test_update_contract_data() {
        let mut state = InMemorySorobanState::new();
        let entry = make_contract_data_entry([1u8; 32]);

        state.create_contract_data(entry).unwrap();
        let initial_size = state.contract_data_state_size;

        let mut updated_entry = make_contract_data_entry([1u8; 32]);
        if let LedgerEntryData::ContractData(cd) = &mut updated_entry.data {
            cd.val = ScVal::I32(99);
        }

        state.update_contract_data(updated_entry).unwrap();

        // Size should be similar (small change in value)
        assert!(state.contract_data_state_size > 0);
        assert_eq!(state.contract_data_count(), 1);
    }

    #[test]
    fn test_delete_contract_data() {
        let mut state = InMemorySorobanState::new();
        let entry = make_contract_data_entry([1u8; 32]);

        state.create_contract_data(entry.clone()).unwrap();
        assert_eq!(state.contract_data_count(), 1);

        let key = LedgerKeyContractData {
            contract: make_contract_address(),
            key: ScVal::Bytes(stellar_xdr::curr::ScBytes(
                [1u8; 32].to_vec().try_into().unwrap(),
            )),
            durability: ContractDataDurability::Persistent,
        };

        state.delete_contract_data(&key).unwrap();

        assert_eq!(state.contract_data_count(), 0);
        assert!(state.is_empty());
        assert_eq!(state.contract_data_state_size, 0);
    }

    #[test]
    fn test_create_contract_code() {
        let mut state = InMemorySorobanState::new();
        let entry = make_contract_code_entry([2u8; 32]);

        state.create_contract_code(entry, 25).unwrap();

        assert_eq!(state.contract_code_count(), 1);
        assert!(state.contract_code_state_size > 0);
    }

    #[test]
    fn test_update_state() {
        let mut state = InMemorySorobanState::new();

        let data_entry = make_contract_data_entry([1u8; 32]);
        let code_entry = make_contract_code_entry([2u8; 32]);

        state
            .update_state(1, &[data_entry.clone(), code_entry.clone()], &[], &[], 25)
            .unwrap();

        assert_eq!(state.ledger_seq(), 1);
        assert_eq!(state.contract_data_count(), 1);
        assert_eq!(state.contract_code_count(), 1);
    }

    #[test]
    fn test_ttl_co_location() {
        let mut state = InMemorySorobanState::new();
        let entry = make_contract_data_entry([1u8; 32]);

        // Create entry (will have default TTL)
        state.create_contract_data(entry.clone()).unwrap();

        // Get the key hash
        let key = LedgerKeyContractData {
            contract: make_contract_address(),
            key: ScVal::Bytes(stellar_xdr::curr::ScBytes(
                [1u8; 32].to_vec().try_into().unwrap(),
            )),
            durability: ContractDataDurability::Persistent,
        };
        let key_hash = InMemorySorobanState::contract_data_key_hash(&key);

        // Update TTL
        let ttl_key = LedgerKeyTtl {
            key_hash: Hash(key_hash),
        };
        state.update_ttl(&ttl_key, TtlData::new(1000, 100));

        // Verify TTL is co-located
        let map_entry = state.get_contract_data(&key).unwrap();
        assert_eq!(map_entry.ttl_data.live_until_ledger_seq, 1000);
        assert_eq!(map_entry.ttl_data.last_modified_ledger_seq, 100);
    }

    #[test]
    fn test_pending_ttl_adoption() {
        let mut state = InMemorySorobanState::new();

        // Create TTL before the entry exists
        let key = LedgerKeyContractData {
            contract: make_contract_address(),
            key: ScVal::Bytes(stellar_xdr::curr::ScBytes(
                [1u8; 32].to_vec().try_into().unwrap(),
            )),
            durability: ContractDataDurability::Persistent,
        };
        let key_hash = InMemorySorobanState::contract_data_key_hash(&key);
        let ttl_key = LedgerKeyTtl {
            key_hash: Hash(key_hash),
        };

        state.update_ttl(&ttl_key, TtlData::new(2000, 200));
        assert_eq!(state.pending_ttls.len(), 1);

        // Now create the entry
        let entry = make_contract_data_entry([1u8; 32]);
        state.create_contract_data(entry).unwrap();

        // Pending TTL should be adopted
        assert!(state.pending_ttls.is_empty());

        // Verify TTL was adopted
        let map_entry = state.get_contract_data(&key).unwrap();
        assert_eq!(map_entry.ttl_data.live_until_ledger_seq, 2000);
    }

    #[test]
    fn test_synthesize_ttl_entry() {
        let mut state = InMemorySorobanState::new();
        let entry = make_contract_data_entry([1u8; 32]);

        state.create_contract_data(entry).unwrap();

        // Set TTL
        let key = LedgerKeyContractData {
            contract: make_contract_address(),
            key: ScVal::Bytes(stellar_xdr::curr::ScBytes(
                [1u8; 32].to_vec().try_into().unwrap(),
            )),
            durability: ContractDataDurability::Persistent,
        };
        let key_hash = InMemorySorobanState::contract_data_key_hash(&key);
        let ttl_key = LedgerKeyTtl {
            key_hash: Hash(key_hash),
        };

        state.update_ttl(&ttl_key, TtlData::new(3000, 300));

        // Get synthesized TTL entry
        let ttl_entry = state.get_ttl_entry(&ttl_key).unwrap();
        if let LedgerEntryData::Ttl(ttl) = &ttl_entry.data {
            assert_eq!(ttl.live_until_ledger_seq, 3000);
            assert_eq!(ttl_entry.last_modified_ledger_seq, 300);
        } else {
            panic!("Expected TTL entry");
        }
    }

    #[test]
    fn test_stats() {
        let mut state = InMemorySorobanState::new();

        let data_entry = make_contract_data_entry([1u8; 32]);
        let code_entry = make_contract_code_entry([2u8; 32]);

        state
            .update_state(10, &[data_entry, code_entry], &[], &[], 25)
            .unwrap();

        let stats = state.stats();
        assert_eq!(stats.ledger_seq, 10);
        assert_eq!(stats.contract_data_count, 1);
        assert_eq!(stats.contract_code_count, 1);
        assert!(stats.contract_data_size > 0);
        assert!(stats.contract_code_size > 0);
        assert_eq!(stats.pending_ttl_count, 0);
    }

    #[test]
    fn test_shared_state() {
        let shared = SharedSorobanState::new();

        {
            let mut write = shared.write();
            let entry = make_contract_data_entry([1u8; 32]);
            write.create_contract_data(entry).unwrap();
        }

        {
            let read = shared.read();
            assert_eq!(read.contract_data_count(), 1);
        }
    }
}
