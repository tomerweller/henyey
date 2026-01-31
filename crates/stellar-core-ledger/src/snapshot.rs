//! Point-in-time snapshots of ledger state.
//!
//! This module provides [`LedgerSnapshot`] and related types for capturing
//! and querying ledger state at specific points in time. Snapshots are
//! essential for:
//!
//! - **Concurrent reads during ledger close**: Transaction processing reads
//!   from a frozen snapshot while writes accumulate in the delta
//! - **Historical state queries**: Access past ledger states for analysis
//! - **Transaction validation**: Validate transactions against consistent state
//!
//! # Snapshot Hierarchy
//!
//! - [`LedgerSnapshot`]: The actual point-in-time state (header + cached entries)
//! - [`SnapshotHandle`]: Thread-safe wrapper with optional lookup functions
//! - [`SnapshotBuilder`]: Fluent API for constructing snapshots
//! - [`SnapshotManager`]: Lifecycle management and retention policy
//!
//! # Lazy Loading
//!
//! Snapshots can be configured with lookup functions that lazily fetch entries
//! not in the cache. This allows efficient snapshots that don't need to copy
//! the entire ledger state upfront.

use crate::{LedgerError, Result};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use stellar_core_common::Hash256;
use stellar_xdr::curr::{
    AccountEntry, AccountId, LedgerEntry, LedgerEntryData, LedgerHeader, LedgerKey, Limits,
    WriteXdr,
};

/// Serialize a ledger key to bytes for use as a map key.
fn key_to_bytes(key: &LedgerKey) -> Result<Vec<u8>> {
    key.to_xdr(Limits::none())
        .map_err(|e| LedgerError::Serialization(e.to_string()))
}

/// A point-in-time snapshot of ledger state.
///
/// `LedgerSnapshot` provides a consistent, read-only view of the ledger
/// at a specific sequence number. The snapshot is immutable after creation
/// and can be safely shared across threads for concurrent reads.
///
/// # Cached vs. Full State
///
/// A snapshot contains a cache of entries, which may be a subset of the
/// full ledger state. Use [`SnapshotHandle`] with a lookup function to
/// enable lazy loading of entries not in the cache.
///
/// # Thread Safety
///
/// The snapshot itself is immutable after creation. For shared ownership
/// across threads, wrap in an [`Arc`] or use [`SnapshotHandle`].
#[derive(Debug)]
pub struct LedgerSnapshot {
    /// The ledger sequence number this snapshot represents.
    ledger_seq: u32,

    /// The complete ledger header at this sequence.
    header: LedgerHeader,

    /// SHA-256 hash of the XDR-encoded header.
    header_hash: Hash256,

    /// Cached entries keyed by XDR-encoded LedgerKey.
    ///
    /// This may be a subset of the full ledger state. Entries not in
    /// this cache can be loaded via the lookup function in SnapshotHandle.
    entries: HashMap<Vec<u8>, LedgerEntry>,
}

impl LedgerSnapshot {
    /// Create a new snapshot from a header and entries.
    pub fn new(
        header: LedgerHeader,
        header_hash: Hash256,
        entries: HashMap<Vec<u8>, LedgerEntry>,
    ) -> Self {
        Self {
            ledger_seq: header.ledger_seq,
            header,
            header_hash,
            entries,
        }
    }

    /// Create an empty snapshot (for genesis or testing).
    pub fn empty(ledger_seq: u32) -> Self {
        Self {
            ledger_seq,
            header: LedgerHeader {
                ledger_version: 0,
                previous_ledger_hash: stellar_xdr::curr::Hash([0u8; 32]),
                scp_value: stellar_xdr::curr::StellarValue {
                    tx_set_hash: stellar_xdr::curr::Hash([0u8; 32]),
                    close_time: stellar_xdr::curr::TimePoint(0),
                    upgrades: stellar_xdr::curr::VecM::default(),
                    ext: stellar_xdr::curr::StellarValueExt::Basic,
                },
                tx_set_result_hash: stellar_xdr::curr::Hash([0u8; 32]),
                bucket_list_hash: stellar_xdr::curr::Hash([0u8; 32]),
                ledger_seq,
                total_coins: 0,
                fee_pool: 0,
                inflation_seq: 0,
                id_pool: 0,
                base_fee: 100,
                base_reserve: 5_000_000,
                max_tx_set_size: 1000,
                skip_list: std::array::from_fn(|_| stellar_xdr::curr::Hash([0u8; 32])),
                ext: stellar_xdr::curr::LedgerHeaderExt::V0,
            },
            header_hash: Hash256::ZERO,
            entries: HashMap::new(),
        }
    }

    /// Get the ledger sequence of this snapshot.
    pub fn ledger_seq(&self) -> u32 {
        self.ledger_seq
    }

    /// Get the ledger header.
    pub fn header(&self) -> &LedgerHeader {
        &self.header
    }

    /// Get the ledger header hash.
    pub fn header_hash(&self) -> &Hash256 {
        &self.header_hash
    }

    /// Get the protocol version.
    pub fn protocol_version(&self) -> u32 {
        self.header.ledger_version
    }

    /// Get the base fee.
    pub fn base_fee(&self) -> u32 {
        self.header.base_fee
    }

    /// Get the base reserve.
    pub fn base_reserve(&self) -> u32 {
        self.header.base_reserve
    }

    /// Get the bucket list hash.
    pub fn bucket_list_hash(&self) -> Hash256 {
        Hash256::from(self.header.bucket_list_hash.0)
    }

    /// Look up an entry by key.
    pub fn get_entry(&self, key: &LedgerKey) -> Result<Option<&LedgerEntry>> {
        let key_bytes = key_to_bytes(key)?;
        Ok(self.entries.get(&key_bytes))
    }

    /// Look up an account by ID.
    pub fn get_account(&self, account_id: &AccountId) -> Result<Option<&AccountEntry>> {
        let key = LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
            account_id: account_id.clone(),
        });

        if let Some(entry) = self.get_entry(&key)? {
            if let LedgerEntryData::Account(ref account) = entry.data {
                return Ok(Some(account));
            }
        }
        Ok(None)
    }

    /// Check if an entry exists.
    pub fn contains(&self, key: &LedgerKey) -> Result<bool> {
        let key_bytes = key_to_bytes(key)?;
        Ok(self.entries.contains_key(&key_bytes))
    }

    /// Get the number of cached entries.
    pub fn num_entries(&self) -> usize {
        self.entries.len()
    }

    /// Iterate over all cached entries.
    pub fn entries(&self) -> impl Iterator<Item = &LedgerEntry> {
        self.entries.values()
    }
}

impl Clone for LedgerSnapshot {
    fn clone(&self) -> Self {
        Self {
            ledger_seq: self.ledger_seq,
            header: self.header.clone(),
            header_hash: self.header_hash,
            entries: self.entries.clone(),
        }
    }
}

/// Callback type for lazy entry lookup (e.g., from bucket list).
pub type EntryLookupFn = Arc<dyn Fn(&LedgerKey) -> Result<Option<LedgerEntry>> + Send + Sync>;

/// Callback type for historical header lookup (e.g., from database).
pub type LedgerHeaderLookupFn = Arc<dyn Fn(u32) -> Result<Option<LedgerHeader>> + Send + Sync>;

/// Callback type for full entry enumeration (e.g., bucket list scan).
pub type EntriesLookupFn = Arc<dyn Fn() -> Result<Vec<LedgerEntry>> + Send + Sync>;

/// Batch entry lookup function for loading multiple entries in a single bucket list pass.
pub type BatchEntryLookupFn = Arc<dyn Fn(&[LedgerKey]) -> Result<Vec<LedgerEntry>> + Send + Sync>;

/// Lookup function for offers by (account, asset) pair.
///
/// Returns all offers owned by the given account that buy or sell the given asset.
pub type OffersByAccountAssetFn =
    Arc<dyn Fn(&AccountId, &stellar_xdr::curr::Asset) -> Result<Vec<LedgerEntry>> + Send + Sync>;

/// Thread-safe handle to a ledger snapshot with optional lazy loading.
///
/// `SnapshotHandle` wraps a [`LedgerSnapshot`] in an `Arc` for efficient
/// sharing across threads, and optionally provides lookup functions for
/// entries not in the snapshot's cache.
///
/// # Lookup Functions
///
/// Three optional lookup functions can be configured:
///
/// - **Entry lookup**: Fetches individual entries (e.g., from bucket list)
/// - **Header lookup**: Fetches historical headers (e.g., from database)
/// - **Entries scan**: Returns all live entries (e.g., for full state analysis)
///
/// # Example
///
/// ```ignore
/// let handle = SnapshotHandle::with_lookup(snapshot, bucket_list_lookup);
///
/// // Entry lookup falls through to bucket list if not cached
/// let entry = handle.get_entry(&key)?;
/// ```
#[derive(Clone)]
pub struct SnapshotHandle {
    /// The underlying snapshot (shared via Arc).
    inner: Arc<LedgerSnapshot>,
    /// Optional fallback for entry lookups not in cache.
    lookup_fn: Option<EntryLookupFn>,
    /// Optional lookup for historical ledger headers.
    header_lookup_fn: Option<LedgerHeaderLookupFn>,
    /// Optional enumeration of all live entries.
    entries_fn: Option<EntriesLookupFn>,
    /// Optional batch lookup for multiple entries in a single pass.
    batch_lookup_fn: Option<BatchEntryLookupFn>,
    /// Optional index-based lookup for offers by (account, asset).
    offers_by_account_asset_fn: Option<OffersByAccountAssetFn>,
}

impl SnapshotHandle {
    /// Create a new handle from a snapshot.
    pub fn new(snapshot: LedgerSnapshot) -> Self {
        Self {
            inner: Arc::new(snapshot),
            lookup_fn: None,
            header_lookup_fn: None,
            entries_fn: None,
            batch_lookup_fn: None,
            offers_by_account_asset_fn: None,
        }
    }

    /// Create a new handle with a lookup function for entries not in cache.
    pub fn with_lookup(snapshot: LedgerSnapshot, lookup_fn: EntryLookupFn) -> Self {
        Self {
            inner: Arc::new(snapshot),
            lookup_fn: Some(lookup_fn),
            header_lookup_fn: None,
            entries_fn: None,
            batch_lookup_fn: None,
            offers_by_account_asset_fn: None,
        }
    }

    /// Create a new handle with lookup functions for entries and headers.
    pub fn with_lookups(
        snapshot: LedgerSnapshot,
        lookup_fn: EntryLookupFn,
        header_lookup_fn: LedgerHeaderLookupFn,
    ) -> Self {
        Self {
            inner: Arc::new(snapshot),
            lookup_fn: Some(lookup_fn),
            header_lookup_fn: Some(header_lookup_fn),
            entries_fn: None,
            batch_lookup_fn: None,
            offers_by_account_asset_fn: None,
        }
    }

    /// Create a new handle with lookup functions for entries, headers, and full scans.
    pub fn with_lookups_and_entries(
        snapshot: LedgerSnapshot,
        lookup_fn: EntryLookupFn,
        header_lookup_fn: LedgerHeaderLookupFn,
        entries_fn: EntriesLookupFn,
    ) -> Self {
        Self {
            inner: Arc::new(snapshot),
            lookup_fn: Some(lookup_fn),
            header_lookup_fn: Some(header_lookup_fn),
            entries_fn: Some(entries_fn),
            batch_lookup_fn: None,
            offers_by_account_asset_fn: None,
        }
    }

    /// Set the lookup function.
    pub fn set_lookup(&mut self, lookup_fn: EntryLookupFn) {
        self.lookup_fn = Some(lookup_fn);
    }

    /// Set the ledger header lookup function.
    pub fn set_header_lookup(&mut self, lookup_fn: LedgerHeaderLookupFn) {
        self.header_lookup_fn = Some(lookup_fn);
    }

    /// Set the full-entry lookup function.
    pub fn set_entries_lookup(&mut self, entries_fn: EntriesLookupFn) {
        self.entries_fn = Some(entries_fn);
    }

    /// Set the batch entry lookup function.
    pub fn set_batch_lookup(&mut self, batch_fn: BatchEntryLookupFn) {
        self.batch_lookup_fn = Some(batch_fn);
    }

    /// Set the offers-by-(account, asset) lookup function.
    pub fn set_offers_by_account_asset(&mut self, f: OffersByAccountAssetFn) {
        self.offers_by_account_asset_fn = Some(f);
    }

    /// Look up all offers owned by `account_id` that buy or sell `asset`.
    ///
    /// Uses the index-based lookup if available, otherwise falls back to
    /// `all_entries()` with a linear scan.
    pub fn offers_by_account_and_asset(
        &self,
        account_id: &AccountId,
        asset: &stellar_xdr::curr::Asset,
    ) -> Result<Vec<LedgerEntry>> {
        if let Some(ref f) = self.offers_by_account_asset_fn {
            return f(account_id, asset);
        }
        // Fallback: linear scan over all entries
        let entries = self.all_entries()?;
        Ok(entries
            .into_iter()
            .filter(|entry| {
                if let LedgerEntryData::Offer(ref offer) = entry.data {
                    offer.seller_id == *account_id
                        && (offer.buying == *asset || offer.selling == *asset)
                } else {
                    false
                }
            })
            .collect())
    }

    /// Load multiple entries by their keys.
    ///
    /// Checks the snapshot cache first, then uses the batch lookup function
    /// (if available) for remaining keys. Falls back to individual lookups.
    pub fn load_entries(&self, keys: &[LedgerKey]) -> Result<Vec<LedgerEntry>> {
        // Check cache first, collect remaining keys
        let mut result = Vec::new();
        let mut remaining = Vec::new();
        for key in keys {
            if let Some(entry) = self.inner.get_entry(key)? {
                result.push(entry.clone());
            } else {
                remaining.push(key.clone());
            }
        }

        if remaining.is_empty() {
            return Ok(result);
        }

        // Use batch lookup if available
        if let Some(ref batch_fn) = self.batch_lookup_fn {
            result.extend(batch_fn(&remaining)?);
        } else if let Some(ref lookup_fn) = self.lookup_fn {
            for key in &remaining {
                if let Some(entry) = lookup_fn(key)? {
                    result.push(entry);
                }
            }
        }

        Ok(result)
    }

    /// Get the underlying snapshot.
    pub fn snapshot(&self) -> &LedgerSnapshot {
        &self.inner
    }

    /// Return all live entries when available, falling back to cached entries.
    pub fn all_entries(&self) -> Result<Vec<LedgerEntry>> {
        if let Some(entries_fn) = &self.entries_fn {
            return entries_fn();
        }
        Ok(self.inner.entries.values().cloned().collect())
    }

    /// Get the ledger sequence.
    pub fn ledger_seq(&self) -> u32 {
        self.inner.ledger_seq
    }

    /// Get the header.
    pub fn header(&self) -> &LedgerHeader {
        &self.inner.header
    }

    /// Look up a ledger header by sequence number.
    pub fn get_ledger_header(&self, seq: u32) -> Result<Option<LedgerHeader>> {
        if seq == self.inner.ledger_seq {
            return Ok(Some(self.inner.header.clone()));
        }

        if let Some(ref lookup_fn) = self.header_lookup_fn {
            return lookup_fn(seq);
        }

        Ok(None)
    }

    /// Look up an entry.
    ///
    /// First checks the snapshot cache, then falls back to the lookup function
    /// if one is configured (e.g., for bucket list lookups).
    pub fn get_entry(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>> {
        // First try the cached entries
        if let Some(entry) = self.inner.get_entry(key)? {
            return Ok(Some(entry.clone()));
        }

        // Fall back to lookup function if available
        if let Some(ref lookup_fn) = self.lookup_fn {
            return lookup_fn(key);
        }

        Ok(None)
    }

    /// Look up an account.
    pub fn get_account(&self, account_id: &AccountId) -> Result<Option<AccountEntry>> {
        let key = LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
            account_id: account_id.clone(),
        });

        if let Some(entry) = self.get_entry(&key)? {
            if let LedgerEntryData::Account(account) = entry.data {
                return Ok(Some(account));
            }
        }
        Ok(None)
    }
}

/// Fluent builder for constructing [`LedgerSnapshot`] instances.
///
/// Use this builder when you need to construct a snapshot programmatically
/// with specific entries preloaded.
///
/// # Example
///
/// ```ignore
/// let snapshot = SnapshotBuilder::new(ledger_seq)
///     .with_header(header, header_hash)
///     .add_entry(key, entry)?
///     .build()?;
/// ```
pub struct SnapshotBuilder {
    /// Target ledger sequence.
    ledger_seq: u32,
    /// Optional header (required for build, optional for build_with_default_header).
    header: Option<LedgerHeader>,
    /// Hash of the header.
    header_hash: Hash256,
    /// Preloaded entries.
    entries: HashMap<Vec<u8>, LedgerEntry>,
}

impl SnapshotBuilder {
    /// Create a new builder for a given ledger sequence.
    pub fn new(ledger_seq: u32) -> Self {
        Self {
            ledger_seq,
            header: None,
            header_hash: Hash256::ZERO,
            entries: HashMap::new(),
        }
    }

    /// Set the ledger header.
    pub fn with_header(mut self, header: LedgerHeader, hash: Hash256) -> Self {
        self.header = Some(header);
        self.header_hash = hash;
        self
    }

    /// Add an entry to the snapshot.
    pub fn add_entry(mut self, key: LedgerKey, entry: LedgerEntry) -> Result<Self> {
        let key_bytes = key_to_bytes(&key)?;
        self.entries.insert(key_bytes, entry);
        Ok(self)
    }

    /// Add multiple entries.
    pub fn add_entries(
        mut self,
        entries: impl IntoIterator<Item = (LedgerKey, LedgerEntry)>,
    ) -> Result<Self> {
        for (key, entry) in entries {
            let key_bytes = key_to_bytes(&key)?;
            self.entries.insert(key_bytes, entry);
        }
        Ok(self)
    }

    /// Build the snapshot.
    pub fn build(self) -> Result<LedgerSnapshot> {
        let header = self
            .header
            .ok_or_else(|| LedgerError::Snapshot("header not set".to_string()))?;

        Ok(LedgerSnapshot {
            ledger_seq: self.ledger_seq,
            header,
            header_hash: self.header_hash,
            entries: self.entries,
        })
    }

    /// Build the snapshot with a default header (for testing).
    pub fn build_with_default_header(self) -> LedgerSnapshot {
        let header = self.header.unwrap_or_else(|| LedgerHeader {
            ledger_version: 20,
            previous_ledger_hash: stellar_xdr::curr::Hash([0u8; 32]),
            scp_value: stellar_xdr::curr::StellarValue {
                tx_set_hash: stellar_xdr::curr::Hash([0u8; 32]),
                close_time: stellar_xdr::curr::TimePoint(0),
                upgrades: stellar_xdr::curr::VecM::default(),
                ext: stellar_xdr::curr::StellarValueExt::Basic,
            },
            tx_set_result_hash: stellar_xdr::curr::Hash([0u8; 32]),
            bucket_list_hash: stellar_xdr::curr::Hash([0u8; 32]),
            ledger_seq: self.ledger_seq,
            total_coins: 100_000_000_000_000_000,
            fee_pool: 0,
            inflation_seq: 0,
            id_pool: 0,
            base_fee: 100,
            base_reserve: 5_000_000,
            max_tx_set_size: 1000,
            skip_list: std::array::from_fn(|_| stellar_xdr::curr::Hash([0u8; 32])),
            ext: stellar_xdr::curr::LedgerHeaderExt::V0,
        });

        LedgerSnapshot {
            ledger_seq: self.ledger_seq,
            header,
            header_hash: self.header_hash,
            entries: self.entries,
        }
    }
}

/// Manager for snapshot lifecycle and retention.
///
/// `SnapshotManager` handles the creation, storage, and cleanup of
/// ledger snapshots. It enforces a configurable retention policy,
/// automatically pruning old snapshots when the limit is exceeded.
///
/// # Retention Policy
///
/// When the number of snapshots exceeds `max_snapshots`, the oldest
/// snapshots (by ledger sequence) are removed to make room for new ones.
///
/// # Thread Safety
///
/// All methods are safe to call from multiple threads. The internal
/// storage is protected by an RwLock.
pub struct SnapshotManager {
    /// Active snapshots indexed by ledger sequence.
    snapshots: RwLock<HashMap<u32, SnapshotHandle>>,

    /// Maximum number of snapshots to retain before pruning.
    max_snapshots: usize,
}

impl SnapshotManager {
    /// Create a new snapshot manager.
    pub fn new(max_snapshots: usize) -> Self {
        Self {
            snapshots: RwLock::new(HashMap::new()),
            max_snapshots,
        }
    }

    /// Register a new snapshot.
    pub fn register(&self, snapshot: LedgerSnapshot) -> SnapshotHandle {
        let seq = snapshot.ledger_seq;
        let handle = SnapshotHandle::new(snapshot);

        let mut snapshots = self.snapshots.write();
        snapshots.insert(seq, handle.clone());

        // Prune old snapshots if needed
        if snapshots.len() > self.max_snapshots {
            let mut seqs: Vec<_> = snapshots.keys().copied().collect();
            seqs.sort();
            for seq in seqs.into_iter().take(snapshots.len() - self.max_snapshots) {
                snapshots.remove(&seq);
            }
        }

        handle
    }

    /// Get a snapshot by sequence number.
    pub fn get(&self, seq: u32) -> Option<SnapshotHandle> {
        self.snapshots.read().get(&seq).cloned()
    }

    /// Get the latest snapshot.
    pub fn latest(&self) -> Option<SnapshotHandle> {
        let snapshots = self.snapshots.read();
        snapshots
            .keys()
            .max()
            .copied()
            .and_then(|seq| snapshots.get(&seq).cloned())
    }

    /// Remove a snapshot.
    pub fn remove(&self, seq: u32) -> Option<SnapshotHandle> {
        self.snapshots.write().remove(&seq)
    }

    /// Get the number of active snapshots.
    pub fn count(&self) -> usize {
        self.snapshots.read().len()
    }

    /// Clear all snapshots.
    pub fn clear(&self) {
        self.snapshots.write().clear();
    }
}

impl Default for SnapshotManager {
    fn default() -> Self {
        Self::new(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        AccountEntry, AccountEntryExt, LedgerEntryExt, PublicKey, SequenceNumber, Thresholds,
        Uint256,
    };

    fn create_test_account(seed: u8) -> (LedgerKey, LedgerEntry) {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;

        let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key_bytes)));

        let key = LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
            account_id: account_id.clone(),
        });

        let entry = LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Account(AccountEntry {
                account_id,
                balance: 1000000000,
                seq_num: SequenceNumber(1),
                num_sub_entries: 0,
                inflation_dest: None,
                flags: 0,
                home_domain: stellar_xdr::curr::String32::default(),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: stellar_xdr::curr::VecM::default(),
                ext: AccountEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        };

        (key, entry)
    }

    #[test]
    fn test_snapshot_builder() {
        let (key, entry) = create_test_account(1);

        let snapshot = SnapshotBuilder::new(10)
            .add_entry(key.clone(), entry.clone())
            .unwrap()
            .build_with_default_header();

        assert_eq!(snapshot.ledger_seq(), 10);
        assert!(snapshot.get_entry(&key).unwrap().is_some());
    }

    #[test]
    fn test_snapshot_manager() {
        let manager = SnapshotManager::new(3);

        // Add snapshots
        for seq in 1..=5 {
            let snapshot = LedgerSnapshot::empty(seq);
            manager.register(snapshot);
        }

        // Should only keep the last 3
        assert_eq!(manager.count(), 3);

        // Check that we have the latest ones
        assert!(manager.get(3).is_some());
        assert!(manager.get(4).is_some());
        assert!(manager.get(5).is_some());
        assert!(manager.get(1).is_none());
        assert!(manager.get(2).is_none());
    }

    #[test]
    fn test_snapshot_get_account() {
        let (key, entry) = create_test_account(1);

        let account_id = if let LedgerKey::Account(ref ak) = key {
            ak.account_id.clone()
        } else {
            panic!("Expected account key");
        };

        let snapshot = SnapshotBuilder::new(1)
            .add_entry(key, entry)
            .unwrap()
            .build_with_default_header();

        let account = snapshot.get_account(&account_id).unwrap();
        assert!(account.is_some());
        assert_eq!(account.unwrap().balance, 1000000000);
    }
}
