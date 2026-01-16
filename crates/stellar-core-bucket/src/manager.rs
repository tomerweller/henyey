//! BucketManager - manages bucket files on disk.
//!
//! The `BucketManager` is responsible for the lifecycle of bucket files,
//! providing a high-level interface for bucket operations.
//!
//! # Responsibilities
//!
//! - **Creating** buckets from entries (sort, serialize, compress, write to disk)
//! - **Loading** buckets by content hash (from cache or disk)
//! - **Caching** frequently accessed buckets in memory
//! - **Merging** buckets and storing the results
//! - **Garbage collecting** unused bucket files
//!
//! # File Layout
//!
//! Bucket files are stored in a configurable directory with names derived
//! from their content hash:
//!
//! ```text
//! <bucket_dir>/
//!   <hash1>.bucket.gz
//!   <hash2>.bucket.gz
//!   ...
//! ```
//!
//! Files are gzip-compressed XDR. The hash is computed from the uncompressed
//! content (including XDR record marks).
//!
//! # Caching
//!
//! The manager maintains an in-memory cache of recently accessed buckets.
//! The cache uses a simple eviction policy (random eviction when full).
//! For production use, consider a more sophisticated LRU policy.
//!
//! # Thread Safety
//!
//! The manager uses `RwLock` for the cache, making it safe for concurrent
//! reads with exclusive writes. File operations are atomic (write to temp,
//! then rename).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use stellar_xdr::curr::{LedgerEntry, LedgerKey, Limits, WriteXdr};

use stellar_core_common::Hash256;

use crate::bucket::Bucket;
use crate::entry::BucketEntry;
use crate::merge::merge_buckets;
use crate::{BucketError, Result};

/// Manager for bucket files on disk.
///
/// The `BucketManager` provides the main interface for working with buckets
/// on disk. It handles all the complexity of serialization, compression,
/// caching, and file management.
///
/// # Example
///
/// ```ignore
/// use stellar_core_bucket::{BucketManager, BucketEntry};
///
/// // Create a manager
/// let manager = BucketManager::new("/path/to/buckets".into())?;
///
/// // Create a bucket from entries
/// let entries = vec![BucketEntry::Live(some_entry)];
/// let bucket = manager.create_bucket(entries)?;
///
/// // Later, load the bucket by hash
/// let loaded = manager.load_bucket(&bucket.hash())?;
///
/// // Garbage collect unused buckets
/// let active_hashes = bucket_list.all_bucket_hashes();
/// manager.retain_buckets(&active_hashes)?;
/// ```
///
/// # Cache Behavior
///
/// The manager caches buckets in memory up to `max_cache_size`. When the
/// cache is full, a random entry is evicted. All cache operations are
/// thread-safe via `RwLock`.
pub struct BucketManager {
    /// Directory where bucket files are stored.
    bucket_dir: PathBuf,
    /// Cache of loaded buckets, keyed by content hash.
    cache: RwLock<HashMap<Hash256, Arc<Bucket>>>,
    /// Maximum number of buckets to keep in cache.
    max_cache_size: usize,
}

impl BucketManager {
    /// Default maximum cache size.
    pub const DEFAULT_MAX_CACHE_SIZE: usize = 100;

    /// Create a new BucketManager with the given directory.
    pub fn new(bucket_dir: PathBuf) -> Result<Self> {
        // Create directory if it doesn't exist
        std::fs::create_dir_all(&bucket_dir)?;

        Ok(Self {
            bucket_dir,
            cache: RwLock::new(HashMap::new()),
            max_cache_size: Self::DEFAULT_MAX_CACHE_SIZE,
        })
    }

    /// Create a new BucketManager with a custom cache size.
    pub fn with_cache_size(bucket_dir: PathBuf, max_cache_size: usize) -> Result<Self> {
        std::fs::create_dir_all(&bucket_dir)?;

        Ok(Self {
            bucket_dir,
            cache: RwLock::new(HashMap::new()),
            max_cache_size,
        })
    }

    /// Get the bucket directory path.
    pub fn bucket_dir(&self) -> &Path {
        &self.bucket_dir
    }

    /// Get the file path for a bucket with the given hash.
    pub fn bucket_path(&self, hash: &Hash256) -> PathBuf {
        self.bucket_dir.join(format!("{}.bucket.gz", hash.to_hex()))
    }

    /// Create a bucket from entries.
    ///
    /// This will:
    /// 1. Sort entries by key
    /// 2. Create the bucket
    /// 3. Save to disk
    /// 4. Add to cache
    pub fn create_bucket(&self, entries: Vec<BucketEntry>) -> Result<Arc<Bucket>> {
        if entries.is_empty() {
            return Ok(Arc::new(Bucket::empty()));
        }

        // Create bucket (entries will be sorted)
        let bucket = Bucket::from_entries(entries)?;
        let hash = bucket.hash();

        // Check if already cached
        {
            let cache = self.cache.read().unwrap();
            if let Some(cached) = cache.get(&hash) {
                return Ok(Arc::clone(cached));
            }
        }

        // Save to disk
        let path = self.bucket_path(&hash);
        bucket.save_to_file(&path)?;

        // Add to cache
        let bucket = Arc::new(bucket);
        self.add_to_cache(hash, Arc::clone(&bucket));

        Ok(bucket)
    }

    /// Create a bucket from live and dead entries.
    pub fn create_bucket_from_ledger_entries(
        &self,
        live_entries: Vec<LedgerEntry>,
        dead_entries: Vec<LedgerKey>,
    ) -> Result<Arc<Bucket>> {
        let mut entries: Vec<BucketEntry> =
            live_entries.into_iter().map(BucketEntry::Live).collect();

        entries.extend(dead_entries.into_iter().map(BucketEntry::Dead));

        self.create_bucket(entries)
    }

    /// Load a bucket by its hash.
    ///
    /// First checks the cache, then loads from disk if not cached.
    pub fn load_bucket(&self, hash: &Hash256) -> Result<Arc<Bucket>> {
        // Check if it's the empty bucket
        if hash.is_zero() {
            return Ok(Arc::new(Bucket::empty()));
        }

        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(bucket) = cache.get(hash) {
                return Ok(Arc::clone(bucket));
            }
        }

        // Load from disk
        let path = self.bucket_path(hash);
        if !path.exists() {
            return Err(BucketError::NotFound(hash.to_hex()));
        }

        let bucket = Bucket::load_from_file(&path)?;

        // Verify hash matches
        if bucket.hash() != *hash {
            return Err(BucketError::HashMismatch {
                expected: hash.to_hex(),
                actual: bucket.hash().to_hex(),
            });
        }

        // Add to cache
        let bucket = Arc::new(bucket);
        self.add_to_cache(*hash, Arc::clone(&bucket));

        Ok(bucket)
    }

    /// Load a hot archive bucket by its hash.
    ///
    /// Hot archive buckets contain `HotArchiveBucketEntry` instead of `BucketEntry`.
    /// This method loads and parses the bucket file with the correct entry type.
    ///
    /// Note: Hot archive buckets are not cached (they use a different entry type).
    pub fn load_hot_archive_bucket(
        &self,
        hash: &Hash256,
    ) -> Result<crate::hot_archive::HotArchiveBucket> {
        // Check if it's the empty bucket
        if hash.is_zero() {
            return Ok(crate::hot_archive::HotArchiveBucket::empty());
        }

        // Load from disk
        let path = self.bucket_path(hash);
        if !path.exists() {
            return Err(BucketError::NotFound(hash.to_hex()));
        }

        let bucket = crate::hot_archive::HotArchiveBucket::load_from_file(&path)?;

        // Verify hash matches
        if bucket.hash() != *hash {
            return Err(BucketError::HashMismatch {
                expected: hash.to_hex(),
                actual: bucket.hash().to_hex(),
            });
        }

        Ok(bucket)
    }

    /// Check if a bucket exists (in cache or on disk).
    pub fn bucket_exists(&self, hash: &Hash256) -> bool {
        if hash.is_zero() {
            return true; // Empty bucket always "exists"
        }

        // Check cache
        {
            let cache = self.cache.read().unwrap();
            if cache.contains_key(hash) {
                return true;
            }
        }

        // Check disk
        self.bucket_path(hash).exists()
    }

    /// Merge two buckets and create a new bucket.
    pub fn merge(
        &self,
        old: &Bucket,
        new: &Bucket,
        max_protocol_version: u32,
    ) -> Result<Arc<Bucket>> {
        let merged = merge_buckets(old, new, true, max_protocol_version)?;

        if merged.is_empty() {
            return Ok(Arc::new(Bucket::empty()));
        }

        // Check if already cached
        let hash = merged.hash();
        {
            let cache = self.cache.read().unwrap();
            if let Some(cached) = cache.get(&hash) {
                return Ok(Arc::clone(cached));
            }
        }

        // Save to disk
        let path = self.bucket_path(&hash);
        merged.save_to_file(&path)?;

        // Add to cache
        let bucket = Arc::new(merged);
        self.add_to_cache(hash, Arc::clone(&bucket));

        Ok(bucket)
    }

    /// Merge two buckets asynchronously.
    pub async fn merge_async(
        &self,
        old: &Bucket,
        new: &Bucket,
        max_protocol_version: u32,
    ) -> Result<Arc<Bucket>> {
        // For now, just call the sync version
        // In the future, this could use tokio::task::spawn_blocking
        self.merge(old, new, max_protocol_version)
    }

    /// Add a bucket to the cache.
    fn add_to_cache(&self, hash: Hash256, bucket: Arc<Bucket>) {
        let mut cache = self.cache.write().unwrap();

        // Evict if cache is full (simple LRU would be better)
        if cache.len() >= self.max_cache_size {
            // Remove a random entry (not ideal, but simple)
            if let Some(key) = cache.keys().next().cloned() {
                cache.remove(&key);
            }
        }

        cache.insert(hash, bucket);
    }

    /// Clear the bucket cache.
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
    }

    /// Get the number of cached buckets.
    pub fn cache_size(&self) -> usize {
        let cache = self.cache.read().unwrap();
        cache.len()
    }

    /// List all bucket files in the directory.
    pub fn list_buckets(&self) -> Result<Vec<Hash256>> {
        let mut hashes = Vec::new();

        for entry in std::fs::read_dir(&self.bucket_dir)? {
            let entry = entry?;
            let path = entry.path();

            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".bucket.gz") {
                    let hash_str = name.trim_end_matches(".bucket.gz");
                    if let Ok(hash) = Hash256::from_hex(hash_str) {
                        hashes.push(hash);
                    }
                }
            }
        }

        Ok(hashes)
    }

    /// Delete a bucket file.
    ///
    /// This also removes the bucket from the cache.
    pub fn delete_bucket(&self, hash: &Hash256) -> Result<()> {
        // Remove from cache
        {
            let mut cache = self.cache.write().unwrap();
            cache.remove(hash);
        }

        // Delete file
        let path = self.bucket_path(hash);
        if path.exists() {
            std::fs::remove_file(path)?;
        }

        Ok(())
    }

    /// Delete all bucket files not in the given set of hashes.
    ///
    /// This is useful for garbage collection.
    pub fn retain_buckets(&self, keep: &[Hash256]) -> Result<usize> {
        let keep_set: std::collections::HashSet<_> = keep.iter().collect();
        let all_buckets = self.list_buckets()?;
        let mut deleted = 0;

        for hash in all_buckets {
            if !keep_set.contains(&hash) {
                self.delete_bucket(&hash)?;
                deleted += 1;
            }
        }

        Ok(deleted)
    }

    /// Get statistics about the bucket manager.
    pub fn stats(&self) -> BucketManagerStats {
        let cached = self.cache_size();
        let on_disk = self.list_buckets().map(|v| v.len()).unwrap_or(0);

        BucketManagerStats {
            cached_buckets: cached,
            disk_buckets: on_disk,
            bucket_dir: self.bucket_dir.clone(),
        }
    }

    /// Import a bucket from raw XDR bytes.
    pub fn import_bucket(&self, xdr_bytes: &[u8]) -> Result<Arc<Bucket>> {
        let bucket = Bucket::from_xdr_bytes(xdr_bytes)?;
        let hash = bucket.hash();

        // Check cache
        {
            let cache = self.cache.read().unwrap();
            if let Some(cached) = cache.get(&hash) {
                return Ok(Arc::clone(cached));
            }
        }

        // Save to disk
        let path = self.bucket_path(&hash);
        bucket.save_to_file(&path)?;

        // Add to cache
        let bucket = Arc::new(bucket);
        self.add_to_cache(hash, Arc::clone(&bucket));

        Ok(bucket)
    }

    /// Export a bucket to raw XDR bytes.
    pub fn export_bucket(&self, hash: &Hash256) -> Result<Vec<u8>> {
        let bucket = self.load_bucket(hash)?;
        bucket.to_xdr_bytes()
    }

    /// Visits all ledger entries in buckets matching the filter criteria.
    ///
    /// This method iterates through bucket entries, applying a filter function
    /// to determine which entries to process, and an accept function to handle
    /// matching entries.
    ///
    /// # Arguments
    ///
    /// * `buckets` - Iterator over buckets to scan
    /// * `filter_entry` - Function that returns `true` for entries to consider
    /// * `accept_entry` - Function called for each matching entry; return `false` to stop
    /// * `min_ledger` - Optional minimum ledger sequence to filter entries
    ///
    /// # Returns
    ///
    /// `true` if iteration completed, `false` if stopped early by `accept_entry`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// manager.visit_ledger_entries(
    ///     &bucket_hashes,
    ///     |entry| matches!(entry.data, LedgerEntryData::Account(_)),
    ///     |entry| {
    ///         println!("Found account: {:?}", entry);
    ///         true // continue
    ///     },
    ///     Some(1000), // only entries modified after ledger 1000
    /// );
    /// ```
    pub fn visit_ledger_entries<F, A>(
        &self,
        bucket_hashes: &[Hash256],
        filter_entry: F,
        mut accept_entry: A,
        min_ledger: Option<u32>,
    ) -> Result<bool>
    where
        F: Fn(&LedgerEntry) -> bool,
        A: FnMut(&LedgerEntry) -> bool,
    {
        use std::collections::HashSet;

        // Track seen keys to avoid processing duplicates
        let mut seen_keys: HashSet<LedgerKey> = HashSet::new();

        for hash in bucket_hashes {
            if hash.is_zero() {
                continue;
            }

            let bucket = self.load_bucket(hash)?;

            for entry in bucket.iter() {
                match entry {
                    crate::BucketEntry::Live(ref ledger_entry)
                    | crate::BucketEntry::Init(ref ledger_entry) => {
                        // Check min_ledger filter
                        if let Some(min) = min_ledger {
                            if ledger_entry.last_modified_ledger_seq < min {
                                continue;
                            }
                        }

                        // Check filter
                        if !filter_entry(ledger_entry) {
                            continue;
                        }

                        // Check if already seen
                        if let Some(key) = crate::entry::ledger_entry_to_key(ledger_entry) {
                            if seen_keys.contains(&key) {
                                continue;
                            }
                            seen_keys.insert(key);
                        }

                        // Accept the entry
                        if !accept_entry(ledger_entry) {
                            return Ok(false);
                        }
                    }
                    crate::BucketEntry::Dead(ref key) => {
                        // Mark key as seen (it's deleted)
                        seen_keys.insert(key.clone());
                    }
                    crate::BucketEntry::Metadata(_) => {
                        // Skip metadata entries
                    }
                }
            }
        }

        Ok(true)
    }

    /// Visits all ledger entries of a specific type in the given buckets.
    ///
    /// This is a convenience wrapper around [`visit_ledger_entries`] that
    /// filters by entry type.
    pub fn visit_ledger_entries_of_type<A>(
        &self,
        bucket_hashes: &[Hash256],
        entry_type: stellar_xdr::curr::LedgerEntryType,
        accept_entry: A,
        min_ledger: Option<u32>,
    ) -> Result<bool>
    where
        A: FnMut(&LedgerEntry) -> bool,
    {
        self.visit_ledger_entries(
            bucket_hashes,
            |entry| ledger_entry_type(&entry.data) == entry_type,
            accept_entry,
            min_ledger,
        )
    }
}

/// Returns the ledger entry type for a given entry data.
fn ledger_entry_type(data: &stellar_xdr::curr::LedgerEntryData) -> stellar_xdr::curr::LedgerEntryType {
    use stellar_xdr::curr::{LedgerEntryData, LedgerEntryType};
    match data {
        LedgerEntryData::Account(_) => LedgerEntryType::Account,
        LedgerEntryData::Trustline(_) => LedgerEntryType::Trustline,
        LedgerEntryData::Offer(_) => LedgerEntryType::Offer,
        LedgerEntryData::Data(_) => LedgerEntryType::Data,
        LedgerEntryData::ClaimableBalance(_) => LedgerEntryType::ClaimableBalance,
        LedgerEntryData::LiquidityPool(_) => LedgerEntryType::LiquidityPool,
        LedgerEntryData::ContractData(_) => LedgerEntryType::ContractData,
        LedgerEntryData::ContractCode(_) => LedgerEntryType::ContractCode,
        LedgerEntryData::ConfigSetting(_) => LedgerEntryType::ConfigSetting,
        LedgerEntryData::Ttl(_) => LedgerEntryType::Ttl,
    }
}

impl BucketManager {
    /// Loads the complete ledger state from a list of bucket hashes.
    ///
    /// This iterates through all buckets from oldest to newest (reverse order),
    /// building a map of all live entries. Dead entries shadow older versions.
    /// The result is a complete view of ledger state at the bucket list snapshot.
    ///
    /// This is the Rust equivalent of C++ `loadCompleteLedgerState`.
    ///
    /// # Arguments
    ///
    /// * `bucket_hashes` - List of bucket hashes in order from level 10 snap to level 0 curr
    ///                     (oldest to newest is correct order for last-write-wins)
    ///
    /// # Returns
    ///
    /// A vector of all live ledger entries, with newer entries shadowing older ones.
    pub fn load_complete_ledger_state(
        &self,
        bucket_hashes: &[Hash256],
    ) -> Result<Vec<LedgerEntry>> {
        use std::collections::BTreeMap;

        // Use BTreeMap to maintain sorted order by key
        let mut state: BTreeMap<Vec<u8>, LedgerEntry> = BTreeMap::new();

        // Process buckets from oldest to newest (so newer entries overwrite older)
        // bucket_hashes should be in order: level 10 snap, level 10 curr, ..., level 0 snap, level 0 curr
        // We iterate in that order so newest entries win
        for hash in bucket_hashes {
            if hash.is_zero() {
                continue;
            }

            let bucket = self.load_bucket(hash)?;

            for entry in bucket.iter() {
                match entry {
                    crate::BucketEntry::Live(ref ledger_entry)
                    | crate::BucketEntry::Init(ref ledger_entry) => {
                        if let Some(key) = crate::entry::ledger_entry_to_key(ledger_entry) {
                            let key_bytes = key.to_xdr(Limits::none()).map_err(|e| {
                                BucketError::Serialization(format!(
                                    "failed to serialize ledger key: {}",
                                    e
                                ))
                            })?;
                            state.insert(key_bytes, ledger_entry.clone());
                        }
                    }
                    crate::BucketEntry::Dead(ref key) => {
                        let key_bytes = key.to_xdr(Limits::none()).map_err(|e| {
                            BucketError::Serialization(format!(
                                "failed to serialize ledger key: {}",
                                e
                            ))
                        })?;
                        // Remove the entry if it exists (dead shadows live)
                        state.remove(&key_bytes);
                    }
                    crate::BucketEntry::Metadata(_) => {
                        // Skip metadata entries
                    }
                }
            }
        }

        Ok(state.into_values().collect())
    }

    /// Merges all buckets in a bucket list into a single "super bucket".
    ///
    /// This creates a consolidated bucket containing all live entries from
    /// the bucket list. Useful for creating offline archives or testing.
    ///
    /// This is the Rust equivalent of C++ `mergeBuckets` (the standalone function
    /// that merges an entire bucket list).
    ///
    /// # Arguments
    ///
    /// * `bucket_hashes` - List of bucket hashes from the bucket list
    /// * `protocol_version` - Protocol version for the output bucket
    ///
    /// # Returns
    ///
    /// A single bucket containing all live entries.
    pub fn merge_all_buckets(
        &self,
        bucket_hashes: &[Hash256],
        protocol_version: u32,
    ) -> Result<Arc<Bucket>> {
        use stellar_xdr::curr::BucketMetadata;

        // Load complete state
        let entries = self.load_complete_ledger_state(bucket_hashes)?;

        if entries.is_empty() {
            return Ok(Arc::new(Bucket::empty()));
        }

        // Create bucket entries with metadata
        let mut bucket_entries: Vec<crate::BucketEntry> = Vec::with_capacity(entries.len() + 1);

        // Add metadata for protocol 11+
        if protocol_version >= 11 {
            bucket_entries.push(crate::BucketEntry::Metadata(BucketMetadata {
                ledger_version: protocol_version,
                ext: stellar_xdr::curr::BucketMetadataExt::V0,
            }));
        }

        // Add all entries as LIVE (not INIT since these are resolved entries)
        bucket_entries.extend(entries.into_iter().map(crate::BucketEntry::Live));

        // Create and save the merged bucket
        self.create_bucket(bucket_entries)
    }

    /// Verifies that all referenced bucket files exist on disk.
    ///
    /// This is a simple synchronous check. For background verification with
    /// hash validation, use `verify_bucket_hashes`.
    ///
    /// # Arguments
    ///
    /// * `bucket_hashes` - List of bucket hashes to verify
    ///
    /// # Returns
    ///
    /// A list of missing bucket hashes, or empty if all exist.
    pub fn verify_buckets_exist(&self, bucket_hashes: &[Hash256]) -> Vec<Hash256> {
        bucket_hashes
            .iter()
            .filter(|hash| !hash.is_zero() && !self.bucket_exists(hash))
            .copied()
            .collect()
    }

    /// Verifies bucket file contents match their expected hashes.
    ///
    /// This performs a full hash verification by reading and decompressing
    /// each bucket file. This is expensive and should be used sparingly.
    ///
    /// This is a simplified version of C++ `scheduleVerifyReferencedBucketsWork`.
    ///
    /// # Arguments
    ///
    /// * `bucket_hashes` - List of bucket hashes to verify
    ///
    /// # Returns
    ///
    /// A list of (expected_hash, actual_hash) pairs for any mismatched buckets.
    pub fn verify_bucket_hashes(&self, bucket_hashes: &[Hash256]) -> Result<Vec<(Hash256, Hash256)>> {
        let mut mismatches = Vec::new();

        for expected_hash in bucket_hashes {
            if expected_hash.is_zero() {
                continue;
            }

            let path = self.bucket_path(expected_hash);
            if !path.exists() {
                continue; // Skip missing files (use verify_buckets_exist for that check)
            }

            match Bucket::load_from_file(&path) {
                Ok(bucket) => {
                    let actual_hash = bucket.hash();
                    if actual_hash != *expected_hash {
                        mismatches.push((*expected_hash, actual_hash));
                    }
                }
                Err(_) => {
                    // File exists but couldn't be loaded - treat as hash mismatch
                    mismatches.push((*expected_hash, Hash256::ZERO));
                }
            }
        }

        Ok(mismatches)
    }

    /// Ensures all referenced bucket files exist, downloading if needed.
    ///
    /// This method checks if each bucket exists locally. For missing buckets,
    /// it calls the provided fetch function to obtain the bucket data.
    ///
    /// This supports the `assumeState` flow for restoring from HistoryArchiveState.
    ///
    /// # Arguments
    ///
    /// * `bucket_hashes` - List of bucket hashes required
    /// * `fetch_bucket` - Function that fetches bucket XDR bytes by hash
    ///
    /// # Returns
    ///
    /// The number of buckets that were fetched (not already present).
    pub fn ensure_buckets_exist<F>(&self, bucket_hashes: &[Hash256], mut fetch_bucket: F) -> Result<usize>
    where
        F: FnMut(&Hash256) -> Result<Vec<u8>>,
    {
        let mut fetched = 0;

        for hash in bucket_hashes {
            if hash.is_zero() {
                continue;
            }

            if self.bucket_exists(hash) {
                continue;
            }

            // Fetch and import the bucket
            let xdr_bytes = fetch_bucket(hash)?;
            let bucket = self.import_bucket(&xdr_bytes)?;

            // Verify hash matches
            if bucket.hash() != *hash {
                return Err(BucketError::HashMismatch {
                    expected: hash.to_hex(),
                    actual: bucket.hash().to_hex(),
                });
            }

            fetched += 1;
        }

        Ok(fetched)
    }
}

impl std::fmt::Debug for BucketManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BucketManager")
            .field("bucket_dir", &self.bucket_dir)
            .field("cache_size", &self.cache_size())
            .field("max_cache_size", &self.max_cache_size)
            .finish()
    }
}

/// Statistics about a BucketManager.
///
/// Provides insight into the manager's state for monitoring and debugging.
#[derive(Debug, Clone)]
pub struct BucketManagerStats {
    /// Number of buckets currently held in the in-memory cache.
    pub cached_buckets: usize,
    /// Number of bucket files on disk (may include garbage).
    pub disk_buckets: usize,
    /// The directory where bucket files are stored.
    pub bucket_dir: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BucketEntry; // Re-import to shadow XDR's BucketEntry
    use stellar_xdr::curr::*;
    use tempfile::TempDir;

    fn make_account_id(bytes: [u8; 32]) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
    }

    fn make_account_entry(bytes: [u8; 32], balance: i64) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Account(AccountEntry {
                account_id: make_account_id(bytes),
                balance,
                seq_num: SequenceNumber(1),
                num_sub_entries: 0,
                inflation_dest: None,
                flags: 0,
                home_domain: String32::default(),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: Vec::new().try_into().unwrap(),
                ext: AccountEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    fn make_account_key(bytes: [u8; 32]) -> LedgerKey {
        LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id(bytes),
        })
    }

    fn create_manager() -> (TempDir, BucketManager) {
        let temp_dir = TempDir::new().unwrap();
        let manager = BucketManager::new(temp_dir.path().to_path_buf()).unwrap();
        (temp_dir, manager)
    }

    #[test]
    fn test_create_bucket() {
        let (_temp_dir, manager) = create_manager();

        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        let bucket = manager.create_bucket(entries).unwrap();
        assert_eq!(bucket.len(), 2);
        assert!(!bucket.hash().is_zero());
    }

    #[test]
    fn test_load_bucket() {
        let (_temp_dir, manager) = create_manager();

        let entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];

        let bucket = manager.create_bucket(entries).unwrap();
        let hash = bucket.hash();

        // Clear cache to force disk load
        manager.clear_cache();

        let loaded = manager.load_bucket(&hash).unwrap();
        assert_eq!(loaded.hash(), hash);
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn test_bucket_caching() {
        let (_temp_dir, manager) = create_manager();

        let entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];

        let bucket = manager.create_bucket(entries).unwrap();
        let hash = bucket.hash();

        assert_eq!(manager.cache_size(), 1);

        // Loading again should use cache
        let loaded = manager.load_bucket(&hash).unwrap();
        assert!(Arc::ptr_eq(&bucket, &loaded));
    }

    #[test]
    fn test_bucket_exists() {
        let (_temp_dir, manager) = create_manager();

        let entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];

        let bucket = manager.create_bucket(entries).unwrap();
        let hash = bucket.hash();

        assert!(manager.bucket_exists(&hash));
        assert!(!manager.bucket_exists(&Hash256::hash(b"nonexistent")));
        assert!(manager.bucket_exists(&Hash256::ZERO)); // Empty bucket
    }

    #[test]
    fn test_merge_buckets() {
        let (_temp_dir, manager) = create_manager();

        let old_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 200))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = manager.merge(&old_bucket, &new_bucket, 0).unwrap();
        assert_eq!(merged.len(), 1);

        let key = make_account_key([1u8; 32]);
        let entry = merged.get_entry(&key).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry.data {
            assert_eq!(account.balance, 200);
        }
    }

    #[test]
    fn test_list_and_delete_buckets() {
        let (_temp_dir, manager) = create_manager();

        let entries1 = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let entries2 = vec![BucketEntry::Live(make_account_entry([2u8; 32], 200))];

        let bucket1 = manager.create_bucket(entries1).unwrap();
        let bucket2 = manager.create_bucket(entries2).unwrap();

        let buckets = manager.list_buckets().unwrap();
        assert_eq!(buckets.len(), 2);

        manager.delete_bucket(&bucket1.hash()).unwrap();

        let buckets = manager.list_buckets().unwrap();
        assert_eq!(buckets.len(), 1);
        assert!(buckets.contains(&bucket2.hash()));
    }

    #[test]
    fn test_retain_buckets() {
        let (_temp_dir, manager) = create_manager();

        let entries1 = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let entries2 = vec![BucketEntry::Live(make_account_entry([2u8; 32], 200))];
        let entries3 = vec![BucketEntry::Live(make_account_entry([3u8; 32], 300))];

        let bucket1 = manager.create_bucket(entries1).unwrap();
        let bucket2 = manager.create_bucket(entries2).unwrap();
        let _bucket3 = manager.create_bucket(entries3).unwrap();

        // Keep only bucket1 and bucket2
        let deleted = manager
            .retain_buckets(&[bucket1.hash(), bucket2.hash()])
            .unwrap();
        assert_eq!(deleted, 1);

        let buckets = manager.list_buckets().unwrap();
        assert_eq!(buckets.len(), 2);
    }

    #[test]
    fn test_import_export_bucket() {
        let (_temp_dir, manager) = create_manager();

        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        let original = manager.create_bucket(entries).unwrap();
        let hash = original.hash();

        // Export
        let xdr_bytes = manager.export_bucket(&hash).unwrap();

        // Import (create new manager)
        let temp_dir2 = TempDir::new().unwrap();
        let manager2 = BucketManager::new(temp_dir2.path().to_path_buf()).unwrap();

        let imported = manager2.import_bucket(&xdr_bytes).unwrap();
        assert_eq!(imported.hash(), hash);
        assert_eq!(imported.len(), 2);
    }

    #[test]
    fn test_empty_bucket() {
        let (_temp_dir, manager) = create_manager();

        let bucket = manager.create_bucket(vec![]).unwrap();
        assert!(bucket.is_empty());
        assert_eq!(bucket.hash(), Hash256::ZERO);

        // Loading empty bucket should work
        let loaded = manager.load_bucket(&Hash256::ZERO).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_stats() {
        let (_temp_dir, manager) = create_manager();

        let entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        manager.create_bucket(entries).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.cached_buckets, 1);
        assert_eq!(stats.disk_buckets, 1);
    }

    #[test]
    fn test_load_complete_ledger_state() {
        let (_temp_dir, manager) = create_manager();

        // Create two buckets - older has entry1, newer has entry2
        let bucket1 = manager
            .create_bucket(vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))])
            .unwrap();
        let bucket2 = manager
            .create_bucket(vec![BucketEntry::Live(make_account_entry([2u8; 32], 200))])
            .unwrap();

        // Load complete state (bucket1 is older, bucket2 is newer)
        let entries = manager
            .load_complete_ledger_state(&[bucket1.hash(), bucket2.hash()])
            .unwrap();

        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_load_complete_ledger_state_with_updates() {
        let (_temp_dir, manager) = create_manager();

        // Create older bucket with initial entry
        let bucket1 = manager
            .create_bucket(vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))])
            .unwrap();

        // Create newer bucket with updated entry
        let bucket2 = manager
            .create_bucket(vec![BucketEntry::Live(make_account_entry([1u8; 32], 500))])
            .unwrap();

        // Load complete state - newer entry should win
        let entries = manager
            .load_complete_ledger_state(&[bucket1.hash(), bucket2.hash()])
            .unwrap();

        assert_eq!(entries.len(), 1);
        if let LedgerEntryData::Account(account) = &entries[0].data {
            assert_eq!(account.balance, 500);
        } else {
            panic!("Expected Account entry");
        }
    }

    #[test]
    fn test_load_complete_ledger_state_with_deletes() {
        let (_temp_dir, manager) = create_manager();

        // Create older bucket with entry
        let bucket1 = manager
            .create_bucket(vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))])
            .unwrap();

        // Create newer bucket with deletion
        let bucket2 = manager
            .create_bucket(vec![BucketEntry::Dead(make_account_key([1u8; 32]))])
            .unwrap();

        // Load complete state - entry should be deleted
        let entries = manager
            .load_complete_ledger_state(&[bucket1.hash(), bucket2.hash()])
            .unwrap();

        assert!(entries.is_empty());
    }

    #[test]
    fn test_merge_all_buckets() {
        let (_temp_dir, manager) = create_manager();

        // Create buckets with different entries
        let bucket1 = manager
            .create_bucket(vec![
                BucketEntry::Live(make_account_entry([1u8; 32], 100)),
                BucketEntry::Live(make_account_entry([2u8; 32], 200)),
            ])
            .unwrap();
        let bucket2 = manager
            .create_bucket(vec![
                BucketEntry::Live(make_account_entry([3u8; 32], 300)),
                BucketEntry::Live(make_account_entry([1u8; 32], 150)), // Update entry 1
            ])
            .unwrap();

        // Merge all buckets
        let merged = manager
            .merge_all_buckets(&[bucket1.hash(), bucket2.hash()], 25)
            .unwrap();

        // Should have 3 entries (entry 1 updated, entries 2 and 3)
        assert_eq!(merged.len(), 4); // 1 metadata + 3 entries

        // Check that entry 1 has the updated value
        let key1 = make_account_key([1u8; 32]);
        let entry1 = merged.get_entry(&key1).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry1.data {
            assert_eq!(account.balance, 150);
        } else {
            panic!("Expected Account entry");
        }
    }

    #[test]
    fn test_verify_buckets_exist() {
        let (_temp_dir, manager) = create_manager();

        let bucket = manager
            .create_bucket(vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))])
            .unwrap();

        let nonexistent = Hash256::hash(b"does not exist");

        // Should find the nonexistent bucket as missing
        let missing = manager.verify_buckets_exist(&[bucket.hash(), nonexistent, Hash256::ZERO]);

        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], nonexistent);
    }

    #[test]
    fn test_verify_bucket_hashes() {
        let (_temp_dir, manager) = create_manager();

        let bucket = manager
            .create_bucket(vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))])
            .unwrap();

        // Verify hash matches
        let mismatches = manager.verify_bucket_hashes(&[bucket.hash()]).unwrap();
        assert!(mismatches.is_empty());
    }

    #[test]
    fn test_ensure_buckets_exist() {
        let (_temp_dir, manager) = create_manager();

        // Create a bucket in another manager
        let temp_dir2 = TempDir::new().unwrap();
        let manager2 = BucketManager::new(temp_dir2.path().to_path_buf()).unwrap();
        let bucket = manager2
            .create_bucket(vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))])
            .unwrap();

        let bucket_xdr = manager2.export_bucket(&bucket.hash()).unwrap();

        // Ensure it exists in manager (needs to fetch)
        let fetched = manager
            .ensure_buckets_exist(&[bucket.hash()], |_hash| Ok(bucket_xdr.clone()))
            .unwrap();

        assert_eq!(fetched, 1);

        // Second call should fetch 0 (already exists)
        let fetched = manager
            .ensure_buckets_exist(&[bucket.hash()], |_hash| {
                panic!("Should not be called")
            })
            .unwrap();
        assert_eq!(fetched, 0);
    }
}
