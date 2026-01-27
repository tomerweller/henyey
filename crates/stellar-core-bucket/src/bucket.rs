//! Individual bucket implementation.
//!
//! A bucket is an immutable container of sorted ledger entries, stored as gzipped XDR.
//! Buckets are identified by their content hash (SHA-256 of uncompressed contents).
//!
//! # Storage Modes
//!
//! Buckets support two storage modes to balance memory usage and performance:
//!
//! - **InMemory**: All entries are loaded into memory with a key index for O(1) lookups.
//!   Best for normal operations, merging, and when entries need to be accessed repeatedly.
//!
//! - **DiskBacked**: Entries remain on disk with a compact index mapping key hashes to
//!   file offsets. Entries are loaded on-demand when accessed. Essential for mainnet
//!   catchup where buckets can contain millions of entries (potentially many GB).
//!
//! # XDR Format
//!
//! Bucket files use the XDR Record Marking Standard (RFC 5531). Each entry is prefixed
//! with a 4-byte record mark: the high bit indicates "last fragment" (always set for
//! buckets), and the remaining 31 bits contain the record length in bytes.
//!
//! The bucket hash is computed over the uncompressed XDR bytes, including record marks.
//! This ensures hash consistency with stellar-core's bucket hash computation.
//!
//! # Thread Safety
//!
//! Buckets are immutable after creation and use `Arc` internally, making them safe
//! to share across threads. The disk-backed mode uses file handles that are opened
//! fresh for each operation to avoid contention.

use std::collections::BTreeMap;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use stellar_xdr::curr::{LedgerEntry, LedgerKey, Limits, ReadXdr, WriteXdr};

use stellar_core_common::Hash256;

use crate::disk_bucket::DiskBucket;
use crate::entry::{compare_entries, compare_keys, BucketEntry};
use crate::{BucketError, Result};

/// Internal storage mode for bucket entries.
///
/// This enum is not public; users interact with buckets through the [`Bucket`]
/// type which abstracts over both storage modes.
#[derive(Clone)]
enum BucketStorage {
    /// All entries loaded in memory with a key-to-index map for O(1) lookups.
    InMemory {
        /// The sorted list of bucket entries.
        entries: Arc<Vec<BucketEntry>>,
        /// Map from serialized key bytes to entry index for fast lookups.
        key_index: Arc<BTreeMap<Vec<u8>, usize>>,
    },
    /// Entries stored on disk with a compact index for on-demand loading.
    DiskBacked {
        /// The disk bucket implementation that handles file I/O.
        disk_bucket: Arc<DiskBucket>,
    },
}

/// An immutable bucket file containing sorted ledger entries.
///
/// Buckets are the fundamental storage unit in Stellar's BucketList.
/// They are:
/// - **Immutable** once created (content-addressable by hash)
/// - **Identified** by their SHA-256 content hash
/// - **Stored** as gzipped XDR on disk with record marking
/// - **Sorted** by key for efficient merging and O(log n) binary search
///
/// # Creating Buckets
///
/// Buckets can be created in several ways:
/// - [`Bucket::empty()`]: Create an empty bucket (zero hash)
/// - [`Bucket::from_entries()`]: Create from a list of entries (will be sorted)
/// - [`Bucket::from_sorted_entries()`]: Create from pre-sorted entries (preserves order)
/// - [`Bucket::load_from_file()`]: Load from a gzipped bucket file
/// - [`Bucket::from_xdr_bytes()`]: Parse from uncompressed XDR bytes
/// - [`Bucket::from_xdr_bytes_disk_backed()`]: Memory-efficient loading for catchup
///
/// # Storage Modes
///
/// For memory efficiency during catchup (when processing mainnet buckets with
/// millions of entries), buckets can use disk-backed storage where entries
/// are loaded on-demand rather than all at once.
///
/// Use [`Bucket::is_disk_backed()`] to check the storage mode.
///
/// # Entry Access
///
/// - [`Bucket::get()`]: Look up a raw bucket entry by key
/// - [`Bucket::get_entry()`]: Look up a ledger entry (returns None for dead entries)
/// - [`Bucket::iter()`]: Iterate over all entries
/// - [`Bucket::entries()`]: Get entries as a slice (in-memory only, panics for disk-backed)
#[derive(Clone)]
pub struct Bucket {
    /// The SHA-256 hash of this bucket's uncompressed XDR contents.
    hash: Hash256,
    /// The storage mode (in-memory or disk-backed).
    storage: BucketStorage,
    /// In-memory entries for level 0 optimization.
    ///
    /// When set, these entries are kept in memory for fast access during
    /// subsequent merges. This avoids disk I/O for level 0 merges which
    /// happen frequently and block the main thread.
    ///
    /// This is separate from `BucketStorage::InMemory` because:
    /// - The bucket is still written to disk for durability
    /// - This is an optional optimization for level 0 only
    /// - The entries are the same as in the storage, just kept in RAM
    level_zero_entries: Option<Arc<Vec<BucketEntry>>>,
}

impl Bucket {
    /// Create an empty bucket with a zero hash.
    ///
    /// Empty buckets are special-cased in bucket list operations and don't
    /// need to be stored on disk. The zero hash serves as a sentinel value.
    ///
    /// # In-memory entries for empty buckets
    ///
    /// In C++ stellar-core, empty buckets have `mEntries` initialized to an empty
    /// vector. This means `hasInMemoryEntries()` returns true for empty buckets.
    /// We match this behavior by setting `level_zero_entries` to an empty vector
    /// rather than None. This is important because:
    ///
    /// 1. When level 0 snaps, curr becomes empty
    /// 2. On the next ledger, prepare_first_level merges this empty curr with new entries
    /// 3. If empty curr doesn't have "in-memory entries", we fall back to regular merge
    /// 4. In C++, both empty curr and new entries have in-memory state, so in-memory merge is used
    /// 5. We need to match this behavior for bucket list hash parity
    pub fn empty() -> Self {
        Self {
            hash: Hash256::ZERO,
            storage: BucketStorage::InMemory {
                entries: Arc::new(Vec::new()),
                key_index: Arc::new(BTreeMap::new()),
            },
            // Empty vector, not None - matches C++ behavior where mEntries is an empty vector
            level_zero_entries: Some(Arc::new(Vec::new())),
        }
    }

    /// Create a bucket from a list of entries.
    ///
    /// The entries will be sorted by key using [`compare_entries`]. This is the
    /// standard way to create buckets when the entry order is not guaranteed.
    ///
    /// # Arguments
    ///
    /// * `entries` - The bucket entries (will be sorted in place)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let entries = vec![
    ///     BucketEntry::Live(account_entry),
    ///     BucketEntry::Dead(deleted_key),
    /// ];
    /// let bucket = Bucket::from_entries(entries)?;
    /// ```
    pub fn from_entries(mut entries: Vec<BucketEntry>) -> Result<Self> {
        // Sort entries by key
        entries.sort_by(compare_entries);

        Self::from_sorted_entries(entries)
    }

    /// Create a bucket from a list of pre-sorted entries.
    ///
    /// This method skips the sorting step, which is useful when entries are
    /// already known to be in the correct order (e.g., extracted from another
    /// bucket via iteration).
    ///
    /// # Safety
    ///
    /// The entries **must** already be sorted by key according to [`compare_entries`].
    /// Using unsorted entries will result in incorrect bucket behavior:
    /// - Lookups may fail to find existing entries
    /// - Merges will produce incorrect results
    /// - Hash verification may fail
    ///
    /// This is intended for entries extracted from disk-backed buckets that were
    /// already sorted by stellar-core, or from bucket iteration which preserves order.
    ///
    /// # Performance
    ///
    /// This method computes the bucket hash incrementally while building the key index,
    /// using a single serialization pass for each entry. This is more efficient than
    /// serializing all entries twice (once for the index, once for the hash).
    pub fn from_sorted_entries(entries: Vec<BucketEntry>) -> Result<Self> {
        use sha2::{Digest, Sha256};
        use stellar_xdr::curr::{Limited, WriteXdr};

        let mut key_index = BTreeMap::new();
        let mut hasher = Sha256::new();

        // Single pass: serialize each entry once, use for both index and hash
        for (idx, entry) in entries.iter().enumerate() {
            // Serialize entry to XDR
            let xdr_entry = entry.to_xdr_entry();
            let mut entry_bytes = Vec::new();
            let mut limited = Limited::new(&mut entry_bytes, Limits::none());
            xdr_entry.write_xdr(&mut limited).map_err(|e| {
                BucketError::Serialization(format!("Failed to serialize entry: {}", e))
            })?;

            // Write record mark + entry to hasher (XDR Record Marking format)
            let size = entry_bytes.len() as u32;
            let record_mark = size | 0x80000000; // Set high bit
            hasher.update(&record_mark.to_be_bytes());
            hasher.update(&entry_bytes);

            // Build key index (only need to serialize key if entry has one)
            if let Some(key) = entry.key() {
                let key_bytes = key.to_xdr(Limits::none()).map_err(|e| {
                    BucketError::Serialization(format!("Failed to serialize key: {}", e))
                })?;
                key_index.insert(key_bytes, idx);
            }
        }

        // Compute final hash
        let hash_bytes: [u8; 32] = hasher.finalize().into();
        let hash = Hash256::from_bytes(hash_bytes);

        Ok(Self {
            hash,
            storage: BucketStorage::InMemory {
                entries: Arc::new(entries),
                key_index: Arc::new(key_index),
            },
            level_zero_entries: None,
        })
    }

    /// Create a bucket from pre-computed parts.
    ///
    /// This is an internal constructor used by optimized merge paths that have
    /// already computed the hash incrementally during the merge operation.
    ///
    /// # Arguments
    ///
    /// * `hash` - Pre-computed SHA256 hash of all entries
    /// * `entries` - All entries including metadata, already sorted
    /// * `key_index` - Pre-built key index mapping serialized keys to entry indices
    /// * `level_zero_entries` - Optional non-metadata entries for level 0 merges
    pub fn from_parts(
        hash: Hash256,
        entries: Arc<Vec<BucketEntry>>,
        key_index: Arc<BTreeMap<Vec<u8>, usize>>,
        level_zero_entries: Option<Arc<Vec<BucketEntry>>>,
    ) -> Self {
        Self {
            hash,
            storage: BucketStorage::InMemory { entries, key_index },
            level_zero_entries,
        }
    }

    /// Load a bucket from a gzipped XDR file.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut decoder = GzDecoder::new(reader);

        // Read and decompress
        let mut uncompressed = Vec::new();
        decoder.read_to_end(&mut uncompressed)?;

        Self::from_xdr_bytes(&uncompressed)
    }

    /// Create a bucket from uncompressed XDR bytes.
    pub fn from_xdr_bytes(bytes: &[u8]) -> Result<Self> {
        let bucket = Self::from_xdr_bytes_internal(bytes, true)?;

        // Debug: verify that re-serializing entries produces the same hash
        if let BucketStorage::InMemory { entries, .. } = &bucket.storage {
            if !entries.is_empty() {
                let reserialized = Self::serialize_entries(entries)?;
                let reserialized_hash = Hash256::hash(&reserialized);
                if reserialized_hash != bucket.hash {
                    tracing::warn!(
                        original_hash = %bucket.hash,
                        reserialized_hash = %reserialized_hash,
                        original_len = bytes.len(),
                        reserialized_len = reserialized.len(),
                        "Bucket roundtrip hash mismatch detected"
                    );
                }
            }
        }

        Ok(bucket)
    }

    /// Create a bucket from uncompressed XDR bytes without building the key index.
    ///
    /// **Note**: This still loads all entries into memory. For memory-efficient
    /// loading during catchup, use `from_xdr_bytes_disk_backed()` instead.
    pub fn from_xdr_bytes_without_index(bytes: &[u8]) -> Result<Self> {
        Self::from_xdr_bytes_internal(bytes, false)
    }

    /// Create a disk-backed bucket from uncompressed XDR bytes.
    ///
    /// This is the most memory-efficient way to load large buckets. Instead of
    /// parsing all entries into memory, it:
    /// 1. Saves the XDR bytes to the specified path
    /// 2. Builds a compact index mapping key hashes to file offsets
    /// 3. Loads entries on-demand when accessed
    ///
    /// This reduces memory usage from O(entries) to O(unique_keys) for the index,
    /// which is much smaller since we only store 8-byte key hashes and file offsets.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The uncompressed XDR bytes
    /// * `save_path` - Path where the bucket file will be saved
    pub fn from_xdr_bytes_disk_backed(bytes: &[u8], save_path: impl AsRef<Path>) -> Result<Self> {
        let disk_bucket = DiskBucket::from_xdr_bytes(bytes, save_path)?;
        let hash = disk_bucket.hash();

        Ok(Self {
            hash,
            storage: BucketStorage::DiskBacked {
                disk_bucket: Arc::new(disk_bucket),
            },
            level_zero_entries: None,
        })
    }

    /// Internal method to create a bucket with optional key index building.
    fn from_xdr_bytes_internal(bytes: &[u8], build_index: bool) -> Result<Self> {
        let entries = Self::parse_entries(bytes)?;

        // Build key index only if requested (skip during catchup for memory efficiency)
        let key_index = if build_index {
            let mut index = BTreeMap::new();
            for (idx, entry) in entries.iter().enumerate() {
                if let Some(key) = entry.key() {
                    let key_bytes = key.to_xdr(Limits::none()).map_err(|e| {
                        BucketError::Serialization(format!("Failed to serialize key: {}", e))
                    })?;
                    index.insert(key_bytes, idx);
                }
            }
            index
        } else {
            BTreeMap::new()
        };

        // Compute hash from raw bytes (including record marks)
        // This matches the bucket file hash used in history archives
        let hash = Hash256::hash(bytes);

        Ok(Self {
            hash,
            storage: BucketStorage::InMemory {
                entries: Arc::new(entries),
                key_index: Arc::new(key_index),
            },
            level_zero_entries: None,
        })
    }

    /// Parse entries from XDR bytes.
    ///
    /// Bucket files use XDR Record Marking Standard (RFC 5531) with 4-byte
    /// record marks before each entry. The high bit indicates "last fragment"
    /// and the remaining 31 bits contain the record length.
    fn parse_entries(bytes: &[u8]) -> Result<Vec<BucketEntry>> {
        use tracing::debug;

        if bytes.is_empty() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let mut offset = 0;

        debug!(
            "Parsing bucket entries from {} bytes, first 16 bytes: {:02x?}",
            bytes.len(),
            &bytes[..std::cmp::min(16, bytes.len())]
        );

        // Check if the file uses XDR record marking (high bit set in first 4 bytes)
        let uses_record_marks = if bytes.len() >= 4 {
            bytes[0] & 0x80 != 0
        } else {
            false
        };

        if uses_record_marks {
            debug!("Bucket file uses XDR record marking format");

            // Parse using XDR Record Marking Standard
            while offset + 4 <= bytes.len() {
                // Read 4-byte record mark (big-endian)
                let record_mark = u32::from_be_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]);
                offset += 4;

                // High bit is "last fragment" flag, remaining 31 bits are length
                let _last_fragment = (record_mark & 0x80000000) != 0;
                let record_len = (record_mark & 0x7FFFFFFF) as usize;

                if offset + record_len > bytes.len() {
                    return Err(BucketError::Serialization(format!(
                        "Record length {} exceeds remaining data {} at offset {}",
                        record_len,
                        bytes.len() - offset,
                        offset - 4
                    )));
                }

                // Parse the XDR record
                let record_data = &bytes[offset..offset + record_len];
                match stellar_xdr::curr::BucketEntry::from_xdr(record_data, Limits::none()) {
                    Ok(xdr_entry) => {
                        entries.push(BucketEntry::from_xdr_entry(xdr_entry)?);
                    }
                    Err(e) => {
                        debug!(
                            "Parse error at offset {}, record_len {}, data: {:02x?}, error: {}",
                            offset,
                            record_len,
                            &record_data[..std::cmp::min(16, record_data.len())],
                            e
                        );
                        return Err(BucketError::Serialization(format!(
                            "Failed to parse bucket entry: {}",
                            e
                        )));
                    }
                }

                offset += record_len;
            }
        } else {
            debug!("Bucket file uses raw XDR format (no record marks)");

            // Parse as raw XDR stream (legacy format)
            use stellar_xdr::curr::Limited;
            let cursor = std::io::Cursor::new(bytes);
            let mut limited = Limited::new(cursor, Limits::none());

            while limited.inner.position() < bytes.len() as u64 {
                match stellar_xdr::curr::BucketEntry::read_xdr(&mut limited) {
                    Ok(xdr_entry) => {
                        entries.push(BucketEntry::from_xdr_entry(xdr_entry)?);
                    }
                    Err(_) => {
                        // End of stream or error
                        break;
                    }
                }
            }
        }

        debug!("Parsed {} bucket entries", entries.len());
        Ok(entries)
    }

    /// Compute hash for a list of entries.
    fn compute_hash_for_entries(entries: &[BucketEntry]) -> Result<Hash256> {
        let bytes = Self::serialize_entries(entries)?;
        Ok(Hash256::hash(&bytes))
    }

    /// Serialize entries to XDR bytes WITH record marks (RFC 5531 XDR Record Marking Standard).
    /// This format is used for bucket files and hash computation.
    /// Each entry is prefixed with a 4-byte mark: high bit set + 31-bit size in big-endian.
    fn serialize_entries(entries: &[BucketEntry]) -> Result<Vec<u8>> {
        use stellar_xdr::curr::Limited;
        let mut bytes = Vec::new();

        for entry in entries {
            let xdr_entry = entry.to_xdr_entry();

            // First serialize the entry to get its size
            let mut entry_bytes = Vec::new();
            let mut limited = Limited::new(&mut entry_bytes, Limits::none());
            xdr_entry.write_xdr(&mut limited).map_err(|e| {
                BucketError::Serialization(format!("Failed to serialize entry: {}", e))
            })?;

            // Write 4-byte record mark: high bit set + size (big-endian)
            let size = entry_bytes.len() as u32;
            let record_mark = size | 0x80000000; // Set high bit
            bytes.extend_from_slice(&record_mark.to_be_bytes());

            // Write the entry data
            bytes.extend_from_slice(&entry_bytes);
        }

        Ok(bytes)
    }

    /// Save this bucket to a gzipped file.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<PathBuf> {
        let path = path.as_ref().to_path_buf();

        match &self.storage {
            BucketStorage::InMemory { entries, .. } => {
                // Serialize entries
                let uncompressed = Self::serialize_entries(entries)?;

                // Compress and write
                let file = std::fs::File::create(&path)?;
                let mut encoder = GzEncoder::new(file, Compression::default());
                encoder.write_all(&uncompressed)?;
                encoder.finish()?;
            }
            BucketStorage::DiskBacked { disk_bucket } => {
                // For disk-backed buckets, read from disk and compress
                let uncompressed = std::fs::read(disk_bucket.file_path())?;
                let file = std::fs::File::create(&path)?;
                let mut encoder = GzEncoder::new(file, Compression::default());
                encoder.write_all(&uncompressed)?;
                encoder.finish()?;
            }
        }

        Ok(path)
    }

    /// Get the hash of this bucket's contents.
    pub fn hash(&self) -> Hash256 {
        self.hash
    }

    /// Check if this bucket is empty.
    pub fn is_empty(&self) -> bool {
        if self.hash.is_zero() {
            return true;
        }
        match &self.storage {
            BucketStorage::InMemory { entries, .. } => entries.is_empty(),
            BucketStorage::DiskBacked { disk_bucket } => disk_bucket.is_empty(),
        }
    }

    /// Get the number of entries in this bucket.
    pub fn len(&self) -> usize {
        match &self.storage {
            BucketStorage::InMemory { entries, .. } => entries.len(),
            BucketStorage::DiskBacked { disk_bucket } => disk_bucket.len(),
        }
    }

    /// Check if this bucket uses disk-backed storage.
    pub fn is_disk_backed(&self) -> bool {
        matches!(&self.storage, BucketStorage::DiskBacked { .. })
    }

    /// Iterate over entries in this bucket.
    ///
    /// For in-memory buckets, this is efficient. For disk-backed buckets,
    /// this reads entries from disk sequentially.
    pub fn iter(&self) -> BucketIter<'_> {
        match &self.storage {
            BucketStorage::InMemory { entries, .. } => BucketIter::InMemory(entries.iter()),
            BucketStorage::DiskBacked { disk_bucket } => {
                // For disk-backed, we create an iterator that reads from disk
                match disk_bucket.iter() {
                    Ok(iter) => BucketIter::DiskBacked(iter),
                    Err(_) => BucketIter::Empty,
                }
            }
        }
    }

    /// Get entries as a slice.
    ///
    /// **Note**: This only works for in-memory buckets. For disk-backed buckets,
    /// use `iter()` instead.
    ///
    /// # Panics
    ///
    /// Panics if called on a disk-backed bucket.
    pub fn entries(&self) -> &[BucketEntry] {
        match &self.storage {
            BucketStorage::InMemory { entries, .. } => entries,
            BucketStorage::DiskBacked { .. } => {
                panic!("entries() not supported for disk-backed buckets, use iter() instead")
            }
        }
    }

    /// Look up an entry by its key.
    ///
    /// For in-memory buckets, returns a reference. For disk-backed buckets,
    /// loads the entry from disk.
    pub fn get(&self, key: &LedgerKey) -> Result<Option<BucketEntry>> {
        match &self.storage {
            BucketStorage::InMemory { entries, key_index } => {
                let key_bytes = key.to_xdr(Limits::none()).map_err(|e| {
                    BucketError::Serialization(format!("Failed to serialize key: {}", e))
                })?;

                if let Some(&idx) = key_index.get(&key_bytes) {
                    Ok(entries.get(idx).cloned())
                } else {
                    Ok(None)
                }
            }
            BucketStorage::DiskBacked { disk_bucket } => disk_bucket.get(key),
        }
    }

    /// Look up a ledger entry by key, returning None if dead or not found.
    pub fn get_entry(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>> {
        match self.get(key)? {
            Some(BucketEntry::Live(entry)) | Some(BucketEntry::Init(entry)) => Ok(Some(entry)),
            Some(BucketEntry::Dead(_)) => Ok(None), // Entry is deleted
            Some(BucketEntry::Metadata(_)) => Ok(None),
            None => Ok(None),
        }
    }

    /// Binary search for an entry by key.
    ///
    /// Returns the index of the entry if found, or None.
    ///
    /// **Note**: Only works for in-memory buckets. Returns None for disk-backed.
    pub fn binary_search(&self, key: &LedgerKey) -> Option<usize> {
        match &self.storage {
            BucketStorage::InMemory { entries, .. } => {
                let result = entries.binary_search_by(|entry| {
                    match entry.key() {
                        Some(entry_key) => compare_keys(&entry_key, key),
                        None => std::cmp::Ordering::Less, // Metadata sorts first
                    }
                });
                result.ok()
            }
            BucketStorage::DiskBacked { .. } => None,
        }
    }

    /// Get the protocol version from bucket metadata, if present.
    pub fn protocol_version(&self) -> Option<u32> {
        for entry in self.iter() {
            if let BucketEntry::Metadata(meta) = entry {
                return Some(meta.ledger_version);
            }
        }
        None
    }

    /// Convert bucket contents to uncompressed XDR bytes.
    ///
    /// **Note**: Only works for in-memory buckets.
    pub fn to_xdr_bytes(&self) -> Result<Vec<u8>> {
        match &self.storage {
            BucketStorage::InMemory { entries, .. } => Self::serialize_entries(entries),
            BucketStorage::DiskBacked { disk_bucket } => {
                // Read from disk file
                let path = disk_bucket.file_path();
                let bytes = std::fs::read(path)?;
                Ok(bytes)
            }
        }
    }

    // ========================================================================
    // Level 0 In-Memory Optimization
    // ========================================================================

    /// Check if this bucket has in-memory entries for level 0 optimization.
    ///
    /// When true, the bucket can participate in fast in-memory merges
    /// without disk I/O.
    pub fn has_in_memory_entries(&self) -> bool {
        self.level_zero_entries.is_some()
    }

    /// Get the in-memory entries for level 0 optimization.
    ///
    /// Returns None if entries are not cached in memory.
    pub fn get_in_memory_entries(&self) -> Option<&[BucketEntry]> {
        self.level_zero_entries.as_ref().map(|v| v.as_slice())
    }

    /// Set the in-memory entries for level 0 optimization.
    ///
    /// This stores entries in memory for fast access during subsequent merges.
    /// Call this after creating a bucket to enable in-memory level 0 merges.
    pub fn set_in_memory_entries(&mut self, entries: Vec<BucketEntry>) {
        self.level_zero_entries = Some(Arc::new(entries));
    }

    /// Clear the in-memory entries.
    ///
    /// This releases the memory used for level 0 optimization.
    /// Call this when a bucket moves beyond level 0.
    pub fn clear_in_memory_entries(&mut self) {
        self.level_zero_entries = None;
    }

    /// Create a bucket with only in-memory entries (no hash, no index).
    ///
    /// This creates a "shell" bucket for immediate in-memory merging.
    /// It does NOT compute the hash or create an index, making creation fast.
    /// The bucket cannot be persisted until properly finalized.
    ///
    /// This is the Rust equivalent of C++ `LiveBucket::freshInMemoryOnly`.
    ///
    /// # Arguments
    ///
    /// * `entries` - Pre-sorted bucket entries (must be sorted by key!)
    ///
    /// # Returns
    ///
    /// A bucket suitable for in-memory merging. The hash is set to ZERO
    /// until the bucket is finalized through merging.
    pub fn fresh_in_memory_only(entries: Vec<BucketEntry>) -> Self {
        Self {
            hash: Hash256::ZERO, // Not computed yet
            storage: BucketStorage::InMemory {
                entries: Arc::new(Vec::new()), // Empty - use level_zero_entries instead
                key_index: Arc::new(BTreeMap::new()),
            },
            level_zero_entries: Some(Arc::new(entries)),
        }
    }

    /// Create a bucket from sorted entries with in-memory optimization enabled.
    ///
    /// This is like `from_sorted_entries` but also keeps entries in memory
    /// for level 0 optimization.
    ///
    /// # Important: METAENTRY exclusion from in-memory state
    ///
    /// Per C++ stellar-core (LiveBucket.h lines 35-38): "Stores all BucketEntries
    /// (except METAENTRY) in the same order that they appear in the bucket file
    /// for level 0 entries."
    ///
    /// The in-memory entries exclude METAENTRY because:
    /// 1. METAENTRY is always first and can be reconstructed from protocol version
    /// 2. In-memory merges generate fresh metadata based on max protocol version
    /// 3. Keeping metadata separate simplifies the merge logic
    ///
    /// # Performance
    ///
    /// This method separates metadata and non-metadata entries in a single pass,
    /// avoiding unnecessary cloning. The entries are partitioned by swapping,
    /// then the hash is computed over all original entries while the non-metadata
    /// entries are stored separately for level 0 optimizations.
    pub fn from_sorted_entries_with_in_memory(entries: Vec<BucketEntry>) -> Result<Self> {
        use sha2::{Digest, Sha256};
        use stellar_xdr::curr::{Limited, WriteXdr};

        let mut key_index = BTreeMap::new();
        let mut hasher = Sha256::new();

        // Count non-metadata entries for pre-allocation
        let non_meta_count = entries.iter().filter(|e| !e.is_metadata()).count();
        let mut in_memory_entries = Vec::with_capacity(non_meta_count);
        let mut in_memory_idx = 0;

        // Single pass: serialize each entry for hash, build key index,
        // and collect non-metadata entries for level 0 storage
        for (idx, entry) in entries.iter().enumerate() {
            // Serialize entry to XDR for hash
            let xdr_entry = entry.to_xdr_entry();
            let mut entry_bytes = Vec::new();
            let mut limited = Limited::new(&mut entry_bytes, Limits::none());
            xdr_entry.write_xdr(&mut limited).map_err(|e| {
                BucketError::Serialization(format!("Failed to serialize entry: {}", e))
            })?;

            // Write record mark + entry to hasher (XDR Record Marking format)
            let size = entry_bytes.len() as u32;
            let record_mark = size | 0x80000000;
            hasher.update(&record_mark.to_be_bytes());
            hasher.update(&entry_bytes);

            // Build key index for non-metadata entries
            if !entry.is_metadata() {
                if let Some(key) = entry.key() {
                    let key_bytes = key.to_xdr(Limits::none()).map_err(|e| {
                        BucketError::Serialization(format!("Failed to serialize key: {}", e))
                    })?;
                    key_index.insert(key_bytes, idx);
                }
                // Clone entry for level 0 storage (metadata excluded)
                in_memory_entries.push(entry.clone());
                in_memory_idx += 1;
            } else if let Some(key) = entry.key() {
                // Metadata entries can have keys too (for index)
                let key_bytes = key.to_xdr(Limits::none()).map_err(|e| {
                    BucketError::Serialization(format!("Failed to serialize key: {}", e))
                })?;
                key_index.insert(key_bytes, idx);
            }
        }
        let _ = in_memory_idx; // silence unused warning

        // Compute final hash
        let hash_bytes: [u8; 32] = hasher.finalize().into();
        let hash = Hash256::from_bytes(hash_bytes);

        Ok(Self {
            hash,
            storage: BucketStorage::InMemory {
                entries: Arc::new(entries),
                key_index: Arc::new(key_index),
            },
            level_zero_entries: Some(Arc::new(in_memory_entries)),
        })
    }
}

/// Iterator over bucket entries.
///
/// This iterator abstracts over both in-memory and disk-backed storage modes.
/// For in-memory buckets, iteration is efficient (just cloning references).
/// For disk-backed buckets, entries are read sequentially from disk.
///
/// # Performance
///
/// - **In-memory**: O(n) time, no I/O
/// - **Disk-backed**: O(n) time with disk reads, sequential access pattern
///
/// The iterator yields owned [`BucketEntry`] values (cloned from in-memory
/// storage or parsed from disk).
pub enum BucketIter<'a> {
    /// Iterating over in-memory entries (efficient, just cloning).
    InMemory(std::slice::Iter<'a, BucketEntry>),
    /// Iterating over disk-backed entries (reads from disk sequentially).
    DiskBacked(crate::disk_bucket::DiskBucketIter),
    /// Empty iterator (used for error recovery).
    Empty,
}

impl<'a> Iterator for BucketIter<'a> {
    type Item = BucketEntry;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            BucketIter::InMemory(iter) => iter.next().cloned(),
            BucketIter::DiskBacked(iter) => iter.next().and_then(|r| r.ok()),
            BucketIter::Empty => None,
        }
    }
}

impl std::fmt::Debug for Bucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entry_count = self.len();
        let is_disk_backed = self.is_disk_backed();
        f.debug_struct("Bucket")
            .field("hash", &self.hash.to_hex())
            .field("entries", &entry_count)
            .field("disk_backed", &is_disk_backed)
            .finish()
    }
}

impl Default for Bucket {
    fn default() -> Self {
        Self::empty()
    }
}

impl PartialEq for Bucket {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for Bucket {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BucketEntry;
    use stellar_xdr::curr::*; // Re-import to shadow XDR's BucketEntry

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

    #[test]
    fn test_empty_bucket() {
        let bucket = Bucket::empty();
        assert!(bucket.is_empty());
        assert_eq!(bucket.len(), 0);
        assert_eq!(bucket.hash(), Hash256::ZERO);
    }

    #[test]
    fn test_bucket_from_entries() {
        let entries = vec![
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
        ];

        let bucket = Bucket::from_entries(entries).unwrap();
        assert!(!bucket.is_empty());
        assert_eq!(bucket.len(), 2);

        // Entries should be sorted
        let entries: Vec<_> = bucket.iter().collect();
        if let BucketEntry::Live(entry) = &entries[0] {
            if let LedgerEntryData::Account(account) = &entry.data {
                assert_eq!(account.balance, 100);
            }
        }
    }

    #[test]
    fn test_bucket_lookup() {
        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        let bucket = Bucket::from_entries(entries).unwrap();

        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id([1u8; 32]),
        });

        let entry = bucket.get_entry(&key).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry.data {
            assert_eq!(account.balance, 100);
        } else {
            panic!("Expected Account entry");
        }
    }

    #[test]
    fn test_bucket_dead_entry() {
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id([1u8; 32]),
        });

        let entries = vec![BucketEntry::Dead(key.clone())];
        let bucket = Bucket::from_entries(entries).unwrap();

        // Looking up a dead entry should return None
        let result = bucket.get_entry(&key).unwrap();
        assert!(result.is_none());

        // But get() should return the dead entry
        let entry = bucket.get(&key).unwrap();
        assert!(entry.is_some());
        assert!(entry.unwrap().is_dead());
    }

    #[test]
    fn test_bucket_hash_consistency() {
        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        let bucket1 = Bucket::from_entries(entries.clone()).unwrap();
        let bucket2 = Bucket::from_entries(entries).unwrap();

        assert_eq!(bucket1.hash(), bucket2.hash());
    }

    #[test]
    fn test_bucket_save_and_load() {
        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        let bucket = Bucket::from_entries(entries).unwrap();
        let original_hash = bucket.hash();

        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.bucket.gz");

        bucket.save_to_file(&path).unwrap();

        let loaded = Bucket::load_from_file(&path).unwrap();
        assert_eq!(loaded.hash(), original_hash);
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_bucket_roundtrip_entries() {
        // Create a bucket with entries
        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];
        let bucket = Bucket::from_entries(entries.clone()).unwrap();
        let original_hash = bucket.hash();

        // Serialize to XDR bytes
        let xdr_bytes = bucket.to_xdr_bytes().unwrap();

        // Parse back from XDR bytes
        let parsed = Bucket::from_xdr_bytes(&xdr_bytes).unwrap();

        // Hashes should match
        assert_eq!(
            parsed.hash(),
            original_hash,
            "Hash mismatch after round-trip"
        );
        assert_eq!(parsed.len(), entries.len(), "Entry count mismatch");
    }

    #[test]
    fn test_bucket_entries_roundtrip() {
        // Create a bucket
        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];
        let bucket1 = Bucket::from_entries(entries).unwrap();

        // Extract entries and create a new bucket
        let extracted: Vec<BucketEntry> = bucket1.iter().collect();
        let bucket2 = Bucket::from_entries(extracted).unwrap();

        // Hashes should match
        assert_eq!(
            bucket2.hash(),
            bucket1.hash(),
            "Hash mismatch after entries roundtrip"
        );
    }

    #[test]
    fn test_disk_backed_bucket_roundtrip() {
        // Create entries
        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
            BucketEntry::Live(make_account_entry([3u8; 32], 300)),
        ];

        // Create an in-memory bucket first
        let in_memory_bucket = Bucket::from_entries(entries).unwrap();
        let original_hash = in_memory_bucket.hash();

        // Serialize to XDR bytes
        let xdr_bytes = in_memory_bucket.to_xdr_bytes().unwrap();

        // Create a disk-backed bucket
        let temp_dir = tempfile::tempdir().unwrap();
        let disk_path = temp_dir.path().join("test.bucket");
        let disk_bucket = Bucket::from_xdr_bytes_disk_backed(&xdr_bytes, &disk_path).unwrap();

        // Hash should match
        assert_eq!(
            disk_bucket.hash(),
            original_hash,
            "Disk bucket hash mismatch"
        );
        assert!(disk_bucket.is_disk_backed());

        // Extract entries via iter() and create a new bucket
        let extracted: Vec<BucketEntry> = disk_bucket.iter().collect();
        let recreated = Bucket::from_entries(extracted).unwrap();

        // Hashes should match after roundtrip
        assert_eq!(
            recreated.hash(),
            original_hash,
            "Hash mismatch after disk bucket roundtrip"
        );
    }

    #[test]
    fn test_disk_backed_bucket_with_metadata() {
        use stellar_xdr::curr::{BucketMetadata, BucketMetadataExt};

        // Create entries with metadata (as stellar-core buckets would have)
        let entries = vec![
            BucketEntry::Metadata(BucketMetadata {
                ledger_version: 24,
                ext: BucketMetadataExt::V0,
            }),
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        // Create an in-memory bucket
        let in_memory_bucket = Bucket::from_entries(entries).unwrap();
        let original_hash = in_memory_bucket.hash();

        // Serialize and create disk-backed
        let xdr_bytes = in_memory_bucket.to_xdr_bytes().unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let disk_path = temp_dir.path().join("test_meta.bucket");
        let disk_bucket = Bucket::from_xdr_bytes_disk_backed(&xdr_bytes, &disk_path).unwrap();

        assert_eq!(disk_bucket.hash(), original_hash);

        // Roundtrip via entries
        let extracted: Vec<BucketEntry> = disk_bucket.iter().collect();

        // Verify metadata is first
        assert!(extracted[0].is_metadata(), "Metadata should be first entry");

        let recreated = Bucket::from_entries(extracted).unwrap();
        assert_eq!(
            recreated.hash(),
            original_hash,
            "Hash mismatch after metadata bucket roundtrip"
        );
    }

    #[test]
    fn test_xdr_serialization_roundtrip_produces_identical_bytes() {
        // Create entries
        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        // Create bucket and get XDR bytes
        let bucket = Bucket::from_entries(entries).unwrap();
        let original_xdr = bucket.to_xdr_bytes().unwrap();

        // Parse entries from XDR and re-serialize
        let parsed = Bucket::from_xdr_bytes(&original_xdr).unwrap();
        let reserialized_xdr = parsed.to_xdr_bytes().unwrap();

        // Bytes should be identical
        assert_eq!(
            reserialized_xdr.len(),
            original_xdr.len(),
            "XDR length differs"
        );
        assert_eq!(
            reserialized_xdr, original_xdr,
            "XDR bytes differ after roundtrip"
        );
    }

    #[test]
    fn test_disk_backed_to_inmemory_xdr_roundtrip() {
        // Create entries
        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        // Create bucket and serialize
        let bucket = Bucket::from_entries(entries).unwrap();
        let original_xdr = bucket.to_xdr_bytes().unwrap();
        let original_hash = bucket.hash();

        // Create disk-backed bucket
        let temp_dir = tempfile::tempdir().unwrap();
        let disk_path = temp_dir.path().join("test.bucket");
        let disk_bucket = Bucket::from_xdr_bytes_disk_backed(&original_xdr, &disk_path).unwrap();
        assert_eq!(disk_bucket.hash(), original_hash);

        // Get XDR from disk-backed bucket (reads from file)
        let disk_xdr = disk_bucket.to_xdr_bytes().unwrap();
        assert_eq!(
            disk_xdr, original_xdr,
            "Disk bucket XDR differs from original"
        );

        // Extract entries and create new in-memory bucket
        let extracted: Vec<_> = disk_bucket.iter().collect();
        let inmemory = Bucket::from_sorted_entries(extracted).unwrap();

        // Get XDR from in-memory bucket (serializes entries)
        let inmemory_xdr = inmemory.to_xdr_bytes().unwrap();

        // These should be identical
        assert_eq!(
            inmemory_xdr, disk_xdr,
            "In-memory XDR differs from disk XDR"
        );
        assert_eq!(inmemory.hash(), original_hash);
    }

    #[test]
    fn test_from_sorted_entries_preserves_hash() {
        // Create entries
        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        // Create bucket (will sort)
        let bucket1 = Bucket::from_entries(entries).unwrap();

        // Extract entries (in sorted order from bucket1)
        let sorted: Vec<_> = bucket1.iter().collect();

        // Create bucket from sorted entries (should NOT re-sort)
        let bucket2 = Bucket::from_sorted_entries(sorted).unwrap();

        // Hashes should match
        assert_eq!(bucket2.hash(), bucket1.hash());
    }

    #[test]
    fn test_disk_bucket_from_sorted_entries_roundtrip() {
        // Create entries
        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
            BucketEntry::Live(make_account_entry([3u8; 32], 300)),
        ];

        // Create bucket and serialize
        let bucket = Bucket::from_entries(entries).unwrap();
        let original_hash = bucket.hash();
        let xdr_bytes = bucket.to_xdr_bytes().unwrap();

        // Create disk-backed bucket
        let temp_dir = tempfile::tempdir().unwrap();
        let disk_path = temp_dir.path().join("test.bucket");
        let disk_bucket = Bucket::from_xdr_bytes_disk_backed(&xdr_bytes, &disk_path).unwrap();
        assert_eq!(disk_bucket.hash(), original_hash);

        // Extract entries (already in sorted order)
        let extracted: Vec<_> = disk_bucket.iter().collect();

        // Use from_sorted_entries instead of from_entries
        let recreated = Bucket::from_sorted_entries(extracted).unwrap();

        // Hash should match!
        assert_eq!(
            recreated.hash(),
            original_hash,
            "from_sorted_entries should preserve disk bucket hash"
        );
    }

    #[test]
    fn test_bucket_mixed_entry_types_ordering() {
        use stellar_xdr::curr::{
            AlphaNum4, AssetCode4, OfferEntry, TrustLineAsset, TrustLineEntry,
        };

        // Create helper functions for different entry types
        let make_offer_entry = |seller: [u8; 32], offer_id: i64| -> LedgerEntry {
            LedgerEntry {
                last_modified_ledger_seq: 1,
                data: LedgerEntryData::Offer(OfferEntry {
                    seller_id: make_account_id(seller),
                    offer_id: offer_id,
                    selling: stellar_xdr::curr::Asset::Native,
                    buying: stellar_xdr::curr::Asset::Native,
                    amount: 1000,
                    price: stellar_xdr::curr::Price { n: 1, d: 1 },
                    flags: 0,
                    ext: stellar_xdr::curr::OfferEntryExt::V0,
                }),
                ext: LedgerEntryExt::V0,
            }
        };

        let make_trustline_entry = |account: [u8; 32], issuer: [u8; 32]| -> LedgerEntry {
            LedgerEntry {
                last_modified_ledger_seq: 1,
                data: LedgerEntryData::Trustline(TrustLineEntry {
                    account_id: make_account_id(account),
                    asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                        asset_code: AssetCode4([b'U', b'S', b'D', 0]),
                        issuer: make_account_id(issuer),
                    }),
                    balance: 1000,
                    limit: 10000,
                    flags: 0, // No flags set
                    ext: stellar_xdr::curr::TrustLineEntryExt::V0,
                }),
                ext: LedgerEntryExt::V0,
            }
        };

        // Create entries of different types (unsorted)
        let entries = vec![
            // Offer (type 2) with high account
            BucketEntry::Live(make_offer_entry([255u8; 32], 1)),
            // Account (type 0) with low account
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            // Trustline (type 1) with mid account
            BucketEntry::Live(make_trustline_entry([128u8; 32], [50u8; 32])),
            // Another Account (type 0) with mid account
            BucketEntry::Live(make_account_entry([128u8; 32], 200)),
        ];

        // Create bucket (will sort entries)
        let bucket = Bucket::from_entries(entries).unwrap();
        let sorted_entries: Vec<_> = bucket.iter().collect();

        // Verify ordering: Account (type 0) < Trustline (type 1) < Offer (type 2)
        assert!(sorted_entries[0].is_live());
        assert!(matches!(
            sorted_entries[0].as_ledger_entry().unwrap().data,
            LedgerEntryData::Account(_)
        ));
        assert!(sorted_entries[1].is_live());
        assert!(matches!(
            sorted_entries[1].as_ledger_entry().unwrap().data,
            LedgerEntryData::Account(_)
        ));
        assert!(sorted_entries[2].is_live());
        assert!(matches!(
            sorted_entries[2].as_ledger_entry().unwrap().data,
            LedgerEntryData::Trustline(_)
        ));
        assert!(sorted_entries[3].is_live());
        assert!(matches!(
            sorted_entries[3].as_ledger_entry().unwrap().data,
            LedgerEntryData::Offer(_)
        ));

        // Verify accounts are sorted by account ID
        if let LedgerEntryData::Account(a1) = &sorted_entries[0].as_ledger_entry().unwrap().data {
            if let LedgerEntryData::Account(a2) = &sorted_entries[1].as_ledger_entry().unwrap().data
            {
                assert_eq!(a1.balance, 100); // [1u8; 32] comes first
                assert_eq!(a2.balance, 200); // [128u8; 32] comes second
            }
        }

        // Roundtrip test
        let extracted: Vec<_> = bucket.iter().collect();
        let recreated = Bucket::from_entries(extracted).unwrap();
        assert_eq!(
            recreated.hash(),
            bucket.hash(),
            "Hash mismatch after mixed type roundtrip"
        );
    }
}
