//! Disk-backed bucket implementation for memory-efficient storage.
//!
//! This module provides a bucket implementation that stores entries on disk
//! and uses a compact index for efficient lookups. This is essential for
//! processing mainnet buckets during catchup, where buckets can contain
//! millions of entries that would require many GB of RAM if loaded entirely.
//!
//! # How It Works
//!
//! Instead of loading all entries into memory, the disk bucket:
//!
//! 1. **Stores** the raw XDR bucket file on disk (uncompressed)
//! 2. **Builds** an index mapping the first 8 bytes of each key's SHA-256 hash
//!    to the file offset and length of the entry
//! 3. **Reads** entries on-demand from disk when accessed
//!
//! # Memory Efficiency
//!
//! Memory usage is reduced from O(entries) to O(unique_keys * 16 bytes):
//! - 8 bytes for the key hash prefix
//! - 8 bytes for the offset and length (IndexEntry)
//!
//! For a bucket with 1 million entries, this is roughly 16 MB for the index
//! instead of potentially several GB for all entry data.
//!
//! # Trade-offs
//!
//! - **Slower lookups**: Each lookup requires disk I/O
//! - **No in-memory slice access**: Must use iteration instead
//! - **Hash collision risk**: The 8-byte key hash may collide (rare, handled by verification)
//!
//! # Usage
//!
//! Disk buckets are created via [`Bucket::from_xdr_bytes_disk_backed`] and are
//! transparent to most bucket operations. Check [`Bucket::is_disk_backed`] to
//! determine the storage mode.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use stellar_xdr::curr::{LedgerEntry, LedgerKey, ReadXdr, Limits};

use stellar_core_common::Hash256;

use crate::bloom_filter::{BucketBloomFilter, HashSeed};
use crate::entry::BucketEntry;
use crate::{BucketError, Result};

/// Minimum number of entries required to build a bloom filter.
/// Smaller buckets don't benefit enough from bloom filter lookups to justify the overhead.
const BLOOM_FILTER_MIN_ENTRIES: usize = 2;

/// Default hash seed for bloom filter construction.
/// This is used when no custom seed is provided.
pub const DEFAULT_BLOOM_SEED: HashSeed = [0u8; 16];

/// Entry in the bucket index: file offset and record length.
///
/// This is a compact 12-byte structure (with padding) that stores the
/// location of an entry in the bucket file.
#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    /// Byte offset in the bucket file where this entry's record mark starts.
    offset: u64,
    /// Length of the XDR record (not including the 4-byte record mark).
    length: u32,
}

/// A disk-backed bucket that stores entries on disk with an in-memory index.
///
/// This implementation is designed for memory efficiency when processing
/// large buckets during catchup. Instead of loading all entries into memory,
/// it maintains a compact index and reads entries on-demand.
///
/// # Index Structure
///
/// The index maps the first 8 bytes of each key's SHA-256 hash to an
/// `IndexEntry` containing the file offset and record length. This uses
/// a `BTreeMap` for ordered iteration and reasonable lookup performance.
///
/// # Bloom Filter
///
/// For buckets with 2 or more entries, a Binary Fuse Filter is built to enable
/// fast negative lookups. This allows `get()` to quickly determine that a key
/// is definitely NOT in the bucket without reading from disk.
///
/// # Hash Collisions
///
/// Since we only use 8 bytes of the key hash, collisions are possible
/// (probability ~1 in 2^64). The `get()` method handles this by verifying
/// the actual key matches after loading the entry from disk.
///
/// # File Access Pattern
///
/// Each lookup opens the file fresh, seeks to the offset, and reads the
/// entry. This avoids file handle contention but may be slower than a
/// cached approach for repeated accesses to the same bucket.
#[derive(Clone)]
pub struct DiskBucket {
    /// The SHA-256 hash of this bucket's contents (for verification).
    hash: Hash256,
    /// Path to the bucket file on disk (uncompressed XDR).
    file_path: PathBuf,
    /// Index mapping 8-byte key hash prefixes to file locations.
    index: Arc<BTreeMap<u64, IndexEntry>>,
    /// Total number of entries in this bucket.
    entry_count: usize,
    /// Optional bloom filter for fast negative lookups.
    /// None if the bucket has fewer than 2 entries.
    bloom_filter: Option<Arc<BucketBloomFilter>>,
    /// Hash seed used for the bloom filter.
    bloom_seed: HashSeed,
}

impl DiskBucket {
    /// Create a disk bucket from an XDR file.
    ///
    /// This parses the file to build the index but doesn't keep entries in memory.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_file_with_seed(path, DEFAULT_BLOOM_SEED)
    }

    /// Create a disk bucket from an XDR file with a custom bloom filter seed.
    ///
    /// This parses the file to build the index but doesn't keep entries in memory.
    pub fn from_file_with_seed(path: impl AsRef<Path>, bloom_seed: HashSeed) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)?;
        let file_len = file.metadata()?.len();
        let mut reader = BufReader::new(file);

        // Read entire file for hash computation
        let mut bytes = Vec::with_capacity(file_len as usize);
        reader.read_to_end(&mut bytes)?;

        // Compute hash
        let hash = Hash256::hash(&bytes);

        // Build index by scanning the file
        let (index, key_hashes, entry_count) = Self::build_index(&bytes, &bloom_seed)?;

        // Build bloom filter if we have enough entries
        let bloom_filter = if key_hashes.len() >= BLOOM_FILTER_MIN_ENTRIES {
            match BucketBloomFilter::from_hashes(&key_hashes, &bloom_seed) {
                Ok(filter) => Some(Arc::new(filter)),
                Err(e) => {
                    tracing::warn!("Failed to build bloom filter for bucket: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            hash,
            file_path: path.to_path_buf(),
            index: Arc::new(index),
            entry_count,
            bloom_filter,
            bloom_seed,
        })
    }

    /// Create a disk bucket from raw XDR bytes, saving to the specified path.
    pub fn from_xdr_bytes(bytes: &[u8], save_path: impl AsRef<Path>) -> Result<Self> {
        Self::from_xdr_bytes_with_seed(bytes, save_path, DEFAULT_BLOOM_SEED)
    }

    /// Create a disk bucket from raw XDR bytes with a custom bloom filter seed.
    pub fn from_xdr_bytes_with_seed(bytes: &[u8], save_path: impl AsRef<Path>, bloom_seed: HashSeed) -> Result<Self> {
        use std::io::Write;

        let save_path = save_path.as_ref();

        // Compute hash
        let hash = Hash256::hash(bytes);

        // Build index
        let (index, key_hashes, entry_count) = Self::build_index(bytes, &bloom_seed)?;

        // Build bloom filter if we have enough entries
        let bloom_filter = if key_hashes.len() >= BLOOM_FILTER_MIN_ENTRIES {
            match BucketBloomFilter::from_hashes(&key_hashes, &bloom_seed) {
                Ok(filter) => Some(Arc::new(filter)),
                Err(e) => {
                    tracing::warn!("Failed to build bloom filter for bucket: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Save to disk
        let mut file = File::create(save_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;

        Ok(Self {
            hash,
            file_path: save_path.to_path_buf(),
            index: Arc::new(index),
            entry_count,
            bloom_filter,
            bloom_seed,
        })
    }

    /// Build an index from XDR bytes.
    ///
    /// Returns (index, bloom_key_hashes, entry_count).
    fn build_index(bytes: &[u8], bloom_seed: &HashSeed) -> Result<(BTreeMap<u64, IndexEntry>, Vec<u64>, usize)> {
        use tracing::debug;

        if bytes.is_empty() {
            return Ok((BTreeMap::new(), Vec::new(), 0));
        }

        let mut index = BTreeMap::new();
        let mut bloom_key_hashes = Vec::new();
        let mut offset: u64 = 0;
        let mut entry_count = 0;

        // Check if the file uses XDR record marking
        let uses_record_marks = bytes.len() >= 4 && (bytes[0] & 0x80) != 0;

        if uses_record_marks {
            debug!("Building index for bucket with XDR record marking format");

            while (offset as usize) + 4 <= bytes.len() {
                let record_start = offset;

                // Read 4-byte record mark
                let record_mark = u32::from_be_bytes([
                    bytes[offset as usize],
                    bytes[offset as usize + 1],
                    bytes[offset as usize + 2],
                    bytes[offset as usize + 3],
                ]);
                offset += 4;

                let record_len = (record_mark & 0x7FFFFFFF) as usize;

                if (offset as usize) + record_len > bytes.len() {
                    break;
                }

                // Parse just enough to get the key
                let record_data = &bytes[offset as usize..(offset as usize) + record_len];
                if let Ok(xdr_entry) = stellar_xdr::curr::BucketEntry::from_xdr(record_data, Limits::none()) {
                    if let Some(key) = Self::extract_key(&xdr_entry) {
                        // Use first 8 bytes of key hash as index key
                        let key_hash = Self::hash_key(&key);
                        index.insert(key_hash, IndexEntry {
                            offset: record_start,
                            length: record_len as u32,
                        });
                        // Also compute bloom filter hash
                        bloom_key_hashes.push(BucketBloomFilter::hash_key(&key, bloom_seed));
                    }
                    entry_count += 1;
                }

                offset += record_len as u64;
            }
        } else {
            // Raw XDR format - need to parse sequentially
            debug!("Building index for bucket with raw XDR format");

            use stellar_xdr::curr::Limited;
            let cursor = std::io::Cursor::new(bytes);
            let mut limited = Limited::new(cursor, Limits::none());

            while limited.inner.position() < bytes.len() as u64 {
                let entry_start = limited.inner.position();

                match stellar_xdr::curr::BucketEntry::read_xdr(&mut limited) {
                    Ok(xdr_entry) => {
                        let entry_end = limited.inner.position();
                        if let Some(key) = Self::extract_key(&xdr_entry) {
                            let key_hash = Self::hash_key(&key);
                            index.insert(key_hash, IndexEntry {
                                offset: entry_start,
                                length: (entry_end - entry_start) as u32,
                            });
                            // Also compute bloom filter hash
                            bloom_key_hashes.push(BucketBloomFilter::hash_key(&key, bloom_seed));
                        }
                        entry_count += 1;
                    }
                    Err(_) => break,
                }
            }
        }

        debug!("Built index with {} entries, {} keys for bloom filter", entry_count, bloom_key_hashes.len());
        Ok((index, bloom_key_hashes, entry_count))
    }

    /// Extract the key from a bucket entry.
    fn extract_key(entry: &stellar_xdr::curr::BucketEntry) -> Option<LedgerKey> {
        use stellar_xdr::curr::BucketEntry as XdrBucketEntry;
        use crate::entry::ledger_entry_to_key;

        match entry {
            XdrBucketEntry::Liveentry(e) | XdrBucketEntry::Initentry(e) => ledger_entry_to_key(e),
            XdrBucketEntry::Deadentry(k) => Some(k.clone()),
            XdrBucketEntry::Metaentry(_) => None,
        }
    }

    /// Compute a compact hash of a key for index lookup.
    fn hash_key(key: &LedgerKey) -> u64 {
        use stellar_xdr::curr::WriteXdr;
        let key_bytes = key.to_xdr(Limits::none()).unwrap_or_default();
        let hash = Sha256::digest(&key_bytes);
        u64::from_be_bytes(hash[0..8].try_into().unwrap())
    }

    /// Get the hash of this bucket.
    pub fn hash(&self) -> Hash256 {
        self.hash
    }

    /// Check if this bucket is empty.
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0 || self.hash.is_zero()
    }

    /// Get the number of entries in this bucket.
    pub fn len(&self) -> usize {
        self.entry_count
    }

    /// Get the path to the bucket file.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Returns true if this bucket has a bloom filter for fast negative lookups.
    pub fn has_bloom_filter(&self) -> bool {
        self.bloom_filter.is_some()
    }

    /// Returns the size of the bloom filter in bytes, or 0 if no filter exists.
    pub fn bloom_filter_size_bytes(&self) -> usize {
        self.bloom_filter.as_ref().map_or(0, |f| f.size_bytes())
    }

    /// Returns the hash seed used for the bloom filter.
    pub fn bloom_seed(&self) -> &HashSeed {
        &self.bloom_seed
    }

    /// Look up an entry by key.
    ///
    /// This reads from disk using the index. If a bloom filter is available,
    /// it first checks the filter to quickly reject keys that are definitely
    /// not present (avoiding disk I/O).
    pub fn get(&self, key: &LedgerKey) -> Result<Option<BucketEntry>> {
        // Check bloom filter first for fast negative lookup
        if let Some(ref filter) = self.bloom_filter {
            if !filter.may_contain(key, &self.bloom_seed) {
                // Key is definitely not in the bucket
                return Ok(None);
            }
        }

        let key_hash = Self::hash_key(key);

        let index_entry = match self.index.get(&key_hash) {
            Some(e) => e,
            None => return Ok(None),
        };

        // Read the entry from disk
        let mut file = File::open(&self.file_path)?;
        file.seek(SeekFrom::Start(index_entry.offset))?;

        // Read record mark if present
        let mut mark_buf = [0u8; 4];
        file.read_exact(&mut mark_buf)?;

        let (record_len, data_offset) = if mark_buf[0] & 0x80 != 0 {
            // Has record mark
            let mark = u32::from_be_bytes(mark_buf);
            ((mark & 0x7FFFFFFF) as usize, 4u64)
        } else {
            // No record mark - use stored length
            (index_entry.length as usize, 0u64)
        };

        // Seek to data start if needed
        if data_offset == 0 {
            file.seek(SeekFrom::Start(index_entry.offset))?;
        }

        // Read the entry data
        let mut data = vec![0u8; record_len];
        file.read_exact(&mut data)?;

        // Parse the entry
        let xdr_entry = stellar_xdr::curr::BucketEntry::from_xdr(&data, Limits::none())
            .map_err(|e| BucketError::Serialization(format!("Failed to parse entry: {}", e)))?;

        // Convert to our BucketEntry type
        let entry = BucketEntry::from_xdr_entry(xdr_entry)?;

        // Verify this is the right entry (hash collisions are possible)
        if let Some(entry_key) = entry.key() {
            if &entry_key == key {
                return Ok(Some(entry));
            }
        }

        Ok(None)
    }

    /// Look up a ledger entry by key.
    pub fn get_entry(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>> {
        match self.get(key)? {
            Some(BucketEntry::Live(entry)) | Some(BucketEntry::Init(entry)) => Ok(Some(entry)),
            Some(BucketEntry::Dead(_)) => Ok(None),
            Some(BucketEntry::Metadata(_)) => Ok(None),
            None => Ok(None),
        }
    }

    /// Iterate over all entries in this bucket.
    ///
    /// This reads from disk sequentially.
    pub fn iter(&self) -> Result<DiskBucketIter> {
        let file = File::open(&self.file_path)?;
        let reader = BufReader::new(file);

        // Read file to check format
        let mut bytes = Vec::new();
        let mut reader = reader;
        reader.read_to_end(&mut bytes)?;

        let uses_record_marks = bytes.len() >= 4 && (bytes[0] & 0x80) != 0;

        Ok(DiskBucketIter {
            bytes,
            offset: 0,
            uses_record_marks,
        })
    }
}

impl std::fmt::Debug for DiskBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiskBucket")
            .field("hash", &self.hash.to_hex())
            .field("entries", &self.entry_count)
            .field("file", &self.file_path)
            .finish()
    }
}

/// Iterator over entries in a disk bucket.
///
/// This iterator reads the entire bucket file into memory once and then
/// parses entries sequentially. While this temporarily uses more memory
/// than on-demand reads, it provides efficient sequential access.
///
/// # Format Detection
///
/// The iterator automatically detects whether the bucket uses XDR record
/// marking (RFC 5531) or raw XDR format, handling both transparently.
///
/// # Error Handling
///
/// Parse errors for individual entries are returned as `Result` items.
/// Callers should handle or filter these appropriately.
pub struct DiskBucketIter {
    /// The complete bucket file contents.
    bytes: Vec<u8>,
    /// Current byte offset in the file.
    offset: usize,
    /// Whether the file uses XDR record marks (vs raw XDR stream).
    uses_record_marks: bool,
}

impl Iterator for DiskBucketIter {
    type Item = Result<BucketEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        if self.uses_record_marks {
            if self.offset + 4 > self.bytes.len() {
                return None;
            }

            let record_mark = u32::from_be_bytes([
                self.bytes[self.offset],
                self.bytes[self.offset + 1],
                self.bytes[self.offset + 2],
                self.bytes[self.offset + 3],
            ]);
            self.offset += 4;

            let record_len = (record_mark & 0x7FFFFFFF) as usize;

            if self.offset + record_len > self.bytes.len() {
                return None;
            }

            let record_data = &self.bytes[self.offset..self.offset + record_len];
            self.offset += record_len;

            match stellar_xdr::curr::BucketEntry::from_xdr(record_data, Limits::none()) {
                Ok(xdr_entry) => Some(BucketEntry::from_xdr_entry(xdr_entry)),
                Err(e) => Some(Err(BucketError::Serialization(format!("Failed to parse: {}", e)))),
            }
        } else {
            use stellar_xdr::curr::Limited;
            let cursor = std::io::Cursor::new(&self.bytes[self.offset..]);
            let mut limited = Limited::new(cursor, Limits::none());

            match stellar_xdr::curr::BucketEntry::read_xdr(&mut limited) {
                Ok(xdr_entry) => {
                    self.offset += limited.inner.position() as usize;
                    Some(BucketEntry::from_xdr_entry(xdr_entry))
                }
                Err(_) => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;
    use tempfile::tempdir;

    fn make_test_bucket_bytes() -> Vec<u8> {
        use stellar_xdr::curr::WriteXdr;

        let mut bytes = Vec::new();

        // Create a simple account entry
        let account = AccountEntry {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1u8; 32]))),
            balance: 100,
            seq_num: SequenceNumber(1),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: Vec::new().try_into().unwrap(),
            ext: AccountEntryExt::V0,
        };

        let entry = LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Account(account),
            ext: LedgerEntryExt::V0,
        };

        let bucket_entry = stellar_xdr::curr::BucketEntry::Liveentry(entry);
        let entry_bytes = bucket_entry.to_xdr(Limits::none()).unwrap();

        // Write with record mark
        let record_mark = (entry_bytes.len() as u32) | 0x80000000;
        bytes.extend_from_slice(&record_mark.to_be_bytes());
        bytes.extend_from_slice(&entry_bytes);

        bytes
    }

    #[test]
    fn test_disk_bucket_creation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bucket");

        let bytes = make_test_bucket_bytes();
        let bucket = DiskBucket::from_xdr_bytes(&bytes, &path).unwrap();

        assert!(!bucket.is_empty());
        assert_eq!(bucket.len(), 1);
        assert!(path.exists());
    }

    #[test]
    fn test_disk_bucket_lookup() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bucket");

        let bytes = make_test_bucket_bytes();
        let bucket = DiskBucket::from_xdr_bytes(&bytes, &path).unwrap();

        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1u8; 32]))),
        });

        let entry = bucket.get(&key).unwrap();
        assert!(entry.is_some());
    }

    fn make_multi_entry_bucket_bytes(count: usize) -> Vec<u8> {
        use stellar_xdr::curr::WriteXdr;

        let mut bytes = Vec::new();

        for i in 0..count {
            let mut id = [0u8; 32];
            id[0] = i as u8;

            let account = AccountEntry {
                account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(id))),
                balance: i as i64 * 100,
                seq_num: SequenceNumber(1),
                num_sub_entries: 0,
                inflation_dest: None,
                flags: 0,
                home_domain: String32::default(),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: Vec::new().try_into().unwrap(),
                ext: AccountEntryExt::V0,
            };

            let entry = LedgerEntry {
                last_modified_ledger_seq: 1,
                data: LedgerEntryData::Account(account),
                ext: LedgerEntryExt::V0,
            };

            let bucket_entry = stellar_xdr::curr::BucketEntry::Liveentry(entry);
            let entry_bytes = bucket_entry.to_xdr(Limits::none()).unwrap();

            // Write with record mark
            let record_mark = (entry_bytes.len() as u32) | 0x80000000;
            bytes.extend_from_slice(&record_mark.to_be_bytes());
            bytes.extend_from_slice(&entry_bytes);
        }

        bytes
    }

    #[test]
    fn test_disk_bucket_no_bloom_filter_with_single_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bucket");

        let bytes = make_test_bucket_bytes(); // Only 1 entry
        let bucket = DiskBucket::from_xdr_bytes(&bytes, &path).unwrap();

        // Single entry bucket should not have a bloom filter
        assert!(!bucket.has_bloom_filter());
        assert_eq!(bucket.bloom_filter_size_bytes(), 0);
    }

    #[test]
    fn test_disk_bucket_bloom_filter_with_multiple_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bucket");

        let bytes = make_multi_entry_bucket_bytes(10);
        let bucket = DiskBucket::from_xdr_bytes(&bytes, &path).unwrap();

        assert_eq!(bucket.len(), 10);
        // Multiple entries should have a bloom filter
        assert!(bucket.has_bloom_filter());
        assert!(bucket.bloom_filter_size_bytes() > 0);
    }

    #[test]
    fn test_disk_bucket_bloom_filter_no_false_negatives() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bucket");

        let count = 50;
        let bytes = make_multi_entry_bucket_bytes(count);
        let bucket = DiskBucket::from_xdr_bytes(&bytes, &path).unwrap();

        assert!(bucket.has_bloom_filter());

        // All keys that are in the bucket must be found
        for i in 0..count {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            let key = LedgerKey::Account(LedgerKeyAccount {
                account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(id))),
            });

            let entry = bucket.get(&key).unwrap();
            assert!(entry.is_some(), "Entry {} should be found", i);
        }
    }

    #[test]
    fn test_disk_bucket_bloom_filter_rejects_missing_keys() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bucket");

        // Create bucket with entries 0-9
        let bytes = make_multi_entry_bucket_bytes(10);
        let bucket = DiskBucket::from_xdr_bytes(&bytes, &path).unwrap();

        assert!(bucket.has_bloom_filter());

        // Keys 100-199 should not be found
        for i in 100..200 {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            let key = LedgerKey::Account(LedgerKeyAccount {
                account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(id))),
            });

            let entry = bucket.get(&key).unwrap();
            assert!(entry.is_none(), "Entry {} should not be found", i);
        }
    }

    #[test]
    fn test_disk_bucket_with_custom_bloom_seed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bucket");

        let custom_seed: HashSeed = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        ];

        let bytes = make_multi_entry_bucket_bytes(10);
        let bucket = DiskBucket::from_xdr_bytes_with_seed(&bytes, &path, custom_seed).unwrap();

        assert!(bucket.has_bloom_filter());
        assert_eq!(bucket.bloom_seed(), &custom_seed);

        // Should still find all entries
        for i in 0..10 {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            let key = LedgerKey::Account(LedgerKeyAccount {
                account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(id))),
            });

            let entry = bucket.get(&key).unwrap();
            assert!(entry.is_some(), "Entry {} should be found", i);
        }
    }
}
