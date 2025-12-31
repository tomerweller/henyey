//! Individual bucket implementation.
//!
//! A bucket is an immutable container of ledger entries, stored as gzipped XDR.
//! Buckets are identified by their content hash (SHA-256 of uncompressed contents).

use std::collections::BTreeMap;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use stellar_xdr::curr::{LedgerEntry, LedgerKey, ReadXdr, WriteXdr, Limits};

use stellar_core_common::Hash256;

use crate::entry::{compare_entries, compare_keys, BucketEntry};
use crate::{BucketError, Result};

/// An immutable bucket file containing sorted ledger entries.
///
/// Buckets are the fundamental storage unit in Stellar's BucketList.
/// They are:
/// - Immutable once created
/// - Identified by their content hash
/// - Stored as gzipped XDR on disk
/// - Sorted by key for efficient merging and lookup
#[derive(Clone)]
pub struct Bucket {
    /// The hash of this bucket's contents (uncompressed XDR).
    hash: Hash256,
    /// The entries in this bucket, sorted by key.
    entries: Arc<Vec<BucketEntry>>,
    /// Index mapping keys to entry positions for fast lookup.
    key_index: Arc<BTreeMap<Vec<u8>, usize>>,
}

impl Bucket {
    /// Create an empty bucket.
    pub fn empty() -> Self {
        Self {
            hash: Hash256::ZERO,
            entries: Arc::new(Vec::new()),
            key_index: Arc::new(BTreeMap::new()),
        }
    }

    /// Create a bucket from a list of entries.
    ///
    /// The entries will be sorted by key.
    pub fn from_entries(mut entries: Vec<BucketEntry>) -> Result<Self> {
        // Sort entries by key
        entries.sort_by(compare_entries);

        // Build key index
        let mut key_index = BTreeMap::new();
        for (idx, entry) in entries.iter().enumerate() {
            if let Some(key) = entry.key() {
                let key_bytes = key
                    .to_xdr(Limits::none())
                    .map_err(|e| BucketError::Serialization(format!("Failed to serialize key: {}", e)))?;
                key_index.insert(key_bytes, idx);
            }
        }

        // Compute hash
        let hash = Self::compute_hash_for_entries(&entries)?;

        Ok(Self {
            hash,
            entries: Arc::new(entries),
            key_index: Arc::new(key_index),
        })
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
        Self::from_xdr_bytes_internal(bytes, true)
    }

    /// Create a bucket from uncompressed XDR bytes without building the key index.
    ///
    /// This is much more memory efficient for large buckets and should be used
    /// during catchup when key lookups are not needed.
    pub fn from_xdr_bytes_without_index(bytes: &[u8]) -> Result<Self> {
        Self::from_xdr_bytes_internal(bytes, false)
    }

    /// Internal method to create a bucket with optional key index building.
    fn from_xdr_bytes_internal(bytes: &[u8], build_index: bool) -> Result<Self> {
        let entries = Self::parse_entries(bytes)?;

        // Build key index only if requested (skip during catchup for memory efficiency)
        let key_index = if build_index {
            let mut index = BTreeMap::new();
            for (idx, entry) in entries.iter().enumerate() {
                if let Some(key) = entry.key() {
                    let key_bytes = key
                        .to_xdr(Limits::none())
                        .map_err(|e| BucketError::Serialization(format!("Failed to serialize key: {}", e)))?;
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
            entries: Arc::new(entries),
            key_index: Arc::new(key_index),
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

    /// Serialize entries to XDR bytes WITHOUT record marks.
    /// Used for internal purposes.
    fn serialize_entries_raw(entries: &[BucketEntry]) -> Result<Vec<u8>> {
        use stellar_xdr::curr::Limited;
        let mut bytes = Vec::new();
        for entry in entries {
            let xdr_entry = entry.to_xdr_entry();
            let mut limited = Limited::new(&mut bytes, Limits::none());
            xdr_entry
                .write_xdr(&mut limited)
                .map_err(|e| BucketError::Serialization(format!("Failed to serialize entry: {}", e)))?;
        }
        Ok(bytes)
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
            xdr_entry
                .write_xdr(&mut limited)
                .map_err(|e| BucketError::Serialization(format!("Failed to serialize entry: {}", e)))?;

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

        // Serialize entries
        let uncompressed = Self::serialize_entries(&self.entries)?;

        // Compress and write
        let file = std::fs::File::create(&path)?;
        let mut encoder = GzEncoder::new(file, Compression::default());
        encoder.write_all(&uncompressed)?;
        encoder.finish()?;

        Ok(path)
    }

    /// Get the hash of this bucket's contents.
    pub fn hash(&self) -> Hash256 {
        self.hash
    }

    /// Check if this bucket is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() || self.hash.is_zero()
    }

    /// Get the number of entries in this bucket.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Iterate over entries in this bucket.
    pub fn iter(&self) -> impl Iterator<Item = &BucketEntry> {
        self.entries.iter()
    }

    /// Get entries as a slice.
    pub fn entries(&self) -> &[BucketEntry] {
        &self.entries
    }

    /// Look up an entry by its key.
    pub fn get(&self, key: &LedgerKey) -> Result<Option<&BucketEntry>> {
        let key_bytes = key
            .to_xdr(Limits::none())
            .map_err(|e| BucketError::Serialization(format!("Failed to serialize key: {}", e)))?;

        if let Some(&idx) = self.key_index.get(&key_bytes) {
            Ok(self.entries.get(idx))
        } else {
            Ok(None)
        }
    }

    /// Look up a ledger entry by key, returning None if dead or not found.
    pub fn get_entry(&self, key: &LedgerKey) -> Result<Option<&LedgerEntry>> {
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
    pub fn binary_search(&self, key: &LedgerKey) -> Option<usize> {
        let entries = &*self.entries;

        let result = entries.binary_search_by(|entry| {
            match entry.key() {
                Some(entry_key) => compare_keys(&entry_key, key),
                None => std::cmp::Ordering::Less, // Metadata sorts first
            }
        });

        result.ok()
    }

    /// Get the protocol version from bucket metadata, if present.
    pub fn protocol_version(&self) -> Option<u32> {
        for entry in self.entries.iter() {
            if let BucketEntry::Metadata(meta) = entry {
                return Some(meta.ledger_version);
            }
        }
        None
    }

    /// Convert bucket contents to uncompressed XDR bytes.
    pub fn to_xdr_bytes(&self) -> Result<Vec<u8>> {
        Self::serialize_entries(&self.entries)
    }
}

impl std::fmt::Debug for Bucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bucket")
            .field("hash", &self.hash.to_hex())
            .field("entries", &self.entries.len())
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
    use stellar_xdr::curr::*;
    use crate::BucketEntry; // Re-import to shadow XDR's BucketEntry

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
}
