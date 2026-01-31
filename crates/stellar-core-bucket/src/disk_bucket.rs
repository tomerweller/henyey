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

use memmap2::Mmap;

use sha2::{Digest, Sha256};
use stellar_xdr::curr::{LedgerEntry, LedgerKey, Limits, ReadXdr};

use stellar_core_common::Hash256;

use crate::bloom_filter::{BucketBloomFilter, HashSeed};
use crate::entry::BucketEntry;
use crate::index::{
    DiskIndex, InMemoryIndex, LiveBucketIndex, DEFAULT_PAGE_SIZE, IN_MEMORY_INDEX_THRESHOLD,
};
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

/// The index type used by a `DiskBucket` for key lookups.
///
/// Supports both the legacy flat index (8-byte key hash → offset) and the
/// new `LiveBucketIndex` (page-based for large buckets, per-key for small).
#[derive(Clone)]
enum DiskBucketIndex {
    /// Legacy flat index: maps 8-byte key hash prefix → file offset.
    ///
    /// This stores one entry per key using an 8-byte hash prefix.
    /// Simple but uses ~16 bytes/key, which is ~960 MB for 60M keys.
    Legacy {
        index: Arc<BTreeMap<u64, IndexEntry>>,
        bloom_filter: Option<Arc<BucketBloomFilter>>,
        bloom_seed: HashSeed,
    },
    /// Advanced index using `LiveBucketIndex` from `index.rs`.
    ///
    /// For small buckets (< 10K entries): per-key `InMemoryIndex`
    /// For large buckets (≥ 10K entries): page-based `DiskIndex`
    ///   - ~60K page entries for 60M keys (~10 MB)
    ///   - Bloom filter for fast negative lookups (~138 MB for 60M keys)
    Advanced(LiveBucketIndex),
}

/// A disk-backed bucket that stores entries on disk with an in-memory index.
///
/// This implementation is designed for memory efficiency when processing
/// large buckets during catchup. Instead of loading all entries into memory,
/// it maintains a compact index and reads entries on-demand.
///
/// # Index Types
///
/// The bucket supports two index modes:
///
/// - **Legacy flat index**: Maps 8-byte key hash prefixes to file offsets.
///   Simple but uses ~16 bytes/key (~960 MB for 60M keys).
///
/// - **Advanced index** (`LiveBucketIndex`): For large buckets, uses a page-based
///   `DiskIndex` with bloom filter, reducing memory from ~960 MB to ~148 MB
///   for 60M keys. For small buckets, uses a per-key `InMemoryIndex`.
///
/// The streaming constructor (`from_file_streaming`) uses the advanced index.
///
/// # Bloom Filter
///
/// Both index modes include bloom filters for fast negative lookups,
/// allowing `get()` to quickly reject keys not in the bucket.
///
/// # File Access Pattern
///
/// Lookups use memory-mapped I/O for lock-free, zero-syscall reads.
/// This is critical for performance on mainnet where thousands of
/// lookups per ledger are needed.
#[derive(Clone)]
pub struct DiskBucket {
    /// The SHA-256 hash of this bucket's contents (for verification).
    hash: Hash256,
    /// Path to the bucket file on disk (uncompressed XDR).
    file_path: PathBuf,
    /// Index for key lookups.
    disk_index: DiskBucketIndex,
    /// Total number of entries in this bucket.
    entry_count: usize,
    /// Memory-mapped file for lock-free reads.
    /// Using mmap eliminates seek+read syscalls and the Mutex,
    /// and lets the OS page cache manage data optimally.
    mmap: Arc<Mmap>,
}

/// Iterator that reads `(BucketEntry, offset)` pairs one at a time from an
/// uncompressed XDR bucket file. Each call to `next()` reads and parses a
/// single record, keeping only O(1) memory (one entry + read buffer).
struct StreamingXdrEntryIterator {
    reader: BufReader<File>,
    file_len: u64,
    position: u64,
}

impl StreamingXdrEntryIterator {
    fn new(path: &Path, file_len: u64) -> Result<Self> {
        let file = File::open(path)?;
        Ok(Self {
            reader: BufReader::new(file),
            file_len,
            position: 0,
        })
    }
}

impl Iterator for StreamingXdrEntryIterator {
    type Item = (BucketEntry, u64);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.position + 4 > self.file_len {
                return None;
            }

            let record_start = self.position;

            // Read 4-byte record mark
            let mut mark_buf = [0u8; 4];
            if self.reader.read_exact(&mut mark_buf).is_err() {
                return None;
            }
            self.position += 4;

            let record_mark = u32::from_be_bytes(mark_buf);
            let record_len = (record_mark & 0x7FFFFFFF) as usize;

            if self.position + record_len as u64 > self.file_len {
                return None;
            }

            // Read record data
            let mut record_data = vec![0u8; record_len];
            if self.reader.read_exact(&mut record_data).is_err() {
                return None;
            }
            self.position += record_len as u64;

            // Parse entry — skip records that fail to parse
            if let Ok(xdr_entry) =
                stellar_xdr::curr::BucketEntry::from_xdr(&record_data, Limits::none())
            {
                if let Ok(bucket_entry) = BucketEntry::from_xdr_entry(xdr_entry) {
                    if bucket_entry.key().is_some() {
                        return Some((bucket_entry, record_start));
                    }
                }
            }
        }
    }
}

impl DiskBucket {
    /// Create a memory-mapped file for lock-free reads.
    /// Uses MADV_RANDOM to optimize for point lookups (no readahead waste).
    fn create_mmap(path: &Path) -> Result<Arc<Mmap>> {
        let file = File::open(path)?;
        // SAFETY: The file is opened read-only, and the mmap is used for read-only access.
        // The bucket file is not modified while the mmap is active.
        let mmap = unsafe { Mmap::map(&file)? };
        #[cfg(unix)]
        {
            mmap.advise(memmap2::Advice::Random)
                .unwrap_or_else(|e| tracing::warn!("madvise(RANDOM) failed: {}", e));
        }
        Ok(Arc::new(mmap))
    }

    /// Create a disk bucket from an XDR file.
    ///
    /// This parses the file to build the index but doesn't keep entries in memory.
    /// For large files, prefer [`from_file_streaming`] which uses O(1) memory.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_file_with_seed(path, DEFAULT_BLOOM_SEED)
    }

    /// Create a disk bucket from an XDR file with a custom bloom filter seed.
    ///
    /// This parses the file to build the index but doesn't keep entries in memory.
    /// Note: This loads the entire file into memory for hash computation and index
    /// building. For large files, prefer [`from_file_streaming`].
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
            disk_index: DiskBucketIndex::Legacy {
                index: Arc::new(index),
                bloom_filter,
                bloom_seed,
            },
            entry_count,
            mmap: Self::create_mmap(path)?,
        })
    }

    /// Create a disk bucket from an uncompressed XDR file using streaming I/O.
    ///
    /// This builds the index by reading entries one at a time from the file,
    /// computing the hash incrementally. Memory usage is O(index_size), not
    /// O(file_size), making it suitable for very large bucket files (multi-GB).
    ///
    /// The file must use XDR record marking format (high bit set in record marks).
    pub fn from_file_streaming(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_file_streaming_with_seed(path, DEFAULT_BLOOM_SEED)
    }

    /// Create a disk bucket from an uncompressed XDR file using streaming I/O
    /// with a custom bloom filter seed.
    ///
    /// Uses the advanced `LiveBucketIndex`:
    /// - Small buckets (< 10K entries): `InMemoryIndex` (per-key O(log n) lookup)
    /// - Large buckets (≥ 10K entries): `DiskIndex` (page-based, ~10 MB for 60M keys)
    pub fn from_file_streaming_with_seed(
        path: impl AsRef<Path>,
        bloom_seed: HashSeed,
    ) -> Result<Self> {
        let path = path.as_ref();
        let file_len = std::fs::metadata(path)?.len();

        // Pass 1: count entries and compute hash (O(1) memory, no entry storage)
        let (entry_count, hash) = {
            let file = File::open(path)?;
            let mut reader = BufReader::new(file);
            let mut hasher = Sha256::new();
            let mut position = 0u64;
            let mut count = 0usize;

            while position + 4 <= file_len {
                let mut mark_buf = [0u8; 4];
                reader.read_exact(&mut mark_buf)?;
                position += 4;

                let record_mark = u32::from_be_bytes(mark_buf);
                let record_len = (record_mark & 0x7FFFFFFF) as usize;

                if position + record_len as u64 > file_len {
                    break;
                }

                let mut record_data = vec![0u8; record_len];
                reader.read_exact(&mut record_data)?;
                position += record_len as u64;

                hasher.update(&mark_buf);
                hasher.update(&record_data);

                count += 1;
            }

            let hash_bytes: [u8; 32] = hasher.finalize().into();
            (count, Hash256::from_bytes(hash_bytes))
        };

        // Pass 2: build index by streaming entries one at a time (O(index_size) memory)
        // The iterator reads and parses one entry at a time from disk.
        let iter = StreamingXdrEntryIterator::new(path, file_len)?;
        let live_index = LiveBucketIndex::from_entries(iter, bloom_seed, entry_count);

        tracing::debug!(
            entry_count,
            file_size = file_len,
            index_type = if live_index.is_in_memory() { "InMemory" } else { "DiskIndex" },
            "Built disk bucket index via streaming"
        );

        Ok(Self {
            hash,
            file_path: path.to_path_buf(),
            disk_index: DiskBucketIndex::Advanced(live_index),
            entry_count,
            mmap: Self::create_mmap(path)?,
        })
    }

    /// Create a disk bucket from raw XDR bytes, saving to the specified path.
    pub fn from_xdr_bytes(bytes: &[u8], save_path: impl AsRef<Path>) -> Result<Self> {
        Self::from_xdr_bytes_with_seed(bytes, save_path, DEFAULT_BLOOM_SEED)
    }

    /// Create a disk bucket from raw XDR bytes with a custom bloom filter seed.
    pub fn from_xdr_bytes_with_seed(
        bytes: &[u8],
        save_path: impl AsRef<Path>,
        bloom_seed: HashSeed,
    ) -> Result<Self> {
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
            disk_index: DiskBucketIndex::Legacy {
                index: Arc::new(index),
                bloom_filter,
                bloom_seed,
            },
            entry_count,
            mmap: Self::create_mmap(save_path.as_ref())?,
        })
    }

    /// Build an index from XDR bytes.
    ///
    /// Returns (index, bloom_key_hashes, entry_count).
    fn build_index(
        bytes: &[u8],
        bloom_seed: &HashSeed,
    ) -> Result<(BTreeMap<u64, IndexEntry>, Vec<u64>, usize)> {
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
                if let Ok(xdr_entry) =
                    stellar_xdr::curr::BucketEntry::from_xdr(record_data, Limits::none())
                {
                    if let Some(key) = Self::extract_key(&xdr_entry) {
                        // Use first 8 bytes of key hash as index key
                        let key_hash = Self::hash_key(&key);
                        index.insert(
                            key_hash,
                            IndexEntry {
                                offset: record_start,
                                length: record_len as u32,
                            },
                        );
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
                            index.insert(
                                key_hash,
                                IndexEntry {
                                    offset: entry_start,
                                    length: (entry_end - entry_start) as u32,
                                },
                            );
                            // Also compute bloom filter hash
                            bloom_key_hashes.push(BucketBloomFilter::hash_key(&key, bloom_seed));
                        }
                        entry_count += 1;
                    }
                    Err(_) => break,
                }
            }
        }

        debug!(
            "Built index with {} entries, {} keys for bloom filter",
            entry_count,
            bloom_key_hashes.len()
        );
        Ok((index, bloom_key_hashes, entry_count))
    }

    /// Extract the key from a bucket entry.
    fn extract_key(entry: &stellar_xdr::curr::BucketEntry) -> Option<LedgerKey> {
        use crate::entry::ledger_entry_to_key;
        use stellar_xdr::curr::BucketEntry as XdrBucketEntry;

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
        match &self.disk_index {
            DiskBucketIndex::Legacy { bloom_filter, .. } => bloom_filter.is_some(),
            // Advanced indexes always build bloom filters for buckets with >= 2 entries
            DiskBucketIndex::Advanced(_) => self.entry_count >= BLOOM_FILTER_MIN_ENTRIES,
        }
    }

    /// Returns the size of the bloom filter in bytes, or 0 if no filter exists.
    pub fn bloom_filter_size_bytes(&self) -> usize {
        match &self.disk_index {
            DiskBucketIndex::Legacy { bloom_filter, .. } => {
                bloom_filter.as_ref().map_or(0, |f| f.size_bytes())
            }
            DiskBucketIndex::Advanced(_) => 0, // Not easily accessible through facade
        }
    }

    /// Returns the hash seed used for the bloom filter.
    pub fn bloom_seed(&self) -> HashSeed {
        match &self.disk_index {
            DiskBucketIndex::Legacy { bloom_seed, .. } => *bloom_seed,
            DiskBucketIndex::Advanced(_) => DEFAULT_BLOOM_SEED,
        }
    }

    /// Look up an entry by key.
    ///
    /// This reads from disk using the index. If a bloom filter is available,
    /// it first checks the filter to quickly reject keys that are definitely
    /// not present (avoiding disk I/O).
    pub fn get(&self, key: &LedgerKey) -> Result<Option<BucketEntry>> {
        match &self.disk_index {
            DiskBucketIndex::Legacy {
                index,
                bloom_filter,
                bloom_seed,
            } => {
                // Check bloom filter first for fast negative lookup
                if let Some(ref filter) = bloom_filter {
                    if !filter.may_contain(key, bloom_seed) {
                        return Ok(None);
                    }
                }

                let key_hash = Self::hash_key(key);

                let index_entry = match index.get(&key_hash) {
                    Some(e) => e,
                    None => return Ok(None),
                };

                // Read the entry from disk
                let entry = self.read_entry_at(index_entry.offset)?;

                // Verify this is the right entry (hash collisions are possible)
                if let Some(entry_key) = entry.key() {
                    if &entry_key == key {
                        return Ok(Some(entry));
                    }
                }

                Ok(None)
            }
            DiskBucketIndex::Advanced(live_index) => {
                // Check bloom filter (built into the index)
                if !live_index.may_contain(key) {
                    return Ok(None);
                }

                match live_index {
                    LiveBucketIndex::InMemory(idx) => {
                        // Exact offset lookup
                        if let Some(offset) = idx.get_offset(key) {
                            let entry = self.read_entry_at(offset)?;
                            if let Some(entry_key) = entry.key() {
                                if &entry_key == key {
                                    return Ok(Some(entry));
                                }
                            }
                        }
                        Ok(None)
                    }
                    LiveBucketIndex::Disk(disk_idx) => {
                        // Page-based lookup: find candidate page, scan within it
                        if let Some(page_offset) = disk_idx.find_page_for_key(key) {
                            self.scan_page_for_key(page_offset, key, disk_idx.page_size())
                        } else {
                            Ok(None)
                        }
                    }
                }
            }
        }
    }

    /// Look up an entry using pre-serialized key bytes to avoid redundant serialization.
    ///
    /// The `key` is needed for final verification (hash collisions), while `key_bytes`
    /// is used for bloom filter checks, hash computation, and index lookups.
    pub fn get_by_key_bytes(
        &self,
        key: &LedgerKey,
        key_bytes: &[u8],
    ) -> Result<Option<BucketEntry>> {
        match &self.disk_index {
            DiskBucketIndex::Legacy {
                index,
                bloom_filter,
                bloom_seed,
            } => {
                if let Some(ref filter) = bloom_filter {
                    let hash = crate::bloom_filter::BucketBloomFilter::hash_bytes(
                        key_bytes, bloom_seed,
                    );
                    if !filter.may_contain_hash(hash) {
                        return Ok(None);
                    }
                }

                let key_hash = {
                    let hash = Sha256::digest(key_bytes);
                    u64::from_be_bytes(hash[0..8].try_into().unwrap())
                };

                let index_entry = match index.get(&key_hash) {
                    Some(e) => e,
                    None => return Ok(None),
                };

                let entry = self.read_entry_at(index_entry.offset)?;

                if let Some(entry_key) = entry.key() {
                    if &entry_key == key {
                        return Ok(Some(entry));
                    }
                }

                Ok(None)
            }
            DiskBucketIndex::Advanced(live_index) => {
                if !live_index.may_contain_bytes(key_bytes) {
                    return Ok(None);
                }

                match live_index {
                    LiveBucketIndex::InMemory(idx) => {
                        if let Some(offset) = idx.get_offset_by_key_bytes(key_bytes) {
                            let entry = self.read_entry_at(offset)?;
                            if let Some(entry_key) = entry.key() {
                                if &entry_key == key {
                                    return Ok(Some(entry));
                                }
                            }
                        }
                        Ok(None)
                    }
                    LiveBucketIndex::Disk(disk_idx) => {
                        // Disk-based index uses key comparison for page search,
                        // fall back to regular method
                        if let Some(page_offset) = disk_idx.find_page_for_key(key) {
                            self.scan_page_for_key(page_offset, key, disk_idx.page_size())
                        } else {
                            Ok(None)
                        }
                    }
                }
            }
        }
    }

    /// Read a single entry from the mmap at the given offset.
    /// No syscalls, no locks — direct memory access through the mmap.
    fn read_entry_at(&self, offset: u64) -> Result<BucketEntry> {
        let offset = offset as usize;
        let data = &*self.mmap;

        if offset + 4 > data.len() {
            return Err(BucketError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("offset {} + 4 exceeds file size {}", offset, data.len()),
            )));
        }

        // Read record mark
        let mark_buf: [u8; 4] = data[offset..offset + 4].try_into().unwrap();

        let (record_len, record_start) = if mark_buf[0] & 0x80 != 0 {
            let mark = u32::from_be_bytes(mark_buf);
            ((mark & 0x7FFFFFFF) as usize, offset + 4)
        } else {
            // No record mark — try reading as raw XDR from offset
            let xdr_entry =
                stellar_xdr::curr::BucketEntry::from_xdr(&data[offset..], Limits::none())
                    .map_err(|e| {
                        BucketError::Serialization(format!("Failed to parse entry: {}", e))
                    })?;
            return BucketEntry::from_xdr_entry(xdr_entry);
        };

        if record_start + record_len > data.len() {
            return Err(BucketError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "record at offset {} (len {}) exceeds file size {}",
                    offset,
                    record_len,
                    data.len()
                ),
            )));
        }

        // Parse from mmap slice — zero-copy until XDR deserialization
        let record_data = &data[record_start..record_start + record_len];
        let xdr_entry = stellar_xdr::curr::BucketEntry::from_xdr(record_data, Limits::none())
            .map_err(|e| BucketError::Serialization(format!("Failed to parse entry: {}", e)))?;

        BucketEntry::from_xdr_entry(xdr_entry)
    }

    /// Scan a page starting at `page_offset` for a key, reading up to `page_size` entries.
    fn scan_page_for_key(
        &self,
        page_offset: u64,
        key: &LedgerKey,
        page_size: u64,
    ) -> Result<Option<BucketEntry>> {
        let data = &*self.mmap;
        let mut position = page_offset as usize;
        let mut entries_scanned = 0u64;

        while (position + 4) <= data.len() && entries_scanned < page_size {
            // Read 4-byte record mark
            let mark_buf: [u8; 4] = data[position..position + 4].try_into().unwrap();
            position += 4;

            let record_mark = u32::from_be_bytes(mark_buf);
            let record_len = (record_mark & 0x7FFFFFFF) as usize;

            if position + record_len > data.len() {
                break;
            }

            // Parse from mmap slice
            let record_data = &data[position..position + record_len];
            position += record_len;

            if let Ok(xdr_entry) =
                stellar_xdr::curr::BucketEntry::from_xdr(record_data, Limits::none())
            {
                let entry = BucketEntry::from_xdr_entry(xdr_entry)?;

                if let Some(entry_key) = entry.key() {
                    if &entry_key == key {
                        return Ok(Some(entry));
                    }
                    if crate::entry::compare_keys(&entry_key, key) == std::cmp::Ordering::Greater {
                        return Ok(None);
                    }
                }
            }

            entries_scanned += 1;
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
    /// This streams entries from disk sequentially using buffered I/O,
    /// holding only one entry plus a read buffer (~8 KB) in memory at a time.
    /// This is O(1) memory regardless of file size.
    pub fn iter(&self) -> Result<DiskBucketIter> {
        let file = File::open(&self.file_path)?;
        let file_len = file.metadata()?.len();
        let mut reader = BufReader::new(file);

        // Check if file uses XDR record marks by reading the first 4 bytes
        let uses_record_marks = if file_len >= 4 {
            let mut mark_buf = [0u8; 4];
            reader.read_exact(&mut mark_buf)?;
            let has_marks = mark_buf[0] & 0x80 != 0;
            // Seek back to the start
            reader.seek(SeekFrom::Start(0))?;
            has_marks
        } else {
            false
        };

        Ok(DiskBucketIter {
            reader,
            file_len,
            position: 0,
            uses_record_marks,
        })
    }

    /// Iterate over entries starting from a byte offset, yielding record sizes.
    ///
    /// This is optimized for the eviction scan: it seeks directly to
    /// `start_offset` in the file (avoiding reading/skipping millions of
    /// entries), and returns the on-disk record size with each entry (avoiding
    /// expensive XDR re-serialization just to compute byte sizes).
    ///
    /// Each item is `(BucketEntry, record_size)` where `record_size` includes
    /// the 4-byte record mark.
    pub fn iter_from_offset_with_sizes(
        &self,
        start_offset: u64,
    ) -> Result<DiskBucketOffsetIter> {
        let file = File::open(&self.file_path)?;
        let file_len = file.metadata()?.len();
        let mut reader = BufReader::new(file);

        if start_offset > 0 && start_offset < file_len {
            reader.seek(SeekFrom::Start(start_offset))?;
        }

        Ok(DiskBucketOffsetIter {
            reader,
            file_len,
            position: if start_offset < file_len {
                start_offset
            } else {
                file_len
            },
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
/// This iterator streams entries from disk using buffered I/O, reading one
/// entry at a time. Memory usage is O(1) — only the current entry and a
/// small read buffer (~8 KB) are held in memory, regardless of file size.
///
/// This matches the C++ `BucketInputIterator` behavior.
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
    /// Buffered reader for streaming file I/O.
    reader: BufReader<File>,
    /// Total file size in bytes.
    file_len: u64,
    /// Current byte position in the file.
    position: u64,
    /// Whether the file uses XDR record marks (vs raw XDR stream).
    uses_record_marks: bool,
}

impl Iterator for DiskBucketIter {
    type Item = Result<BucketEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.file_len {
            return None;
        }

        if self.uses_record_marks {
            if self.position + 4 > self.file_len {
                return None;
            }

            // Read 4-byte record mark
            let mut mark_buf = [0u8; 4];
            if let Err(e) = self.reader.read_exact(&mut mark_buf) {
                return Some(Err(BucketError::Io(e)));
            }
            self.position += 4;

            let record_mark = u32::from_be_bytes(mark_buf);
            let record_len = (record_mark & 0x7FFFFFFF) as usize;

            if self.position + record_len as u64 > self.file_len {
                return None;
            }

            // Read the entry data
            let mut record_data = vec![0u8; record_len];
            if let Err(e) = self.reader.read_exact(&mut record_data) {
                return Some(Err(BucketError::Io(e)));
            }
            self.position += record_len as u64;

            match stellar_xdr::curr::BucketEntry::from_xdr(&record_data, Limits::none()) {
                Ok(xdr_entry) => Some(BucketEntry::from_xdr_entry(xdr_entry)),
                Err(e) => Some(Err(BucketError::Serialization(format!(
                    "Failed to parse: {}",
                    e
                )))),
            }
        } else {
            use stellar_xdr::curr::{Limited, ReadXdr};
            // For raw XDR format, use the XDR streaming reader
            let mut limited = Limited::new(&mut self.reader, Limits::none());

            match stellar_xdr::curr::BucketEntry::read_xdr(&mut limited) {
                Ok(xdr_entry) => {
                    // Update our position tracking
                    self.position = self
                        .reader
                        .seek(SeekFrom::Current(0))
                        .unwrap_or(self.file_len);
                    Some(BucketEntry::from_xdr_entry(xdr_entry))
                }
                Err(_) => None,
            }
        }
    }
}

/// Iterator over disk bucket entries that yields record sizes alongside entries.
///
/// This iterator is designed for the eviction scan where byte offsets and
/// record sizes are needed. It starts from an arbitrary file offset (seeking
/// directly, not iterating from the start) and yields `(BucketEntry, u64)`
/// tuples where the `u64` is the total on-disk record size (4-byte record
/// mark + XDR data), eliminating the need for expensive XDR re-serialization
/// just to compute entry byte sizes.
///
/// All bucket files at this point use XDR record marks (RFC 5531 format).
pub struct DiskBucketOffsetIter {
    reader: BufReader<File>,
    file_len: u64,
    position: u64,
}

impl Iterator for DiskBucketOffsetIter {
    /// (entry, total_record_size_including_mark)
    type Item = Result<(BucketEntry, u64)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position + 4 > self.file_len {
            return None;
        }

        // Read 4-byte record mark
        let mut mark_buf = [0u8; 4];
        if let Err(e) = self.reader.read_exact(&mut mark_buf) {
            return Some(Err(BucketError::Io(e)));
        }
        self.position += 4;

        let record_mark = u32::from_be_bytes(mark_buf);
        let record_len = (record_mark & 0x7FFFFFFF) as usize;
        let total_record_size = record_len as u64 + 4;

        if self.position + record_len as u64 > self.file_len {
            return None;
        }

        // Read entry data
        let mut record_data = vec![0u8; record_len];
        if let Err(e) = self.reader.read_exact(&mut record_data) {
            return Some(Err(BucketError::Io(e)));
        }
        self.position += record_len as u64;

        match stellar_xdr::curr::BucketEntry::from_xdr(&record_data, Limits::none()) {
            Ok(xdr_entry) => match BucketEntry::from_xdr_entry(xdr_entry) {
                Ok(entry) => Some(Ok((entry, total_record_size))),
                Err(e) => Some(Err(e)),
            },
            Err(e) => Some(Err(BucketError::Serialization(format!(
                "Failed to parse entry: {}",
                e
            )))),
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
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];

        let bytes = make_multi_entry_bucket_bytes(10);
        let bucket = DiskBucket::from_xdr_bytes_with_seed(&bytes, &path, custom_seed).unwrap();

        assert!(bucket.has_bloom_filter());
        assert_eq!(bucket.bloom_seed(), custom_seed);

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
