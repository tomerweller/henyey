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
//! 2. **Builds** a `LiveBucketIndex` by streaming entries from the file
//! 3. **Reads** entries on-demand from disk when accessed via mmap
//!
//! # Index Types
//!
//! The index is automatically selected based on bucket size:
//!
//! - **Small buckets** (< 10K entries): `InMemoryIndex` with per-key offsets
//! - **Large buckets** (>= 10K entries): `DiskIndex` with page-based ranges
//!   and bloom filter (~148 MB for 60M keys vs ~960 MB with a flat index)
//!
//! # Trade-offs
//!
//! - **Slower lookups**: Each lookup requires disk I/O (mitigated by mmap)
//! - **No in-memory slice access**: Must use iteration instead
//!
//! # Usage
//!
//! Disk buckets are created via [`Bucket::from_xdr_bytes_disk_backed`] and are
//! transparent to most bucket operations. Check [`Bucket::is_disk_backed`] to
//! determine the storage mode.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use memmap2::Mmap;

use sha2::{Digest, Sha256};
use stellar_xdr::curr::{LedgerEntry, LedgerKey, Limits, ReadXdr};

use stellar_core_common::Hash256;

use crate::bloom_filter::HashSeed;
use crate::entry::BucketEntry;
use crate::index::LiveBucketIndex;
use crate::{BucketError, Result};

/// Minimum number of entries required to build a bloom filter.
/// Smaller buckets don't benefit enough from bloom filter lookups to justify the overhead.
const BLOOM_FILTER_MIN_ENTRIES: usize = 2;

/// Default hash seed for bloom filter construction.
/// This is used when no custom seed is provided.
pub const DEFAULT_BLOOM_SEED: HashSeed = [0u8; 16];

/// A disk-backed bucket that stores entries on disk with an in-memory index.
///
/// This implementation is designed for memory efficiency when processing
/// large buckets during catchup. Instead of loading all entries into memory,
/// it maintains a compact index and reads entries on-demand.
///
/// # Index Type
///
/// Uses `LiveBucketIndex` which automatically selects the appropriate strategy:
///
/// - **Small buckets** (< 10K entries): `InMemoryIndex` with per-key offsets
/// - **Large buckets** (≥ 10K entries): `DiskIndex` with page-based ranges
///   and bloom filter, reducing memory from ~960 MB to ~148 MB for 60M keys
///
/// # Bloom Filter
///
/// The index includes bloom filters for fast negative lookups,
/// allowing `get()` to quickly reject keys that are definitely
/// not present (avoiding disk I/O).
///
/// # File Access Pattern
///
/// Lookups use memory-mapped I/O for lock-free, zero-syscall reads.
/// This is critical for performance on mainnet where thousands of
/// lookups per ledger are needed.
///
/// # Lazy Initialization
///
/// The index and mmap can be lazily initialized. During catchup, we only
/// need Pass 1 (count + hash) since lookups aren't needed until live
/// operation begins. Pass 2 (index building) and mmap creation are deferred
/// until the first `get()` call. This dramatically reduces memory usage
/// during catchup — from O(index_size × num_buckets) to essentially zero.
#[derive(Clone)]
pub struct DiskBucket {
    /// The SHA-256 hash of this bucket's contents (for verification).
    hash: Hash256,
    /// Path to the bucket file on disk (uncompressed XDR).
    file_path: PathBuf,
    /// Total number of entries in this bucket.
    entry_count: usize,
    /// Bloom filter seed used for index construction (needed for lazy init).
    bloom_seed: HashSeed,
    /// Index for key lookups, lazily initialized on first get().
    /// Using OnceLock for thread-safe lazy initialization without external locking.
    index: OnceLock<Box<LiveBucketIndex>>,
    /// Memory-mapped file for lock-free reads, lazily initialized on first get().
    mmap: OnceLock<Arc<Mmap>>,
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

    /// Ensure the index is initialized, building it lazily if needed.
    fn ensure_index(&self) -> &LiveBucketIndex {
        self.index.get_or_init(|| {
            tracing::info!(
                hash = %self.hash.to_hex(),
                entry_count = self.entry_count,
                file = ?self.file_path,
                "Lazily building disk bucket index on first access"
            );
            let file_len = std::fs::metadata(&self.file_path)
                .expect("bucket file must exist for index build")
                .len();
            let iter = StreamingXdrEntryIterator::new(&self.file_path, file_len)
                .expect("failed to open bucket file for index build");
            let live_index = LiveBucketIndex::from_entries(iter, self.bloom_seed, self.entry_count);

            tracing::debug!(
                hash = %self.hash.to_hex(),
                index_type = if live_index.is_in_memory() { "InMemory" } else { "DiskIndex" },
                "Lazy index construction complete"
            );

            Box::new(live_index)
        })
    }

    /// Ensure the mmap is initialized, creating it lazily if needed.
    fn ensure_mmap(&self) -> &Arc<Mmap> {
        self.mmap
            .get_or_init(|| Self::create_mmap(&self.file_path).expect("failed to mmap bucket file"))
    }

    /// Create a disk bucket from an XDR file.
    ///
    /// This streams the file to build the index without keeping entries in memory.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_file_streaming_with_seed(path, DEFAULT_BLOOM_SEED)
    }

    /// Create a disk bucket from an XDR file with a custom bloom filter seed.
    ///
    /// This streams the file to build the index without keeping entries in memory.
    pub fn from_file_with_seed(path: impl AsRef<Path>, bloom_seed: HashSeed) -> Result<Self> {
        Self::from_file_streaming_with_seed(path, bloom_seed)
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
        let (entry_count, hash) = Self::count_and_hash(path, file_len)?;

        // Pass 2: build index by streaming entries one at a time (O(index_size) memory)
        // The iterator reads and parses one entry at a time from disk.
        let iter = StreamingXdrEntryIterator::new(path, file_len)?;
        let live_index = LiveBucketIndex::from_entries(iter, bloom_seed, entry_count);

        tracing::debug!(
            entry_count,
            file_size = file_len,
            index_type = if live_index.is_in_memory() {
                "InMemory"
            } else {
                "DiskIndex"
            },
            "Built disk bucket index via streaming"
        );

        let index = OnceLock::new();
        index
            .set(Box::new(live_index))
            .unwrap_or_else(|_| unreachable!());
        let mmap = OnceLock::new();
        mmap.set(Self::create_mmap(path)?)
            .unwrap_or_else(|_| unreachable!());

        Ok(Self {
            hash,
            file_path: path.to_path_buf(),
            entry_count,
            bloom_seed,
            index,
            mmap,
        })
    }

    /// Create a disk bucket with **lazy** index and mmap construction.
    ///
    /// This performs only Pass 1 (count entries + compute hash), deferring
    /// the expensive Pass 2 (index building) and mmap creation until the first
    /// `get()` call. This is ideal during catchup where we need to build the
    /// bucket list structure but don't need lookups until live operation begins.
    ///
    /// Memory savings: for mainnet with ~60M entries across ~30 buckets, this
    /// avoids allocating ~200+ MB of bloom filters, page indexes, and mmap
    /// virtual address space until they're actually needed.
    pub fn from_file_lazy(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_file_lazy_with_seed(path, DEFAULT_BLOOM_SEED)
    }

    /// Create a disk bucket with lazy index/mmap, using a custom bloom filter seed.
    pub fn from_file_lazy_with_seed(path: impl AsRef<Path>, bloom_seed: HashSeed) -> Result<Self> {
        let path = path.as_ref();
        let file_len = std::fs::metadata(path)?.len();

        // Pass 1 only: count entries and compute hash
        let (entry_count, hash) = Self::count_and_hash(path, file_len)?;

        tracing::debug!(
            entry_count,
            file_size = file_len,
            hash = %hash.to_hex(),
            "Created lazy disk bucket (index deferred)"
        );

        Ok(Self {
            hash,
            file_path: path.to_path_buf(),
            entry_count,
            bloom_seed,
            index: OnceLock::new(),
            mmap: OnceLock::new(),
        })
    }

    /// Pass 1: count entries and compute SHA-256 hash by streaming through the file.
    /// Uses O(1) memory — only a small read buffer and hasher state.
    fn count_and_hash(path: &Path, file_len: u64) -> Result<(usize, Hash256)> {
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

            hasher.update(mark_buf);
            hasher.update(&record_data);

            count += 1;
        }

        let hash_bytes: [u8; 32] = hasher.finalize().into();
        Ok((count, Hash256::from_bytes(hash_bytes)))
    }

    /// Create a disk bucket from a pre-built index, skipping file scanning.
    ///
    /// This is used when loading a persisted index from disk, avoiding the
    /// expensive 2-pass streaming build. The caller is responsible for ensuring
    /// that the index matches the bucket file contents.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the uncompressed XDR bucket file
    /// * `hash` - The known SHA-256 hash of the bucket contents
    /// * `entry_count` - Total number of entries in the bucket
    /// * `index` - Pre-built LiveBucketIndex (from persistence or prior build)
    pub fn from_prebuilt(
        path: impl AsRef<Path>,
        hash: Hash256,
        entry_count: usize,
        prebuilt_index: LiveBucketIndex,
    ) -> Result<Self> {
        let path = path.as_ref();

        let index = OnceLock::new();
        index
            .set(Box::new(prebuilt_index))
            .unwrap_or_else(|_| unreachable!());
        let mmap = OnceLock::new();
        mmap.set(Self::create_mmap(path)?)
            .unwrap_or_else(|_| unreachable!());

        Ok(Self {
            hash,
            file_path: path.to_path_buf(),
            entry_count,
            bloom_seed: DEFAULT_BLOOM_SEED,
            index,
            mmap,
        })
    }

    /// Create a disk bucket from raw XDR bytes, saving to the specified path.
    pub fn from_xdr_bytes(bytes: &[u8], save_path: impl AsRef<Path>) -> Result<Self> {
        Self::from_xdr_bytes_with_seed(bytes, save_path, DEFAULT_BLOOM_SEED)
    }

    /// Create a disk bucket from raw XDR bytes with a custom bloom filter seed.
    ///
    /// Writes the bytes to disk, then builds the index by streaming.
    pub fn from_xdr_bytes_with_seed(
        bytes: &[u8],
        save_path: impl AsRef<Path>,
        bloom_seed: HashSeed,
    ) -> Result<Self> {
        use std::io::Write;

        let save_path = save_path.as_ref();

        // Save to disk first
        let mut file = File::create(save_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);

        // Build index by streaming the saved file
        Self::from_file_streaming_with_seed(save_path, bloom_seed)
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

    /// Returns a reference to the live bucket index.
    /// Lazily initializes the index if it hasn't been built yet.
    pub fn live_index(&self) -> &LiveBucketIndex {
        self.ensure_index()
    }

    /// Returns true if this bucket has a bloom filter for fast negative lookups.
    pub fn has_bloom_filter(&self) -> bool {
        self.entry_count >= BLOOM_FILTER_MIN_ENTRIES
    }

    /// Returns the size of the bloom filter in bytes, or 0 if no filter exists.
    pub fn bloom_filter_size_bytes(&self) -> usize {
        self.ensure_index().bloom_filter_size_bytes()
    }

    /// Returns the hash seed used for the bloom filter.
    pub fn bloom_seed(&self) -> HashSeed {
        self.bloom_seed
    }

    /// Look up an entry by key.
    ///
    /// This reads from disk using the index. The bloom filter is checked first
    /// to quickly reject keys that are definitely not present (avoiding disk I/O).
    ///
    /// On first call, this lazily initializes the index (Pass 2) and mmap.
    pub fn get(&self, key: &LedgerKey) -> Result<Option<BucketEntry>> {
        let index = self.ensure_index();

        // Check bloom filter (built into the index)
        if !index.may_contain(key) {
            return Ok(None);
        }

        match index {
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

    /// Look up an entry using pre-serialized key bytes to avoid redundant serialization.
    ///
    /// The `key` is needed for final verification (hash collisions), while `key_bytes`
    /// is used for bloom filter checks and index lookups.
    pub fn get_by_key_bytes(
        &self,
        key: &LedgerKey,
        key_bytes: &[u8],
    ) -> Result<Option<BucketEntry>> {
        let index = self.ensure_index();

        if !index.may_contain_bytes(key_bytes) {
            return Ok(None);
        }

        match index {
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

    /// Read a single entry from the mmap at the given offset.
    /// No syscalls, no locks — direct memory access through the mmap.
    fn read_entry_at(&self, offset: u64) -> Result<BucketEntry> {
        let offset = offset as usize;
        let data = &**self.ensure_mmap();

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
                stellar_xdr::curr::BucketEntry::from_xdr(&data[offset..], Limits::none()).map_err(
                    |e| BucketError::Serialization(format!("Failed to parse entry: {}", e)),
                )?;
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
        let data = &**self.ensure_mmap();
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
    pub fn iter_from_offset_with_sizes(&self, start_offset: u64) -> Result<DiskBucketOffsetIter> {
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
                    self.position = self.reader.stream_position().unwrap_or(self.file_len);
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
