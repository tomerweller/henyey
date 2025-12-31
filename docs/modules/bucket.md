# Bucket Module Specification

**Crate**: `stellar-core-bucket`
**stellar-core mapping**: `src/bucket/`

## 1. Overview

The bucket module implements the BucketList - a two-level skip list structure that maintains the canonical ledger state as a series of temporal "buckets". This is the heart of Stellar's state management.

Key concepts:
- **Bucket**: An immutable file containing sorted ledger entries
- **BucketList**: A hierarchy of buckets organized by temporal depth
- **Merging**: Combining buckets at level promotion

## 2. stellar-core Reference

In stellar-core, the bucket module (`src/bucket/`) contains:
- `Bucket.h/cpp` - Individual bucket representation
- `BucketIndex.h/cpp` - Bucket indexing for lookups
- `BucketList.h/cpp` - The full bucket list structure
- `BucketListSnapshot.h/cpp` - Point-in-time snapshot
- `BucketManager.h/cpp` - Lifecycle management
- `BucketMerger.h/cpp` - Bucket merge operations
- `LiveBucket.h/cpp` - Mutable bucket during ledger close
- `HotArchiveBucket.h/cpp` - Hot archive bucket type

### 2.1 BucketList Structure

The BucketList consists of 11 levels (0-10), each containing:
- `curr`: Current bucket at this level
- `snap`: Snapshot bucket (previous curr before spill)
- `next`: Future state for async merge

Spill schedule:
- Level 0 spills every ledger
- Level N spills every 2^(2N) ledgers
- Each level is ~4x larger than the previous

```
Level 0:  Updated every ledger (newest entries)
Level 1:  Updated every 4 ledgers
Level 2:  Updated every 16 ledgers
Level 3:  Updated every 64 ledgers
...
Level 10: Updated every ~1M ledgers (oldest entries)
```

## 3. Rust Implementation

### 3.1 Dependencies

```toml
[dependencies]
stellar-xdr = { version = "25.0.0", features = ["std", "curr"] }
stellar-core-crypto = { path = "../stellar-core-crypto" }

# Compression - pure Rust
flate2 = { version = "1.0", default-features = false, features = ["rust_backend"] }

# Async file operations
tokio = { version = "1", features = ["fs", "io-util"] }

# Memory mapping (optional, for large buckets)
memmap2 = "0.9"

# Utilities
thiserror = "1"
tracing = "0.1"
tempfile = "3"
parking_lot = "0.12"
bytes = "1"
```

### 3.2 Module Structure

```
stellar-core-bucket/
├── src/
│   ├── lib.rs
│   ├── entry.rs         # Bucket entry types
│   ├── bucket.rs        # Individual bucket
│   ├── bucket_list.rs   # Full bucket list
│   ├── bucket_index.rs  # Lookup index
│   ├── merger.rs        # Bucket merging
│   ├── manager.rs       # Lifecycle management
│   ├── snapshot.rs      # Point-in-time snapshots
│   ├── live_bucket.rs   # Mutable bucket during close
│   └── error.rs
└── tests/
```

### 3.3 Core Types

#### BucketEntry

```rust
use stellar_xdr::curr::{
    BucketEntry as XdrBucketEntry,
    LedgerEntry,
    LedgerKey,
    BucketMetadata,
};

/// A single entry in a bucket
#[derive(Clone, Debug)]
pub enum BucketEntry {
    /// Live entry (exists in ledger)
    LiveEntry(LedgerEntry),
    /// Dead entry (tombstone - entry was deleted)
    DeadEntry(LedgerKey),
    /// Metadata entry (protocol version, etc.)
    Metadata(BucketMetadata),
    /// Init entry (marks start of live entries at this level)
    InitEntry(LedgerEntry),
}

impl BucketEntry {
    /// Get the key for this entry (for sorting/lookup)
    pub fn key(&self) -> Option<LedgerKey> {
        match self {
            BucketEntry::LiveEntry(e) => Some(e.to_key()),
            BucketEntry::DeadEntry(k) => Some(k.clone()),
            BucketEntry::InitEntry(e) => Some(e.to_key()),
            BucketEntry::Metadata(_) => None,
        }
    }

    /// Is this a live (non-dead) entry?
    pub fn is_live(&self) -> bool {
        matches!(self, BucketEntry::LiveEntry(_) | BucketEntry::InitEntry(_))
    }

    /// Compare entries by key for sorting
    pub fn compare_keys(a: &Self, b: &Self) -> std::cmp::Ordering {
        match (a.key(), b.key()) {
            (Some(ka), Some(kb)) => compare_ledger_keys(&ka, &kb),
            (Some(_), None) => std::cmp::Ordering::Greater,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (None, None) => std::cmp::Ordering::Equal,
        }
    }
}
```

#### Bucket

```rust
use stellar_core_crypto::Hash256;
use std::path::PathBuf;

/// An immutable bucket file
pub struct Bucket {
    /// Hash of the bucket contents
    hash: Hash256,
    /// Path to the bucket file
    path: PathBuf,
    /// In-memory index for fast lookups
    index: BucketIndex,
    /// Number of entries
    entry_count: usize,
    /// Size in bytes
    size_bytes: u64,
}

impl Bucket {
    /// Empty bucket singleton
    pub fn empty() -> &'static Self {
        static EMPTY: once_cell::sync::Lazy<Bucket> = once_cell::sync::Lazy::new(|| {
            Bucket {
                hash: Hash256::ZERO,
                path: PathBuf::new(),
                index: BucketIndex::empty(),
                entry_count: 0,
                size_bytes: 0,
            }
        });
        &EMPTY
    }

    /// Load bucket from file
    pub async fn load(path: PathBuf) -> Result<Self, BucketError> {
        let data = tokio::fs::read(&path).await?;
        let decompressed = decompress_bucket(&data)?;

        let (entries, hash) = parse_bucket_entries(&decompressed)?;
        let index = BucketIndex::build(&entries)?;

        Ok(Self {
            hash,
            path,
            index,
            entry_count: entries.len(),
            size_bytes: data.len() as u64,
        })
    }

    /// Get the bucket hash
    pub fn hash(&self) -> &Hash256 {
        &self.hash
    }

    /// Look up an entry by key
    pub fn get(&self, key: &LedgerKey) -> Result<Option<BucketEntry>, BucketError> {
        self.index.get(key)
    }

    /// Iterate over all entries
    pub fn iter(&self) -> impl Iterator<Item = Result<BucketEntry, BucketError>> + '_ {
        BucketIterator::new(&self.path)
    }

    /// Is this bucket empty?
    pub fn is_empty(&self) -> bool {
        self.hash == Hash256::ZERO
    }
}
```

#### BucketList

```rust
/// Number of levels in the bucket list
pub const BUCKET_LIST_LEVELS: usize = 11;

/// A single level in the bucket list
pub struct BucketListLevel {
    /// Current bucket at this level
    pub curr: Arc<Bucket>,
    /// Snapshot bucket (previous curr)
    pub snap: Arc<Bucket>,
    /// Future merge result (if merge in progress)
    pub next: Option<FutureBucket>,
}

/// The full bucket list structure
pub struct BucketList {
    levels: [BucketListLevel; BUCKET_LIST_LEVELS],
}

impl BucketList {
    /// Create empty bucket list
    pub fn new() -> Self {
        let empty = Arc::new(Bucket::empty().clone());
        let levels = std::array::from_fn(|_| BucketListLevel {
            curr: Arc::clone(&empty),
            snap: Arc::clone(&empty),
            next: None,
        });
        Self { levels }
    }

    /// Compute the hash of the entire bucket list
    pub fn hash(&self) -> Hash256 {
        let mut hasher = sha2::Sha256::new();
        for level in &self.levels {
            hasher.update(level.curr.hash().as_bytes());
            hasher.update(level.snap.hash().as_bytes());
        }
        Hash256::from_hasher(hasher)
    }

    /// Add entries from a closed ledger
    pub async fn add_batch(
        &mut self,
        ledger_seq: u32,
        entries: Vec<BucketEntry>,
        manager: &BucketManager,
    ) -> Result<(), BucketError> {
        // Create new level 0 curr bucket from entries
        let new_curr = manager.create_bucket(entries).await?;

        // Prepare spills at each level
        self.prepare_spills(ledger_seq, manager).await?;

        // Update level 0
        self.levels[0].snap = std::mem::replace(
            &mut self.levels[0].curr,
            Arc::new(new_curr),
        );

        Ok(())
    }

    /// Should level N spill at this ledger?
    pub fn should_spill(level: usize, ledger_seq: u32) -> bool {
        if level == 0 {
            return true; // Level 0 always spills
        }
        let spill_frequency = 1u32 << (2 * level);
        ledger_seq % spill_frequency == 0
    }

    /// Lookup an entry across all levels
    pub fn get(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>, BucketError> {
        // Search from newest (level 0) to oldest (level 10)
        for level in &self.levels {
            // Check curr first
            if let Some(entry) = level.curr.get(key)? {
                return match entry {
                    BucketEntry::LiveEntry(e) => Ok(Some(e)),
                    BucketEntry::DeadEntry(_) => Ok(None), // Tombstone
                    _ => continue,
                };
            }
            // Then check snap
            if let Some(entry) = level.snap.get(key)? {
                return match entry {
                    BucketEntry::LiveEntry(e) => Ok(Some(e)),
                    BucketEntry::DeadEntry(_) => Ok(None),
                    _ => continue,
                };
            }
        }
        Ok(None)
    }

    /// Create a point-in-time snapshot
    pub fn snapshot(&self) -> BucketListSnapshot {
        BucketListSnapshot {
            levels: self.levels.clone(),
        }
    }
}
```

#### BucketIndex

```rust
use std::collections::BTreeMap;

/// Index for fast key lookups within a bucket
pub struct BucketIndex {
    /// Map from key hash to file offset
    offsets: BTreeMap<Hash256, u64>,
    /// Bloom filter for fast negative lookups
    bloom: BloomFilter,
}

impl BucketIndex {
    pub fn empty() -> Self {
        Self {
            offsets: BTreeMap::new(),
            bloom: BloomFilter::new(0),
        }
    }

    pub fn build(entries: &[(BucketEntry, u64)]) -> Result<Self, BucketError> {
        let mut offsets = BTreeMap::new();
        let mut bloom = BloomFilter::new(entries.len());

        for (entry, offset) in entries {
            if let Some(key) = entry.key() {
                let key_hash = hash_ledger_key(&key);
                offsets.insert(key_hash, *offset);
                bloom.insert(&key_hash);
            }
        }

        Ok(Self { offsets, bloom })
    }

    pub fn maybe_contains(&self, key: &LedgerKey) -> bool {
        let key_hash = hash_ledger_key(key);
        self.bloom.may_contain(&key_hash)
    }

    pub fn get_offset(&self, key: &LedgerKey) -> Option<u64> {
        let key_hash = hash_ledger_key(key);
        self.offsets.get(&key_hash).copied()
    }
}
```

### 3.4 Bucket Merging

```rust
/// Merge two buckets into one
pub struct BucketMerger {
    /// Shadow entries from older bucket
    keep_dead_entries: bool,
    /// Protocol version for merge behavior
    protocol_version: u32,
}

impl BucketMerger {
    /// Merge old bucket with new entries
    pub async fn merge(
        &self,
        old: &Bucket,
        new: &Bucket,
        manager: &BucketManager,
    ) -> Result<Bucket, BucketError> {
        // Both buckets are sorted by key
        // Merge like merge sort, taking newer entries when keys match

        let mut result = Vec::new();
        let mut old_iter = old.iter().peekable();
        let mut new_iter = new.iter().peekable();

        loop {
            match (old_iter.peek(), new_iter.peek()) {
                (None, None) => break,
                (Some(_), None) => {
                    // Drain remaining old entries
                    while let Some(entry) = old_iter.next() {
                        let entry = entry?;
                        if self.should_keep(&entry) {
                            result.push(entry);
                        }
                    }
                }
                (None, Some(_)) => {
                    // Drain remaining new entries
                    while let Some(entry) = new_iter.next() {
                        result.push(entry?);
                    }
                }
                (Some(old_res), Some(new_res)) => {
                    let old_entry = old_res.as_ref().map_err(|e| e.clone())?;
                    let new_entry = new_res.as_ref().map_err(|e| e.clone())?;

                    match BucketEntry::compare_keys(old_entry, new_entry) {
                        std::cmp::Ordering::Less => {
                            let entry = old_iter.next().unwrap()?;
                            if self.should_keep(&entry) {
                                result.push(entry);
                            }
                        }
                        std::cmp::Ordering::Greater => {
                            result.push(new_iter.next().unwrap()?);
                        }
                        std::cmp::Ordering::Equal => {
                            // New shadows old - skip old
                            old_iter.next();
                            result.push(new_iter.next().unwrap()?);
                        }
                    }
                }
            }
        }

        manager.create_bucket(result).await
    }

    fn should_keep(&self, entry: &BucketEntry) -> bool {
        match entry {
            BucketEntry::DeadEntry(_) => self.keep_dead_entries,
            _ => true,
        }
    }
}
```

### 3.5 Bucket Manager

```rust
use std::path::PathBuf;

/// Manages bucket lifecycle (creation, caching, cleanup)
pub struct BucketManager {
    /// Directory for bucket files
    bucket_dir: PathBuf,
    /// Cache of loaded buckets
    cache: parking_lot::RwLock<HashMap<Hash256, Arc<Bucket>>>,
    /// Temporary directory for merges
    tmp_dir: PathBuf,
}

impl BucketManager {
    pub fn new(bucket_dir: PathBuf) -> Result<Self, BucketError> {
        std::fs::create_dir_all(&bucket_dir)?;
        let tmp_dir = bucket_dir.join("tmp");
        std::fs::create_dir_all(&tmp_dir)?;

        Ok(Self {
            bucket_dir,
            cache: parking_lot::RwLock::new(HashMap::new()),
            tmp_dir,
        })
    }

    /// Create a new bucket from entries
    pub async fn create_bucket(&self, entries: Vec<BucketEntry>) -> Result<Bucket, BucketError> {
        // Sort entries by key
        let mut entries = entries;
        entries.sort_by(BucketEntry::compare_keys);

        // Serialize to XDR
        let xdr_data = serialize_bucket_entries(&entries)?;

        // Compute hash
        let hash = Hash256::hash(&xdr_data);

        // Compress
        let compressed = compress_bucket(&xdr_data)?;

        // Write to temp file, then rename
        let temp_path = self.tmp_dir.join(format!("{}.tmp", hex::encode(hash.as_bytes())));
        let final_path = self.bucket_path(&hash);

        tokio::fs::write(&temp_path, &compressed).await?;
        tokio::fs::rename(&temp_path, &final_path).await?;

        // Build index and return
        let bucket = Bucket {
            hash,
            path: final_path,
            index: BucketIndex::build(&entries.iter().map(|e| (e.clone(), 0)).collect::<Vec<_>>())?,
            entry_count: entries.len(),
            size_bytes: compressed.len() as u64,
        };

        // Cache it
        self.cache.write().insert(hash, Arc::new(bucket.clone()));

        Ok(bucket)
    }

    /// Get or load a bucket by hash
    pub async fn get_bucket(&self, hash: &Hash256) -> Result<Arc<Bucket>, BucketError> {
        // Check cache first
        if let Some(bucket) = self.cache.read().get(hash) {
            return Ok(Arc::clone(bucket));
        }

        // Load from disk
        let path = self.bucket_path(hash);
        let bucket = Arc::new(Bucket::load(path).await?);

        // Cache and return
        self.cache.write().insert(*hash, Arc::clone(&bucket));
        Ok(bucket)
    }

    fn bucket_path(&self, hash: &Hash256) -> PathBuf {
        let hex = hex::encode(hash.as_bytes());
        self.bucket_dir
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(format!("bucket-{}.xdr.gz", hex))
    }
}
```

## 4. Protocol 23 Specifics

### 4.1 Live State in Memory (CAP-0062)

Protocol 23 stores all live Soroban state in memory:
- BucketList entries for Soroban data are kept in RAM
- No disk reads for smart contract execution
- Requires careful memory management

### 4.2 Hot Archive Buckets

For archived Soroban entries:
- Separate bucket type for "hot archive"
- Used for automatic restoration (CAP-0066)

## 5. Tests to Port from stellar-core

From `src/bucket/test/`:
- `BucketListTests.cpp` - BucketList operations
- `BucketMergeTest.cpp` - Merge correctness
- `BucketIndexTests.cpp` - Index lookups
- `BucketManagerTests.cpp` - Lifecycle management

Key test scenarios:
1. Bucket creation and hashing
2. Merge with shadowing
3. Dead entry handling
4. Level spill timing
5. Concurrent access
6. Recovery from crashes

## 6. Performance Considerations

1. **Memory mapping**: Use mmap for large bucket reads
2. **Bloom filters**: Avoid disk reads for missing keys
3. **Parallel merges**: Merge multiple bucket pairs concurrently
4. **Compression**: Use fast compression (zstd or lz4 if available in pure Rust)
5. **Index caching**: Keep hot bucket indexes in memory
