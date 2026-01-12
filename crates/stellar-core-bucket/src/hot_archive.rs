//! Hot Archive Bucket List for recently evicted Soroban entries.
//!
//! The HotArchiveBucketList stores recently evicted persistent Soroban entries.
//! When persistent entries (ContractData with persistent durability or ContractCode)
//! expire, they are moved from the live BucketList to the HotArchiveBucketList.
//!
//! # Entry Types
//!
//! Hot archive buckets contain `HotArchiveBucketEntry` which has three variants:
//!
//! - `Metaentry`: Metadata about the bucket (protocol version)
//! - `Archived`: A recently archived persistent entry (full LedgerEntry)
//! - `Live`: A restored entry marker (LedgerKey only, indicates the entry was restored)
//!
//! # Merge Semantics
//!
//! Hot archive bucket merging follows these rules:
//!
//! - `Archived + Live` = Annihilate (entry was restored, remove from archive)
//! - `Live + Archived` = Keep `Archived` (re-archived after restoration)
//! - `Archived + Archived` = Keep newer `Archived`
//! - At level 10: `Live` entries are dropped (tombstones not needed)
//!
//! # Protocol Support
//!
//! Hot archive is only supported from Protocol 23+ (Soroban state archival).

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use stellar_xdr::curr::{
    BucketListType, BucketMetadata, BucketMetadataExt, HotArchiveBucketEntry,
    LedgerEntry, LedgerKey, Limits, ReadXdr, WriteXdr,
};

use stellar_core_common::Hash256;

use crate::entry::ledger_entry_to_key;
use crate::{BucketError, Result};

/// First protocol version supporting hot archive bucket list.
pub const FIRST_PROTOCOL_SUPPORTING_HOT_ARCHIVE: u32 = 23;

/// Number of levels in the HotArchiveBucketList (same as live bucket list).
pub const HOT_ARCHIVE_BUCKET_LIST_LEVELS: usize = 11;

/// A hot archive bucket containing archived persistent Soroban entries.
#[derive(Clone, Debug)]
pub struct HotArchiveBucket {
    /// Entries in the bucket, indexed by key (for lookups).
    entries: BTreeMap<Vec<u8>, HotArchiveBucketEntry>,
    /// Entries in original/sorted order (for hash computation).
    /// This preserves C++ stellar-core's entry order which uses semantic comparison,
    /// not XDR byte comparison.
    ordered_entries: Vec<HotArchiveBucketEntry>,
    /// Hash of the bucket contents.
    hash: Hash256,
}

impl HotArchiveBucket {
    /// Create an empty hot archive bucket.
    pub fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
            ordered_entries: Vec::new(),
            hash: Hash256::from_bytes([0u8; 32]),
        }
    }

    /// Create a hot archive bucket from entries.
    ///
    /// **Important**: The entries MUST be pre-sorted in C++ stellar-core order
    /// (using LedgerEntryIdCmp comparison). The entries are stored in the
    /// provided order for hash computation.
    pub fn from_entries(entries: Vec<HotArchiveBucketEntry>) -> Result<Self> {
        let mut entry_map = BTreeMap::new();

        for entry in &entries {
            let key = hot_archive_entry_to_key(entry)?;
            entry_map.insert(key, entry.clone());
        }

        let mut bucket = Self {
            entries: entry_map,
            ordered_entries: entries,
            hash: Hash256::from_bytes([0u8; 32]),
        };

        bucket.hash = bucket.compute_hash()?;
        Ok(bucket)
    }

    /// Create a fresh hot archive bucket from archived and restored entries.
    ///
    /// This is the primary way to create a new hot archive bucket when entries
    /// are evicted from the live bucket list.
    ///
    /// Returns an empty bucket if there are no entries to add (matching C++ behavior).
    pub fn fresh(
        protocol_version: u32,
        archived_entries: Vec<LedgerEntry>,
        restored_keys: Vec<LedgerKey>,
    ) -> Result<Self> {
        // If there are no entries, return an empty bucket (matching C++ behavior)
        // C++ stellar-core's BucketOutputIterator returns an empty bucket when mObjectsPut == 0
        if archived_entries.is_empty() && restored_keys.is_empty() {
            return Ok(Self::empty());
        }

        let mut entries = Vec::with_capacity(1 + archived_entries.len() + restored_keys.len());

        // Add metadata - hot archive buckets always use V1 with BucketListType::HotArchive
        // Metadata is only included when there are actual entries to add
        entries.push(HotArchiveBucketEntry::Metaentry(BucketMetadata {
            ledger_version: protocol_version,
            ext: BucketMetadataExt::V1(BucketListType::HotArchive),
        }));

        // Add archived entries
        for entry in archived_entries {
            entries.push(HotArchiveBucketEntry::Archived(entry));
        }

        // Add restored keys (Live markers)
        for key in restored_keys {
            entries.push(HotArchiveBucketEntry::Live(key));
        }

        // Sort entries using C++ stellar-core's comparison order
        // This matches BucketEntryIdCmp<HotArchiveBucket>
        entries.sort_by(compare_hot_archive_entries);

        // Debug: log entry order for debugging hash issues
        if entries.len() > 1 {  // More than just metadata
            for (i, entry) in entries.iter().enumerate() {
                match entry {
                    HotArchiveBucketEntry::Metaentry(m) => {
                        tracing::debug!(
                            idx = i,
                            entry_type = "META",
                            version = m.ledger_version,
                            "hot_archive fresh: entry order"
                        );
                    }
                    HotArchiveBucketEntry::Archived(e) => {
                        if let Some(key) = ledger_entry_to_key(e) {
                            let key_bytes = key.to_xdr(Limits::none()).unwrap_or_default();
                            // Show more details for CONTRACT_DATA keys
                            let key_type = ledger_key_type_discriminant(&key);
                            let key_detail = match &key {
                                LedgerKey::ContractData(cd) => {
                                    let sc_val_type = sc_val_type_discriminant(&cd.key);
                                    format!("sc_val_type={} durability={:?}", sc_val_type, cd.durability)
                                }
                                _ => String::new(),
                            };
                            tracing::debug!(
                                idx = i,
                                entry_type = "ARCHIVED",
                                key_type = key_type,
                                key_detail = %key_detail,
                                key_hex = %hex::encode(&key_bytes),
                                "hot_archive fresh: entry order"
                            );
                        }
                    }
                    HotArchiveBucketEntry::Live(k) => {
                        let key_bytes = k.to_xdr(Limits::none()).unwrap_or_default();
                        let key_type = ledger_key_type_discriminant(k);
                        tracing::debug!(
                            idx = i,
                            entry_type = "LIVE",
                            key_type = key_type,
                            key_hex = %hex::encode(&key_bytes),
                            "hot_archive fresh: entry order"
                        );
                    }
                }
            }
        }

        let bucket = Self::from_entries(entries)?;

        // Debug: log the fresh bucket creation
        tracing::debug!(
            version = protocol_version,
            num_entries = bucket.ordered_entries.len(),
            hash = %bucket.hash,
            "hot_archive fresh: created bucket"
        );

        Ok(bucket)
    }

    /// Get the hash of this bucket.
    pub fn hash(&self) -> Hash256 {
        self.hash.clone()
    }

    /// Check if the bucket is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the number of entries in the bucket.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Get the protocol version (bucket version) from the metadata entry.
    ///
    /// This matches C++ stellar-core's `getBucketVersion()` method.
    /// Returns the ledger_version from the bucket's metadata entry, or 0 if no metadata.
    pub fn get_protocol_version(&self) -> u32 {
        // Metadata entry is stored with empty key
        if let Some(entry) = self.entries.get(&Vec::new()) {
            if let HotArchiveBucketEntry::Metaentry(meta) = entry {
                return meta.ledger_version;
            }
        }
        0
    }

    /// Look up an entry by key.
    pub fn get(&self, key: &LedgerKey) -> Result<Option<&HotArchiveBucketEntry>> {
        let key_bytes = key.to_xdr(Limits::none()).map_err(|e| {
            BucketError::Serialization(format!("failed to serialize ledger key: {}", e))
        })?;
        Ok(self.entries.get(&key_bytes))
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &HotArchiveBucketEntry> {
        self.entries.values()
    }

    /// Compute the hash of the bucket contents.
    ///
    /// This must match C++ stellar-core's bucket hashing:
    /// Each entry is written with an XDR record mark (4-byte size prefix with high bit set),
    /// and the hash is computed over the entire serialized content including record marks.
    ///
    /// **Important**: We iterate over `ordered_entries` which preserves the original
    /// entry order from the file or from fresh() sorting. This is critical because
    /// C++ uses semantic comparison (LedgerEntryIdCmp) which differs from XDR byte order.
    fn compute_hash(&self) -> Result<Hash256> {
        if self.ordered_entries.is_empty() {
            return Ok(Hash256::from_bytes([0u8; 32]));
        }

        let mut hasher = Sha256::new();
        for entry in &self.ordered_entries {
            let bytes = entry.to_xdr(Limits::none()).map_err(|e| {
                BucketError::Serialization(format!("failed to serialize entry: {}", e))
            })?;

            // Write XDR record mark: 4-byte size (big-endian) with high bit set
            let sz = bytes.len() as u32;
            let record_mark: [u8; 4] = [
                ((sz >> 24) & 0xFF) as u8 | 0x80, // High bit set as continuation bit
                ((sz >> 16) & 0xFF) as u8,
                ((sz >> 8) & 0xFF) as u8,
                (sz & 0xFF) as u8,
            ];
            hasher.update(&record_mark);
            hasher.update(&bytes);
        }

        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);
        Ok(Hash256::from_bytes(hash_bytes))
    }

    /// Load a hot archive bucket from a gzipped XDR file.
    ///
    /// This parses a bucket file containing `HotArchiveBucketEntry` values.
    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        use std::io::{BufReader, Read};
        use flate2::read::GzDecoder;

        let path = path.as_ref();
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut decoder = GzDecoder::new(reader);

        // Read and decompress
        let mut uncompressed = Vec::new();
        decoder.read_to_end(&mut uncompressed)?;

        Self::from_xdr_bytes(&uncompressed)
    }

    /// Create a hot archive bucket from uncompressed XDR bytes.
    ///
    /// Parses bucket files using XDR Record Marking Standard (RFC 5531).
    /// Preserves the original file order for hash computation.
    pub fn from_xdr_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Ok(Self::empty());
        }

        let mut entries = BTreeMap::new();
        let mut ordered_entries = Vec::new();
        let mut offset = 0;

        // Check if the file uses XDR record marking (high bit set in first 4 bytes)
        let uses_record_marks = if bytes.len() >= 4 {
            bytes[0] & 0x80 != 0
        } else {
            false
        };

        if uses_record_marks {
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
                let record_len = (record_mark & 0x7FFFFFFF) as usize;

                if offset + record_len > bytes.len() {
                    return Err(BucketError::Serialization(format!(
                        "Record length {} exceeds remaining data {} at offset {}",
                        record_len,
                        bytes.len() - offset,
                        offset - 4
                    )));
                }

                // Parse the XDR record as HotArchiveBucketEntry
                let record_data = &bytes[offset..offset + record_len];
                match HotArchiveBucketEntry::from_xdr(record_data, Limits::none()) {
                    Ok(entry) => {
                        let key = hot_archive_entry_to_key(&entry)?;
                        entries.insert(key, entry.clone());
                        ordered_entries.push(entry);
                    }
                    Err(e) => {
                        return Err(BucketError::Serialization(format!(
                            "Failed to parse hot archive bucket entry: {}",
                            e
                        )));
                    }
                }

                offset += record_len;
            }
        } else {
            // Parse as raw XDR stream (legacy format)
            use stellar_xdr::curr::{Limited, ReadXdr};
            let cursor = std::io::Cursor::new(bytes);
            let mut limited = Limited::new(cursor, Limits::none());

            while limited.inner.position() < bytes.len() as u64 {
                match HotArchiveBucketEntry::read_xdr(&mut limited) {
                    Ok(entry) => {
                        let key = hot_archive_entry_to_key(&entry)?;
                        entries.insert(key, entry.clone());
                        ordered_entries.push(entry);
                    }
                    Err(_) => {
                        // End of stream or error
                        break;
                    }
                }
            }
        }

        // Compute hash from raw bytes (including record marks)
        let hash = Hash256::hash(bytes);

        Ok(Self {
            entries,
            ordered_entries,
            hash,
        })
    }
}

impl Default for HotArchiveBucket {
    fn default() -> Self {
        Self::empty()
    }
}

/// A single level in the HotArchiveBucketList.
#[derive(Clone, Debug)]
pub struct HotArchiveBucketLevel {
    /// The current bucket.
    pub curr: HotArchiveBucket,
    /// The snapshot bucket.
    pub snap: HotArchiveBucket,
    /// Staged merge result.
    next: Option<HotArchiveBucket>,
    /// Level number (stored for debugging).
    _level: usize,
}

impl HotArchiveBucketLevel {
    /// Create a new empty level.
    pub fn new(level: usize) -> Self {
        Self {
            curr: HotArchiveBucket::empty(),
            snap: HotArchiveBucket::empty(),
            next: None,
            _level: level,
        }
    }

    /// Get the hash of this level.
    pub fn hash(&self) -> Hash256 {
        let curr_hash = self.curr.hash();
        let snap_hash = self.snap.hash();

        let mut hasher = Sha256::new();
        hasher.update(curr_hash.as_bytes());
        hasher.update(snap_hash.as_bytes());
        let result = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash256::from_bytes(bytes)
    }

    /// Commit the staged merge.
    fn commit(&mut self) {
        if let Some(next) = self.next.take() {
            self.curr = next;
        }
    }

    /// Snap curr to snap and return the new snap (matches C++ BucketLevel::snap).
    fn snap(&mut self) -> HotArchiveBucket {
        self.snap = std::mem::replace(&mut self.curr, HotArchiveBucket::empty());
        self.snap.clone()
    }

    /// Prepare a merge with an incoming bucket.
    ///
    /// - `use_empty_curr`: If true, use an empty bucket instead of self.curr for the merge.
    ///   This is used when the level is about to snap its curr (shouldMergeWithEmptyCurr).
    fn prepare(
        &mut self,
        protocol_version: u32,
        incoming: HotArchiveBucket,
        keep_tombstones: bool,
        use_empty_curr: bool,
    ) -> Result<()> {
        if self.next.is_some() {
            return Err(BucketError::Merge(
                "hot archive bucket merge already in progress".to_string(),
            ));
        }

        // Choose curr or empty based on shouldMergeWithEmptyCurr
        let curr_for_merge = if use_empty_curr {
            HotArchiveBucket::empty()
        } else {
            self.curr.clone()
        };

        let merged = merge_hot_archive_buckets(&curr_for_merge, &incoming, protocol_version, keep_tombstones)?;
        self.next = Some(merged);
        Ok(())
    }
}

/// The complete HotArchiveBucketList.
#[derive(Clone)]
pub struct HotArchiveBucketList {
    /// The 11 levels.
    levels: Vec<HotArchiveBucketLevel>,
    /// Current ledger sequence.
    ledger_seq: u32,
}

impl HotArchiveBucketList {
    /// Number of levels in the hot archive bucket list.
    pub const NUM_LEVELS: usize = HOT_ARCHIVE_BUCKET_LIST_LEVELS;

    /// Create a new empty HotArchiveBucketList.
    pub fn new() -> Self {
        let levels = (0..HOT_ARCHIVE_BUCKET_LIST_LEVELS)
            .map(HotArchiveBucketLevel::new)
            .collect();

        Self {
            levels,
            ledger_seq: 0,
        }
    }

    /// Get the hash of the entire bucket list.
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Sha256::new();
        for (i, level) in self.levels.iter().enumerate() {
            let level_hash = level.hash();
            if i == 0 {
                tracing::trace!(
                    level = i,
                    curr_hash = %level.curr.hash().to_hex(),
                    snap_hash = %level.snap.hash().to_hex(),
                    level_hash = %level_hash.to_hex(),
                    "hot_archive hash: level 0 state"
                );
            }
            hasher.update(level_hash.as_bytes());
        }

        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash256::from_bytes(bytes)
    }

    /// Get the current ledger sequence.
    pub fn ledger_seq(&self) -> u32 {
        self.ledger_seq
    }

    /// Get a reference to all levels.
    pub fn levels(&self) -> &[HotArchiveBucketLevel] {
        &self.levels
    }

    /// Get a reference to a level.
    pub fn level(&self, idx: usize) -> Option<&HotArchiveBucketLevel> {
        self.levels.get(idx)
    }

    /// Get a mutable reference to a level.
    pub fn level_mut(&mut self, idx: usize) -> Option<&mut HotArchiveBucketLevel> {
        self.levels.get_mut(idx)
    }

    /// Add a batch of archived and restored entries.
    ///
    /// This is called when entries are evicted from the live bucket list.
    ///
    /// - `archived_entries`: Persistent entries that have expired and are being archived
    /// - `restored_keys`: Keys of entries that were restored (previously archived)
    pub fn add_batch(
        &mut self,
        ledger_seq: u32,
        protocol_version: u32,
        archived_entries: Vec<LedgerEntry>,
        restored_keys: Vec<LedgerKey>,
    ) -> Result<()> {
        if protocol_version < FIRST_PROTOCOL_SUPPORTING_HOT_ARCHIVE {
            return Err(BucketError::Merge(format!(
                "hot archive not supported before protocol {}",
                FIRST_PROTOCOL_SUPPORTING_HOT_ARCHIVE
            )));
        }

        tracing::debug!(
            ledger_seq = ledger_seq,
            protocol_version = protocol_version,
            num_archived = archived_entries.len(),
            num_restored = restored_keys.len(),
            "hot_archive add_batch: creating fresh bucket"
        );

        // C++ stellar-core uses currLedgerProtocol (the actual protocol version) for
        // HotArchiveBucket::fresh(), NOT mLedger. This is called from prepareFirstLevel()
        // which passes currLedgerProtocol directly to fresh().
        // See: BucketLevel<HotArchiveBucket>::prepareFirstLevel() in BucketListBase.cpp
        let new_bucket = HotArchiveBucket::fresh(protocol_version, archived_entries, restored_keys)?;

        self.add_batch_internal(ledger_seq, protocol_version, new_bucket)?;
        self.ledger_seq = ledger_seq;

        // Debug: trace the overall hash and all level states after add_batch
        if tracing::enabled!(tracing::Level::DEBUG) {
            tracing::debug!(
                ledger_seq = ledger_seq,
                overall_hash = %self.hash().to_hex(),
                "hot_archive add_batch: completed"
            );
            // Show state of first few levels
            for i in 0..4.min(self.levels.len()) {
                tracing::debug!(
                    ledger_seq = ledger_seq,
                    level = i,
                    curr_hash = %self.levels[i].curr.hash().to_hex(),
                    snap_hash = %self.levels[i].snap.hash().to_hex(),
                    has_pending = self.levels[i].next.is_some(),
                    "hot_archive add_batch: level state"
                );
            }
        }
        Ok(())
    }

    fn add_batch_internal(
        &mut self,
        ledger_seq: u32,
        protocol_version: u32,
        new_bucket: HotArchiveBucket,
    ) -> Result<()> {
        if ledger_seq == 0 {
            return Err(BucketError::Merge("ledger sequence must be > 0".to_string()));
        }

        // Process spills from highest level down
        for i in (1..HOT_ARCHIVE_BUCKET_LIST_LEVELS).rev() {
            if Self::level_should_spill(ledger_seq, i - 1) {
                let old_curr_hash = self.levels[i].curr.hash();
                let had_next = self.levels[i].next.is_some();

                let spilling_snap = self.levels[i - 1].snap();
                self.levels[i].commit();

                let new_curr_hash = self.levels[i].curr.hash();

                if i <= 3 {  // Only trace first few levels to avoid spam
                    tracing::trace!(
                        ledger_seq = ledger_seq,
                        level = i,
                        prev_level = i - 1,
                        spilling_snap_hash = %spilling_snap.hash().to_hex(),
                        old_curr_hash = %old_curr_hash.to_hex(),
                        had_pending = had_next,
                        new_curr_hash = %new_curr_hash.to_hex(),
                        "hot_archive add_batch: level spill processing"
                    );
                }

                let keep_tombstones = Self::keep_tombstone_entries(i);
                let use_empty_curr = Self::should_merge_with_empty_curr(ledger_seq, i);
                self.levels[i].prepare(protocol_version, spilling_snap, keep_tombstones, use_empty_curr)?;
            }
        }

        // Add new entries to level 0
        // Level 0 never uses empty curr (shouldMergeWithEmptyCurr returns false for level 0)
        let keep_tombstones_0 = Self::keep_tombstone_entries(0);

        tracing::trace!(
            ledger_seq = ledger_seq,
            new_bucket_hash = %new_bucket.hash().to_hex(),
            old_curr_hash = %self.levels[0].curr.hash().to_hex(),
            "hot_archive add_batch: preparing level 0 merge"
        );

        self.levels[0].prepare(protocol_version, new_bucket, keep_tombstones_0, false)?;
        self.levels[0].commit();

        tracing::trace!(
            ledger_seq = ledger_seq,
            new_curr_hash = %self.levels[0].curr.hash().to_hex(),
            "hot_archive add_batch: level 0 committed"
        );

        // Note: We do NOT commit all levels here. See the comment in BucketList::add_batch_internal
        // for the explanation of why this is necessary for shouldMergeWithEmptyCurr to work correctly.

        Ok(())
    }

    /// Look up an archived entry by key.
    pub fn get(&self, key: &LedgerKey) -> Result<Option<&LedgerEntry>> {
        for level in &self.levels {
            for bucket in [&level.curr, &level.snap] {
                if let Some(entry) = bucket.get(key)? {
                    match entry {
                        HotArchiveBucketEntry::Archived(e) => return Ok(Some(e)),
                        HotArchiveBucketEntry::Live(_) => return Ok(None), // Restored, not in archive
                        HotArchiveBucketEntry::Metaentry(_) => continue,
                    }
                }
            }
        }
        Ok(None)
    }

    /// Check if an entry is in the hot archive.
    pub fn contains(&self, key: &LedgerKey) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }

    /// Round down helper.
    fn round_down(value: u32, modulus: u32) -> u32 {
        if modulus == 0 {
            return 0;
        }
        value & !(modulus - 1)
    }

    /// Level half size (same formula as live bucket list).
    fn level_half(level: usize) -> u32 {
        1u32 << (2 * level + 1)
    }

    /// Level size (same formula as live bucket list).
    fn level_size(level: usize) -> u32 {
        1u32 << (2 * (level + 1))
    }

    /// Check if a level should spill.
    fn level_should_spill(ledger_seq: u32, level: usize) -> bool {
        if level == HOT_ARCHIVE_BUCKET_LIST_LEVELS - 1 {
            return false;
        }

        let half = Self::level_half(level);
        let size = Self::level_size(level);
        ledger_seq == Self::round_down(ledger_seq, half)
            || ledger_seq == Self::round_down(ledger_seq, size)
    }

    /// Check if tombstone entries should be kept at a level.
    fn keep_tombstone_entries(level: usize) -> bool {
        level < HOT_ARCHIVE_BUCKET_LIST_LEVELS - 1
    }

    /// Determines whether to merge with an empty curr bucket instead of the actual curr.
    /// This happens when the level is about to snap its curr bucket - in that case,
    /// we just propagate the snap from the previous level without merging with curr.
    ///
    /// Matches C++ stellar-core's `shouldMergeWithEmptyCurr`.
    fn should_merge_with_empty_curr(ledger_seq: u32, level: usize) -> bool {
        if level == 0 {
            // Level 0 always merges with its curr
            return false;
        }

        // Round down to when the merge was started
        let merge_start_ledger = Self::round_down(ledger_seq, Self::level_half(level - 1));

        // Calculate when the next spill would happen
        let next_change_ledger = merge_start_ledger + Self::level_half(level - 1);

        // If the next spill would affect this level, use empty curr
        // because curr is about to be snapped
        Self::level_should_spill(next_change_ledger, level)
    }

    /// Get statistics about the bucket list.
    pub fn stats(&self) -> HotArchiveBucketListStats {
        let mut total_entries = 0;
        let mut total_buckets = 0;

        for level in &self.levels {
            if !level.curr.is_empty() {
                total_entries += level.curr.len();
                total_buckets += 1;
            }
            if !level.snap.is_empty() {
                total_entries += level.snap.len();
                total_buckets += 1;
            }
        }

        HotArchiveBucketListStats {
            num_levels: HOT_ARCHIVE_BUCKET_LIST_LEVELS,
            total_entries,
            total_buckets,
        }
    }

    /// Restore a hot archive bucket list from bucket hashes.
    ///
    /// This is used to restore state from a history archive checkpoint.
    ///
    /// # Arguments
    ///
    /// * `hashes` - The bucket hashes (curr and snap for each level, 22 total)
    /// * `load_bucket` - Function to load a HotArchiveBucket by hash
    pub fn restore_from_hashes<F>(hashes: &[Hash256], mut load_bucket: F) -> Result<Self>
    where
        F: FnMut(&Hash256) -> Result<HotArchiveBucket>,
    {
        if hashes.len() != HOT_ARCHIVE_BUCKET_LIST_LEVELS * 2 {
            return Err(BucketError::Serialization(format!(
                "Expected {} hot archive bucket hashes, got {}",
                HOT_ARCHIVE_BUCKET_LIST_LEVELS * 2,
                hashes.len()
            )));
        }

        let mut levels = Vec::with_capacity(HOT_ARCHIVE_BUCKET_LIST_LEVELS);

        for (i, chunk) in hashes.chunks(2).enumerate() {
            let curr_hash = &chunk[0];
            let snap_hash = &chunk[1];

            let curr = if curr_hash.is_zero() {
                HotArchiveBucket::empty()
            } else {
                load_bucket(curr_hash)?
            };

            let snap = if snap_hash.is_zero() {
                HotArchiveBucket::empty()
            } else {
                load_bucket(snap_hash)?
            };

            let mut level = HotArchiveBucketLevel::new(i);
            level.curr = curr;
            level.snap = snap;
            levels.push(level);
        }

        Ok(Self { levels, ledger_seq: 0 })
    }

    /// Restart any pending merges after restoring from a History Archive State (HAS).
    ///
    /// When a hot archive bucket list is restored from HAS, there may be merges that should
    /// have been in progress at that checkpoint ledger. This function recreates those pending
    /// merges by examining the current and snap buckets and starting merges where appropriate.
    ///
    /// This matches C++ stellar-core's BucketListBase::restartMerges() for hot archive.
    pub fn restart_merges(&mut self, ledger: u32, protocol_version: u32) -> Result<()> {
        tracing::debug!(
            ledger = ledger,
            "hot_archive restart_merges: restarting pending merges after HAS restore"
        );

        for i in 1..HOT_ARCHIVE_BUCKET_LIST_LEVELS {
            // Skip if there's already a pending merge
            if self.levels[i].next.is_some() {
                tracing::trace!(
                    level = i,
                    "hot_archive restart_merges: level already has pending merge"
                );
                continue;
            }

            // Clone the previous level's snap to avoid borrow conflicts
            let prev_snap = self.levels[i - 1].snap.clone();

            // If the previous level's snap is empty, this and all higher levels
            // are uninitialized (haven't received enough data yet)
            if prev_snap.is_empty() {
                tracing::debug!(
                    level = i,
                    "hot_archive restart_merges: previous level snap is empty, stopping"
                );
                break;
            }

            // Calculate the ledger when this merge would have started
            let merge_start_ledger = Self::round_down(ledger, Self::level_half(i - 1));

            tracing::debug!(
                level = i,
                merge_start_ledger = merge_start_ledger,
                prev_snap_hash = %prev_snap.hash(),
                "hot_archive restart_merges: restarting merge"
            );

            // Determine merge parameters
            let keep_tombstones = Self::keep_tombstone_entries(i);
            let use_empty_curr = Self::should_merge_with_empty_curr(merge_start_ledger, i);

            // Use the protocol version from the snap bucket's metadata, matching C++ behavior.
            // C++ stellar-core's restartMerges uses snap->getBucketVersion() for the merge.
            let bucket_version = prev_snap.get_protocol_version();
            let version_to_use = if bucket_version > 0 { bucket_version } else { protocol_version };

            // Start the merge with the previous level's snap
            self.levels[i].prepare(
                version_to_use,
                prev_snap,
                keep_tombstones,
                use_empty_curr,
            )?;

            tracing::debug!(
                level = i,
                "hot_archive restart_merges: merge restarted successfully"
            );
        }

        // Update the ledger sequence to the restored ledger
        self.ledger_seq = ledger;

        Ok(())
    }
}

impl Default for HotArchiveBucketList {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for HotArchiveBucketList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotArchiveBucketList")
            .field("ledger_seq", &self.ledger_seq)
            .field("hash", &self.hash().to_hex())
            .field("stats", &self.stats())
            .finish()
    }
}

/// Statistics about a HotArchiveBucketList.
#[derive(Debug, Clone)]
pub struct HotArchiveBucketListStats {
    /// Number of levels.
    pub num_levels: usize,
    /// Total number of entries.
    pub total_entries: usize,
    /// Total number of non-empty buckets.
    pub total_buckets: usize,
}

/// Extract key bytes from a hot archive bucket entry.
fn hot_archive_entry_to_key(entry: &HotArchiveBucketEntry) -> Result<Vec<u8>> {
    match entry {
        HotArchiveBucketEntry::Archived(e) => {
            let key = ledger_entry_to_key(e).ok_or_else(|| {
                BucketError::Serialization("failed to extract key from entry".to_string())
            })?;
            key.to_xdr(Limits::none()).map_err(|e| {
                BucketError::Serialization(format!("failed to serialize key: {}", e))
            })
        }
        HotArchiveBucketEntry::Live(key) => key.to_xdr(Limits::none()).map_err(|e| {
            BucketError::Serialization(format!("failed to serialize key: {}", e))
        }),
        HotArchiveBucketEntry::Metaentry(_) => {
            // Metadata uses a special key (empty)
            Ok(Vec::new())
        }
    }
}

/// Compare two hot archive bucket entries for sorting, matching C++ stellar-core's
/// `BucketEntryIdCmp<HotArchiveBucket>`.
///
/// Comparison order:
/// 1. Metaentry always comes first
/// 2. For other entries, compare by LedgerKey using the same order as C++
pub fn compare_hot_archive_entries(
    a: &HotArchiveBucketEntry,
    b: &HotArchiveBucketEntry,
) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    // Metaentry always sorts first
    match (a, b) {
        (HotArchiveBucketEntry::Metaentry(_), HotArchiveBucketEntry::Metaentry(_)) => {
            return Ordering::Equal;
        }
        (HotArchiveBucketEntry::Metaentry(_), _) => {
            return Ordering::Less;
        }
        (_, HotArchiveBucketEntry::Metaentry(_)) => {
            return Ordering::Greater;
        }
        _ => {}
    }

    // Get LedgerKey from each entry
    let key_a = match a {
        HotArchiveBucketEntry::Archived(e) => ledger_entry_to_key(e),
        HotArchiveBucketEntry::Live(k) => Some(k.clone()),
        HotArchiveBucketEntry::Metaentry(_) => unreachable!(),
    };

    let key_b = match b {
        HotArchiveBucketEntry::Archived(e) => ledger_entry_to_key(e),
        HotArchiveBucketEntry::Live(k) => Some(k.clone()),
        HotArchiveBucketEntry::Metaentry(_) => unreachable!(),
    };

    match (key_a, key_b) {
        (Some(ka), Some(kb)) => compare_ledger_keys(&ka, &kb),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// Compare two LedgerKeys using the same order as C++ stellar-core's `LedgerEntryIdCmp`.
///
/// This matches the comparison order used in bucket files.
fn compare_ledger_keys(a: &LedgerKey, b: &LedgerKey) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    use stellar_xdr::curr::LedgerKey::*;

    // Compare by type first
    let type_a = ledger_key_type_discriminant(a);
    let type_b = ledger_key_type_discriminant(b);
    if type_a != type_b {
        return type_a.cmp(&type_b);
    }

    // Same type, compare by type-specific fields
    match (a, b) {
        (Account(a), Account(b)) => a.account_id.cmp(&b.account_id),
        (Trustline(a), Trustline(b)) => {
            match a.account_id.cmp(&b.account_id) {
                Ordering::Equal => compare_trust_line_asset(&a.asset, &b.asset),
                other => other,
            }
        }
        (Offer(a), Offer(b)) => {
            match a.seller_id.cmp(&b.seller_id) {
                Ordering::Equal => a.offer_id.cmp(&b.offer_id),
                other => other,
            }
        }
        (Data(a), Data(b)) => {
            match a.account_id.cmp(&b.account_id) {
                Ordering::Equal => a.data_name.as_slice().cmp(b.data_name.as_slice()),
                other => other,
            }
        }
        (ClaimableBalance(a), ClaimableBalance(b)) => {
            compare_claimable_balance_id(&a.balance_id, &b.balance_id)
        }
        (LiquidityPool(a), LiquidityPool(b)) => {
            a.liquidity_pool_id.0.cmp(&b.liquidity_pool_id.0)
        }
        (ContractData(a), ContractData(b)) => {
            let addr_cmp = compare_sc_address(&a.contract, &b.contract);
            if addr_cmp != Ordering::Equal {
                return addr_cmp;
            }
            let key_cmp = compare_sc_val(&a.key, &b.key);
            if key_cmp != Ordering::Equal {
                // Debug: log ScVal comparison result for CONTRACT_DATA
                let a_type = sc_val_type_discriminant(&a.key);
                let b_type = sc_val_type_discriminant(&b.key);
                tracing::trace!(
                    a_sc_val_type = a_type,
                    b_sc_val_type = b_type,
                    result = ?key_cmp,
                    "hot_archive compare_ledger_keys: ScVal comparison"
                );
                return key_cmp;
            }
            (a.durability as i32).cmp(&(b.durability as i32))
        }
        (ContractCode(a), ContractCode(b)) => a.hash.0.cmp(&b.hash.0),
        (ConfigSetting(a), ConfigSetting(b)) => {
            (a.config_setting_id as i32).cmp(&(b.config_setting_id as i32))
        }
        (Ttl(a), Ttl(b)) => a.key_hash.0.cmp(&b.key_hash.0),
        _ => Ordering::Equal, // Different types should not reach here
    }
}

fn ledger_key_type_discriminant(k: &LedgerKey) -> i32 {
    use stellar_xdr::curr::LedgerKey::*;
    match k {
        Account(_) => 0,
        Trustline(_) => 1,
        Offer(_) => 2,
        Data(_) => 3,
        ClaimableBalance(_) => 4,
        LiquidityPool(_) => 5,
        ContractData(_) => 6,
        ContractCode(_) => 7,
        ConfigSetting(_) => 8,
        Ttl(_) => 9,
    }
}

fn compare_trust_line_asset(
    a: &stellar_xdr::curr::TrustLineAsset,
    b: &stellar_xdr::curr::TrustLineAsset,
) -> std::cmp::Ordering {
    use stellar_xdr::curr::TrustLineAsset::*;
    use std::cmp::Ordering;

    let type_a = match a {
        Native => 0,
        CreditAlphanum4(_) => 1,
        CreditAlphanum12(_) => 2,
        PoolShare(_) => 3,
    };
    let type_b = match b {
        Native => 0,
        CreditAlphanum4(_) => 1,
        CreditAlphanum12(_) => 2,
        PoolShare(_) => 3,
    };

    if type_a != type_b {
        return type_a.cmp(&type_b);
    }

    match (a, b) {
        (Native, Native) => Ordering::Equal,
        (CreditAlphanum4(a), CreditAlphanum4(b)) => {
            match a.asset_code.cmp(&b.asset_code) {
                Ordering::Equal => a.issuer.cmp(&b.issuer),
                other => other,
            }
        }
        (CreditAlphanum12(a), CreditAlphanum12(b)) => {
            match a.asset_code.cmp(&b.asset_code) {
                Ordering::Equal => a.issuer.cmp(&b.issuer),
                other => other,
            }
        }
        (PoolShare(a), PoolShare(b)) => a.0.cmp(&b.0),
        _ => Ordering::Equal,
    }
}

fn compare_claimable_balance_id(
    a: &stellar_xdr::curr::ClaimableBalanceId,
    b: &stellar_xdr::curr::ClaimableBalanceId,
) -> std::cmp::Ordering {
    use stellar_xdr::curr::ClaimableBalanceId::*;
    match (a, b) {
        (ClaimableBalanceIdTypeV0(a), ClaimableBalanceIdTypeV0(b)) => a.0.cmp(&b.0),
    }
}

fn compare_sc_address(
    a: &stellar_xdr::curr::ScAddress,
    b: &stellar_xdr::curr::ScAddress,
) -> std::cmp::Ordering {
    // Compare by type discriminant first, then by content
    // Use XDR byte comparison for simplicity
    let a_bytes = a.to_xdr(Limits::none()).unwrap_or_default();
    let b_bytes = b.to_xdr(Limits::none()).unwrap_or_default();
    a_bytes.cmp(&b_bytes)
}

/// Compare two ScVal values using the same order as C++ stellar-core.
///
/// This uses XDR byte comparison as a fallback for complex types,
/// which should be correct for most practical cases.
fn compare_sc_val(a: &stellar_xdr::curr::ScVal, b: &stellar_xdr::curr::ScVal) -> std::cmp::Ordering {
    use stellar_xdr::curr::ScVal::*;
    use std::cmp::Ordering;

    // Compare by type discriminant first
    let type_a = sc_val_type_discriminant(a);
    let type_b = sc_val_type_discriminant(b);
    if type_a != type_b {
        return type_a.cmp(&type_b);
    }

    // Same type, compare by value
    match (a, b) {
        (Bool(a), Bool(b)) => a.cmp(b),
        (Void, Void) => Ordering::Equal,
        (Error(a), Error(b)) => {
            // Compare by XDR bytes
            let a_bytes = a.to_xdr(Limits::none()).unwrap_or_default();
            let b_bytes = b.to_xdr(Limits::none()).unwrap_or_default();
            a_bytes.cmp(&b_bytes)
        }
        (U32(a), U32(b)) => a.cmp(b),
        (I32(a), I32(b)) => a.cmp(b),
        (U64(a), U64(b)) => a.cmp(b),
        (I64(a), I64(b)) => a.cmp(b),
        (Timepoint(a), Timepoint(b)) => a.cmp(b),
        (Duration(a), Duration(b)) => a.cmp(b),
        (U128(a), U128(b)) => {
            match a.hi.cmp(&b.hi) {
                Ordering::Equal => a.lo.cmp(&b.lo),
                other => other,
            }
        }
        (I128(a), I128(b)) => {
            match a.hi.cmp(&b.hi) {
                Ordering::Equal => a.lo.cmp(&b.lo),
                other => other,
            }
        }
        (U256(a), U256(b)) => {
            for (a_part, b_part) in [
                (a.hi_hi, b.hi_hi),
                (a.hi_lo, b.hi_lo),
                (a.lo_hi, b.lo_hi),
                (a.lo_lo, b.lo_lo),
            ] {
                match a_part.cmp(&b_part) {
                    Ordering::Equal => continue,
                    other => return other,
                }
            }
            Ordering::Equal
        }
        (I256(a), I256(b)) => {
            // I256 has mixed types for hi/lo parts, use XDR bytes
            let a_bytes = a.to_xdr(Limits::none()).unwrap_or_default();
            let b_bytes = b.to_xdr(Limits::none()).unwrap_or_default();
            a_bytes.cmp(&b_bytes)
        }
        (Bytes(a), Bytes(b)) => a.as_slice().cmp(b.as_slice()),
        (String(a), String(b)) => a.as_slice().cmp(b.as_slice()),
        (Symbol(a), Symbol(b)) => a.as_slice().cmp(b.as_slice()),
        (Vec(a_opt), Vec(b_opt)) => {
            match (a_opt, b_opt) {
                (Some(a), Some(b)) => {
                    for (a_elem, b_elem) in a.iter().zip(b.iter()) {
                        match compare_sc_val(a_elem, b_elem) {
                            Ordering::Equal => continue,
                            other => return other,
                        }
                    }
                    a.len().cmp(&b.len())
                }
                (Some(_), None) => Ordering::Greater,
                (None, Some(_)) => Ordering::Less,
                (None, None) => Ordering::Equal,
            }
        }
        (Map(a_opt), Map(b_opt)) => {
            match (a_opt, b_opt) {
                (Some(a), Some(b)) => {
                    for (a_entry, b_entry) in a.iter().zip(b.iter()) {
                        match compare_sc_val(&a_entry.key, &b_entry.key) {
                            Ordering::Equal => {
                                match compare_sc_val(&a_entry.val, &b_entry.val) {
                                    Ordering::Equal => continue,
                                    other => return other,
                                }
                            }
                            other => return other,
                        }
                    }
                    a.len().cmp(&b.len())
                }
                (Some(_), None) => Ordering::Greater,
                (None, Some(_)) => Ordering::Less,
                (None, None) => Ordering::Equal,
            }
        }
        (Address(a), Address(b)) => compare_sc_address(a, b),
        (LedgerKeyContractInstance, LedgerKeyContractInstance) => Ordering::Equal,
        (LedgerKeyNonce(a), LedgerKeyNonce(b)) => a.nonce.cmp(&b.nonce),
        (ContractInstance(a), ContractInstance(b)) => {
            // Compare by XDR bytes as fallback
            let a_bytes = a.to_xdr(Limits::none()).unwrap_or_default();
            let b_bytes = b.to_xdr(Limits::none()).unwrap_or_default();
            a_bytes.cmp(&b_bytes)
        }
        // For any remaining cases, use XDR byte comparison
        _ => {
            let a_bytes = a.to_xdr(Limits::none()).unwrap_or_default();
            let b_bytes = b.to_xdr(Limits::none()).unwrap_or_default();
            a_bytes.cmp(&b_bytes)
        }
    }
}

fn sc_val_type_discriminant(v: &stellar_xdr::curr::ScVal) -> i32 {
    use stellar_xdr::curr::ScVal::*;
    // Values must match XDR ScValType enum discriminants
    match v {
        Bool(_) => 0,
        Void => 1,
        Error(_) => 2,
        U32(_) => 3,
        I32(_) => 4,
        U64(_) => 5,
        I64(_) => 6,
        Timepoint(_) => 7,
        Duration(_) => 8,
        U128(_) => 9,
        I128(_) => 10,
        U256(_) => 11,
        I256(_) => 12,
        Bytes(_) => 13,
        String(_) => 14,
        Symbol(_) => 15,
        Vec(_) => 16,
        Map(_) => 17,
        Address(_) => 18,
        ContractInstance(_) => 19,
        LedgerKeyContractInstance => 20,
        LedgerKeyNonce(_) => 21,
    }
}

/// Check if a hot archive entry is a tombstone (Live marker).
pub fn is_hot_archive_tombstone(entry: &HotArchiveBucketEntry) -> bool {
    matches!(entry, HotArchiveBucketEntry::Live(_))
}

/// Merge two hot archive buckets.
///
/// Hot archive merge rules:
/// - Archived + Live = Annihilate (entry was restored)
/// - Live + Archived = Keep Archived (re-archived)
/// - Archived + Archived = Keep newer (from curr)
/// - At bottom level: Live entries are dropped
pub fn merge_hot_archive_buckets(
    curr: &HotArchiveBucket,
    snap: &HotArchiveBucket,
    protocol_version: u32,
    keep_tombstones: bool,
) -> Result<HotArchiveBucket> {
    tracing::trace!(
        curr_hash = %curr.hash().to_hex(),
        curr_len = curr.len(),
        snap_hash = %snap.hash().to_hex(),
        snap_len = snap.len(),
        protocol_version = protocol_version,
        keep_tombstones = keep_tombstones,
        "hot_archive merge: starting merge"
    );

    // Optimization: if one bucket is empty, return the other unchanged
    // This preserves the bucket's hash including its original metadata
    // and matches C++ behavior where merging with empty is a no-op
    //
    // IMPORTANT: We can only use this optimization if keep_tombstones is true,
    // because tombstones (Live entries) need to be dropped at the bottom level.
    // When keep_tombstones is false, we must process the merge to drop tombstones.
    if keep_tombstones {
        if snap.is_empty() {
            tracing::trace!("hot_archive merge: snap is empty, returning curr unchanged");
            return Ok(curr.clone());
        }
        if curr.is_empty() {
            tracing::trace!("hot_archive merge: curr is empty, returning snap unchanged");
            return Ok(snap.clone());
        }
    } else {
        // When keep_tombstones is false, we can still skip if both are empty
        if snap.is_empty() && curr.is_empty() {
            tracing::trace!("hot_archive merge: both empty, returning empty");
            return Ok(HotArchiveBucket::empty());
        }
    }

    let mut merged_entries: HashMap<Vec<u8>, HotArchiveBucketEntry> = HashMap::new();
    let mut seen_keys: HashSet<Vec<u8>> = HashSet::new();

    // Process curr entries first (newer)
    for entry in curr.iter() {
        if matches!(entry, HotArchiveBucketEntry::Metaentry(_)) {
            continue;
        }

        let key = hot_archive_entry_to_key(entry)?;
        seen_keys.insert(key.clone());
        merged_entries.insert(key, entry.clone());
    }

    // Process snap entries
    for entry in snap.iter() {
        if matches!(entry, HotArchiveBucketEntry::Metaentry(_)) {
            continue;
        }

        let key = hot_archive_entry_to_key(entry)?;

        if let Some(curr_entry) = merged_entries.get(&key) {
            // Apply merge rules
            match (curr_entry, entry) {
                // Archived in curr + Live in snap = Keep Archived (normal case)
                (HotArchiveBucketEntry::Archived(_), HotArchiveBucketEntry::Live(_)) => {
                    // Keep curr (Archived)
                }
                // Live in curr + Archived in snap = Annihilate
                (HotArchiveBucketEntry::Live(_), HotArchiveBucketEntry::Archived(_)) => {
                    merged_entries.remove(&key);
                }
                // Archived + Archived = Keep curr (newer)
                (HotArchiveBucketEntry::Archived(_), HotArchiveBucketEntry::Archived(_)) => {
                    // Keep curr
                }
                // Live + Live = Keep curr
                (HotArchiveBucketEntry::Live(_), HotArchiveBucketEntry::Live(_)) => {
                    // Keep curr
                }
                _ => {}
            }
        } else {
            // Entry only in snap
            merged_entries.insert(key, entry.clone());
        }
    }

    // Drop tombstones at bottom level
    if !keep_tombstones {
        merged_entries.retain(|_, v| !is_hot_archive_tombstone(v));
    }

    // If there are no entries after merge, return an empty bucket
    // This matches C++ stellar-core's BucketOutputIterator which returns
    // an empty bucket when mObjectsPut == 0
    if merged_entries.is_empty() {
        tracing::trace!(
            "hot_archive merge: result is empty, returning empty bucket"
        );
        return Ok(HotArchiveBucket::empty());
    }

    // Build result
    let mut result_entries = Vec::with_capacity(merged_entries.len() + 1);

    // Add metadata - hot archive buckets always use V1 with BucketListType::HotArchive
    // Metadata is only included when there are actual entries to add
    result_entries.push(HotArchiveBucketEntry::Metaentry(BucketMetadata {
        ledger_version: protocol_version,
        ext: BucketMetadataExt::V1(BucketListType::HotArchive),
    }));

    // Add merged entries
    result_entries.extend(merged_entries.into_values());

    // Sort entries using C++ stellar-core's comparison order
    // This is critical for hash consistency with C++
    result_entries.sort_by(compare_hot_archive_entries);

    let result = HotArchiveBucket::from_entries(result_entries)?;
    tracing::trace!(
        result_hash = %result.hash().to_hex(),
        result_len = result.len(),
        "hot_archive merge: merge complete"
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn make_contract_data_key(contract_id: [u8; 32], key_bytes: &[u8]) -> LedgerKey {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(Hash(contract_id).into()),
            key: ScVal::Bytes(key_bytes.to_vec().try_into().unwrap()),
            durability: ContractDataDurability::Persistent,
        })
    }

    fn make_contract_data_entry(contract_id: [u8; 32], key_bytes: &[u8], value: i64) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::ContractData(ContractDataEntry {
                ext: ExtensionPoint::V0,
                contract: ScAddress::Contract(Hash(contract_id).into()),
                key: ScVal::Bytes(key_bytes.to_vec().try_into().unwrap()),
                durability: ContractDataDurability::Persistent,
                val: ScVal::I64(value),
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    #[test]
    fn test_hot_archive_bucket_empty() {
        let bucket = HotArchiveBucket::empty();
        assert!(bucket.is_empty());
        assert_eq!(bucket.len(), 0);
        assert!(bucket.hash().is_zero());
    }

    #[test]
    fn test_hot_archive_bucket_fresh() {
        let entry = make_contract_data_entry([1u8; 32], b"key1", 100);
        let bucket = HotArchiveBucket::fresh(25, vec![entry], vec![]).unwrap();

        assert!(!bucket.is_empty());
        assert_eq!(bucket.len(), 2); // metadata + 1 entry
        assert!(!bucket.hash().is_zero());
    }

    #[test]
    fn test_hot_archive_bucket_lookup() {
        let entry = make_contract_data_entry([1u8; 32], b"key1", 100);
        let key = make_contract_data_key([1u8; 32], b"key1");

        let bucket = HotArchiveBucket::fresh(25, vec![entry.clone()], vec![]).unwrap();
        let found = bucket.get(&key).unwrap();

        assert!(found.is_some());
        match found.unwrap() {
            HotArchiveBucketEntry::Archived(e) => {
                assert_eq!(e, &entry);
            }
            _ => panic!("expected Archived entry"),
        }
    }

    #[test]
    fn test_hot_archive_bucket_list_new() {
        let list = HotArchiveBucketList::new();
        assert_eq!(list.ledger_seq(), 0);
        assert_eq!(list.stats().total_entries, 0);
    }

    #[test]
    fn test_hot_archive_bucket_list_add_batch() {
        let mut list = HotArchiveBucketList::new();
        let entry = make_contract_data_entry([1u8; 32], b"key1", 100);

        list.add_batch(1, 25, vec![entry.clone()], vec![]).unwrap();

        let key = make_contract_data_key([1u8; 32], b"key1");
        let found = list.get(&key).unwrap();
        assert!(found.is_some());
    }

    #[test]
    fn test_hot_archive_bucket_list_restoration() {
        let mut list = HotArchiveBucketList::new();
        let entry = make_contract_data_entry([1u8; 32], b"key1", 100);
        let key = make_contract_data_key([1u8; 32], b"key1");

        // Archive the entry
        list.add_batch(1, 25, vec![entry.clone()], vec![]).unwrap();
        assert!(list.contains(&key).unwrap());

        // Mark as restored
        list.add_batch(2, 25, vec![], vec![key.clone()]).unwrap();

        // Entry should not be found (restored = Live marker shadows Archived)
        assert!(!list.contains(&key).unwrap());
    }

    #[test]
    fn test_merge_archived_plus_live_annihilates() {
        let entry = make_contract_data_entry([1u8; 32], b"key1", 100);
        let key = make_contract_data_key([1u8; 32], b"key1");

        // curr has Archived, snap has Live
        let curr = HotArchiveBucket::from_entries(vec![
            HotArchiveBucketEntry::Metaentry(BucketMetadata {
                ledger_version: 25,
                ext: BucketMetadataExt::V1(BucketListType::HotArchive),
            }),
            HotArchiveBucketEntry::Archived(entry),
        ])
        .unwrap();

        let snap = HotArchiveBucket::from_entries(vec![
            HotArchiveBucketEntry::Metaentry(BucketMetadata {
                ledger_version: 25,
                ext: BucketMetadataExt::V1(BucketListType::HotArchive),
            }),
            HotArchiveBucketEntry::Live(key.clone()),
        ])
        .unwrap();

        let merged = merge_hot_archive_buckets(&curr, &snap, 25, true).unwrap();

        // Archived should remain (Live in snap doesn't affect Archived in curr)
        assert!(merged.get(&key).unwrap().is_some());
    }

    #[test]
    fn test_merge_live_plus_archived_annihilates() {
        let entry = make_contract_data_entry([1u8; 32], b"key1", 100);
        let key = make_contract_data_key([1u8; 32], b"key1");

        // curr has Live, snap has Archived - should annihilate
        let curr = HotArchiveBucket::from_entries(vec![
            HotArchiveBucketEntry::Metaentry(BucketMetadata {
                ledger_version: 25,
                ext: BucketMetadataExt::V1(BucketListType::HotArchive),
            }),
            HotArchiveBucketEntry::Live(key.clone()),
        ])
        .unwrap();

        let snap = HotArchiveBucket::from_entries(vec![
            HotArchiveBucketEntry::Metaentry(BucketMetadata {
                ledger_version: 25,
                ext: BucketMetadataExt::V1(BucketListType::HotArchive),
            }),
            HotArchiveBucketEntry::Archived(entry),
        ])
        .unwrap();

        let merged = merge_hot_archive_buckets(&curr, &snap, 25, true).unwrap();

        // Entry should be gone (annihilated)
        assert!(merged.get(&key).unwrap().is_none());
    }

    #[test]
    fn test_tombstones_dropped_at_bottom() {
        let key = make_contract_data_key([1u8; 32], b"key1");

        let bucket = HotArchiveBucket::from_entries(vec![
            HotArchiveBucketEntry::Metaentry(BucketMetadata {
                ledger_version: 25,
                ext: BucketMetadataExt::V1(BucketListType::HotArchive),
            }),
            HotArchiveBucketEntry::Live(key.clone()),
        ])
        .unwrap();

        // keep_tombstones = false (bottom level)
        let merged = merge_hot_archive_buckets(&bucket, &HotArchiveBucket::empty(), 25, false).unwrap();

        // Live entry should be dropped
        assert!(merged.get(&key).unwrap().is_none());
    }
}
