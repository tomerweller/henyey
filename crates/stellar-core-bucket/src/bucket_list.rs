//! BucketList implementation - the full hierarchical bucket structure.
//!
//! The BucketList is Stellar's core data structure for storing ledger state.
//! It consists of 11 levels (0-10), where each level contains two buckets:
//!
//! - `curr`: The current bucket being filled with new entries
//! - `snap`: The snapshot bucket from the previous spill
//!
//! # Architecture
//!
//! The bucket list is a log-structured merge tree (LSM tree) optimized for
//! Stellar's append-heavy workload. Lower levels update more frequently and
//! contain recent data, while higher levels contain older, more stable data.
//!
//! ```text
//! Level 0:  [curr] [snap]   <- Updates every 2 ledgers
//! Level 1:  [curr] [snap]   <- Updates every 8 ledgers
//! Level 2:  [curr] [snap]   <- Updates every 32 ledgers
//! ...
//! Level 10: [curr] [snap]   <- Never spills (top level)
//! ```
//!
//! # Spill Mechanics
//!
//! When a level "spills", its `curr` bucket becomes its new `snap`, and
//! the old `snap` is merged into the next level's `curr`. Spill boundaries
//! follow stellar-core's `levelShouldSpill` rules:
//!
//! - `level_size(N)` = 4^(N+1): Size boundary for level N
//! - `level_half(N)` = level_size(N) / 2: Half-size boundary
//! - A level spills when the ledger is at a half or full size boundary
//!
//! # Hash Computation
//!
//! The bucket list hash is computed by hashing all level hashes together.
//! Each level hash is `SHA256(curr_hash || snap_hash)`. This Merkle tree
//! structure enables efficient integrity verification.
//!
//! # Entry Lookup
//!
//! Lookups search from level 0 to level 10, checking `curr` then `snap`
//! at each level. The first match is returned (newer entries shadow older).
//! Dead entries (tombstones) shadow live entries, returning None.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use stellar_core_common::protocol::MIN_SOROBAN_PROTOCOL_VERSION;
use stellar_xdr::curr::{
    BucketListType, BucketMetadata, BucketMetadataExt, LedgerEntry, LedgerKey, Limits, WriteXdr,
};

use stellar_core_common::Hash256;

use crate::bucket::Bucket;
use crate::entry::{
    get_ttl_key, is_persistent_entry, is_soroban_entry, is_temporary_entry, is_ttl_expired,
    ledger_entry_to_key, BucketEntry,
};
use crate::eviction::{
    update_starting_eviction_iterator, EvictionIterator, EvictionResult, StateArchivalSettings,
};
use crate::merge::{merge_buckets_with_options_and_shadows, merge_in_memory};
use crate::{
    BucketError, Result, FIRST_PROTOCOL_SHADOWS_REMOVED,
    FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY,
    FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION,
};

/// Number of levels in the BucketList (matches stellar-core's `kNumLevels`).
pub const BUCKET_LIST_LEVELS: usize = 11;

/// FutureBucket state constants (matches C++ stellar-core's FBStatus enum in HAS JSON).
/// HAS_NEXT_STATE_CLEAR: No pending merge
/// HAS_NEXT_STATE_OUTPUT: Merge complete, output hash is known
pub const HAS_NEXT_STATE_CLEAR: u32 = 0;
pub const HAS_NEXT_STATE_OUTPUT: u32 = 1;

/// State of a pending bucket merge from History Archive State (HAS).
///
/// When restoring from a HAS, each level may have a pending merge. If state is
/// HAS_NEXT_STATE_OUTPUT (1), the output hash contains the hash of the completed merge
/// result that should be set as the level's `next` bucket.
#[derive(Clone, Debug, Default)]
pub struct HasNextState {
    /// Merge state (0 = clear, 1 = hash output known, etc.)
    pub state: u32,
    /// Output bucket hash if merge is complete (state == 1)
    pub output: Option<Hash256>,
}

/// A single level in the BucketList, containing `curr` and `snap` buckets.
///
/// Each level maintains two buckets:
/// - `curr`: Receives merged data from the level below when it spills
/// - `snap`: Previous `curr` that was "snapped" during a spill
///
/// The level also has a `next` bucket used during merge operations to
/// stage the result before committing it to `curr`.
///
/// # Spill Behavior
///
/// When a level spills:
/// 1. The old `snap` is returned (flows to the next level)
/// 2. `curr` becomes the new `snap`
/// 3. `curr` is reset to empty (ready for new merges)
#[derive(Clone, Debug)]
pub struct BucketLevel {
    /// The current bucket being filled with merged entries.
    pub curr: Bucket,
    /// The snapshot bucket from the previous spill.
    pub snap: Bucket,
    /// Staged merge result awaiting commit (replaces `curr` on commit).
    next: Option<Bucket>,
    /// The level number (0-10).
    level: usize,
}

impl BucketLevel {
    /// Create a new empty level.
    pub fn new(level: usize) -> Self {
        Self {
            curr: Bucket::empty(),
            snap: Bucket::empty(),
            next: None,
            level,
        }
    }

    /// Get the hash of this level: SHA256(curr_hash || snap_hash).
    ///
    /// This matches stellar-core's BucketLevel::getHash() implementation.
    pub fn hash(&self) -> Hash256 {
        let curr_hash = self.curr.hash();
        let snap_hash = self.snap.hash();

        // SHA256(curr_hash || snap_hash)
        let mut hasher = Sha256::new();
        hasher.update(curr_hash.as_bytes());
        hasher.update(snap_hash.as_bytes());
        let result = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash256::from_bytes(bytes)
    }

    /// Set the curr bucket.
    pub fn set_curr(&mut self, bucket: Bucket) {
        self.curr = bucket;
    }

    /// Set the snap bucket.
    pub fn set_snap(&mut self, bucket: Bucket) {
        self.snap = bucket;
    }

    /// Get the level number.
    pub fn level_number(&self) -> usize {
        self.level
    }

    /// Promote the prepared bucket into curr, if any.
    fn commit(&mut self) {
        if let Some(next) = self.next.take() {
            self.curr = next;
        }
    }

    /// Get a reference to the next bucket if any (pending merge result).
    /// Used for lookups to check pending merges.
    pub fn next(&self) -> Option<&Bucket> {
        self.next.as_ref()
    }

    /// Snap the current bucket to become the new snapshot.
    ///
    /// This implements the bucket list spill behavior (matches C++ BucketLevel::snap):
    /// - Sets snap = curr (old curr becomes the new snap)
    /// - Clears curr (ready for new entries)
    /// - Returns the NEW snap (old curr), which flows to the next level
    ///
    /// Note: Unlike commit(), snap() does NOT commit pending merges. In C++,
    /// mNextCurr is a FutureBucket that stays pending until explicitly committed.
    fn snap(&mut self) -> Bucket {
        // Move curr to snap (curr becomes empty via replace)
        self.snap = std::mem::take(&mut self.curr);
        // Return the new snap (old curr) for merging into next level
        self.snap.clone()
    }

    /// Prepare the next bucket for this level with explicit INIT normalization control.
    ///
    /// This merges the current bucket (self.curr) with the incoming bucket.
    /// The curr may be empty if this level was already snapped from processing
    /// higher levels first.
    ///
    /// - `normalize_init`: If true, INIT entries are converted to LIVE. Note: This should
    ///   ALWAYS be false in production to match C++ stellar-core behavior. C++ never
    ///   normalizes INIT entries to LIVE during merges. This parameter exists for
    ///   backward compatibility with tests.
    /// - `use_empty_curr`: If true, use an empty bucket instead of self.curr for the merge.
    ///   This is used when the level is about to snap its curr (shouldMergeWithEmptyCurr).
    #[allow(clippy::too_many_arguments)]
    fn prepare_with_normalization(
        &mut self,
        _ledger_seq: u32,
        protocol_version: u32,
        incoming: Bucket,
        keep_dead_entries: bool,
        shadow_buckets: &[Bucket],
        normalize_init: bool,
        use_empty_curr: bool,
    ) -> Result<()> {
        if self.next.is_some() {
            return Err(BucketError::Merge(
                "bucket merge already in progress".to_string(),
            ));
        }

        // Choose curr or empty based on shouldMergeWithEmptyCurr
        let curr_for_merge = if use_empty_curr {
            tracing::debug!(
                level = self.level,
                "prepare_with_normalization: using EMPTY curr (shouldMergeWithEmptyCurr=true)"
            );
            Bucket::empty()
        } else {
            tracing::debug!(
                level = self.level,
                curr_hash = %self.curr.hash(),
                curr_entries = self.curr.len(),
                "prepare_with_normalization: using actual curr"
            );
            self.curr.clone()
        };

        tracing::debug!(
            level = self.level,
            curr_for_merge_hash = %curr_for_merge.hash(),
            curr_for_merge_entries = curr_for_merge.len(),
            incoming_hash = %incoming.hash(),
            incoming_entries = incoming.len(),
            keep_dead_entries = keep_dead_entries,
            normalize_init = normalize_init,
            "prepare_with_normalization: about to merge"
        );

        // Merge curr (or empty) with the incoming bucket
        let merged = merge_buckets_with_options_and_shadows(
            &curr_for_merge,
            &incoming,
            keep_dead_entries,
            protocol_version,
            normalize_init,
            shadow_buckets,
        )?;

        tracing::debug!(
            level = self.level,
            merged_hash = %merged.hash(),
            merged_entries = merged.len(),
            "prepare_with_normalization: merge complete"
        );

        self.next = Some(merged);
        Ok(())
    }

    /// Prepare level 0 with in-memory optimization.
    ///
    /// This method is specifically for level 0 and uses the in-memory merge
    /// optimization when possible. It avoids disk I/O for reading entries
    /// and keeps entries in memory for subsequent fast merges.
    ///
    /// # Arguments
    ///
    /// * `protocol_version` - The protocol version for the output bucket
    /// * `incoming` - The new bucket to merge with curr (must have in-memory entries)
    ///
    /// # Returns
    ///
    /// The merged bucket with in-memory entries set for the next merge.
    fn prepare_first_level(&mut self, protocol_version: u32, incoming: Bucket) -> Result<()> {
        if self.level != 0 {
            return Err(BucketError::Merge(
                "prepare_first_level can only be called on level 0".to_string(),
            ));
        }

        if self.next.is_some() {
            return Err(BucketError::Merge(
                "bucket merge already in progress".to_string(),
            ));
        }

        // Check if we can use in-memory merge
        let can_use_in_memory_merge =
            self.curr.has_in_memory_entries() && incoming.has_in_memory_entries();

        let merged = if can_use_in_memory_merge {
            tracing::debug!(level = 0, "prepare_first_level: using in-memory merge path");
            merge_in_memory(&self.curr, &incoming, protocol_version)?
        } else {
            tracing::debug!(
                level = 0,
                curr_has_in_memory = self.curr.has_in_memory_entries(),
                incoming_has_in_memory = incoming.has_in_memory_entries(),
                "prepare_first_level: falling back to regular merge (in-memory entries not available)"
            );
            // Fall back to regular merge
            // Level 0 always keeps tombstones and never normalizes INIT entries
            merge_buckets_with_options_and_shadows(
                &self.curr,
                &incoming,
                true, // keep_dead_entries
                protocol_version,
                false, // normalize_init_entries
                &[],   // no shadow buckets at level 0
            )?
        };

        // If the merged bucket doesn't have in-memory entries but we want them
        // for the next merge, try to enable them
        let merged = if !merged.has_in_memory_entries() {
            // Get entries and create bucket with in-memory optimization
            let entries: Vec<BucketEntry> = merged.iter().collect();
            Bucket::from_sorted_entries_with_in_memory(entries)?
        } else {
            merged
        };

        self.next = Some(merged);
        Ok(())
    }

    /// Clear in-memory entries from curr and snap buckets.
    ///
    /// This should be called when entries from this level move to higher levels
    /// and no longer need to participate in fast in-memory merges.
    pub fn clear_in_memory_entries(&mut self) {
        self.curr.clear_in_memory_entries();
        self.snap.clear_in_memory_entries();
    }
}

impl Default for BucketLevel {
    fn default() -> Self {
        Self::new(0)
    }
}

/// The complete BucketList structure representing all ledger state.
///
/// The BucketList is Stellar's canonical on-disk state representation. It contains
/// 11 levels of buckets that together hold every ledger entry in the network.
///
/// # Structure
///
/// Each level contains two buckets (`curr` and `snap`), and levels update at
/// different frequencies based on their position:
///
/// | Level | Spill Period | Typical Contents              |
/// |-------|--------------|-------------------------------|
/// | 0     | 2 ledgers    | Very recent entries           |
/// | 1     | 8 ledgers    | Recent entries                |
/// | 2     | 32 ledgers   | Moderately recent entries     |
/// | ...   | ...          | ...                           |
/// | 10    | Never        | Oldest, most stable entries   |
///
/// # Key Operations
///
/// - [`add_batch`](BucketList::add_batch): Add entries from a closed ledger
/// - [`get`](BucketList::get): Look up a ledger entry by key
/// - [`hash`](BucketList::hash): Compute the Merkle root hash
/// - [`scan_for_eviction_incremental`](BucketList::scan_for_eviction_incremental): Soroban eviction scan
///
/// # Thread Safety
///
/// BucketList is `Clone` but not `Send` or `Sync` by default. For concurrent
/// access, wrap in appropriate synchronization primitives.
#[derive(Clone)]
pub struct BucketList {
    /// The 11 levels of the bucket list (indices 0-10).
    levels: Vec<BucketLevel>,
    /// The current ledger sequence number (last ledger added).
    ledger_seq: u32,
}

/// Deduplicate ledger entries by key, keeping only the last occurrence.
/// This ensures that when the same entry is updated multiple times in a single
/// ledger, only the final state is included in the bucket.
fn deduplicate_entries(entries: Vec<LedgerEntry>) -> Vec<LedgerEntry> {
    // Use a HashMap to track the last position of each key
    let mut key_positions: HashMap<Vec<u8>, usize> = HashMap::new();

    // First pass: record the position of each key (later entries overwrite earlier ones)
    for (idx, entry) in entries.iter().enumerate() {
        if let Some(key) = ledger_entry_to_key(entry) {
            if let Ok(key_bytes) = key.to_xdr(Limits::none()) {
                key_positions.insert(key_bytes, idx);
            }
        }
    }

    // Second pass: collect only entries at the recorded positions (final state of each key)
    let positions: HashSet<usize> = key_positions.values().copied().collect();
    entries
        .into_iter()
        .enumerate()
        .filter_map(|(idx, entry)| {
            if positions.contains(&idx) {
                Some(entry)
            } else {
                None
            }
        })
        .collect()
}

impl BucketList {
    /// Number of levels in the BucketList.
    pub const NUM_LEVELS: usize = BUCKET_LIST_LEVELS;

    /// Create a new empty BucketList.
    pub fn new() -> Self {
        let levels = (0..BUCKET_LIST_LEVELS).map(BucketLevel::new).collect();

        Self {
            levels,
            ledger_seq: 0,
        }
    }

    /// Get the hash of the entire BucketList.
    ///
    /// This is computed by hashing all level hashes together.
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Sha256::new();

        for level in &self.levels {
            hasher.update(level.hash().as_bytes());
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

    /// Set the ledger sequence.
    ///
    /// This is used after restoring a bucket list from history archive hashes
    /// to set the correct ledger sequence. The `restore_from_hashes` method
    /// sets ledger_seq to 0, so callers must set it to the actual ledger
    /// sequence to ensure proper bucket list advancement behavior.
    pub fn set_ledger_seq(&mut self, ledger_seq: u32) {
        self.ledger_seq = ledger_seq;
    }

    /// Get a reference to a level.
    pub fn level(&self, idx: usize) -> Option<&BucketLevel> {
        self.levels.get(idx)
    }

    /// Get a mutable reference to a level.
    pub fn level_mut(&mut self, idx: usize) -> Option<&mut BucketLevel> {
        self.levels.get_mut(idx)
    }

    /// Get all levels.
    pub fn levels(&self) -> &[BucketLevel] {
        &self.levels
    }

    /// Look up an entry by its key.
    ///
    /// Searches from the newest (level 0) to oldest levels.
    /// Returns the first matching entry found, or None if not found.
    pub fn get(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>> {
        self.get_with_debug(key, false)
    }

    /// Look up an entry by its key with optional debug tracing.
    pub fn get_with_debug(&self, key: &LedgerKey, debug: bool) -> Result<Option<LedgerEntry>> {
        // Search from newest to oldest (curr then snap). Pending merges (next)
        // are not part of the bucket list state yet.
        for (level_idx, level) in self.levels.iter().enumerate() {
            // Check curr bucket first
            if let Some(entry) = level.curr.get(key)? {
                if debug {
                    tracing::info!(
                        level = level_idx,
                        bucket = "curr",
                        entry_type = ?std::mem::discriminant(&entry),
                        "Found entry in bucket list"
                    );
                }
                return match entry {
                    BucketEntry::Live(e) | BucketEntry::Init(e) => Ok(Some(e.clone())),
                    BucketEntry::Dead(_) => Ok(None), // Entry is deleted
                    BucketEntry::Metadata(_) => continue,
                };
            }

            // Then check snap bucket
            if let Some(entry) = level.snap.get(key)? {
                if debug {
                    tracing::info!(
                        level = level_idx,
                        bucket = "snap",
                        entry_type = ?std::mem::discriminant(&entry),
                        "Found entry in bucket list"
                    );
                }
                return match entry {
                    BucketEntry::Live(e) | BucketEntry::Init(e) => Ok(Some(e.clone())),
                    BucketEntry::Dead(_) => Ok(None), // Entry is deleted
                    BucketEntry::Metadata(_) => continue,
                };
            }
        }

        if debug {
            tracing::info!("Entry not found in any bucket");
        }
        Ok(None)
    }

    /// Debug method to find ALL occurrences of a key across all buckets.
    /// Returns a list of (level, bucket_type, entry) for each occurrence.
    /// Order: curr (newest) → snap (oldest) within each level.
    pub fn find_all_occurrences(
        &self,
        key: &LedgerKey,
    ) -> Result<Vec<(usize, &'static str, BucketEntry)>> {
        let mut results = Vec::new();

        for (level_idx, level) in self.levels.iter().enumerate() {
            if let Some(entry) = level.curr.get(key)? {
                results.push((level_idx, "curr", entry));
            }
            if let Some(entry) = level.snap.get(key)? {
                results.push((level_idx, "snap", entry));
            }
        }

        Ok(results)
    }

    /// Return all live entries as of the current bucket list state.
    pub fn live_entries(&self) -> Result<Vec<LedgerEntry>> {
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        let mut entries = Vec::new();

        for level in &self.levels {
            // Collect buckets to iterate: curr (newest), snap (oldest)
            // The order matters because first occurrence shadows later ones.
            let buckets: [&Bucket; 2] = [&level.curr, &level.snap];

            for bucket in buckets {
                for entry in bucket.iter() {
                    match entry {
                        BucketEntry::Live(live) | BucketEntry::Init(live) => {
                            let Some(key) = crate::entry::ledger_entry_to_key(&live) else {
                                continue;
                            };
                            let key_bytes = key.to_xdr(Limits::none()).map_err(|e| {
                                BucketError::Serialization(format!(
                                    "failed to serialize ledger key: {}",
                                    e
                                ))
                            })?;
                            if seen.insert(key_bytes) {
                                entries.push(live);
                            }
                        }
                        BucketEntry::Dead(dead) => {
                            let key_bytes = dead.to_xdr(Limits::none()).map_err(|e| {
                                BucketError::Serialization(format!(
                                    "failed to serialize ledger key: {}",
                                    e
                                ))
                            })?;
                            seen.insert(key_bytes);
                        }
                        BucketEntry::Metadata(_) => {}
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Check if an entry exists (is live) for the given key.
    pub fn contains(&self, key: &LedgerKey) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }

    /// Add ledger entries from a newly closed ledger.
    ///
    /// This mirrors stellar-core's bucket list update pipeline, preparing
    /// merges on spill boundaries and committing prior merges as needed.
    pub fn add_batch(
        &mut self,
        ledger_seq: u32,
        protocol_version: u32,
        bucket_list_type: BucketListType,
        init_entries: Vec<LedgerEntry>,
        live_entries: Vec<LedgerEntry>,
        dead_entries: Vec<LedgerKey>,
    ) -> Result<()> {
        let use_init = protocol_version >= FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY;

        let mut entries: Vec<BucketEntry> = Vec::new();

        if use_init {
            let mut meta = BucketMetadata {
                ledger_version: protocol_version,
                ext: BucketMetadataExt::V0,
            };
            if protocol_version >= FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION {
                meta.ext = BucketMetadataExt::V1(bucket_list_type);
            }
            entries.push(BucketEntry::Metadata(meta));
        }

        // Deduplicate init_entries - keep only the last occurrence of each key
        // This handles the case where the same entry is created and updated in the same ledger
        let dedup_init = deduplicate_entries(init_entries);
        if use_init {
            entries.extend(dedup_init.into_iter().map(BucketEntry::Init));
        } else {
            entries.extend(dedup_init.into_iter().map(BucketEntry::Live));
        }

        // Deduplicate live_entries - keep only the last occurrence of each key
        // This handles the case where the same entry is updated multiple times in the same ledger
        let dedup_live = deduplicate_entries(live_entries);
        entries.extend(dedup_live.into_iter().map(BucketEntry::Live));

        // Deduplicate dead_entries - keep only unique keys
        let mut seen_dead: HashSet<Vec<u8>> = HashSet::new();
        let dedup_dead: Vec<LedgerKey> = dead_entries
            .into_iter()
            .filter(|key| {
                if let Ok(key_bytes) = key.to_xdr(Limits::none()) {
                    seen_dead.insert(key_bytes)
                } else {
                    true
                }
            })
            .collect();
        entries.extend(dedup_dead.into_iter().map(BucketEntry::Dead));

        // Create the new bucket with in-memory entries for level 0 optimization
        // This enables fast in-memory merges at level 0
        let new_bucket = Bucket::from_sorted_entries_with_in_memory({
            let mut e = entries;
            e.sort_by(crate::entry::compare_entries);
            e
        })?;

        self.add_batch_internal(ledger_seq, protocol_version, new_bucket)?;
        self.ledger_seq = ledger_seq;
        Ok(())
    }

    fn add_batch_internal(
        &mut self,
        ledger_seq: u32,
        protocol_version: u32,
        new_bucket: Bucket,
    ) -> Result<()> {
        if ledger_seq == 0 {
            return Err(BucketError::Merge(
                "ledger sequence must be > 0".to_string(),
            ));
        }

        // Step 1: Process spills from highest level down to level 1
        // This matches C++ stellar-core's BucketListBase::addBatchInternal
        //
        // The key insight is that snap() moves curr→snap and returns the NEW snap
        // (which is the old curr). This is the bucket that flows to the next level.
        //
        // By processing from highest to lowest, we ensure each level's curr is
        // available to be snapped before any modifications occur.
        //
        // When multiple levels spill at once (e.g., at checkpoint boundaries),
        // entries cascade up through the levels correctly.

        for i in (1..BUCKET_LIST_LEVELS).rev() {
            if Self::level_should_spill(ledger_seq, i - 1) {
                // Snap level i-1: moves curr→snap, returns the NEW snap (old curr)
                // This is the bucket that flows to level i
                let spilling_snap = self.levels[i - 1].snap();

                tracing::debug!(
                    level = i - 1,
                    spilling_snap_hash = %spilling_snap.hash(),
                    new_snap_hash = %self.levels[i - 1].snap.hash(),
                    "Level snapped"
                );

                // Commit any pending merge at level i (promotes next→curr)
                self.levels[i].commit();

                // Prepare level i: merge curr with the spilling_snap from level i-1
                let keep_dead = Self::keep_tombstone_entries(i);
                let normalize_init = false; // Never normalize INIT to LIVE during merges
                let use_empty_curr = Self::should_merge_with_empty_curr(ledger_seq, i);
                let shadow_buckets = if protocol_version < FIRST_PROTOCOL_SHADOWS_REMOVED {
                    let mut shadows = Vec::new();
                    for level in self.levels.iter().take(i - 1) {
                        shadows.push(level.curr.clone());
                        shadows.push(level.snap.clone());
                    }
                    shadows
                } else {
                    Vec::new()
                };
                self.levels[i].prepare_with_normalization(
                    ledger_seq,
                    protocol_version,
                    spilling_snap,
                    keep_dead,
                    &shadow_buckets,
                    normalize_init,
                    use_empty_curr,
                )?;
            }
        }

        // Step 2: Apply new entries to level 0
        // Use the in-memory optimization for level 0
        // This avoids disk I/O for level 0 merges which happen frequently
        self.levels[0].prepare_first_level(protocol_version, new_bucket)?;
        self.levels[0].commit();

        Ok(())
    }

    /// Advance the bucket list from its current ledger to a target ledger by
    /// applying empty batches for all intermediate ledgers.
    ///
    /// This is required because the bucket list merge algorithm depends on being
    /// called for every ledger in sequence. The spill boundaries and merge timing
    /// are determined by the ledger sequence number.
    ///
    /// # Arguments
    ///
    /// * `target_ledger` - The ledger to advance to (exclusive of actual changes)
    /// * `protocol_version` - Protocol version for empty batches
    /// * `bucket_list_type` - Type of bucket list (Live)
    ///
    /// # Returns
    ///
    /// Ok(()) if successful, or an error if the target is not greater than current.
    pub fn advance_to_ledger(
        &mut self,
        target_ledger: u32,
        protocol_version: u32,
        bucket_list_type: BucketListType,
    ) -> Result<()> {
        let current = self.ledger_seq;
        if target_ledger <= current {
            // Nothing to do - we're already at or past this ledger
            return Ok(());
        }

        // Apply empty batches for each intermediate ledger
        // This maintains the correct merge timing in the bucket list
        tracing::info!(
            current = current,
            target_ledger = target_ledger,
            count = target_ledger - current - 1,
            "advance_to_ledger: applying empty batches"
        );
        for seq in (current + 1)..target_ledger {
            tracing::debug!(
                from_ledger = current,
                to_ledger = target_ledger,
                current_seq = seq,
                "Advancing bucket list through empty ledger"
            );
            self.add_batch(
                seq,
                protocol_version,
                bucket_list_type.clone(),
                Vec::new(), // empty init
                Vec::new(), // empty live
                Vec::new(), // empty dead
            )?;
        }
        tracing::info!(
            current = current,
            target_ledger = target_ledger,
            "advance_to_ledger: completed"
        );

        Ok(())
    }

    /// Round down `value` to the nearest multiple of `modulus`.
    fn round_down(value: u32, modulus: u32) -> u32 {
        if modulus == 0 {
            return 0;
        }
        value & !(modulus - 1)
    }

    /// Half the idealized size of a level (matches C++ stellar-core's levelHalf).
    /// Level 0: 2, Level 1: 8, Level 2: 32, Level 3: 128, etc.
    fn level_half(level: usize) -> u32 {
        1u32 << (2 * level + 1)
    }

    /// Idealized size of a level for spill boundaries (matches C++ stellar-core's levelSize).
    /// Level 0: 4, Level 1: 16, Level 2: 64, Level 3: 256, etc.
    fn level_size(level: usize) -> u32 {
        1u32 << (2 * (level + 1))
    }

    /// Returns true if a level should spill at a given ledger.
    /// This matches C++ stellar-core's `levelShouldSpill`:
    ///   return (ledger == roundDown(ledger, levelHalf(level)) ||
    ///           ledger == roundDown(ledger, levelSize(level)));
    ///
    /// Which simplifies to: ledger is a multiple of levelHalf(level).
    /// For level 0 (half=2): spills at ledgers 0, 2, 4, 6, ...
    /// For level 1 (half=8): spills at ledgers 0, 8, 16, 24, ...
    /// For level 2 (half=32): spills at ledgers 0, 32, 64, 96, ...
    pub fn level_should_spill(ledger_seq: u32, level: usize) -> bool {
        if level == BUCKET_LIST_LEVELS - 1 {
            // There's no level above the highest level, so it can't spill.
            return false;
        }

        let half = Self::level_half(level);
        let size = Self::level_size(level);
        ledger_seq % half == 0 || ledger_seq % size == 0
    }

    fn keep_tombstone_entries(level: usize) -> bool {
        level < BUCKET_LIST_LEVELS - 1
    }

    /// Determines whether to merge with an empty curr bucket instead of the actual curr.
    ///
    /// This is a critical piece of the bucket list merge algorithm that prevents data
    /// duplication. When a level is about to snap its curr bucket (because the next
    /// spill boundary will affect this level), we should NOT merge with curr. Instead,
    /// we merge with an empty bucket and let curr be preserved until it becomes snap.
    ///
    /// # Why This Matters
    ///
    /// Consider level 1 (half=8, size=16):
    /// - At ledger 6: Level 0 spills, level 1 receives data. But ledger 8 is when
    ///   level 1 itself will spill. If we merge with curr at ledger 6, and then at
    ///   ledger 8 curr becomes snap, we'd have duplicated the data in curr.
    /// - Solution: At ledger 6, we merge with empty instead of curr. Curr stays
    ///   unchanged. At ledger 8, curr becomes snap (preserving its entries), and
    ///   the merge result from ledger 6 becomes the new curr.
    ///
    /// # Algorithm
    ///
    /// 1. Calculate when the merge was started: `roundDown(ledger, levelHalf(level-1))`
    /// 2. Calculate when the next change would happen: `mergeStart + levelHalf(level-1)`
    /// 3. If the next change would cause this level to spill, use empty curr
    ///
    /// # Synchronous vs Asynchronous
    ///
    /// In C++ stellar-core, merges are asynchronous and the result stays in `mNextCurr`
    /// until committed. In our synchronous implementation, the result goes into `next`
    /// and we check `next` during lookups to make entries accessible. The key invariant
    /// is that `curr` is preserved until the level snaps.
    ///
    /// Matches C++ stellar-core's `shouldMergeWithEmptyCurr` in BucketListBase.cpp.
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

    /// Get all hashes in the bucket list (for serialization).
    pub fn all_bucket_hashes(&self) -> Vec<Hash256> {
        let mut hashes = Vec::with_capacity(BUCKET_LIST_LEVELS * 2);
        for level in &self.levels {
            hashes.push(level.curr.hash());
            hashes.push(level.snap.hash());
        }
        hashes
    }

    /// Restore a bucket list from hashes and a bucket lookup function.
    pub fn restore_from_hashes<F>(hashes: &[Hash256], mut load_bucket: F) -> Result<Self>
    where
        F: FnMut(&Hash256) -> Result<Bucket>,
    {
        if hashes.len() != BUCKET_LIST_LEVELS * 2 {
            return Err(BucketError::Serialization(format!(
                "Expected {} bucket hashes, got {}",
                BUCKET_LIST_LEVELS * 2,
                hashes.len()
            )));
        }

        let mut levels = Vec::with_capacity(BUCKET_LIST_LEVELS);

        for (i, chunk) in hashes.chunks(2).enumerate() {
            let curr_hash = &chunk[0];
            let snap_hash = &chunk[1];

            let curr = if curr_hash.is_zero() {
                Bucket::empty()
            } else {
                load_bucket(curr_hash)?
            };

            let snap = if snap_hash.is_zero() {
                Bucket::empty()
            } else {
                load_bucket(snap_hash)?
            };

            let mut level = BucketLevel::new(i);
            level.curr = curr;
            level.snap = snap;
            levels.push(level);
        }

        Ok(Self {
            levels,
            ledger_seq: 0,
        })
    }

    /// Restore a bucket list from History Archive State with full FutureBucket support.
    ///
    /// Unlike `restore_from_hashes`, this function also restores pending merge results
    /// when the HAS indicates a completed merge (state == HAS_NEXT_STATE_OUTPUT). This is
    /// necessary for correct bucket list hash computation at checkpoints.
    ///
    /// # Arguments
    ///
    /// * `hashes` - Vec of (curr_hash, snap_hash) pairs for each level
    /// * `next_states` - Vec of HasNextState for each level
    /// * `load_bucket` - Function to load a bucket from its hash
    pub fn restore_from_has<F>(
        hashes: &[(Hash256, Hash256)],
        next_states: &[HasNextState],
        mut load_bucket: F,
    ) -> Result<Self>
    where
        F: FnMut(&Hash256) -> Result<Bucket>,
    {
        if hashes.len() != BUCKET_LIST_LEVELS {
            return Err(BucketError::Serialization(format!(
                "Expected {} bucket level hashes, got {}",
                BUCKET_LIST_LEVELS,
                hashes.len()
            )));
        }

        let mut levels = Vec::with_capacity(BUCKET_LIST_LEVELS);

        for (i, (curr_hash, snap_hash)) in hashes.iter().enumerate() {
            let curr = if curr_hash.is_zero() {
                Bucket::empty()
            } else {
                load_bucket(curr_hash)?
            };

            let snap = if snap_hash.is_zero() {
                Bucket::empty()
            } else {
                load_bucket(snap_hash)?
            };

            // Check if there's a completed merge (state == HAS_NEXT_STATE_OUTPUT) for this level
            let next = if let Some(state) = next_states.get(i) {
                if state.state == HAS_NEXT_STATE_OUTPUT {
                    if let Some(ref output_hash) = state.output {
                        if !output_hash.is_zero() {
                            tracing::debug!(
                                level = i,
                                output_hash = %output_hash.to_hex(),
                                "restore_from_has: loading completed merge output"
                            );
                            Some(load_bucket(output_hash)?)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let mut level = BucketLevel::new(i);
            level.curr = curr;
            level.snap = snap;
            level.next = next;
            levels.push(level);
        }

        Ok(Self {
            levels,
            ledger_seq: 0,
        })
    }

    /// Restart any pending merges after restoring from a History Archive State (HAS).
    ///
    /// When a bucket list is restored from HAS, there may be merges that should have been
    /// in progress at that checkpoint ledger. This function recreates those pending merges
    /// by examining the current and snap buckets and starting merges where appropriate.
    ///
    /// This matches C++ stellar-core's BucketListBase::restartMerges().
    ///
    /// For each level > 0 with no pending merge:
    /// 1. Check if the previous level's snap is non-empty
    /// 2. If so, start a merge using that snap
    /// 3. The merge will be committed when the next spill occurs
    pub fn restart_merges(&mut self, ledger: u32, protocol_version: u32) -> Result<()> {
        tracing::debug!(
            ledger = ledger,
            "restart_merges: restarting pending merges after HAS restore"
        );

        for i in 1..BUCKET_LIST_LEVELS {
            // Skip if there's already a pending merge
            if self.levels[i].next.is_some() {
                tracing::trace!(level = i, "restart_merges: level already has pending merge");
                continue;
            }

            // Clone the previous level's snap to avoid borrow conflicts
            let prev_snap = self.levels[i - 1].snap.clone();

            // If the previous level's snap is empty, this and all higher levels
            // are uninitialized (haven't received enough data yet)
            if prev_snap.is_empty() {
                tracing::debug!(
                    level = i,
                    "restart_merges: previous level snap is empty, stopping"
                );
                break;
            }

            // Calculate the ledger when this merge would have started
            // This is roundDown(ledger, levelHalf(i - 1))
            let merge_start_ledger = Self::round_down(ledger, Self::level_half(i - 1));

            tracing::debug!(
                level = i,
                merge_start_ledger = merge_start_ledger,
                prev_snap_hash = %prev_snap.hash(),
                "restart_merges: restarting merge"
            );

            // Determine merge parameters
            let merge_protocol_version = prev_snap.protocol_version().unwrap_or(protocol_version);
            // Note: C++ never normalizes INIT to LIVE during merges - the keepTombstoneEntries
            // flag only affects DEAD entry filtering, not INIT entry transformation.
            let keep_dead = Self::keep_tombstone_entries(i);
            let normalize_init = false; // C++ never normalizes INIT to LIVE during merges
            let use_empty_curr = Self::should_merge_with_empty_curr(merge_start_ledger, i);

            // Log detailed merge parameters for debugging
            tracing::info!(
                level = i,
                ledger = ledger,
                merge_start_ledger = merge_start_ledger,
                use_empty_curr = use_empty_curr,
                level_curr_hash = %self.levels[i].curr.hash().to_hex(),
                level_snap_hash = %self.levels[i].snap.hash().to_hex(),
                prev_snap_hash = %prev_snap.hash().to_hex(),
                "restart_merges: starting merge"
            );

            // Start the merge with the previous level's snap
            self.levels[i].prepare_with_normalization(
                merge_start_ledger,
                merge_protocol_version,
                prev_snap,
                keep_dead,
                &[],
                normalize_init,
                use_empty_curr,
            )?;

            tracing::info!(
                level = i,
                next_hash = %self.levels[i].next.as_ref().map(|b| b.hash().to_hex()).unwrap_or_else(|| "None".to_string()),
                "restart_merges: merge restarted successfully"
            );
        }

        // Update the ledger sequence to the restored ledger
        self.ledger_seq = ledger;

        Ok(())
    }

    /// Get statistics about the bucket list.
    pub fn stats(&self) -> BucketListStats {
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

        BucketListStats {
            num_levels: BUCKET_LIST_LEVELS,
            total_entries,
            total_buckets,
        }
    }

    /// Debug print level state.
    pub fn debug_print_levels(&self) {
        for (i, level) in self.levels.iter().enumerate() {
            let curr_hash = level.curr.hash();
            let snap_hash = level.snap.hash();
            let next_hash = level
                .next
                .as_ref()
                .map(|b| b.hash().to_hex())
                .unwrap_or_else(|| "None".to_string());
            eprintln!(
                "  L{}: curr={}, snap={}, next={}",
                i,
                curr_hash.to_hex(),
                snap_hash.to_hex(),
                next_hash
            );
        }
    }

    /// Scan for expired Soroban entries in the bucket list.
    ///
    /// This scans all Soroban entries (ContractData, ContractCode) and checks their
    /// TTL entries to determine which have expired.
    ///
    /// Returns:
    /// - `archived_entries`: Persistent entries (ContractCode or persistent ContractData)
    ///   that should be archived to the hot archive bucket list
    /// - `deleted_keys`: Temporary entries that should be deleted
    ///
    /// An entry is considered expired when its TTL's `live_until_ledger_seq < current_ledger`.
    pub fn scan_for_eviction(
        &self,
        current_ledger: u32,
    ) -> Result<(Vec<LedgerEntry>, Vec<LedgerKey>)> {
        let mut archived_entries: Vec<LedgerEntry> = Vec::new();
        let mut deleted_keys: Vec<LedgerKey> = Vec::new();

        // Track which keys we've already processed (to avoid duplicates from different levels)
        let mut seen_keys: HashSet<Vec<u8>> = HashSet::new();

        // Iterate through all levels from newest to oldest
        for level in &self.levels {
            for bucket in [&level.curr, &level.snap] {
                for entry in bucket.iter() {
                    // Only process LIVE and INIT entries (not DEAD or Metadata)
                    let live_entry = match entry {
                        BucketEntry::Live(e) | BucketEntry::Init(e) => e,
                        BucketEntry::Dead(key) => {
                            // Mark dead keys as seen so we don't process older versions
                            let key_bytes = key.to_xdr(Limits::none()).map_err(|e| {
                                BucketError::Serialization(format!(
                                    "failed to serialize ledger key: {}",
                                    e
                                ))
                            })?;
                            seen_keys.insert(key_bytes);
                            continue;
                        }
                        BucketEntry::Metadata(_) => continue,
                    };

                    // Only check Soroban entries (ContractData, ContractCode)
                    if !is_soroban_entry(&live_entry) {
                        continue;
                    }

                    // Get the key for this entry
                    let Some(key) = ledger_entry_to_key(&live_entry) else {
                        continue;
                    };

                    // Check if we've already processed this key
                    let key_bytes = key.to_xdr(Limits::none()).map_err(|e| {
                        BucketError::Serialization(format!("failed to serialize ledger key: {}", e))
                    })?;
                    if !seen_keys.insert(key_bytes) {
                        // Already processed this key from a newer level
                        continue;
                    }

                    // Get the TTL key for this Soroban entry
                    let Some(ttl_key) = get_ttl_key(&key) else {
                        continue;
                    };

                    // Look up the TTL entry in the bucket list
                    let Some(ttl_entry) = self.get(&ttl_key)? else {
                        // No TTL entry found - this shouldn't happen for valid Soroban entries
                        // but we skip rather than error
                        tracing::warn!(?key, "Soroban entry has no TTL entry during eviction scan");
                        continue;
                    };

                    // Check if the entry is expired
                    let Some(is_expired) = is_ttl_expired(&ttl_entry, current_ledger) else {
                        // Not a TTL entry (shouldn't happen)
                        continue;
                    };

                    if !is_expired {
                        // Entry is still live, skip it
                        continue;
                    }

                    // Entry is expired - categorize it
                    if is_temporary_entry(&live_entry) {
                        // Temporary entries are deleted
                        deleted_keys.push(key);
                    } else if is_persistent_entry(&live_entry) {
                        // Persistent entries are archived to hot archive
                        archived_entries.push(live_entry);
                    }
                }
            }
        }

        tracing::debug!(
            current_ledger,
            archived_count = archived_entries.len(),
            deleted_count = deleted_keys.len(),
            "Eviction scan completed"
        );

        Ok((archived_entries, deleted_keys))
    }

    /// Perform an incremental eviction scan starting from the given iterator position.
    ///
    /// This matches C++ stellar-core's `scanForEviction` behavior:
    /// - Scans entries starting from the iterator's current position
    /// - Stops when `settings.eviction_scan_size` bytes have been scanned
    /// - Updates the iterator to the new position
    /// - Returns evicted entries (archived persistent + deleted temporary)
    ///
    /// The scan automatically advances through buckets when reaching the end of one.
    pub fn scan_for_eviction_incremental(
        &self,
        mut iter: EvictionIterator,
        current_ledger: u32,
        settings: &StateArchivalSettings,
    ) -> Result<EvictionResult> {
        let mut result = EvictionResult {
            archived_entries: Vec::new(),
            evicted_keys: Vec::new(),
            end_iterator: iter,
            bytes_scanned: 0,
            scan_complete: false,
        };

        // Update iterator based on spills (reset offset if bucket received new data)
        update_starting_eviction_iterator(
            &mut iter,
            settings.starting_eviction_scan_level,
            current_ledger,
        );

        let start_iter = iter;
        let mut bytes_remaining = settings.eviction_scan_size;
        // Track how many data entries we've evicted (not counting TTL entries)
        let mut entries_remaining = settings.max_entries_to_archive;

        // Track keys we've seen to avoid duplicates (from shadowed entries)
        let mut seen_keys: HashSet<Vec<u8>> = HashSet::new();

        loop {
            // Get the current bucket
            let level = iter.bucket_list_level as usize;
            if level >= BUCKET_LIST_LEVELS {
                // Wrapped around, done
                result.scan_complete = true;
                break;
            }

            let bucket = if iter.is_curr_bucket {
                &self.levels[level].curr
            } else {
                &self.levels[level].snap
            };

            // Scan entries in this bucket starting from the offset
            let (_entries_scanned, bytes_used, data_entries_evicted, finished_bucket) = self
                .scan_bucket_region(
                    bucket,
                    &mut iter,
                    bytes_remaining,
                    entries_remaining,
                    current_ledger,
                    &mut result.archived_entries,
                    &mut result.evicted_keys,
                    &mut seen_keys,
                )?;

            result.bytes_scanned += bytes_used;
            if entries_remaining > data_entries_evicted {
                entries_remaining -= data_entries_evicted;
            } else {
                entries_remaining = 0;
            }

            if bytes_remaining > bytes_used {
                bytes_remaining -= bytes_used;
            } else {
                bytes_remaining = 0;
            }

            // If we've hit either limit (bytes or entry count), we're done
            if bytes_remaining == 0 || entries_remaining == 0 {
                result.scan_complete = true;
                break;
            }

            // If we finished this bucket, move to the next one
            if finished_bucket {
                iter.advance_to_next_bucket(settings.starting_eviction_scan_level);

                // Check if we've completed a full cycle - only break when we return
                // to the exact starting bucket (same level AND same is_curr).
                // Note: The `wrapped` flag from advance_to_next_bucket just means we
                // went from level 10 back to the starting level - it doesn't mean
                // we've completed a full cycle since we still need to scan curr
                // before reaching snap.
                if iter.bucket_list_level == start_iter.bucket_list_level
                    && iter.is_curr_bucket == start_iter.is_curr_bucket
                {
                    result.scan_complete = true;
                    break;
                }
            }
        }

        result.end_iterator = iter;

        Ok(result)
    }

    /// Scan a region of a bucket for evictable entries.
    ///
    /// Returns (entries_scanned, bytes_used, data_entries_evicted, finished_bucket).
    #[allow(clippy::too_many_arguments)]
    fn scan_bucket_region(
        &self,
        bucket: &Bucket,
        iter: &mut EvictionIterator,
        max_bytes: u64,
        max_entries: u32,
        current_ledger: u32,
        archived_entries: &mut Vec<LedgerEntry>,
        evicted_keys: &mut Vec<LedgerKey>,
        seen_keys: &mut HashSet<Vec<u8>>,
    ) -> Result<(usize, u64, u32, bool)> {
        let mut entries_scanned = 0;
        let mut bytes_used = 0u64;
        let mut data_entries_evicted = 0u32;

        // Skip buckets that predate Soroban; they cannot contain evictable entries.
        let bucket_protocol = bucket.protocol_version().unwrap_or(0);
        if bucket_protocol < MIN_SOROBAN_PROTOCOL_VERSION {
            iter.bucket_file_offset = 0;
            return Ok((entries_scanned, bytes_used, data_entries_evicted, true));
        }

        // bucket_file_offset is a byte offset in the bucket file.
        let start_offset = iter.bucket_file_offset;
        let mut current_offset = 0u64;

        // Iterate directly instead of collecting all entries into memory
        // This is critical for performance with disk-backed buckets
        for entry in bucket.iter() {
            let entry = &entry;
            let entry_size = entry.to_xdr()?.len() as u64 + 4; // 4-byte record mark

            let entry_end = current_offset + entry_size;
            if entry_end <= start_offset {
                current_offset = entry_end;
                continue;
            }

            bytes_used += entry_size;
            entries_scanned += 1;

            // Process the entry for eviction
            let live_entry = match entry {
                BucketEntry::Live(e) | BucketEntry::Init(e) => e,
                BucketEntry::Dead(key) => {
                    // Mark dead keys as seen
                    if let Ok(key_bytes) = key.to_xdr(Limits::none()) {
                        seen_keys.insert(key_bytes);
                    }
                    current_offset = entry_end;
                    if bytes_used >= max_bytes {
                        iter.bucket_file_offset = current_offset;
                        return Ok((entries_scanned, bytes_used, data_entries_evicted, false));
                    }
                    continue;
                }
                BucketEntry::Metadata(_) => {
                    current_offset = entry_end;
                    if bytes_used >= max_bytes {
                        iter.bucket_file_offset = current_offset;
                        return Ok((entries_scanned, bytes_used, data_entries_evicted, false));
                    }
                    continue;
                }
            };

            // Only check Soroban entries
            if !is_soroban_entry(live_entry) {
                current_offset = entry_end;
                if bytes_used >= max_bytes {
                    iter.bucket_file_offset = current_offset;
                    return Ok((entries_scanned, bytes_used, data_entries_evicted, false));
                }
                continue;
            }

            // Get the key for this entry
            let Some(key) = ledger_entry_to_key(live_entry) else {
                current_offset = entry_end;
                if bytes_used >= max_bytes {
                    iter.bucket_file_offset = current_offset;
                    return Ok((entries_scanned, bytes_used, data_entries_evicted, false));
                }
                continue;
            };

            // Check if we've already seen this key (from a newer bucket)
            let key_bytes = match key.to_xdr(Limits::none()) {
                Ok(bytes) => bytes,
                Err(_) => {
                    current_offset = entry_end;
                    if bytes_used >= max_bytes {
                        iter.bucket_file_offset = current_offset;
                        return Ok((entries_scanned, bytes_used, data_entries_evicted, false));
                    }
                    continue;
                }
            };

            if !seen_keys.insert(key_bytes) {
                current_offset = entry_end;
                if bytes_used >= max_bytes {
                    iter.bucket_file_offset = current_offset;
                    return Ok((entries_scanned, bytes_used, data_entries_evicted, false));
                }
                // Already processed from a newer level
                continue;
            }

            // Get the TTL key
            let Some(ttl_key) = get_ttl_key(&key) else {
                current_offset = entry_end;
                if bytes_used >= max_bytes {
                    iter.bucket_file_offset = current_offset;
                    return Ok((entries_scanned, bytes_used, data_entries_evicted, false));
                }
                continue;
            };

            // Look up the TTL entry
            let Some(ttl_entry) = self.get(&ttl_key)? else {
                current_offset = entry_end;
                if bytes_used >= max_bytes {
                    iter.bucket_file_offset = current_offset;
                    return Ok((entries_scanned, bytes_used, data_entries_evicted, false));
                }
                continue;
            };

            // Check if expired
            let Some(is_expired) = is_ttl_expired(&ttl_entry, current_ledger) else {
                current_offset = entry_end;
                if bytes_used >= max_bytes {
                    iter.bucket_file_offset = current_offset;
                    return Ok((entries_scanned, bytes_used, data_entries_evicted, false));
                }
                continue;
            };

            if !is_expired {
                current_offset = entry_end;
                if bytes_used >= max_bytes {
                    iter.bucket_file_offset = current_offset;
                    return Ok((entries_scanned, bytes_used, data_entries_evicted, false));
                }
                continue;
            }

            // Entry is expired - categorize it
            // When evicting an entry, we must remove BOTH the data entry AND its TTL entry
            // Also check the max_entries limit (counts data entries only, not TTL)
            if is_temporary_entry(live_entry) {
                evicted_keys.push(key);
                evicted_keys.push(ttl_key);
                data_entries_evicted += 1;
            } else if is_persistent_entry(live_entry) {
                // Persistent entries go to hot archive AND are evicted from live
                archived_entries.push(live_entry.clone());
                evicted_keys.push(key);
                evicted_keys.push(ttl_key);
                data_entries_evicted += 1;
            }

            current_offset = entry_end;
            // Check both limits: bytes scanned and entries evicted
            if bytes_used >= max_bytes || data_entries_evicted >= max_entries {
                iter.bucket_file_offset = current_offset;
                return Ok((entries_scanned, bytes_used, data_entries_evicted, false));
            }
        }

        // Finished the bucket
        iter.bucket_file_offset = current_offset;
        Ok((entries_scanned, bytes_used, data_entries_evicted, true))
    }
}

impl Default for BucketList {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BucketList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BucketList")
            .field("ledger_seq", &self.ledger_seq)
            .field("hash", &self.hash().to_hex())
            .field("stats", &self.stats())
            .finish()
    }
}

/// Statistics about a BucketList.
///
/// Provides summary information about the bucket list state, useful for
/// monitoring, debugging, and capacity planning.
#[derive(Debug, Clone)]
pub struct BucketListStats {
    /// Number of levels in the bucket list (always 11).
    pub num_levels: usize,
    /// Total number of entries across all buckets (including metadata).
    pub total_entries: usize,
    /// Total number of non-empty buckets (max 22: 11 levels * 2 buckets each).
    pub total_buckets: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::BucketEntry as BucketListEntry;
    use crate::merge::merge_buckets_with_options;
    use stellar_xdr::curr::*;

    const TEST_PROTOCOL: u32 = 25;

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

    #[test]
    fn test_new_bucket_list() {
        let bl = BucketList::new();
        assert_eq!(bl.levels().len(), BUCKET_LIST_LEVELS);
        assert_eq!(bl.ledger_seq(), 0);
    }

    #[test]
    fn test_add_batch_simple() {
        let mut bl = BucketList::new();

        let entry = make_account_entry([1u8; 32], 100);
        bl.add_batch(
            1,
            TEST_PROTOCOL,
            BucketListType::Live,
            vec![entry],
            vec![],
            vec![],
        )
        .unwrap();

        let key = make_account_key([1u8; 32]);
        let found = bl.get(&key).unwrap().unwrap();

        if let LedgerEntryData::Account(account) = &found.data {
            assert_eq!(account.balance, 100);
        } else {
            panic!("Expected Account entry");
        }
    }

    #[test]
    fn test_add_batch_update() {
        let mut bl = BucketList::new();

        // Add initial entry
        let entry1 = make_account_entry([1u8; 32], 100);
        bl.add_batch(
            1,
            TEST_PROTOCOL,
            BucketListType::Live,
            vec![entry1],
            vec![],
            vec![],
        )
        .unwrap();

        // Update entry
        let entry2 = make_account_entry([1u8; 32], 200);
        bl.add_batch(
            2,
            TEST_PROTOCOL,
            BucketListType::Live,
            vec![],
            vec![entry2],
            vec![],
        )
        .unwrap();

        let key = make_account_key([1u8; 32]);
        let found = bl.get(&key).unwrap().unwrap();

        if let LedgerEntryData::Account(account) = &found.data {
            assert_eq!(account.balance, 200);
        } else {
            panic!("Expected Account entry");
        }
    }

    #[test]
    fn test_live_entries_respects_deletes() {
        let mut bl = BucketList::new();

        let entry = make_account_entry([1u8; 32], 100);
        bl.add_batch(
            1,
            TEST_PROTOCOL,
            BucketListType::Live,
            vec![entry],
            vec![],
            vec![],
        )
        .unwrap();

        let dead = make_account_key([1u8; 32]);
        bl.add_batch(
            2,
            TEST_PROTOCOL,
            BucketListType::Live,
            vec![],
            vec![],
            vec![dead],
        )
        .unwrap();

        let entries = bl.live_entries().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_add_batch_delete() {
        let mut bl = BucketList::new();

        // Add entry
        let entry = make_account_entry([1u8; 32], 100);
        bl.add_batch(
            1,
            TEST_PROTOCOL,
            BucketListType::Live,
            vec![entry],
            vec![],
            vec![],
        )
        .unwrap();

        // Delete entry
        let key = make_account_key([1u8; 32]);
        bl.add_batch(
            2,
            TEST_PROTOCOL,
            BucketListType::Live,
            vec![],
            vec![],
            vec![key.clone()],
        )
        .unwrap();

        // Should not be found
        let found = bl.get(&key).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn test_level_sizes() {
        assert_eq!(BucketList::level_size(0), 4);
        assert_eq!(BucketList::level_size(1), 16);
        assert_eq!(BucketList::level_size(2), 64);
        assert_eq!(BucketList::level_size(3), 256);
        assert_eq!(BucketList::level_half(0), 2);
        assert_eq!(BucketList::level_half(1), 8);
        assert_eq!(BucketList::level_half(2), 32);
        assert_eq!(BucketList::level_half(3), 128);
    }

    #[test]
    fn test_level_should_spill_boundaries() {
        // Level 0 spills at even ledgers (multiples of 2)
        assert!(BucketList::level_should_spill(0, 0));
        assert!(BucketList::level_should_spill(2, 0));
        assert!(BucketList::level_should_spill(4, 0));
        assert!(!BucketList::level_should_spill(1, 0));
        assert!(!BucketList::level_should_spill(3, 0));

        // Level 1 spills at multiples of 8
        assert!(BucketList::level_should_spill(0, 1));
        assert!(BucketList::level_should_spill(8, 1));
        assert!(BucketList::level_should_spill(16, 1));
        assert!(!BucketList::level_should_spill(4, 1));
        assert!(!BucketList::level_should_spill(12, 1));

        // Level 2 spills at multiples of 32
        assert!(BucketList::level_should_spill(0, 2));
        assert!(BucketList::level_should_spill(32, 2));
        assert!(BucketList::level_should_spill(64, 2));
        assert!(!BucketList::level_should_spill(16, 2));

        // Top level never spills
        assert!(!BucketList::level_should_spill(0, BUCKET_LIST_LEVELS - 1));
        assert!(!BucketList::level_should_spill(64, BUCKET_LIST_LEVELS - 1));
    }

    #[test]
    fn test_prepare_with_normalization_converts_init() {
        let mut level = BucketLevel::new(BUCKET_LIST_LEVELS - 1);
        let entry = make_account_entry([1u8; 32], 100);
        let meta = BucketMetadata {
            ledger_version: TEST_PROTOCOL,
            ext: BucketMetadataExt::V1(BucketListType::Live),
        };
        let incoming = Bucket::from_entries(vec![
            BucketListEntry::Metadata(meta),
            BucketListEntry::Init(entry.clone()),
        ])
        .unwrap();

        level
            .prepare_with_normalization(5, TEST_PROTOCOL, incoming, false, &[], true, false)
            .unwrap();
        level.commit();

        let mut saw_live = false;
        for entry in level.curr.iter() {
            match entry {
                BucketListEntry::Live(live) => {
                    saw_live = true;
                    assert!(matches!(live.data, LedgerEntryData::Account(_)));
                }
                BucketListEntry::Init(_) => panic!("init entry should be normalized"),
                _ => {}
            }
        }
        assert!(saw_live);
    }

    #[test]
    fn test_merge_drops_dead_when_keep_dead_false() {
        let key = make_account_key([1u8; 32]);
        let bucket = Bucket::from_entries(vec![BucketListEntry::Dead(key)]).unwrap();
        let merged =
            merge_buckets_with_options(&Bucket::empty(), &bucket, false, TEST_PROTOCOL, true)
                .unwrap();
        let mut has_non_meta = false;
        for entry in merged.iter() {
            if !entry.is_metadata() {
                has_non_meta = true;
                break;
            }
        }
        assert!(!has_non_meta);
    }

    #[test]
    fn test_bucket_list_hash_changes() {
        let mut bl = BucketList::new();
        let hash1 = bl.hash();

        let entry = make_account_entry([1u8; 32], 100);
        bl.add_batch(
            1,
            TEST_PROTOCOL,
            BucketListType::Live,
            vec![entry],
            vec![],
            vec![],
        )
        .unwrap();
        let hash2 = bl.hash();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_contains() {
        let mut bl = BucketList::new();

        let key = make_account_key([1u8; 32]);
        assert!(!bl.contains(&key).unwrap());

        let entry = make_account_entry([1u8; 32], 100);
        bl.add_batch(
            1,
            TEST_PROTOCOL,
            BucketListType::Live,
            vec![entry],
            vec![],
            vec![],
        )
        .unwrap();

        assert!(bl.contains(&key).unwrap());
    }

    #[test]
    fn test_multiple_levels() {
        let mut bl = BucketList::new();

        // Add many entries to trigger spills to higher levels
        for i in 1..=20u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_be_bytes());
            let entry = make_account_entry(id, i as i64 * 100);
            bl.add_batch(
                i,
                TEST_PROTOCOL,
                BucketListType::Live,
                vec![entry],
                vec![],
                vec![],
            )
            .unwrap();
        }

        // Verify all entries are accessible
        for i in 1..=20u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_be_bytes());
            let key = make_account_key(id);
            let found = bl.get(&key).unwrap();
            assert!(found.is_some(), "Entry {} not found", i);
        }
    }

    #[test]
    fn test_should_merge_with_empty_curr() {
        // Level 0 always returns false
        assert!(!BucketList::should_merge_with_empty_curr(1, 0));
        assert!(!BucketList::should_merge_with_empty_curr(2, 0));
        assert!(!BucketList::should_merge_with_empty_curr(100, 0));

        // Level 1: half=8, size=16
        // At ledger 2: mergeStartLedger=2, nextChangeLedger=4
        // levelShouldSpill(4, 1) = false (4 is not at 8 or 16 boundary)
        assert!(!BucketList::should_merge_with_empty_curr(2, 1));

        // At ledger 4: mergeStartLedger=4, nextChangeLedger=6
        // levelShouldSpill(6, 1) = false
        assert!(!BucketList::should_merge_with_empty_curr(4, 1));

        // At ledger 6: mergeStartLedger=6, nextChangeLedger=8
        // levelShouldSpill(8, 1) = true (8 is at half boundary for level 1)
        assert!(BucketList::should_merge_with_empty_curr(6, 1));

        // At ledger 8: mergeStartLedger=8, nextChangeLedger=10
        // levelShouldSpill(10, 1) = false
        assert!(!BucketList::should_merge_with_empty_curr(8, 1));

        // At ledger 14: mergeStartLedger=14, nextChangeLedger=16
        // levelShouldSpill(16, 1) = true (16 is at size boundary for level 1)
        assert!(BucketList::should_merge_with_empty_curr(14, 1));
    }

    #[test]
    fn test_entries_preserved_across_should_merge_with_empty_curr() {
        // This test specifically verifies that entries are not lost when
        // shouldMergeWithEmptyCurr returns true.
        //
        // The critical ledger sequence for level 1 is:
        // - Ledger 4: Entry added, spill to level 1, shouldMergeWithEmptyCurr(4,1)=false
        // - Ledger 6: Entry added, spill to level 1, shouldMergeWithEmptyCurr(6,1)=true
        // - Ledger 8: Entry added, level 1 snaps, shouldMergeWithEmptyCurr(8,1)=false
        //
        // Entry from ledger 4 should be accessible at ledger 6 (in level 1's next),
        // at ledger 7 (in level 1's next), and at ledger 8 (in level 1's snap).

        let mut bl = BucketList::new();

        // Add entries at ledgers 1-8
        for ledger in 1..=8u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&ledger.to_be_bytes());
            let entry = make_account_entry(id, ledger as i64 * 100);
            bl.add_batch(
                ledger,
                TEST_PROTOCOL,
                BucketListType::Live,
                vec![entry],
                vec![],
                vec![],
            )
            .unwrap();

            // Verify ALL previous entries are still accessible
            for prev_ledger in 1..=ledger {
                let mut prev_id = [0u8; 32];
                prev_id[0..4].copy_from_slice(&prev_ledger.to_be_bytes());
                let key = make_account_key(prev_id);
                let found = bl.get(&key).unwrap();
                assert!(
                    found.is_some(),
                    "Entry from ledger {} not found at ledger {}",
                    prev_ledger,
                    ledger
                );
            }
        }
    }
}
