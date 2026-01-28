//! Bucket merging implementation.
//!
//! Merging is the fundamental operation that maintains bucket list integrity.
//! When buckets are merged, entries from a newer bucket "shadow" entries from
//! an older bucket with the same key.
//!
//! # Merge Operation
//!
//! The merge operation combines two sorted buckets into one, applying shadowing:
//!
//! ```text
//! Old Bucket: [A=1, C=3, E=5]
//! New Bucket: [B=2, C=30, D=4]
//! Merged:     [A=1, B=2, C=30, D=4, E=5]
//!            (C from new shadows C from old)
//! ```
//!
//! # CAP-0020 INITENTRY Semantics
//!
//! The `Init` entry type (introduced in protocol 11) enables optimizations:
//!
//! - `INIT + DEAD` = Both entries are annihilated (nothing output)
//! - `DEAD + INIT` = Becomes `LIVE` (recreation cancels tombstone)
//! - `INIT + LIVE` = Becomes `INIT` with new value (preserves init status)
//!
//! This prevents tombstones from accumulating when entries are created and
//! deleted within the same merge window.
//!
//! # Dead Entry Handling
//!
//! The `keep_dead_entries` parameter controls tombstone behavior:
//!
//! - `true`: Keep dead entries (needed at lower levels where they may still shadow)
//! - `false`: Remove dead entries (safe at higher levels, reduces bucket size)
//!
//! # Normalization
//!
//! When entries cross level boundaries during a spill, `Init` entries are
//! "normalized" to `Live`. This is because the init status is only relevant
//! within the merge window where the entry was created.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use stellar_core_common::Hash256;
use stellar_xdr::curr::{BucketMetadata, BucketMetadataExt, LedgerKey, Limits, WriteXdr};

use crate::bucket::{Bucket, BucketIter};
use crate::entry::{compare_keys, BucketEntry};
use crate::{
    BucketError, Result, FIRST_PROTOCOL_SHADOWS_REMOVED,
    FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY,
    FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION,
};

/// Merge two buckets into a new bucket.
///
/// The `new_bucket` contains newer entries that shadow entries in `old_bucket`.
///
/// # Arguments
/// * `old_bucket` - The older bucket (entries may be shadowed)
/// * `new_bucket` - The newer bucket (entries take precedence)
/// * `keep_dead_entries` - Whether to keep dead entries in the output
/// * `max_protocol_version` - Maximum protocol version allowed for the merge
///
/// # Merge Semantics
/// - When keys match, the newer entry wins
/// - Dead entries shadow live entries (the entry is deleted)
/// - If `keep_dead_entries` is false and a dead entry shadows nothing, it's removed
/// - Init entries are converted to Live entries when crossing level boundaries
///
/// Note: This wrapper always normalizes INIT→LIVE for backward compatibility with
/// tests. For bucket list operations, use `merge_buckets_with_options`.
pub fn merge_buckets(
    old_bucket: &Bucket,
    new_bucket: &Bucket,
    keep_dead_entries: bool,
    max_protocol_version: u32,
) -> Result<Bucket> {
    merge_buckets_with_options(
        old_bucket,
        new_bucket,
        keep_dead_entries,
        max_protocol_version,
        true,
    )
}

/// Merge two buckets into a new bucket with explicit normalization control.
///
/// # Arguments
/// * `old_bucket` - The older bucket (entries may be shadowed)
/// * `new_bucket` - The newer bucket (entries take precedence)
/// * `keep_dead_entries` - Whether to keep dead entries in the output
/// * `max_protocol_version` - Maximum protocol version allowed for the merge
/// * `normalize_init_entries` - Whether to convert INIT entries to LIVE entries.
///   Set to true when merging spills (crossing level boundaries), false for
///   same-level merges (e.g., at level 0).
///
/// # Merge Semantics
/// - When keys match, the newer entry wins
/// - Dead entries shadow live entries (the entry is deleted)
/// - If `keep_dead_entries` is false and a dead entry shadows nothing, it's removed
/// - Init entries are converted to Live entries only if `normalize_init_entries` is true
pub fn merge_buckets_with_options(
    old_bucket: &Bucket,
    new_bucket: &Bucket,
    keep_dead_entries: bool,
    max_protocol_version: u32,
    normalize_init_entries: bool,
) -> Result<Bucket> {
    // Note: We intentionally do NOT use fast paths for empty buckets here.
    // C++ stellar-core always goes through the full merge process even when
    // one input is empty. This is important because:
    // 1. The output bucket gets new metadata (protocol version)
    // 2. The bucket hash includes metadata
    // 3. Returning input unchanged would preserve old metadata and potentially wrong hash
    //
    // The only optimization is when BOTH inputs are empty.
    if new_bucket.is_empty() && old_bucket.is_empty() {
        return Ok(Bucket::empty());
    }

    // Get entries from both buckets (already sorted)
    // Note: use iter() instead of entries() to support disk-backed buckets
    let old_entries: Vec<BucketEntry> = old_bucket.iter().collect();
    let new_entries: Vec<BucketEntry> = new_bucket.iter().collect();

    tracing::trace!(
        old_hash = %old_bucket.hash(),
        new_hash = %new_bucket.hash(),
        old_entries = old_entries.len(),
        new_entries = new_entries.len(),
        "merge_buckets starting"
    );

    let old_meta = extract_metadata(&old_entries);
    let new_meta = extract_metadata(&new_entries);
    let (_, output_meta) =
        build_output_metadata(old_meta.as_ref(), new_meta.as_ref(), max_protocol_version)?;

    let mut merged = Vec::with_capacity(
        old_entries.len() + new_entries.len() + output_meta.as_ref().map(|_| 1).unwrap_or(0),
    );

    if let Some(ref meta) = output_meta {
        merged.push(meta.clone());
    }

    let mut old_idx = 0;
    let mut new_idx = 0;

    // Skip metadata entries from old and new buckets; we'll insert output metadata ourselves.
    while old_idx < old_entries.len() && old_entries[old_idx].is_metadata() {
        old_idx += 1;
    }

    while new_idx < new_entries.len() && new_entries[new_idx].is_metadata() {
        new_idx += 1;
    }

    // Merge the remaining entries
    while old_idx < old_entries.len() && new_idx < new_entries.len() {
        let old_entry = &old_entries[old_idx];
        let new_entry = &new_entries[new_idx];

        let old_key = old_entry.key();
        let new_key = new_entry.key();

        match (old_key, new_key) {
            (Some(ref ok), Some(ref nk)) => {
                match compare_keys(ok, nk) {
                    Ordering::Less => {
                        // Old entry comes first, no shadow.
                        // DON'T normalize old entries - they should stay as-is.
                        // Init entries in old bucket are from before this merge boundary.
                        if should_keep_entry(old_entry, keep_dead_entries) {
                            merged.push(old_entry.clone());
                        }
                        old_idx += 1;
                    }
                    Ordering::Greater => {
                        // New entry comes first
                        if should_keep_entry(new_entry, keep_dead_entries) {
                            merged.push(maybe_normalize_entry(
                                new_entry.clone(),
                                normalize_init_entries,
                            ));
                        }
                        new_idx += 1;
                    }
                    Ordering::Equal => {
                        // Keys match - new entry shadows old entry
                        // Apply merge semantics (per CAP-0020)
                        if let Some(merged_entry) = merge_entries(
                            old_entry,
                            new_entry,
                            keep_dead_entries,
                            normalize_init_entries,
                        ) {
                            merged.push(merged_entry);
                        }
                        old_idx += 1;
                        new_idx += 1;
                    }
                }
            }
            (None, Some(_)) => old_idx += 1,
            (Some(_), None) => new_idx += 1,
            (None, None) => {
                old_idx += 1;
                new_idx += 1;
            }
        }
    }

    // Add remaining old entries
    while old_idx < old_entries.len() {
        let entry = &old_entries[old_idx];
        if !entry.is_metadata() && should_keep_entry(entry, keep_dead_entries) {
            merged.push(entry.clone());
        }
        old_idx += 1;
    }

    // Add remaining new entries
    while new_idx < new_entries.len() {
        let entry = &new_entries[new_idx];
        if !entry.is_metadata() && should_keep_entry(entry, keep_dead_entries) {
            merged.push(maybe_normalize_entry(entry.clone(), normalize_init_entries));
        }
        new_idx += 1;
    }

    if merged.is_empty() {
        // In C++, even a merge that results in no data entries still produces a bucket
        // with a metadata entry (for protocol 11+). This ensures that the bucket list
        // hash is consistent. An uninitialized bucket has hash 0, but an initialized
        // empty bucket has the hash of its metadata.
        if let Some(meta) = output_meta {
            return Bucket::from_sorted_entries(vec![meta]);
        }
        return Ok(Bucket::empty());
    }

    // Use from_sorted_entries since the merge algorithm maintains sorted order.
    // This avoids the overhead of re-sorting already-sorted data.
    let result = Bucket::from_sorted_entries(merged)?;

    tracing::trace!(
        result_hash = %result.hash(),
        result_entries = result.len(),
        "merge_buckets complete"
    );
    Ok(result)
}

/// Merge two buckets using in-memory entries (level 0 optimization).
///
/// This function performs an in-memory merge of two buckets, avoiding disk I/O
/// for reading. The result is a new bucket with entries kept in memory for
/// subsequent fast merges.
///
/// This is the Rust equivalent of C++ `LiveBucket::mergeInMemory`.
///
/// # Requirements
///
/// Both input buckets MUST have in-memory entries available
/// (i.e., `has_in_memory_entries()` returns true).
///
/// # Arguments
///
/// * `old_bucket` - The older bucket (entries may be shadowed)
/// * `new_bucket` - The newer bucket (entries take precedence)
/// * `max_protocol_version` - Maximum protocol version for output
///
/// # Returns
///
/// A new bucket with:
/// - All entries merged according to CAP-0020 semantics
/// - In-memory entries populated for the next merge
/// - Proper hash computed
///
/// # Panics
///
/// Panics if either bucket does not have in-memory entries.
pub fn merge_in_memory(
    old_bucket: &Bucket,
    new_bucket: &Bucket,
    max_protocol_version: u32,
) -> Result<Bucket> {
    // Verify both buckets have in-memory entries
    assert!(
        old_bucket.has_in_memory_entries(),
        "old_bucket must have in-memory entries for merge_in_memory"
    );
    assert!(
        new_bucket.has_in_memory_entries(),
        "new_bucket must have in-memory entries for merge_in_memory"
    );

    // Get in-memory entries directly (no disk I/O)
    let old_entries = old_bucket.get_in_memory_entries().unwrap();
    let new_entries = new_bucket.get_in_memory_entries().unwrap();

    // DEBUG: Print merge inputs
    tracing::debug!(
        old_entries_count = old_entries.len(),
        new_entries_count = new_entries.len(),
        max_protocol_version = max_protocol_version,
        "merge_in_memory: starting"
    );

    // Build output metadata using max_protocol_version directly.
    // This matches C++ mergeInMemory behavior where meta.ledgerVersion = maxProtocolVersion
    // without calling calculateMergeProtocolVersion.
    let output_meta = if max_protocol_version >= FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY {
        let mut meta = BucketMetadata {
            ledger_version: max_protocol_version,
            ext: BucketMetadataExt::V0,
        };
        if max_protocol_version >= FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION {
            meta.ext = BucketMetadataExt::V1(stellar_xdr::curr::BucketListType::Live);
        }
        Some(BucketEntry::Metadata(meta))
    } else {
        None
    };

    tracing::debug!(
        output_meta = ?output_meta,
        max_protocol_version = max_protocol_version,
        "merge_in_memory: built output metadata"
    );

    // Initialize incremental hash and entry collection
    let mut hasher = Sha256::new();
    let mut key_index = BTreeMap::new();

    // Pre-allocate output vectors
    // all_entries: includes metadata for storage/indexing
    // level_zero_entries: excludes metadata for in-memory merges
    let capacity =
        old_entries.len() + new_entries.len() + output_meta.as_ref().map(|_| 1).unwrap_or(0);
    let mut all_entries = Vec::with_capacity(capacity);
    let mut level_zero_entries = Vec::with_capacity(old_entries.len() + new_entries.len());
    let mut entry_idx = 0;

    // Reusable buffer for XDR serialization (avoids repeated allocations)
    let mut entry_buf: Vec<u8> = Vec::with_capacity(4096);
    let mut key_buf: Vec<u8> = Vec::with_capacity(256);

    // Helper to add entry to output with incremental hashing
    // Uses reusable buffers to minimize allocations
    let add_entry = |entry: BucketEntry,
                     hasher: &mut Sha256,
                     key_index: &mut BTreeMap<Vec<u8>, usize>,
                     all_entries: &mut Vec<BucketEntry>,
                     level_zero_entries: &mut Vec<BucketEntry>,
                     entry_idx: &mut usize,
                     entry_buf: &mut Vec<u8>,
                     key_buf: &mut Vec<u8>|
     -> Result<()> {
        use stellar_xdr::curr::Limited;

        // Serialize entry for hash using reusable buffer
        // Uses write_xdr_to which avoids intermediate allocation
        entry_buf.clear();
        entry.write_xdr_to(entry_buf)?;

        // Update hash with XDR Record Marking format
        let size = entry_buf.len() as u32;
        let record_mark = size | 0x80000000;
        hasher.update(&record_mark.to_be_bytes());
        hasher.update(entry_buf.as_slice());

        // Build key index for non-metadata entries
        if !entry.is_metadata() {
            if let Some(key) = entry.key() {
                // Serialize key using reusable buffer, then copy to owned vec for index
                key_buf.clear();
                {
                    let mut limited = Limited::new(key_buf as &mut Vec<u8>, Limits::none());
                    key.write_xdr(&mut limited).map_err(|e| {
                        BucketError::Serialization(format!("Failed to serialize key: {}", e))
                    })?;
                }
                key_index.insert(key_buf.clone(), *entry_idx);
            }
            level_zero_entries.push(entry.clone());
        }

        all_entries.push(entry);
        *entry_idx += 1;
        Ok(())
    };

    // Add metadata first if present
    if let Some(ref meta) = output_meta {
        add_entry(
            meta.clone(),
            &mut hasher,
            &mut key_index,
            &mut all_entries,
            &mut level_zero_entries,
            &mut entry_idx,
            &mut entry_buf,
            &mut key_buf,
        )?;
    }

    // Set up indices, skipping metadata entries
    let mut old_idx = 0;
    let mut new_idx = 0;

    while old_idx < old_entries.len() && old_entries[old_idx].is_metadata() {
        old_idx += 1;
    }
    while new_idx < new_entries.len() && new_entries[new_idx].is_metadata() {
        new_idx += 1;
    }

    // Level 0 always keeps tombstones (they may shadow entries in deeper levels)
    let keep_dead_entries = true;
    // Level 0 does NOT normalize INIT entries (they stay INIT within the merge window)
    let normalize_init_entries = false;

    // Merge entries with incremental hashing
    while old_idx < old_entries.len() && new_idx < new_entries.len() {
        let old_entry = &old_entries[old_idx];
        let new_entry = &new_entries[new_idx];

        let old_key = old_entry.key();
        let new_key = new_entry.key();

        match (old_key, new_key) {
            (Some(ref ok), Some(ref nk)) => {
                use crate::entry::compare_keys;
                match compare_keys(ok, nk) {
                    std::cmp::Ordering::Less => {
                        if should_keep_entry(old_entry, keep_dead_entries) {
                            add_entry(
                                old_entry.clone(),
                                &mut hasher,
                                &mut key_index,
                                &mut all_entries,
                                &mut level_zero_entries,
                                &mut entry_idx,
                                &mut entry_buf,
                                &mut key_buf,
                            )?;
                        }
                        old_idx += 1;
                    }
                    std::cmp::Ordering::Greater => {
                        if should_keep_entry(new_entry, keep_dead_entries) {
                            add_entry(
                                maybe_normalize_entry(new_entry.clone(), normalize_init_entries),
                                &mut hasher,
                                &mut key_index,
                                &mut all_entries,
                                &mut level_zero_entries,
                                &mut entry_idx,
                                &mut entry_buf,
                                &mut key_buf,
                            )?;
                        }
                        new_idx += 1;
                    }
                    std::cmp::Ordering::Equal => {
                        if let Some(merged_entry) = merge_entries(
                            old_entry,
                            new_entry,
                            keep_dead_entries,
                            normalize_init_entries,
                        ) {
                            add_entry(
                                merged_entry,
                                &mut hasher,
                                &mut key_index,
                                &mut all_entries,
                                &mut level_zero_entries,
                                &mut entry_idx,
                                &mut entry_buf,
                                &mut key_buf,
                            )?;
                        }
                        old_idx += 1;
                        new_idx += 1;
                    }
                }
            }
            (None, Some(_)) => old_idx += 1,
            (Some(_), None) => new_idx += 1,
            (None, None) => {
                old_idx += 1;
                new_idx += 1;
            }
        }
    }

    // Add remaining old entries
    while old_idx < old_entries.len() {
        let entry = &old_entries[old_idx];
        if !entry.is_metadata() && should_keep_entry(entry, keep_dead_entries) {
            add_entry(
                entry.clone(),
                &mut hasher,
                &mut key_index,
                &mut all_entries,
                &mut level_zero_entries,
                &mut entry_idx,
                &mut entry_buf,
                &mut key_buf,
            )?;
        }
        old_idx += 1;
    }

    // Add remaining new entries
    while new_idx < new_entries.len() {
        let entry = &new_entries[new_idx];
        if !entry.is_metadata() && should_keep_entry(entry, keep_dead_entries) {
            add_entry(
                maybe_normalize_entry(entry.clone(), normalize_init_entries),
                &mut hasher,
                &mut key_index,
                &mut all_entries,
                &mut level_zero_entries,
                &mut entry_idx,
                &mut entry_buf,
                &mut key_buf,
            )?;
        }
        new_idx += 1;
    }

    // Handle empty result
    if all_entries.is_empty() {
        if let Some(meta) = output_meta {
            return Bucket::from_sorted_entries_with_in_memory(vec![meta]);
        }
        return Ok(Bucket::empty());
    }

    // Compute final hash
    let hash_bytes: [u8; 32] = hasher.finalize().into();
    let hash = Hash256::from_bytes(hash_bytes);

    // DEBUG: Print merge output
    tracing::debug!(
        merged_count = all_entries.len(),
        has_meta = all_entries.first().map(|e| e.is_metadata()).unwrap_or(false),
        hash = %hash.to_hex(),
        "merge_in_memory: finished merge"
    );

    // Create bucket directly with pre-computed hash
    Ok(Bucket::from_parts(
        hash,
        Arc::new(all_entries),
        Arc::new(key_index),
        Some(Arc::new(level_zero_entries)),
    ))
}

/// Merge two buckets with shadow elimination for pre-shadow-removal protocols.
///
/// Shadows are only used before protocol 12 to avoid reintroducing entries
/// that are already shadowed by newer levels of the bucket list.
pub fn merge_buckets_with_options_and_shadows(
    old_bucket: &Bucket,
    new_bucket: &Bucket,
    keep_dead_entries: bool,
    max_protocol_version: u32,
    normalize_init_entries: bool,
    shadow_buckets: &[Bucket],
) -> Result<Bucket> {
    let merged = merge_buckets_with_options(
        old_bucket,
        new_bucket,
        keep_dead_entries,
        max_protocol_version,
        normalize_init_entries,
    )?;

    if shadow_buckets.is_empty() || max_protocol_version >= FIRST_PROTOCOL_SHADOWS_REMOVED {
        return Ok(merged);
    }

    let keep_shadowed_lifecycle_entries =
        max_protocol_version >= FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY;
    filter_shadowed_entries(&merged, shadow_buckets, keep_shadowed_lifecycle_entries)
}

struct ShadowCursor<'a> {
    iter: BucketIter<'a>,
    current: Option<BucketEntry>,
}

impl<'a> ShadowCursor<'a> {
    fn new(bucket: &'a Bucket) -> Self {
        let mut iter = bucket.iter();
        let current = next_non_meta(&mut iter);
        Self { iter, current }
    }

    fn advance_to_key_or_after(&mut self, key: &LedgerKey) -> bool {
        loop {
            let Some(entry) = self.current.as_ref() else {
                return false;
            };
            let Some(entry_key) = entry.key() else {
                self.current = next_non_meta(&mut self.iter);
                continue;
            };

            match compare_keys(&entry_key, key) {
                Ordering::Less => {
                    self.current = next_non_meta(&mut self.iter);
                }
                Ordering::Equal => return true,
                Ordering::Greater => return false,
            }
        }
    }
}

fn next_non_meta(iter: &mut BucketIter<'_>) -> Option<BucketEntry> {
    iter.by_ref().find(|entry| !entry.is_metadata())
}

fn is_shadowed(entry: &BucketEntry, cursors: &mut [ShadowCursor<'_>]) -> bool {
    let Some(key) = entry.key() else {
        return false;
    };

    for cursor in cursors.iter_mut() {
        if cursor.advance_to_key_or_after(&key) {
            return true;
        }
    }

    false
}

fn filter_shadowed_entries(
    merged: &Bucket,
    shadow_buckets: &[Bucket],
    keep_shadowed_lifecycle_entries: bool,
) -> Result<Bucket> {
    let mut cursors: Vec<ShadowCursor<'_>> = shadow_buckets.iter().map(ShadowCursor::new).collect();

    let mut filtered = Vec::with_capacity(merged.len());
    for entry in merged.iter() {
        if entry.is_metadata() {
            filtered.push(entry);
            continue;
        }

        if keep_shadowed_lifecycle_entries && (entry.is_init() || entry.is_dead()) {
            filtered.push(entry);
            continue;
        }

        if !is_shadowed(&entry, &mut cursors) {
            filtered.push(entry);
        }
    }

    Bucket::from_sorted_entries(filtered)
}

/// Check if an entry should be kept in the merged output.
fn should_keep_entry(entry: &BucketEntry, keep_dead_entries: bool) -> bool {
    match entry {
        BucketEntry::Dead(_) => keep_dead_entries,
        _ => true,
    }
}

/// Normalize an entry (convert Init to Live).
fn normalize_entry(entry: BucketEntry) -> BucketEntry {
    match entry {
        BucketEntry::Init(e) => BucketEntry::Live(e),
        other => other,
    }
}

/// Conditionally normalize an entry.
///
/// If `normalize` is true, converts INIT to LIVE. Otherwise returns entry unchanged.
fn maybe_normalize_entry(entry: BucketEntry, normalize: bool) -> BucketEntry {
    if normalize {
        normalize_entry(entry)
    } else {
        entry
    }
}

/// Merge two entries with the same key.
///
/// Returns the merged entry, or None if the entry should be removed.
///
/// Merge semantics per CAP-0020:
/// - INITENTRY + DEADENTRY → Both annihilated (nothing output)
/// - INITENTRY=x + LIVEENTRY=y → Output as INITENTRY=y (preserves INIT status)
/// - DEADENTRY + INITENTRY=x → Output as LIVEENTRY=x
/// - LIVEENTRY + DEADENTRY → Dead (if keep_dead_entries) or nothing
/// - Any + LIVEENTRY → LIVEENTRY wins
fn merge_entries(
    old: &BucketEntry,
    new: &BucketEntry,
    keep_dead_entries: bool,
    normalize_init_entries: bool,
) -> Option<BucketEntry> {
    match (old, new) {
        // CAP-0020: INITENTRY + DEADENTRY → Both annihilated
        // This is a key optimization: if we created and then deleted in the same
        // merge window, we output nothing at all.
        (BucketEntry::Init(_), BucketEntry::Dead(_)) => None,

        // CAP-0020: DEADENTRY + INITENTRY=x → Output as LIVEENTRY=x
        // The old tombstone is cancelled by the new creation
        (BucketEntry::Dead(_), BucketEntry::Init(entry)) => Some(BucketEntry::Live(entry.clone())),

        // CAP-0020: INITENTRY=x + LIVEENTRY=y → Output as INITENTRY=y
        // Preserve the INIT status (entry was created in this merge range)
        (BucketEntry::Init(_), BucketEntry::Live(entry)) => Some(BucketEntry::Init(entry.clone())),

        // New Live shadows old Live - new wins
        (BucketEntry::Live(_), BucketEntry::Live(entry)) => Some(BucketEntry::Live(entry.clone())),

        // New Live shadows old Dead - live wins
        (BucketEntry::Dead(_), BucketEntry::Live(entry)) => Some(BucketEntry::Live(entry.clone())),

        // Any old + new Init (not covered above) → convert to Live only if crossing levels
        (_, BucketEntry::Init(entry)) => {
            if normalize_init_entries {
                Some(BucketEntry::Live(entry.clone()))
            } else {
                Some(BucketEntry::Init(entry.clone()))
            }
        }

        // LIVEENTRY + DEADENTRY → Dead entry (tombstone) if keeping, else nothing
        (BucketEntry::Live(_), BucketEntry::Dead(key)) => {
            if keep_dead_entries {
                Some(BucketEntry::Dead(key.clone()))
            } else {
                None
            }
        }

        // Dead shadows Dead - keep newest if needed
        (BucketEntry::Dead(_), BucketEntry::Dead(key)) => {
            if keep_dead_entries {
                Some(BucketEntry::Dead(key.clone()))
            } else {
                None
            }
        }

        // Metadata shouldn't have matching keys
        (BucketEntry::Metadata(_), _) | (_, BucketEntry::Metadata(_)) => None,
    }
}

/// Iterator that yields merged entries from two buckets.
///
/// This iterator implements lazy/streaming merge, yielding one entry at a time.
/// It's useful when you want to process merged entries without materializing
/// the full merged bucket in memory.
///
/// # Memory Usage
///
/// For disk-backed buckets, entries are collected upfront (same as `merge_buckets`).
/// For in-memory buckets, the iterator references existing entries without copying.
///
/// # Example
///
/// ```ignore
/// let iter = MergeIterator::new(&old_bucket, &new_bucket, true, 20);
/// for entry in iter {
///     process_entry(entry);
/// }
/// ```
///
/// Note: Always normalizes `Init` entries to `Live` for backward compatibility.
/// For more control, use `merge_buckets_with_options` instead.
pub struct MergeIterator {
    /// Entries from the older bucket (collected upfront).
    old_entries: Vec<BucketEntry>,
    /// Entries from the newer bucket (collected upfront).
    new_entries: Vec<BucketEntry>,
    /// Current index into old_entries.
    old_idx: usize,
    /// Current index into new_entries.
    new_idx: usize,
    /// Whether to keep dead entries in output.
    keep_dead_entries: bool,
    /// Metadata entry to emit first (if any).
    output_metadata: Option<BucketEntry>,
}

impl MergeIterator {
    /// Create a new merge iterator.
    pub fn new(
        old_bucket: &Bucket,
        new_bucket: &Bucket,
        keep_dead_entries: bool,
        max_protocol_version: u32,
    ) -> Self {
        // Collect entries - works for both in-memory and disk-backed buckets
        let old_entries: Vec<BucketEntry> = old_bucket.iter().collect();
        let new_entries: Vec<BucketEntry> = new_bucket.iter().collect();
        let old_meta = extract_metadata(&old_entries);
        let new_meta = extract_metadata(&new_entries);
        let (_, output_metadata) =
            build_output_metadata(old_meta.as_ref(), new_meta.as_ref(), max_protocol_version)
                .unwrap_or((0, None));

        Self {
            old_entries,
            new_entries,
            old_idx: 0,
            new_idx: 0,
            keep_dead_entries,
            output_metadata,
        }
    }
}

impl Iterator for MergeIterator {
    type Item = BucketEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(meta) = self.output_metadata.take() {
            while self.old_idx < self.old_entries.len()
                && self.old_entries[self.old_idx].is_metadata()
            {
                self.old_idx += 1;
            }
            while self.new_idx < self.new_entries.len()
                && self.new_entries[self.new_idx].is_metadata()
            {
                self.new_idx += 1;
            }
            return Some(meta);
        }

        loop {
            // Check if we're done with both
            if self.old_idx >= self.old_entries.len() && self.new_idx >= self.new_entries.len() {
                return None;
            }

            // Only old entries left
            if self.new_idx >= self.new_entries.len() {
                let entry = self.old_entries[self.old_idx].clone();
                self.old_idx += 1;
                if !entry.is_metadata() {
                    return Some(entry);
                }
                continue;
            }

            // Only new entries left
            if self.old_idx >= self.old_entries.len() {
                let entry = self.new_entries[self.new_idx].clone();
                self.new_idx += 1;
                if !entry.is_metadata() && should_keep_entry(&entry, self.keep_dead_entries) {
                    return Some(normalize_entry(entry));
                }
                continue;
            }

            // Both have entries
            let old_entry = &self.old_entries[self.old_idx];
            let new_entry = &self.new_entries[self.new_idx];

            let old_key = old_entry.key();
            let new_key = new_entry.key();

            match (old_key, new_key) {
                (Some(ref ok), Some(ref nk)) => {
                    match compare_keys(ok, nk) {
                        Ordering::Less => {
                            self.old_idx += 1;
                            return Some(old_entry.clone());
                        }
                        Ordering::Greater => {
                            self.new_idx += 1;
                            if should_keep_entry(new_entry, self.keep_dead_entries) {
                                return Some(normalize_entry(new_entry.clone()));
                            }
                            continue;
                        }
                        Ordering::Equal => {
                            self.old_idx += 1;
                            self.new_idx += 1;
                            // Always normalize in MergeIterator for backward compatibility
                            if let Some(merged) =
                                merge_entries(old_entry, new_entry, self.keep_dead_entries, true)
                            {
                                return Some(merged);
                            }
                            continue;
                        }
                    }
                }
                (None, Some(_)) => {
                    self.old_idx += 1;
                    continue;
                }
                (Some(_), None) => {
                    self.new_idx += 1;
                    continue;
                }
                (None, None) => {
                    self.old_idx += 1;
                    self.new_idx += 1;
                    continue;
                }
            }
        }
    }
}

/// Merge multiple buckets in order (first is oldest).
pub fn merge_multiple(
    buckets: &[&Bucket],
    keep_dead_entries: bool,
    max_protocol_version: u32,
) -> Result<Bucket> {
    if buckets.is_empty() {
        return Ok(Bucket::empty());
    }

    let mut result = buckets[0].clone();

    for bucket in &buckets[1..] {
        result = merge_buckets(&result, bucket, keep_dead_entries, max_protocol_version)?;
    }

    Ok(result)
}

fn extract_metadata(entries: &[BucketEntry]) -> Option<BucketMetadata> {
    entries.iter().find_map(|entry| match entry {
        BucketEntry::Metadata(meta) => Some(meta.clone()),
        _ => None,
    })
}

fn build_output_metadata(
    old_meta: Option<&BucketMetadata>,
    new_meta: Option<&BucketMetadata>,
    max_protocol_version: u32,
) -> Result<(u32, Option<BucketEntry>)> {
    // Calculate the merge protocol version as max of input bucket versions.
    // This matches C++ stellar-core's calculateMergeProtocolVersion() in BucketBase.cpp.
    let mut protocol_version = 0u32;
    if let Some(meta) = old_meta {
        protocol_version = protocol_version.max(meta.ledger_version);
    }
    if let Some(meta) = new_meta {
        protocol_version = protocol_version.max(meta.ledger_version);
    }

    // Validate that the calculated version doesn't exceed max_protocol_version.
    // max_protocol_version is a constraint, not the output version.
    if max_protocol_version > 0 && protocol_version > max_protocol_version {
        return Err(BucketError::Merge(format!(
            "bucket protocol version {} exceeds max_protocol_version {}",
            protocol_version, max_protocol_version
        )));
    }

    let use_meta = protocol_version >= FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY;
    if !use_meta {
        return Ok((protocol_version, None));
    }

    let mut output = BucketMetadata {
        ledger_version: protocol_version,
        ext: BucketMetadataExt::V0,
    };

    // For Protocol 23+, Live buckets must use V1 extension with BucketListType::LIVE.
    // merge_buckets_with_options is specifically for the Live bucket list.
    if protocol_version >= FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION {
        output.ext = BucketMetadataExt::V1(stellar_xdr::curr::BucketListType::Live);
    }

    Ok((protocol_version, Some(BucketEntry::Metadata(output))))
}

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

    fn make_account_key(bytes: [u8; 32]) -> LedgerKey {
        LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id(bytes),
        })
    }

    #[test]
    fn test_merge_empty_buckets() {
        let empty1 = Bucket::empty();
        let empty2 = Bucket::empty();

        let merged = merge_buckets(&empty1, &empty2, true, 0).unwrap();
        assert!(merged.is_empty());
    }

    #[test]
    fn test_merge_with_empty() {
        let entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let bucket = Bucket::from_entries(entries).unwrap();
        let empty = Bucket::empty();

        // New is empty
        let merged = merge_buckets(&bucket, &empty, true, 0).unwrap();
        assert_eq!(merged.len(), 1);

        // Old is empty
        let merged = merge_buckets(&empty, &bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn test_merge_no_overlap() {
        let old_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Live(make_account_entry([2u8; 32], 200))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_merge_shadow() {
        let old_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 200))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 1);

        // Verify new entry won
        let key = make_account_key([1u8; 32]);
        let entry = merged.get_entry(&key).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry.data {
            assert_eq!(account.balance, 200);
        } else {
            panic!("Expected Account entry");
        }
    }

    #[test]
    fn test_merge_dead_shadows_live() {
        let old_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Dead(make_account_key([1u8; 32]))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        // With keep_dead_entries = true
        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 1);
        assert!(merged.entries()[0].is_dead());

        // With keep_dead_entries = false
        let merged = merge_buckets(&old_bucket, &new_bucket, false, 0).unwrap();
        assert_eq!(merged.len(), 0);
    }

    #[test]
    fn test_merge_init_to_live() {
        let entries = vec![BucketEntry::Init(make_account_entry([1u8; 32], 100))];
        let bucket = Bucket::from_entries(entries).unwrap();

        let merged = merge_buckets(&Bucket::empty(), &bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 1);

        // Init should be converted to Live
        assert!(merged.entries()[0].is_live());
    }

    #[test]
    fn test_merge_complex() {
        let old_entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
            BucketEntry::Live(make_account_entry([3u8; 32], 300)),
        ];

        let new_entries = vec![
            BucketEntry::Dead(make_account_key([1u8; 32])), // Delete first
            BucketEntry::Live(make_account_entry([2u8; 32], 250)), // Update second
            BucketEntry::Live(make_account_entry([4u8; 32], 400)), // Add new
        ];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();

        // Should have: Dead(1), Live(2, 250), Live(3, 300), Live(4, 400)
        assert_eq!(merged.len(), 4);

        // Verify entries
        let key1 = make_account_key([1u8; 32]);
        assert!(merged.get(&key1).unwrap().unwrap().is_dead());

        let key2 = make_account_key([2u8; 32]);
        let entry2 = merged.get_entry(&key2).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry2.data {
            assert_eq!(account.balance, 250);
        }

        let key3 = make_account_key([3u8; 32]);
        let entry3 = merged.get_entry(&key3).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry3.data {
            assert_eq!(account.balance, 300);
        }

        let key4 = make_account_key([4u8; 32]);
        let entry4 = merged.get_entry(&key4).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry4.data {
            assert_eq!(account.balance, 400);
        }
    }

    #[test]
    fn test_merge_iterator() {
        let old_entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([3u8; 32], 300)),
        ];

        let new_entries = vec![BucketEntry::Live(make_account_entry([2u8; 32], 200))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let iter = MergeIterator::new(&old_bucket, &new_bucket, true, 0);
        let merged: Vec<_> = iter.collect();

        assert_eq!(merged.len(), 3);
    }

    #[test]
    fn test_merge_multiple() {
        let bucket1 =
            Bucket::from_entries(vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))])
                .unwrap();

        let bucket2 =
            Bucket::from_entries(vec![BucketEntry::Live(make_account_entry([1u8; 32], 200))])
                .unwrap();

        let bucket3 =
            Bucket::from_entries(vec![BucketEntry::Live(make_account_entry([1u8; 32], 300))])
                .unwrap();

        let buckets = vec![&bucket1, &bucket2, &bucket3];
        let merged = merge_multiple(&buckets, true, 0).unwrap();

        assert_eq!(merged.len(), 1);

        let key = make_account_key([1u8; 32]);
        let entry = merged.get_entry(&key).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry.data {
            assert_eq!(account.balance, 300); // Newest wins
        }
    }

    // ============ CAP-0020 INITENTRY Tests ============

    #[test]
    fn test_cap0020_init_plus_dead_annihilation() {
        // CAP-0020: INITENTRY + DEADENTRY → Both annihilated
        let old_entries = vec![BucketEntry::Init(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Dead(make_account_key([1u8; 32]))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        // Even with keep_dead_entries = true, INIT + DEAD should annihilate
        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 0, "INIT + DEAD should produce nothing");
    }

    #[test]
    fn test_cap0020_dead_plus_init_becomes_live() {
        // CAP-0020: DEADENTRY + INITENTRY=x → Output as LIVEENTRY=x
        let old_entries = vec![BucketEntry::Dead(make_account_key([1u8; 32]))];
        let new_entries = vec![BucketEntry::Init(make_account_entry([1u8; 32], 200))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 1);
        assert!(
            merged.entries()[0].is_live(),
            "DEAD + INIT should become LIVE"
        );

        let key = make_account_key([1u8; 32]);
        let entry = merged.get_entry(&key).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry.data {
            assert_eq!(account.balance, 200);
        }
    }

    #[test]
    fn test_cap0020_init_plus_live_preserves_init() {
        // CAP-0020: INITENTRY=x + LIVEENTRY=y → Output as INITENTRY=y
        let old_entries = vec![BucketEntry::Init(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 200))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 1);

        // Should preserve INIT status with new value
        let entry = &merged.entries()[0];
        assert!(entry.is_init(), "INIT + LIVE should preserve INIT status");

        let _key = make_account_key([1u8; 32]);
        if let BucketEntry::Init(ledger_entry) = entry {
            if let LedgerEntryData::Account(account) = &ledger_entry.data {
                assert_eq!(account.balance, 200, "Should have new value");
            }
        }
    }

    #[test]
    fn test_cap0020_init_init_undefined() {
        // Two INITs for the same key should not happen in practice (it's undefined behavior).
        // Our implementation converts it to LIVE through the catch-all case.
        let old_entries = vec![BucketEntry::Init(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Init(make_account_entry([1u8; 32], 200))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 1);

        // New entry wins and becomes LIVE (via catch-all)
        let entry = &merged.entries()[0];
        assert!(
            entry.is_live(),
            "INIT + INIT should become LIVE (undefined case)"
        );

        let key = make_account_key([1u8; 32]);
        let ledger_entry = merged.get_entry(&key).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &ledger_entry.data {
            assert_eq!(account.balance, 200, "New value should win");
        }
    }

    #[test]
    fn test_cap0020_complex_scenario() {
        // Complex scenario testing multiple CAP-0020 rules
        let old_entries = vec![
            BucketEntry::Init(make_account_entry([1u8; 32], 100)), // Will be deleted (annihilated)
            BucketEntry::Dead(make_account_key([2u8; 32])),        // Will be recreated
            BucketEntry::Init(make_account_entry([3u8; 32], 300)), // Will be updated (preserve INIT)
            BucketEntry::Live(make_account_entry([4u8; 32], 400)), // Will be deleted
        ];

        let new_entries = vec![
            BucketEntry::Dead(make_account_key([1u8; 32])), // Annihilates with old INIT
            BucketEntry::Init(make_account_entry([2u8; 32], 200)), // Recreates, becomes LIVE
            BucketEntry::Live(make_account_entry([3u8; 32], 350)), // Updates, preserves INIT
            BucketEntry::Dead(make_account_key([4u8; 32])), // Deletes LIVE
        ];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();

        // Entry 1: INIT + DEAD = nothing (annihilated)
        let key1 = make_account_key([1u8; 32]);
        assert!(
            merged.get(&key1).unwrap().is_none(),
            "Entry 1 should be annihilated"
        );

        // Entry 2: DEAD + INIT = LIVE
        let key2 = make_account_key([2u8; 32]);
        let entry2 = merged.get(&key2).unwrap().unwrap();
        assert!(entry2.is_live(), "Entry 2 should be LIVE");

        // Entry 3: INIT + LIVE = INIT (preserved)
        let key3 = make_account_key([3u8; 32]);
        let entry3 = merged.get(&key3).unwrap().unwrap();
        assert!(entry3.is_init(), "Entry 3 should preserve INIT");

        // Entry 4: LIVE + DEAD = DEAD
        let key4 = make_account_key([4u8; 32]);
        let entry4 = merged.get(&key4).unwrap().unwrap();
        assert!(entry4.is_dead(), "Entry 4 should be DEAD");
    }

    // ============ In-Memory Level 0 Optimization Tests ============

    #[test]
    fn test_merge_in_memory_basic() {
        // Create buckets with in-memory entries enabled
        let old_entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];
        let new_entries = vec![
            BucketEntry::Live(make_account_entry([2u8; 32], 250)), // Update entry 2
            BucketEntry::Live(make_account_entry([3u8; 32], 300)), // Add new entry
        ];

        let old_bucket = Bucket::from_sorted_entries_with_in_memory(old_entries).unwrap();
        let new_bucket = Bucket::from_sorted_entries_with_in_memory(new_entries).unwrap();

        // Verify both have in-memory entries
        assert!(old_bucket.has_in_memory_entries());
        assert!(new_bucket.has_in_memory_entries());

        // Perform in-memory merge
        let merged = merge_in_memory(&old_bucket, &new_bucket, 25).unwrap();

        // Result should have in-memory entries
        assert!(merged.has_in_memory_entries());

        // Verify entries
        let key1 = make_account_key([1u8; 32]);
        let key2 = make_account_key([2u8; 32]);
        let key3 = make_account_key([3u8; 32]);

        let entry1 = merged.get_entry(&key1).unwrap().unwrap();
        let entry2 = merged.get_entry(&key2).unwrap().unwrap();
        let entry3 = merged.get_entry(&key3).unwrap().unwrap();

        if let LedgerEntryData::Account(a) = &entry1.data {
            assert_eq!(a.balance, 100);
        }
        if let LedgerEntryData::Account(a) = &entry2.data {
            assert_eq!(a.balance, 250); // Updated
        }
        if let LedgerEntryData::Account(a) = &entry3.data {
            assert_eq!(a.balance, 300);
        }
    }

    #[test]
    fn test_merge_in_memory_preserves_init_entries() {
        // INIT entries should NOT be normalized to LIVE in level 0 merges
        let old_entries = vec![BucketEntry::Init(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 200))];

        let old_bucket = Bucket::from_sorted_entries_with_in_memory(old_entries).unwrap();
        let new_bucket = Bucket::from_sorted_entries_with_in_memory(new_entries).unwrap();

        let merged = merge_in_memory(&old_bucket, &new_bucket, 25).unwrap();

        // INIT + LIVE should become INIT with new value
        let key = make_account_key([1u8; 32]);
        let entry = merged.get(&key).unwrap().unwrap();
        assert!(entry.is_init(), "Level 0 merge should preserve INIT status");

        if let BucketEntry::Init(le) = entry {
            if let LedgerEntryData::Account(a) = &le.data {
                assert_eq!(a.balance, 200, "Should have updated value");
            }
        }
    }

    #[test]
    fn test_merge_in_memory_keeps_tombstones() {
        // Level 0 merges should always keep tombstones
        let old_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Dead(make_account_key([1u8; 32]))];

        let old_bucket = Bucket::from_sorted_entries_with_in_memory(old_entries).unwrap();
        let new_bucket = Bucket::from_sorted_entries_with_in_memory(new_entries).unwrap();

        let merged = merge_in_memory(&old_bucket, &new_bucket, 25).unwrap();

        // Should have the dead entry
        let key = make_account_key([1u8; 32]);
        let entry = merged.get(&key).unwrap().unwrap();
        assert!(entry.is_dead(), "Level 0 merge should keep tombstones");
    }

    #[test]
    fn test_merge_in_memory_annihilation() {
        // INIT + DEAD should annihilate even in in-memory merge
        let old_entries = vec![BucketEntry::Init(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Dead(make_account_key([1u8; 32]))];

        let old_bucket = Bucket::from_sorted_entries_with_in_memory(old_entries).unwrap();
        let new_bucket = Bucket::from_sorted_entries_with_in_memory(new_entries).unwrap();

        let merged = merge_in_memory(&old_bucket, &new_bucket, 25).unwrap();

        // Entry should be annihilated
        let key = make_account_key([1u8; 32]);
        assert!(
            merged.get(&key).unwrap().is_none(),
            "INIT + DEAD should annihilate"
        );
    }

    #[test]
    fn test_fresh_in_memory_only() {
        // Test creating a shell bucket for immediate merging
        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        let bucket = Bucket::fresh_in_memory_only(entries.clone());

        // Should have in-memory entries
        assert!(bucket.has_in_memory_entries());

        // Hash should be ZERO (not computed)
        assert!(bucket.hash().is_zero());

        // Should be able to get in-memory entries
        let in_mem = bucket.get_in_memory_entries().unwrap();
        assert_eq!(in_mem.len(), 2);
    }

    // ============ Protocol Version Handling Regression Tests ============
    //
    // These tests verify the fix for bucket list hash divergence caused by
    // incorrect protocol version handling in merges.
    //
    // C++ stellar-core has TWO different merge behaviors:
    // 1. In-memory merge (level 0): Uses maxProtocolVersion directly
    // 2. Disk-based merge (levels 1+): Uses max(old_bucket_version, new_bucket_version)
    //
    // Our Rust code was incorrectly using max_protocol_version as output for ALL merges.

    #[test]
    fn test_build_output_metadata_uses_max_of_inputs() {
        // Regression test: build_output_metadata must use max(old, new) as output version,
        // NOT max_protocol_version. max_protocol_version is only a constraint.

        // Create metadata with different versions
        let old_meta = BucketMetadata {
            ledger_version: 20,
            ext: BucketMetadataExt::V0,
        };
        let new_meta = BucketMetadata {
            ledger_version: 22,
            ext: BucketMetadataExt::V0,
        };

        // max_protocol_version is 25 (current ledger), but output should be max(20, 22) = 22
        let (version, output_meta) =
            build_output_metadata(Some(&old_meta), Some(&new_meta), 25).unwrap();

        assert_eq!(
            version, 22,
            "Output version should be max(old=20, new=22) = 22, NOT max_protocol_version=25"
        );
        assert!(output_meta.is_some());
        if let Some(BucketEntry::Metadata(meta)) = output_meta {
            assert_eq!(meta.ledger_version, 22);
        }
    }

    #[test]
    fn test_build_output_metadata_validates_constraint() {
        // Regression test: max_protocol_version should be validated as a constraint
        let old_meta = BucketMetadata {
            ledger_version: 20,
            ext: BucketMetadataExt::V0,
        };
        let new_meta = BucketMetadata {
            ledger_version: 26, // Exceeds max_protocol_version
            ext: BucketMetadataExt::V0,
        };

        // Should fail because 26 > 25 (the constraint)
        let result = build_output_metadata(Some(&old_meta), Some(&new_meta), 25);
        assert!(
            result.is_err(),
            "Should fail when bucket version exceeds max_protocol_version constraint"
        );
    }

    #[test]
    fn test_build_output_metadata_with_only_old_meta() {
        // When only old bucket has metadata, output version = old version
        let old_meta = BucketMetadata {
            ledger_version: 18,
            ext: BucketMetadataExt::V0,
        };

        let (version, _) = build_output_metadata(Some(&old_meta), None, 25).unwrap();
        assert_eq!(version, 18, "Output version should be old bucket's version");
    }

    #[test]
    fn test_build_output_metadata_with_only_new_meta() {
        // When only new bucket has metadata, output version = new version
        let new_meta = BucketMetadata {
            ledger_version: 21,
            ext: BucketMetadataExt::V0,
        };

        let (version, _) = build_output_metadata(None, Some(&new_meta), 25).unwrap();
        assert_eq!(version, 21, "Output version should be new bucket's version");
    }

    #[test]
    fn test_build_output_metadata_no_metadata_inputs() {
        // When neither bucket has metadata (pre-protocol 11), output has no metadata
        let (version, output_meta) = build_output_metadata(None, None, 25).unwrap();
        assert_eq!(version, 0, "Version should be 0 when no metadata present");
        assert!(
            output_meta.is_none(),
            "No metadata should be output for pre-protocol-11 buckets"
        );
    }

    #[test]
    fn test_merge_in_memory_uses_max_protocol_version_directly() {
        // Regression test: merge_in_memory (level 0) uses max_protocol_version directly,
        // matching C++ LiveBucket::mergeInMemory behavior.

        // Create buckets with protocol version 20 metadata
        let old_meta = BucketMetadata {
            ledger_version: 20,
            ext: BucketMetadataExt::V0,
        };
        let new_meta = BucketMetadata {
            ledger_version: 20,
            ext: BucketMetadataExt::V0,
        };

        let old_entries = vec![
            BucketEntry::Metadata(old_meta),
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
        ];
        let new_entries = vec![
            BucketEntry::Metadata(new_meta),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        let old_bucket = Bucket::from_sorted_entries_with_in_memory(old_entries).unwrap();
        let new_bucket = Bucket::from_sorted_entries_with_in_memory(new_entries).unwrap();

        // Merge with max_protocol_version = 25 (current ledger's protocol)
        let merged = merge_in_memory(&old_bucket, &new_bucket, 25).unwrap();

        // The output metadata should use 25 (max_protocol_version), NOT 20 (max of inputs)
        let merged_entries: Vec<_> = merged.iter().collect();
        let meta_entry = merged_entries
            .iter()
            .find(|e| e.is_metadata())
            .expect("Merged bucket should have metadata");

        if let BucketEntry::Metadata(meta) = meta_entry {
            assert_eq!(
                meta.ledger_version, 25,
                "In-memory merge should use max_protocol_version=25 directly, NOT max(old,new)=20"
            );
        } else {
            panic!("Expected metadata entry");
        }
    }

    #[test]
    fn test_disk_merge_uses_max_of_inputs() {
        // Regression test: disk-based merge (merge_buckets) uses max(old, new) for version,
        // matching C++ BucketBase::merge/calculateMergeProtocolVersion behavior.

        // Create buckets with different protocol versions
        let old_meta = BucketMetadata {
            ledger_version: 18,
            ext: BucketMetadataExt::V0,
        };
        let new_meta = BucketMetadata {
            ledger_version: 22,
            ext: BucketMetadataExt::V0,
        };

        let old_entries = vec![
            BucketEntry::Metadata(old_meta),
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
        ];
        let new_entries = vec![
            BucketEntry::Metadata(new_meta),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        // Merge with max_protocol_version = 25 (current ledger's protocol)
        let merged = merge_buckets(&old_bucket, &new_bucket, true, 25).unwrap();

        // The output metadata should use max(18, 22) = 22, NOT 25
        let merged_entries: Vec<_> = merged.iter().collect();
        let meta_entry = merged_entries
            .iter()
            .find(|e| e.is_metadata())
            .expect("Merged bucket should have metadata");

        if let BucketEntry::Metadata(meta) = meta_entry {
            assert_eq!(
                meta.ledger_version, 22,
                "Disk merge should use max(old=18, new=22)=22, NOT max_protocol_version=25"
            );
        } else {
            panic!("Expected metadata entry");
        }
    }

    #[test]
    fn test_protocol_version_difference_in_memory_vs_disk() {
        // Regression test: Verify the key difference between in-memory and disk merges.
        // This is the exact scenario that caused bucket list hash divergence.

        let old_meta = BucketMetadata {
            ledger_version: 22,
            ext: BucketMetadataExt::V0,
        };
        let new_meta = BucketMetadata {
            ledger_version: 22,
            ext: BucketMetadataExt::V0,
        };

        let old_entries = vec![
            BucketEntry::Metadata(old_meta.clone()),
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
        ];
        let new_entries = vec![
            BucketEntry::Metadata(new_meta.clone()),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        // Create two sets of buckets
        let old_bucket_disk = Bucket::from_entries(old_entries.clone()).unwrap();
        let new_bucket_disk = Bucket::from_entries(new_entries.clone()).unwrap();

        let old_bucket_mem = Bucket::from_sorted_entries_with_in_memory(old_entries).unwrap();
        let new_bucket_mem = Bucket::from_sorted_entries_with_in_memory(new_entries).unwrap();

        // max_protocol_version = 25 (ledger's current protocol)
        let max_pv = 25u32;

        // Disk merge: uses max(old, new) = max(22, 22) = 22
        let merged_disk = merge_buckets(&old_bucket_disk, &new_bucket_disk, true, max_pv).unwrap();
        let disk_meta = merged_disk
            .iter()
            .find(|e| e.is_metadata())
            .expect("disk merged should have meta");

        // In-memory merge: uses max_protocol_version = 25 directly
        let merged_mem = merge_in_memory(&old_bucket_mem, &new_bucket_mem, max_pv).unwrap();
        let mem_meta = merged_mem
            .iter()
            .find(|e| e.is_metadata())
            .expect("mem merged should have meta");

        if let (BucketEntry::Metadata(disk_m), BucketEntry::Metadata(mem_m)) = (disk_meta, mem_meta)
        {
            assert_eq!(
                disk_m.ledger_version, 22,
                "Disk merge version should be max(inputs) = 22"
            );
            assert_eq!(
                mem_m.ledger_version, 25,
                "In-memory merge version should be max_protocol_version = 25"
            );
            assert_ne!(
                disk_m.ledger_version, mem_m.ledger_version,
                "Disk and in-memory merges should produce different versions when max_pv > max(inputs)"
            );
        } else {
            panic!("Expected metadata entries");
        }
    }
}
