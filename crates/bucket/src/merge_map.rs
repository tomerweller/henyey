//! Merge deduplication for bucket merging.
//!
//! This module provides a completed-merge output cache (`BucketMergeMap`) that
//! tracks the relationship between merge inputs and their output buckets,
//! enabling reuse of previously computed merge results.
//!
//! # Merge Key
//!
//! Merges are identified by their [`MergeKey`], which consists of:
//! - The hash of the curr bucket
//! - The hash of the snap bucket
//! - Whether tombstones are kept (affects merge behavior)
//!
//! # Memory Management
//!
//! The merge map tracks relationships between input and output buckets:
//! - `input_to_output`: Maps input bucket hashes to output hashes
//! - `output_to_merge_key`: Maps output hashes to merge keys for GC
//!
//! When outputs are no longer referenced, their entries can be cleaned up.

use std::collections::{HashMap, HashSet};

use henyey_common::Hash256;

use crate::future_bucket::MergeKey;

// ============================================================================
// Bucket Merge Map
// ============================================================================

/// Tracks merge operations for deduplication.
///
/// This structure maintains the relationship between merge inputs and outputs,
/// enabling:
/// - Deduplication of concurrent merge requests
/// - Reattachment to in-progress merges
/// - Garbage collection of completed merge records
#[derive(Debug, Default)]
pub struct BucketMergeMap {
    /// Maps merge keys to output bucket hashes (for completed merges).
    merge_key_to_output: HashMap<MergeKey, Hash256>,
    /// Maps input bucket hashes to the set of output bucket hashes they produced.
    input_to_output: HashMap<Hash256, HashSet<Hash256>>,
    /// Maps output bucket hashes to the merge keys that produced them.
    output_to_merge_key: HashMap<Hash256, Vec<MergeKey>>,
}

impl BucketMergeMap {
    /// Creates a new empty merge map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a completed merge.
    ///
    /// # Arguments
    ///
    /// * `merge_key` - The key identifying the merge operation
    /// * `output_hash` - The hash of the resulting merged bucket
    pub fn record_merge(&mut self, merge_key: MergeKey, output_hash: Hash256) {
        // Record merge key -> output
        self.merge_key_to_output
            .insert(merge_key.clone(), output_hash);

        // Record input -> output mappings
        self.input_to_output
            .entry(merge_key.curr_hash)
            .or_default()
            .insert(output_hash);
        self.input_to_output
            .entry(merge_key.snap_hash)
            .or_default()
            .insert(output_hash);

        // Record output -> merge key mapping
        self.output_to_merge_key
            .entry(output_hash)
            .or_default()
            .push(merge_key);
    }

    /// Gets the output hash for a merge if it was previously completed.
    pub fn get_output(&self, merge_key: &MergeKey) -> Option<&Hash256> {
        self.merge_key_to_output.get(merge_key)
    }

    /// Checks if a merge was previously completed.
    pub fn has_output(&self, merge_key: &MergeKey) -> bool {
        self.merge_key_to_output.contains_key(merge_key)
    }

    /// Gets all outputs that used a given input bucket.
    pub fn get_outputs_for_input(&self, input_hash: &Hash256) -> Option<&HashSet<Hash256>> {
        self.input_to_output.get(input_hash)
    }

    /// Removes a merge record.
    ///
    /// This should be called when the output bucket is no longer needed.
    pub fn remove_merge(&mut self, merge_key: &MergeKey) {
        if let Some(output_hash) = self.merge_key_to_output.remove(merge_key) {
            // Remove from input mappings
            if let Some(outputs) = self.input_to_output.get_mut(&merge_key.curr_hash) {
                outputs.remove(&output_hash);
                if outputs.is_empty() {
                    self.input_to_output.remove(&merge_key.curr_hash);
                }
            }
            if let Some(outputs) = self.input_to_output.get_mut(&merge_key.snap_hash) {
                outputs.remove(&output_hash);
                if outputs.is_empty() {
                    self.input_to_output.remove(&merge_key.snap_hash);
                }
            }

            // Remove from output mapping
            if let Some(keys) = self.output_to_merge_key.get_mut(&output_hash) {
                keys.retain(|k| k != merge_key);
                if keys.is_empty() {
                    self.output_to_merge_key.remove(&output_hash);
                }
            }
        }
    }

    /// Removes all merge records for outputs not in the given set.
    ///
    /// Spec: BUCKETLISTDB_SPEC §8.2 (analogue) — retains only merge outputs referenced
    /// by the current bucket list. Henyey's GC model differs from stellar-core's
    /// refcount-based approach.
    ///
    /// This is used for garbage collection when buckets are removed.
    pub fn retain_outputs(&mut self, keep: &HashSet<Hash256>) {
        // Find merge keys to remove
        let keys_to_remove: Vec<MergeKey> = self
            .merge_key_to_output
            .iter()
            .filter(|(_, output)| !keep.contains(*output))
            .map(|(key, _)| key.clone())
            .collect();

        // Remove them
        for key in keys_to_remove {
            self.remove_merge(&key);
        }
    }

    /// Removes all merge records that produce the given output hash.
    ///
    /// Spec: BUCKETLISTDB_SPEC §8.2 (analogue) — removes merge map entries producing
    /// a given output hash.
    ///
    /// Returns the set of merge keys that were removed.
    /// This is the Rust equivalent of stellar-core `forgetAllMergesProducing`.
    pub fn forget_all_merges_producing(&mut self, output_hash: &Hash256) -> HashSet<MergeKey> {
        // Get all merge keys that produced this output
        let keys_to_remove: Vec<MergeKey> = self
            .output_to_merge_key
            .get(output_hash)
            .cloned()
            .unwrap_or_default();

        let mut removed = HashSet::new();
        for key in keys_to_remove {
            if self.merge_key_to_output.get(&key) == Some(output_hash) {
                self.remove_merge(&key);
                removed.insert(key);
            }
        }
        removed
    }

    /// Returns the number of recorded merges.
    pub fn len(&self) -> usize {
        self.merge_key_to_output.len()
    }

    /// Checks if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.merge_key_to_output.is_empty()
    }

    /// Clears all recorded merges.
    pub fn clear(&mut self) {
        self.merge_key_to_output.clear();
        self.input_to_output.clear();
        self.output_to_merge_key.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge::DeadEntryPolicy;

    fn make_hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn make_merge_key(curr: u8, snap: u8, keep_tombstones: DeadEntryPolicy) -> MergeKey {
        MergeKey::new(keep_tombstones, make_hash(curr), make_hash(snap))
    }

    #[test]
    fn test_bucket_merge_map_basic() {
        let mut map = BucketMergeMap::new();
        assert!(map.is_empty());

        let key = make_merge_key(1, 2, DeadEntryPolicy::Keep);
        let output = make_hash(3);

        map.record_merge(key.clone(), output);
        assert_eq!(map.len(), 1);
        assert!(map.has_output(&key));
        assert_eq!(map.get_output(&key), Some(&output));

        // Check input -> output mapping
        let outputs = map.get_outputs_for_input(&make_hash(1)).unwrap();
        assert!(outputs.contains(&output));
    }

    #[test]
    fn test_bucket_merge_map_remove() {
        let mut map = BucketMergeMap::new();

        let key1 = make_merge_key(1, 2, DeadEntryPolicy::Keep);
        let key2 = make_merge_key(3, 4, DeadEntryPolicy::Keep);
        let output1 = make_hash(10);
        let output2 = make_hash(11);

        map.record_merge(key1.clone(), output1);
        map.record_merge(key2.clone(), output2);
        assert_eq!(map.len(), 2);

        map.remove_merge(&key1);
        assert_eq!(map.len(), 1);
        assert!(!map.has_output(&key1));
        assert!(map.has_output(&key2));
    }

    #[test]
    fn test_bucket_merge_map_retain() {
        let mut map = BucketMergeMap::new();

        let key1 = make_merge_key(1, 2, DeadEntryPolicy::Keep);
        let key2 = make_merge_key(3, 4, DeadEntryPolicy::Keep);
        let output1 = make_hash(10);
        let output2 = make_hash(11);

        map.record_merge(key1.clone(), output1);
        map.record_merge(key2.clone(), output2);

        // Keep only output2
        let keep: HashSet<Hash256> = [output2].into_iter().collect();
        map.retain_outputs(&keep);

        assert_eq!(map.len(), 1);
        assert!(!map.has_output(&key1));
        assert!(map.has_output(&key2));
    }

    #[test]
    fn test_merge_key_equality() {
        let key1 = make_merge_key(1, 2, DeadEntryPolicy::Keep);
        let key2 = make_merge_key(1, 2, DeadEntryPolicy::Keep);
        let key3 = make_merge_key(1, 2, DeadEntryPolicy::Remove);
        let key4 = make_merge_key(1, 3, DeadEntryPolicy::Keep);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3); // Different keep_tombstones
        assert_ne!(key1, key4); // Different snap_hash
    }
}
