//! Merge deduplication for bucket merging.
//!
//! This module provides tracking for bucket merge operations to enable
//! deduplication and reattachment of in-progress merges. When the same
//! merge is requested multiple times (same inputs), the existing merge
//! can be reattached rather than starting a new one.
//!
//! # Deduplication Strategy
//!
//! Merges are identified by their [`MergeKey`], which consists of:
//! - The hash of the curr bucket
//! - The hash of the snap bucket
//! - Whether tombstones are kept (affects merge behavior)
//!
//! When a merge is requested:
//! 1. Check if a merge with the same key is already in progress
//! 2. If so, return the existing future (reattachment)
//! 3. If not, start a new merge and register it
//!
//! # Memory Management
//!
//! The merge map tracks relationships between input and output buckets:
//! - `input_to_output`: Maps input bucket hashes to output hashes
//! - `output_to_merge_key`: Maps output hashes to merge keys for GC
//!
//! When outputs are no longer referenced, their entries can be cleaned up.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::RwLock;
use henyey_common::Hash256;

use crate::future_bucket::{FutureBucket, MergeKey};

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

// ============================================================================
// Live Merge Futures Tracker
// ============================================================================

/// Tracks in-progress merge operations for reattachment.
///
/// This structure holds references to `FutureBucket` instances that are
/// currently merging, allowing new requests for the same merge to reattach
/// to the existing operation.
pub struct LiveMergeFutures {
    /// Maps merge keys to in-progress futures.
    futures: RwLock<HashMap<MergeKey, Arc<RwLock<FutureBucket>>>>,
    /// Statistics about merge operations.
    stats: RwLock<MergeFuturesStats>,
}

/// Statistics about merge future operations.
#[derive(Debug, Clone, Default)]
pub struct MergeFuturesStats {
    /// Number of new merges started.
    pub merges_started: u64,
    /// Number of merge reattachments (deduplication hits).
    pub merges_reattached: u64,
    /// Number of merges completed.
    pub merges_completed: u64,
}

impl LiveMergeFutures {
    /// Creates a new futures tracker.
    pub fn new() -> Self {
        Self {
            futures: RwLock::new(HashMap::new()),
            stats: RwLock::new(MergeFuturesStats::default()),
        }
    }

    /// Gets an existing merge future for the given key.
    ///
    /// Returns `Some` if a merge with this key is already in progress.
    pub fn get(&self, merge_key: &MergeKey) -> Option<Arc<RwLock<FutureBucket>>> {
        let futures = self.futures.read();
        if let Some(future) = futures.get(merge_key) {
            self.stats.write().merges_reattached += 1;
            Some(Arc::clone(future))
        } else {
            None
        }
    }

    /// Registers a new merge future.
    ///
    /// If a future with this key already exists, returns the existing one.
    /// Otherwise, inserts the new future and returns it.
    pub fn get_or_insert(
        &self,
        merge_key: MergeKey,
        future: FutureBucket,
    ) -> Arc<RwLock<FutureBucket>> {
        let mut futures = self.futures.write();

        // Check if already exists
        if let Some(existing) = futures.get(&merge_key) {
            self.stats.write().merges_reattached += 1;
            return Arc::clone(existing);
        }

        // Insert new
        let future = Arc::new(RwLock::new(future));
        futures.insert(merge_key, Arc::clone(&future));
        self.stats.write().merges_started += 1;
        future
    }

    /// Removes a completed merge future.
    pub fn remove(&self, merge_key: &MergeKey) -> Option<Arc<RwLock<FutureBucket>>> {
        let mut futures = self.futures.write();
        if let Some(future) = futures.remove(merge_key) {
            self.stats.write().merges_completed += 1;
            Some(future)
        } else {
            None
        }
    }

    /// Returns the number of in-progress merges.
    pub fn len(&self) -> usize {
        self.futures.read().len()
    }

    /// Checks if there are no in-progress merges.
    pub fn is_empty(&self) -> bool {
        self.futures.read().is_empty()
    }

    /// Returns statistics about merge operations.
    pub fn stats(&self) -> MergeFuturesStats {
        self.stats.read().clone()
    }

    /// Clears all tracked futures.
    pub fn clear(&self) {
        self.futures.write().clear();
    }

    /// Removes all completed futures.
    ///
    /// A future is considered completed if it's in the `LiveOutput` state.
    pub fn cleanup_completed(&self) {
        let mut futures = self.futures.write();
        let keys_to_remove: Vec<MergeKey> = futures
            .iter()
            .filter_map(|(key, future)| {
                let fb = future.read();
                if fb.merge_complete() {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        let mut stats = self.stats.write();
        for key in keys_to_remove {
            futures.remove(&key);
            stats.merges_completed += 1;
        }
    }
}

impl Default for LiveMergeFutures {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for LiveMergeFutures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveMergeFutures")
            .field("count", &self.len())
            .field("stats", &self.stats())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn make_merge_key(curr: u8, snap: u8, keep_tombstones: bool) -> MergeKey {
        MergeKey::new(keep_tombstones, make_hash(curr), make_hash(snap))
    }

    #[test]
    fn test_bucket_merge_map_basic() {
        let mut map = BucketMergeMap::new();
        assert!(map.is_empty());

        let key = make_merge_key(1, 2, true);
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

        let key1 = make_merge_key(1, 2, true);
        let key2 = make_merge_key(3, 4, true);
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

        let key1 = make_merge_key(1, 2, true);
        let key2 = make_merge_key(3, 4, true);
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
    fn test_live_merge_futures_basic() {
        let tracker = LiveMergeFutures::new();
        assert!(tracker.is_empty());

        let key = make_merge_key(1, 2, true);
        let future = FutureBucket::clear();

        let f1 = tracker.get_or_insert(key.clone(), future);
        assert_eq!(tracker.len(), 1);

        // Getting again should return same Arc
        let f2 = tracker.get(&key).unwrap();
        assert!(Arc::ptr_eq(&f1, &f2));

        let stats = tracker.stats();
        assert_eq!(stats.merges_started, 1);
        assert_eq!(stats.merges_reattached, 1);
    }

    #[test]
    fn test_live_merge_futures_remove() {
        let tracker = LiveMergeFutures::new();

        let key = make_merge_key(1, 2, true);
        let future = FutureBucket::clear();

        tracker.get_or_insert(key.clone(), future);
        assert_eq!(tracker.len(), 1);

        tracker.remove(&key);
        assert!(tracker.is_empty());

        let stats = tracker.stats();
        assert_eq!(stats.merges_completed, 1);
    }

    #[test]
    fn test_merge_key_equality() {
        let key1 = make_merge_key(1, 2, true);
        let key2 = make_merge_key(1, 2, true);
        let key3 = make_merge_key(1, 2, false);
        let key4 = make_merge_key(1, 3, true);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3); // Different keep_tombstones
        assert_ne!(key1, key4); // Different snap_hash
    }
}
