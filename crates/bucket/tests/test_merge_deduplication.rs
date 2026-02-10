//! Integration tests for merge deduplication.
//!
//! These tests match the behavior of the upstream C++ BucketMergeMapTests.cpp
//! to ensure parity with stellar-core.

use std::collections::HashSet;

use henyey_bucket::{BucketMergeMap, FutureBucket, LiveMergeFutures, MergeKey};
use henyey_common::Hash256;

/// Creates a unique hash from a byte value.
fn make_hash(byte: u8) -> Hash256 {
    Hash256::from_bytes([byte; 32])
}

/// Creates a merge key from curr, snap, and keep_tombstones.
fn make_merge_key(curr: u8, snap: u8, keep_tombstones: bool) -> MergeKey {
    MergeKey::new(keep_tombstones, make_hash(curr), make_hash(snap))
}

/// Test matching upstream BucketMergeMapTests.cpp "bucket merge map" test case.
///
/// This test verifies:
/// - Recording merges with various input combinations
/// - Same output from multiple merges
/// - Shared inputs across merges
/// - Finding merges by merge key
/// - Getting outputs by input hash
/// - Forgetting merges by output hash
#[test]
fn test_bucket_merge_map_upstream_parity() {
    // Create unique input bucket hashes
    // in1a, in1b, in1c are inputs for merge m1
    let in1a = make_hash(1);
    let in1b = make_hash(2);

    // in2a, in2b are inputs for merge m2
    let in2a = make_hash(11);
    let in2b = make_hash(12);

    // in3a, in3b are inputs for merge m3
    let in3a = make_hash(21);
    let in3b = make_hash(22);

    // in4a, in4b are inputs for merge m4
    let in4a = make_hash(31);
    let in4b = make_hash(32);

    // in5a, in5b are inputs for merge m5 (not recorded)
    let in5a = make_hash(41);
    let in5b = make_hash(42);

    // in6a, in6b are inputs for merge m6 (reuses in1a)
    let in6a = make_hash(51);

    // Create unique output bucket hashes
    let out1 = make_hash(101);
    let out2 = make_hash(102);
    let out4 = make_hash(104);
    let out6 = make_hash(106);

    let mut bmm = BucketMergeMap::new();

    // Create merge keys
    // Note: Our MergeKey only takes curr and snap hashes, no shadows
    let m1 = MergeKey::new(true, in1a, in1b);
    let m2 = MergeKey::new(true, in2a, in2b);
    let m3 = MergeKey::new(true, in3a, in3b);
    let m4 = MergeKey::new(true, in4a, in4b);
    let m5 = MergeKey::new(true, in5a, in5b);
    let m6 = MergeKey::new(true, in6a, in1a); // Reuses in1a as snap

    // Record merges
    bmm.record_merge(m1.clone(), out1);
    bmm.record_merge(m2.clone(), out2);
    // m3 produces same output as m2
    bmm.record_merge(m3.clone(), out2);
    bmm.record_merge(m4.clone(), out4);
    // m5 isn't recorded
    // m6 reuses an input from m1 (in1a)
    bmm.record_merge(m6.clone(), out6);

    // Verify findMergeFor (get_output)
    assert_eq!(bmm.get_output(&m1), Some(&out1));
    assert_eq!(bmm.get_output(&m2), Some(&out2));
    assert_eq!(bmm.get_output(&m3), Some(&out2));
    assert_eq!(bmm.get_output(&m4), Some(&out4));
    assert_eq!(bmm.get_output(&m5), None); // Not recorded
    assert_eq!(bmm.get_output(&m6), Some(&out6));

    // Verify getOutputsUsingInput
    // in1a is used by m1 (producing out1) and m6 (producing out6)
    let outputs_for_in1a = bmm.get_outputs_for_input(&in1a).unwrap();
    assert!(outputs_for_in1a.contains(&out1));
    assert!(outputs_for_in1a.contains(&out6));
    assert_eq!(outputs_for_in1a.len(), 2);

    // in1b is only used by m1
    let outputs_for_in1b = bmm.get_outputs_for_input(&in1b).unwrap();
    assert!(outputs_for_in1b.contains(&out1));
    assert_eq!(outputs_for_in1b.len(), 1);

    // Verify forgetAllMergesProducing
    // Forget out1, should remove m1
    let removed = bmm.forget_all_merges_producing(&out1);
    assert_eq!(removed.len(), 1);
    assert!(removed.contains(&m1));
    assert_eq!(bmm.get_output(&m1), None);

    // After forgetting out1, in1a should only map to out6
    let outputs_for_in1a = bmm.get_outputs_for_input(&in1a).unwrap();
    assert!(!outputs_for_in1a.contains(&out1));
    assert!(outputs_for_in1a.contains(&out6));
    assert_eq!(outputs_for_in1a.len(), 1);

    // Forget out2, should remove both m2 and m3
    let removed = bmm.forget_all_merges_producing(&out2);
    assert_eq!(removed.len(), 2);
    assert!(removed.contains(&m2));
    assert!(removed.contains(&m3));
    assert_eq!(bmm.get_output(&m2), None);
    assert_eq!(bmm.get_output(&m3), None);

    // Forget out4, should remove m4
    let removed = bmm.forget_all_merges_producing(&out4);
    assert_eq!(removed.len(), 1);
    assert!(removed.contains(&m4));
    assert_eq!(bmm.get_output(&m4), None);

    // Forget out6, should remove m6
    let removed = bmm.forget_all_merges_producing(&out6);
    assert_eq!(removed.len(), 1);
    assert!(removed.contains(&m6));
    assert_eq!(bmm.get_output(&m6), None);

    // in6a should no longer map to any outputs
    assert!(bmm.get_outputs_for_input(&in6a).is_none());
    // in1a should also have no outputs now
    assert!(bmm.get_outputs_for_input(&in1a).is_none());

    // Second forget produces empty set
    let removed = bmm.forget_all_merges_producing(&out1);
    assert!(removed.is_empty());

    // Map should be empty now
    assert!(bmm.is_empty());
}

/// Test that multiple merges can produce the same output.
#[test]
fn test_multiple_merges_same_output() {
    let mut bmm = BucketMergeMap::new();

    // Two different merge keys produce the same output
    let m1 = make_merge_key(1, 2, true);
    let m2 = make_merge_key(3, 4, true);
    let output = make_hash(100);

    bmm.record_merge(m1.clone(), output);
    bmm.record_merge(m2.clone(), output);

    // Both should find the same output
    assert_eq!(bmm.get_output(&m1), Some(&output));
    assert_eq!(bmm.get_output(&m2), Some(&output));

    // Forgetting should remove both
    let removed = bmm.forget_all_merges_producing(&output);
    assert_eq!(removed.len(), 2);
    assert!(removed.contains(&m1));
    assert!(removed.contains(&m2));

    assert!(bmm.is_empty());
}

/// Test that keep_tombstones affects merge key identity.
#[test]
fn test_keep_tombstones_affects_identity() {
    let mut bmm = BucketMergeMap::new();

    // Same curr/snap but different keep_tombstones
    let m1 = make_merge_key(1, 2, true);
    let m2 = make_merge_key(1, 2, false);
    let out1 = make_hash(100);
    let out2 = make_hash(101);

    bmm.record_merge(m1.clone(), out1);
    bmm.record_merge(m2.clone(), out2);

    // They should be different merge keys
    assert_eq!(bmm.get_output(&m1), Some(&out1));
    assert_eq!(bmm.get_output(&m2), Some(&out2));
    assert_eq!(bmm.len(), 2);
}

/// Test live merge futures tracker for deduplication.
#[test]
fn test_live_merge_futures_deduplication() {
    let tracker = LiveMergeFutures::new();

    let key = make_merge_key(1, 2, true);
    let future = FutureBucket::clear();

    // First insertion creates new
    let f1 = tracker.get_or_insert(key.clone(), future);
    assert_eq!(tracker.len(), 1);

    // Getting should return same Arc and increment reattach count
    let f2 = tracker.get(&key).unwrap();
    assert!(std::sync::Arc::ptr_eq(&f1, &f2));

    // Inserting again should return existing
    let f3 = tracker.get_or_insert(key.clone(), FutureBucket::clear());
    assert!(std::sync::Arc::ptr_eq(&f1, &f3));

    let stats = tracker.stats();
    assert_eq!(stats.merges_started, 1);
    assert_eq!(stats.merges_reattached, 2); // get + second get_or_insert

    // Remove should mark as completed
    tracker.remove(&key);
    assert!(tracker.is_empty());

    let stats = tracker.stats();
    assert_eq!(stats.merges_completed, 1);
}

/// Test concurrent access to live merge futures.
#[test]
fn test_live_merge_futures_concurrent() {
    use std::sync::Arc;
    use std::thread;

    let tracker = Arc::new(LiveMergeFutures::new());

    // Spawn multiple threads that try to get_or_insert the same key
    let handles: Vec<_> = (0..10)
        .map(|_| {
            let tracker = Arc::clone(&tracker);
            thread::spawn(move || {
                let key = make_merge_key(1, 2, true);
                tracker.get_or_insert(key, FutureBucket::clear())
            })
        })
        .collect();

    // Collect all futures
    let futures: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All should point to the same underlying future
    for i in 1..futures.len() {
        assert!(std::sync::Arc::ptr_eq(&futures[0], &futures[i]));
    }

    // Only one merge should have been started
    let stats = tracker.stats();
    assert_eq!(stats.merges_started, 1);
    // 9 reattachments (first one starts, rest reattach)
    assert_eq!(stats.merges_reattached, 9);
}

/// Test retain_outputs garbage collection.
#[test]
fn test_retain_outputs_gc() {
    let mut bmm = BucketMergeMap::new();

    let m1 = make_merge_key(1, 2, true);
    let m2 = make_merge_key(3, 4, true);
    let m3 = make_merge_key(5, 6, true);
    let out1 = make_hash(100);
    let out2 = make_hash(101);
    let out3 = make_hash(102);

    bmm.record_merge(m1.clone(), out1);
    bmm.record_merge(m2.clone(), out2);
    bmm.record_merge(m3.clone(), out3);

    // Keep only out2
    let keep: HashSet<Hash256> = [out2].into_iter().collect();
    bmm.retain_outputs(&keep);

    // Only m2 should remain
    assert_eq!(bmm.len(), 1);
    assert_eq!(bmm.get_output(&m1), None);
    assert_eq!(bmm.get_output(&m2), Some(&out2));
    assert_eq!(bmm.get_output(&m3), None);
}

/// Test that input mappings are properly cleaned up.
#[test]
fn test_input_mapping_cleanup() {
    let mut bmm = BucketMergeMap::new();

    // Create two merges that share an input
    let shared_input = make_hash(1);
    let m1 = MergeKey::new(true, shared_input, make_hash(2));
    let m2 = MergeKey::new(true, make_hash(3), shared_input);
    let out1 = make_hash(100);
    let out2 = make_hash(101);

    bmm.record_merge(m1.clone(), out1);
    bmm.record_merge(m2.clone(), out2);

    // Shared input should map to both outputs
    let outputs = bmm.get_outputs_for_input(&shared_input).unwrap();
    assert_eq!(outputs.len(), 2);

    // Remove m1
    bmm.remove_merge(&m1);

    // Shared input should now only map to out2
    let outputs = bmm.get_outputs_for_input(&shared_input).unwrap();
    assert_eq!(outputs.len(), 1);
    assert!(outputs.contains(&out2));

    // Remove m2
    bmm.remove_merge(&m2);

    // Shared input should have no mappings
    assert!(bmm.get_outputs_for_input(&shared_input).is_none());
}
