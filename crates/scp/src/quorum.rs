//! Quorum set operations for SCP.
//!
//! This module provides core utilities for working with quorum sets in the
//! Stellar Consensus Protocol. Quorum sets define which validators a node
//! trusts and how consensus decisions are made.
//!
//! # Key Concepts
//!
//! ## Quorum Slice
//!
//! A quorum slice is a set of nodes that a particular node trusts for consensus.
//! Each node defines its own quorum slice. A slice is satisfied when at least
//! `threshold` of its members (validators or inner sets) agree.
//!
//! ## Quorum
//!
//! A quorum is a set of nodes where every member's quorum slice is satisfied
//! by other members of the set. Quorums are used to confirm values - when a
//! quorum agrees, the decision is irreversible.
//!
//! ## Blocking Set (V-Blocking)
//!
//! A blocking set intersects every quorum slice, meaning it can prevent
//! any quorum from being formed. Blocking sets are used to accept values -
//! if a blocking set accepts a value, the node must accept it too.
//!
//! # Quorum Set Structure
//!
//! A quorum set consists of:
//! - `threshold`: Minimum number of members that must agree
//! - `validators`: Direct validator nodes in the slice
//! - `inner_sets`: Nested quorum sets (for hierarchical trust)
//!
//! # Example
//!
//! ```ignore
//! // A 2-of-3 quorum set
//! let qs = simple_quorum_set(2, vec![node_a, node_b, node_c]);
//!
//! // Check if nodes form a quorum
//! let nodes = HashSet::from([node_a, node_b]);
//! if is_quorum(&qs, &nodes, get_quorum_set) {
//!     // Nodes form a quorum
//! }
//! ```

use std::collections::HashSet;

use henyey_common::Hash256;
use stellar_xdr::curr::{NodeId, ScpQuorumSet};

/// Maximum allowed nesting level for quorum sets.
///
/// This constant defines the maximum depth of nested inner sets allowed
/// in a quorum set. This limit prevents excessive recursion during
/// quorum set validation and ensures bounded memory usage.
///
/// The value matches the stellar-core implementation.
pub const MAXIMUM_QUORUM_NESTING_LEVEL: u32 = 4;

/// Maximum allowed number of nodes in a quorum set.
///
/// This constant defines the maximum total number of unique nodes
/// (validators) that can be referenced in a quorum set, including
/// all nested inner sets.
///
/// The value matches the stellar-core implementation.
pub const MAXIMUM_QUORUM_NODES: usize = 1000;

/// Check if a set of nodes satisfies a quorum slice.
///
/// A quorum slice is satisfied if at least `threshold` of its members
/// (validators + inner sets) are satisfied.
///
/// # Arguments
/// * `quorum_set` - The quorum set defining the slice
/// * `nodes` - The set of nodes to check
/// * `get_quorum_set` - Function to get quorum set for a node
///
/// # Returns
/// True if the nodes satisfy this quorum slice.
// `get_quorum_set` is threaded through recursion to maintain a uniform interface
// with `is_quorum`, which calls this function. Clippy's lint is a false positive.
#[allow(clippy::only_used_in_recursion)]
pub fn is_quorum_slice<F>(
    quorum_set: &ScpQuorumSet,
    nodes: &HashSet<NodeId>,
    get_quorum_set: &F,
) -> bool
where
    F: Fn(&NodeId) -> Option<ScpQuorumSet>,
{
    let threshold = quorum_set.threshold as usize;
    if threshold == 0 {
        return true;
    }

    let mut count = 0;

    // Count validators
    for validator in quorum_set.validators.iter() {
        if nodes.contains(validator) {
            count += 1;
            if count >= threshold {
                return true;
            }
        }
    }

    // Count inner sets
    for inner_set in quorum_set.inner_sets.iter() {
        if is_quorum_slice(inner_set, nodes, get_quorum_set) {
            count += 1;
            if count >= threshold {
                return true;
            }
        }
    }

    count >= threshold
}

/// Check if a set of nodes forms a quorum.
///
/// Uses iterative pruning to find a quorum within the given set of nodes.
/// Repeatedly removes nodes whose quorum slices aren't satisfied by the
/// remaining set until the set stabilizes. Then checks if the local node's
/// quorum slice is satisfied by the surviving set.
///
/// This matches the stellar-core `LocalNode::isQuorum()` behavior, which allows
/// finding valid quorums as subsets of the input nodes.
///
/// # Arguments
/// * `quorum_set` - The local node's quorum set
/// * `nodes` - The set of nodes to check
/// * `get_quorum_set` - Function to get quorum set for a node
///
/// # Returns
/// True if a subset of the nodes forms a quorum that satisfies the local
/// node's quorum slice.
pub fn is_quorum<F>(quorum_set: &ScpQuorumSet, nodes: &HashSet<NodeId>, get_quorum_set: F) -> bool
where
    F: Fn(&NodeId) -> Option<ScpQuorumSet>,
{
    // Iteratively prune nodes whose quorum slices aren't satisfied
    // until the set stabilizes (matches stellar-core do-while loop in LocalNode::isQuorum)
    let mut remaining: Vec<NodeId> = nodes.iter().cloned().collect();

    loop {
        let count = remaining.len();

        // Keep only nodes whose quorum slices are satisfied by the current set
        let remaining_set: HashSet<NodeId> = remaining.iter().cloned().collect();
        remaining.retain(|node_id| {
            if let Some(qs) = get_quorum_set(node_id) {
                is_quorum_slice(&qs, &remaining_set, &get_quorum_set)
            } else {
                false
            }
        });

        if remaining.len() == count {
            break;
        }
    }

    // Check if the local node's quorum slice is satisfied by the surviving set
    let remaining_set: HashSet<NodeId> = remaining.into_iter().collect();
    is_quorum_slice(quorum_set, &remaining_set, &get_quorum_set)
}

/// Check if a set of nodes is a blocking set.
///
/// A set B is a blocking set if it intersects every quorum slice.
/// This means that no quorum can be formed without at least one
/// node from B participating.
///
/// # Arguments
/// * `quorum_set` - The quorum set to check against
/// * `nodes` - The set of nodes to check
///
/// # Returns
/// True if the nodes form a blocking set.
pub fn is_blocking_set(quorum_set: &ScpQuorumSet, nodes: &HashSet<NodeId>) -> bool {
    is_blocking_set_helper(quorum_set, nodes)
}

fn is_blocking_set_helper(quorum_set: &ScpQuorumSet, nodes: &HashSet<NodeId>) -> bool {
    let total = quorum_set.validators.len() + quorum_set.inner_sets.len();
    let threshold = quorum_set.threshold as usize;

    // There is no v-blocking set for the empty set (matches stellar-core LocalNode::isVBlockingInternal)
    if threshold == 0 {
        return false;
    }

    // We need to block (total - threshold + 1) members to prevent any quorum slice
    let blocking_threshold = total.saturating_sub(threshold) + 1;

    let mut count = 0;

    // Count validators in the blocking set
    for validator in quorum_set.validators.iter() {
        if nodes.contains(validator) {
            count += 1;
        }
    }

    // Count inner sets that are blocked
    for inner_set in quorum_set.inner_sets.iter() {
        if is_blocking_set_helper(inner_set, nodes) {
            count += 1;
        }
    }

    count >= blocking_threshold
}

/// Check if a set of nodes is a v-blocking set for a given quorum set.
///
/// A set B is v-blocking for node v if B intersects all of v's quorum slices.
/// This is equivalent to is_blocking_set for the node's quorum set.
pub fn is_v_blocking(quorum_set: &ScpQuorumSet, nodes: &HashSet<NodeId>) -> bool {
    is_blocking_set(quorum_set, nodes)
}

/// Check if a quorum set is sane.
///
/// This validates structural constraints, duplicate nodes, and optionally
/// enforces a safety threshold (> 50%).
pub fn is_quorum_set_sane(quorum_set: &ScpQuorumSet, extra_checks: bool) -> Result<(), String> {
    let mut checker = QuorumSetSanityChecker {
        extra_checks,
        known_nodes: HashSet::new(),
        count: 0,
    };
    checker.check_sanity(quorum_set, 0)?;

    if checker.count < 1 || checker.count > MAXIMUM_QUORUM_NODES {
        return Err("Total number of nodes in a quorum must be within 1 and 1000".to_string());
    }

    Ok(())
}

struct QuorumSetSanityChecker {
    extra_checks: bool,
    known_nodes: HashSet<NodeId>,
    count: usize,
}

impl QuorumSetSanityChecker {
    fn check_sanity(&mut self, quorum_set: &ScpQuorumSet, depth: u32) -> Result<(), String> {
        if depth > MAXIMUM_QUORUM_NESTING_LEVEL {
            return Err("Maximum quorum nesting level exceeded".to_string());
        }

        if quorum_set.threshold < 1 {
            return Err("Threshold must be greater than 0".to_string());
        }

        let total = quorum_set.validators.len() + quorum_set.inner_sets.len();
        if quorum_set.threshold as usize > total {
            return Err("Threshold exceeds total number of entries".to_string());
        }

        let v_blocking_size = total.saturating_sub(quorum_set.threshold as usize) + 1;
        if self.extra_checks && (quorum_set.threshold as usize) < v_blocking_size {
            return Err("Threshold is lower than the v-blocking size (< 51%).".to_string());
        }

        self.count = self.count.saturating_add(quorum_set.validators.len());
        for node in quorum_set.validators.iter() {
            if !self.known_nodes.insert(node.clone()) {
                return Err("Duplicate node found in quorum configuration".to_string());
            }
        }

        for inner in quorum_set.inner_sets.iter() {
            self.check_sanity(inner, depth + 1)?;
        }

        Ok(())
    }
}

/// Find the closest v-blocking set for a quorum set.
///
/// Returns a minimal set of nodes from `nodes` that would v-block the quorum
/// set, excluding `excluded` if provided. An empty result means the set is
/// already v-blocking.
pub fn find_closest_v_blocking(
    quorum_set: &ScpQuorumSet,
    nodes: &HashSet<NodeId>,
    excluded: Option<&NodeId>,
) -> Vec<NodeId> {
    let mut left_till_block =
        1i64 + quorum_set.validators.len() as i64 + quorum_set.inner_sets.len() as i64
            - quorum_set.threshold as i64;

    if left_till_block <= 0 {
        return Vec::new();
    }

    let mut res = Vec::new();

    for validator in quorum_set.validators.iter() {
        if excluded == Some(validator) {
            continue;
        }

        if nodes.contains(validator) {
            res.push(validator.clone());
        } else {
            left_till_block -= 1;
            if left_till_block == 0 {
                return Vec::new();
            }
        }
    }

    let mut res_internals: Vec<(usize, usize, Vec<NodeId>)> = Vec::new();
    for (index, inner) in quorum_set.inner_sets.iter().enumerate() {
        let v = find_closest_v_blocking(inner, nodes, excluded);
        if v.is_empty() {
            left_till_block -= 1;
            if left_till_block == 0 {
                return Vec::new();
            }
        } else {
            res_internals.push((v.len(), index, v));
        }
    }

    if res.len() > left_till_block as usize {
        res.truncate(left_till_block as usize);
    }
    left_till_block -= res.len() as i64;

    res_internals.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut idx = 0;
    while left_till_block != 0 && idx < res_internals.len() {
        res.extend(res_internals[idx].2.iter().cloned());
        left_till_block -= 1;
        idx += 1;
    }

    res
}

/// Compute the hash of a quorum set.
///
/// This hash is used to reference quorum sets by their content
/// in SCP messages, allowing efficient comparison and storage.
pub fn hash_quorum_set(quorum_set: &ScpQuorumSet) -> Hash256 {
    Hash256::hash_xdr(quorum_set).unwrap_or(Hash256::ZERO)
}

/// Normalize a quorum set by sorting validators and inner sets.
///
/// This ensures consistent hashing regardless of the order in which
/// validators were added to the quorum set.
///
/// If `id_to_remove` is provided, removes that node from the quorum set
/// at all levels and adjusts thresholds accordingly. This is used during
/// the EXTERNALIZE phase and leader computation to exclude a node from
/// the quorum set while maintaining correct semantics.
pub fn normalize_quorum_set(quorum_set: &mut ScpQuorumSet) {
    normalize_quorum_set_with_remove(quorum_set, None);
}

/// Normalize a quorum set, optionally removing a node.
///
/// Like `normalize_quorum_set`, but accepts an optional `id_to_remove`
/// parameter that removes the specified node from validators at all levels
/// and decrements thresholds accordingly. Matches the stellar-core `normalizeQSet`
/// function signature.
pub fn normalize_quorum_set_with_remove(
    quorum_set: &mut ScpQuorumSet,
    id_to_remove: Option<&NodeId>,
) {
    normalize_quorum_set_simplify(quorum_set, id_to_remove);

    let mut validators: Vec<_> = quorum_set.validators.iter().cloned().collect();
    validators.sort_by(node_id_cmp);
    quorum_set.validators = validators.try_into().unwrap_or_default();

    let mut inner_sets: Vec<_> = quorum_set.inner_sets.iter().cloned().collect();
    for inner_set in &mut inner_sets {
        // Only pass id_to_remove for the simplify step (already done above recursively),
        // but the reorder step doesn't need it again
        normalize_quorum_set_reorder(inner_set);
    }

    inner_sets.sort_by(quorum_set_cmp);
    quorum_set.inner_sets = inner_sets.try_into().unwrap_or_default();
}

fn normalize_quorum_set_reorder(quorum_set: &mut ScpQuorumSet) {
    let mut validators: Vec<_> = quorum_set.validators.iter().cloned().collect();
    validators.sort_by(node_id_cmp);
    quorum_set.validators = validators.try_into().unwrap_or_default();

    let mut inner_sets: Vec<_> = quorum_set.inner_sets.iter().cloned().collect();
    for inner_set in &mut inner_sets {
        normalize_quorum_set_reorder(inner_set);
    }

    inner_sets.sort_by(quorum_set_cmp);
    quorum_set.inner_sets = inner_sets.try_into().unwrap_or_default();
}

fn normalize_quorum_set_simplify(quorum_set: &mut ScpQuorumSet, id_to_remove: Option<&NodeId>) {
    let mut inner_sets: Vec<ScpQuorumSet> = quorum_set.inner_sets.iter().cloned().collect();
    let mut merged_validators: Vec<NodeId> = quorum_set.validators.iter().cloned().collect();

    // Remove the specified node from validators and adjust threshold
    if let Some(id) = id_to_remove {
        let original_len = merged_validators.len();
        merged_validators.retain(|n| n != id);
        let removed_count = original_len - merged_validators.len();
        quorum_set.threshold = quorum_set.threshold.saturating_sub(removed_count as u32);
    }

    let mut idx = 0;
    while idx < inner_sets.len() {
        normalize_quorum_set_simplify(&mut inner_sets[idx], id_to_remove);

        let is_singleton = inner_sets[idx].threshold == 1
            && inner_sets[idx].validators.len() == 1
            && inner_sets[idx].inner_sets.is_empty();
        if is_singleton {
            merged_validators.push(inner_sets[idx].validators[0].clone());
            inner_sets.remove(idx);
        } else {
            idx += 1;
        }
    }

    quorum_set.validators = merged_validators.try_into().unwrap_or_default();
    quorum_set.inner_sets = inner_sets.try_into().unwrap_or_default();

    if quorum_set.threshold == 1
        && quorum_set.validators.is_empty()
        && quorum_set.inner_sets.len() == 1
    {
        let inner = quorum_set.inner_sets[0].clone();
        *quorum_set = inner;
    }
}

fn node_id_bytes(node_id: &NodeId) -> [u8; 32] {
    match &node_id.0 {
        stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::curr::Uint256(bytes)) => {
            *bytes
        }
    }
}

fn node_id_cmp(a: &NodeId, b: &NodeId) -> std::cmp::Ordering {
    node_id_bytes(a).cmp(&node_id_bytes(b))
}

fn quorum_set_cmp(a: &ScpQuorumSet, b: &ScpQuorumSet) -> std::cmp::Ordering {
    let mut index = 0;
    let a_vals: Vec<NodeId> = a.validators.iter().cloned().collect();
    let b_vals: Vec<NodeId> = b.validators.iter().cloned().collect();
    while index < a_vals.len() && index < b_vals.len() {
        let ord = node_id_cmp(&a_vals[index], &b_vals[index]);
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
        index += 1;
    }
    if a_vals.len() != b_vals.len() {
        return a_vals.len().cmp(&b_vals.len());
    }

    let mut inner_index = 0;
    let a_inners: Vec<ScpQuorumSet> = a.inner_sets.iter().cloned().collect();
    let b_inners: Vec<ScpQuorumSet> = b.inner_sets.iter().cloned().collect();
    while inner_index < a_inners.len() && inner_index < b_inners.len() {
        let ord = quorum_set_cmp(&a_inners[inner_index], &b_inners[inner_index]);
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
        inner_index += 1;
    }
    if a_inners.len() != b_inners.len() {
        return a_inners.len().cmp(&b_inners.len());
    }

    a.threshold.cmp(&b.threshold)
}

/// Check if a quorum set is valid.
///
/// A quorum set is valid if:
/// 1. Threshold is <= number of validators + inner sets
/// 2. All inner sets are valid
pub fn is_valid_quorum_set(quorum_set: &ScpQuorumSet) -> bool {
    let total = quorum_set.validators.len() + quorum_set.inner_sets.len();
    let threshold = quorum_set.threshold as usize;

    if threshold > total {
        return false;
    }

    // Check inner sets
    for inner_set in quorum_set.inner_sets.iter() {
        if !is_valid_quorum_set(inner_set) {
            return false;
        }
    }

    true
}

/// Get all node IDs referenced in a quorum set.
pub fn get_all_nodes(quorum_set: &ScpQuorumSet) -> HashSet<NodeId> {
    let mut nodes = HashSet::new();
    collect_nodes(quorum_set, &mut nodes);
    nodes
}

fn collect_nodes(quorum_set: &ScpQuorumSet, nodes: &mut HashSet<NodeId>) {
    for validator in quorum_set.validators.iter() {
        nodes.insert(validator.clone());
    }

    for inner_set in quorum_set.inner_sets.iter() {
        collect_nodes(inner_set, nodes);
    }
}

/// Create a simple quorum set with just validators.
pub fn simple_quorum_set(threshold: u32, validators: Vec<NodeId>) -> ScpQuorumSet {
    ScpQuorumSet {
        threshold,
        validators: validators.try_into().unwrap_or_default(),
        inner_sets: Vec::new().try_into().unwrap_or_default(),
    }
}

/// Create a singleton quorum set containing just one node.
///
/// A singleton quorum set has threshold 1 and contains only the given node.
/// This is useful when a node needs to represent itself in quorum calculations.
pub fn singleton_quorum_set(node_id: NodeId) -> ScpQuorumSet {
    simple_quorum_set(1, vec![node_id])
}

/// Cache for singleton quorum sets to avoid repeated allocations.
///
/// This struct provides efficient caching of singleton quorum sets,
/// matching the stellar-core `getSingletonQSet()` optimization.
#[derive(Debug, Default)]
pub struct SingletonQuorumSetCache {
    cache: std::sync::RwLock<std::collections::HashMap<NodeId, ScpQuorumSet>>,
}

impl SingletonQuorumSetCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            cache: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Get or create a singleton quorum set for the given node.
    ///
    /// If the quorum set is already cached, returns a clone.
    /// Otherwise, creates a new one and caches it.
    pub fn get_or_create(&self, node_id: &NodeId) -> ScpQuorumSet {
        // Try read first
        if let Ok(cache) = self.cache.read() {
            if let Some(qs) = cache.get(node_id) {
                return qs.clone();
            }
        }

        // Need to create and cache
        let qs = singleton_quorum_set(node_id.clone());
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(node_id.clone(), qs.clone());
        }
        qs
    }

    /// Clear the cache.
    pub fn clear(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }
}

#[cfg(test)]
mod tests;
