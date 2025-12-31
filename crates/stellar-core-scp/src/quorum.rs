//! Quorum set operations for SCP.
//!
//! This module provides utilities for working with quorum sets,
//! including checking if a set of nodes forms a quorum or blocking set.

use std::collections::HashSet;

use stellar_core_common::Hash256;
use stellar_xdr::curr::{NodeId, ScpQuorumSet};

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
/// A set Q is a quorum if:
/// 1. Every node in Q has a quorum slice contained in Q
/// 2. This is checked recursively
///
/// # Arguments
/// * `quorum_set` - The local node's quorum set
/// * `nodes` - The set of nodes to check
/// * `get_quorum_set` - Function to get quorum set for a node
///
/// # Returns
/// True if the nodes form a quorum.
pub fn is_quorum<F>(
    quorum_set: &ScpQuorumSet,
    nodes: &HashSet<NodeId>,
    get_quorum_set: F,
) -> bool
where
    F: Fn(&NodeId) -> Option<ScpQuorumSet>,
{
    // First check if nodes satisfy our quorum slice
    if !is_quorum_slice(quorum_set, nodes, &get_quorum_set) {
        return false;
    }

    // Then check that all nodes in the set also have their quorum slices satisfied
    for node in nodes {
        if let Some(qs) = get_quorum_set(node) {
            if !is_quorum_slice(&qs, nodes, &get_quorum_set) {
                return false;
            }
        } else {
            // Unknown node - can't verify quorum
            return false;
        }
    }

    true
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
pub fn is_blocking_set(
    quorum_set: &ScpQuorumSet,
    nodes: &HashSet<NodeId>,
) -> bool {
    is_blocking_set_helper(quorum_set, nodes)
}

fn is_blocking_set_helper(
    quorum_set: &ScpQuorumSet,
    nodes: &HashSet<NodeId>,
) -> bool {
    let total = quorum_set.validators.len() + quorum_set.inner_sets.len();
    let threshold = quorum_set.threshold as usize;

    if threshold == 0 {
        // Empty quorum set is always blocked
        return true;
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
pub fn is_v_blocking(
    quorum_set: &ScpQuorumSet,
    nodes: &HashSet<NodeId>,
) -> bool {
    is_blocking_set(quorum_set, nodes)
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
pub fn normalize_quorum_set(quorum_set: &mut ScpQuorumSet) {
    // Sort validators by their public key bytes
    let mut validators: Vec<_> = quorum_set.validators.iter().cloned().collect();
    validators.sort_by(|a, b| {
        let a_bytes = match &a.0 {
            stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                stellar_xdr::curr::Uint256(bytes),
            ) => bytes,
        };
        let b_bytes = match &b.0 {
            stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                stellar_xdr::curr::Uint256(bytes),
            ) => bytes,
        };
        a_bytes.cmp(b_bytes)
    });
    quorum_set.validators = validators.try_into().unwrap_or_default();

    // Recursively normalize inner sets
    let mut inner_sets: Vec<_> = quorum_set.inner_sets.iter().cloned().collect();
    for inner_set in &mut inner_sets {
        normalize_quorum_set(inner_set);
    }

    // Sort inner sets by their hash
    inner_sets.sort_by_cached_key(|qs| hash_quorum_set(qs).0);
    quorum_set.inner_sets = inner_sets.try_into().unwrap_or_default();
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

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{PublicKey, Uint256};

    fn make_node_id(seed: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
    }

    fn make_simple_quorum_set(threshold: u32, node_ids: &[NodeId]) -> ScpQuorumSet {
        simple_quorum_set(threshold, node_ids.to_vec())
    }

    #[test]
    fn test_is_quorum_slice_simple() {
        let node1 = make_node_id(1);
        let node2 = make_node_id(2);
        let node3 = make_node_id(3);

        // 2-of-3 quorum set
        let qs = make_simple_quorum_set(2, &[node1.clone(), node2.clone(), node3.clone()]);

        let get_qs = |_: &NodeId| -> Option<ScpQuorumSet> { None };

        // 2 nodes should satisfy
        let mut nodes = HashSet::new();
        nodes.insert(node1.clone());
        nodes.insert(node2.clone());
        assert!(is_quorum_slice(&qs, &nodes, &get_qs));

        // 1 node should not satisfy
        let mut nodes = HashSet::new();
        nodes.insert(node1.clone());
        assert!(!is_quorum_slice(&qs, &nodes, &get_qs));

        // 3 nodes should satisfy
        let mut nodes = HashSet::new();
        nodes.insert(node1);
        nodes.insert(node2);
        nodes.insert(node3);
        assert!(is_quorum_slice(&qs, &nodes, &get_qs));
    }

    #[test]
    fn test_is_blocking_set() {
        let node1 = make_node_id(1);
        let node2 = make_node_id(2);
        let node3 = make_node_id(3);

        // 2-of-3 quorum set
        let qs = make_simple_quorum_set(2, &[node1.clone(), node2.clone(), node3.clone()]);

        // 2 nodes should be blocking (blocks all 2-of-3 combinations)
        let mut nodes = HashSet::new();
        nodes.insert(node1.clone());
        nodes.insert(node2.clone());
        assert!(is_blocking_set(&qs, &nodes));

        // 1 node should not be blocking
        let mut nodes = HashSet::new();
        nodes.insert(node1);
        assert!(!is_blocking_set(&qs, &nodes));
    }

    #[test]
    fn test_get_all_nodes() {
        let node1 = make_node_id(1);
        let node2 = make_node_id(2);

        let qs = make_simple_quorum_set(1, &[node1.clone(), node2.clone()]);
        let nodes = get_all_nodes(&qs);

        assert!(nodes.contains(&node1));
        assert!(nodes.contains(&node2));
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn test_is_valid_quorum_set() {
        let node1 = make_node_id(1);
        let node2 = make_node_id(2);

        // Valid: 2-of-2
        let qs = make_simple_quorum_set(2, &[node1.clone(), node2.clone()]);
        assert!(is_valid_quorum_set(&qs));

        // Invalid: 3-of-2
        let qs = make_simple_quorum_set(3, &[node1, node2]);
        assert!(!is_valid_quorum_set(&qs));
    }
}
