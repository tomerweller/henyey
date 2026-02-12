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

fn make_node_id_with_index(index: u16) -> NodeId {
    let mut bytes = [0u8; 32];
    bytes[0] = (index & 0xff) as u8;
    bytes[1] = (index >> 8) as u8;
    NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
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

#[test]
fn test_is_quorum_set_sane_basic() {
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);

    let qs = make_simple_quorum_set(1, &[node1.clone(), node2.clone()]);
    assert!(is_quorum_set_sane(&qs, false).is_ok());
}

#[test]
fn test_is_quorum_set_sane_threshold_zero() {
    let mut qs = make_simple_quorum_set(1, &[]);
    qs.threshold = 0;
    assert!(is_quorum_set_sane(&qs, false).is_err());
}

#[test]
fn test_is_quorum_set_sane_threshold_too_high() {
    let node1 = make_node_id(1);
    let mut qs = make_simple_quorum_set(1, &[node1]);
    qs.threshold = 2;
    assert!(is_quorum_set_sane(&qs, false).is_err());
}

#[test]
fn test_is_quorum_set_sane_duplicate_nodes() {
    let node1 = make_node_id(1);
    let mut qs = make_simple_quorum_set(1, std::slice::from_ref(&node1));
    qs.validators = vec![node1.clone(), node1].try_into().unwrap_or_default();
    assert!(is_quorum_set_sane(&qs, false).is_err());
}

#[test]
fn test_is_quorum_set_sane_max_depth() {
    let node1 = make_node_id(1);
    let mut qs = make_simple_quorum_set(1, std::slice::from_ref(&node1));
    for _ in 0..=MAXIMUM_QUORUM_NESTING_LEVEL {
        let inner = qs.clone();
        qs = ScpQuorumSet {
            threshold: 1,
            validators: Vec::new().try_into().unwrap_or_default(),
            inner_sets: vec![inner].try_into().unwrap_or_default(),
        };
    }
    assert!(is_quorum_set_sane(&qs, false).is_err());
}

#[test]
fn test_is_quorum_set_sane_node_count_limit() {
    let mut validators = Vec::new();
    for idx in 0..=MAXIMUM_QUORUM_NODES {
        validators.push(make_node_id_with_index(idx as u16));
    }
    let qs = simple_quorum_set(1, validators);
    assert!(is_quorum_set_sane(&qs, false).is_err());
}

#[test]
fn test_is_quorum_set_sane_node_count_limit_with_inner_sets() {
    let mut nodes = Vec::new();
    for idx in 0..=MAXIMUM_QUORUM_NODES {
        nodes.push(make_node_id_with_index(idx as u16));
    }

    let mut qs = ScpQuorumSet {
        threshold: 1,
        validators: vec![nodes[0].clone()].try_into().unwrap_or_default(),
        inner_sets: Vec::new().try_into().unwrap_or_default(),
    };

    let mut inners = Vec::new();
    for set_index in 0..10 {
        let start = 1 + set_index * 100;
        let end = start + 100;
        let slice: Vec<NodeId> = nodes[start..end].iter().cloned().collect();
        inners.push(simple_quorum_set(1, slice));
    }
    qs.inner_sets = inners.try_into().unwrap_or_default();

    assert!(is_quorum_set_sane(&qs, false).is_err());
}

#[test]
fn test_is_quorum_set_sane_extra_checks() {
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);

    let qs = make_simple_quorum_set(1, &[node1, node2]);
    assert!(is_quorum_set_sane(&qs, true).is_err());
}

#[test]
fn test_is_quorum_set_sane_extra_checks_threshold_ok() {
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);

    let qs = make_simple_quorum_set(2, &[node1, node2, node3]);
    assert!(is_quorum_set_sane(&qs, true).is_ok());
}

#[test]
fn test_normalize_quorum_set_merges_singletons() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);

    let mut qs = ScpQuorumSet {
        threshold: 1,
        validators: vec![node0.clone()].try_into().unwrap_or_default(),
        inner_sets: vec![make_simple_quorum_set(1, std::slice::from_ref(&node1))]
            .try_into()
            .unwrap_or_default(),
    };

    normalize_quorum_set(&mut qs);

    assert_eq!(qs.threshold, 1);
    let validators: Vec<NodeId> = qs.validators.iter().cloned().collect();
    assert_eq!(validators, vec![node0, node1]);
    assert!(qs.inner_sets.is_empty());
}

#[test]
fn test_normalize_quorum_set_flattens_nested_singletons() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);

    let mut qs = ScpQuorumSet {
        threshold: 1,
        validators: Vec::new().try_into().unwrap_or_default(),
        inner_sets: vec![ScpQuorumSet {
            threshold: 1,
            validators: vec![node0.clone()].try_into().unwrap_or_default(),
            inner_sets: vec![
                make_simple_quorum_set(1, std::slice::from_ref(&node1)),
                make_simple_quorum_set(1, &[node2.clone(), node3.clone()]),
            ]
            .try_into()
            .unwrap_or_default(),
        }]
        .try_into()
        .unwrap_or_default(),
    };

    normalize_quorum_set(&mut qs);

    assert_eq!(qs.threshold, 1);
    let validators: Vec<NodeId> = qs.validators.iter().cloned().collect();
    assert_eq!(validators, vec![node0, node1]);
    assert_eq!(qs.inner_sets.len(), 1);
    let inner = &qs.inner_sets[0];
    assert_eq!(inner.threshold, 1);
    let inner_validators: Vec<NodeId> = inner.validators.iter().cloned().collect();
    assert_eq!(inner_validators, vec![node2, node3]);
}

#[test]
fn test_normalize_quorum_set_promotes_single_inner() {
    let node0 = make_node_id(0);
    let mut qs = ScpQuorumSet {
        threshold: 1,
        validators: Vec::new().try_into().unwrap_or_default(),
        inner_sets: vec![make_simple_quorum_set(1, std::slice::from_ref(&node0))]
            .try_into()
            .unwrap_or_default(),
    };

    normalize_quorum_set(&mut qs);

    assert_eq!(qs.threshold, 1);
    let validators: Vec<NodeId> = qs.validators.iter().cloned().collect();
    assert_eq!(validators, vec![node0]);
    assert!(qs.inner_sets.is_empty());
}

#[test]
fn test_normalize_quorum_set_sorts_validators() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);

    let mut qs = ScpQuorumSet {
        threshold: 2,
        validators: vec![node2.clone(), node0.clone(), node1.clone()]
            .try_into()
            .unwrap_or_default(),
        inner_sets: Vec::new().try_into().unwrap_or_default(),
    };

    normalize_quorum_set(&mut qs);

    let validators: Vec<NodeId> = qs.validators.iter().cloned().collect();
    assert_eq!(validators, vec![node0, node1, node2]);
}

#[test]
fn test_normalize_quorum_set_sorts_inner_sets() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);

    let inner_a = ScpQuorumSet {
        threshold: 2,
        validators: vec![node2.clone(), node3.clone()]
            .try_into()
            .unwrap_or_default(),
        inner_sets: Vec::new().try_into().unwrap_or_default(),
    };
    let inner_b = ScpQuorumSet {
        threshold: 2,
        validators: vec![node0.clone(), node1.clone()]
            .try_into()
            .unwrap_or_default(),
        inner_sets: Vec::new().try_into().unwrap_or_default(),
    };

    let mut qs = ScpQuorumSet {
        threshold: 2,
        validators: Vec::new().try_into().unwrap_or_default(),
        inner_sets: vec![inner_a, inner_b].try_into().unwrap_or_default(),
    };

    normalize_quorum_set(&mut qs);

    assert_eq!(qs.inner_sets.len(), 2);
    let first_validators: Vec<NodeId> = qs.inner_sets[0].validators.iter().cloned().collect();
    let second_validators: Vec<NodeId> = qs.inner_sets[1].validators.iter().cloned().collect();
    assert_eq!(first_validators, vec![node0, node1]);
    assert_eq!(second_validators, vec![node2, node3]);
}

#[test]
fn test_vblocking_and_quorum() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);

    let qs = make_simple_quorum_set(
        3,
        &[node0.clone(), node1.clone(), node2.clone(), node3.clone()],
    );

    let mut nodes = HashSet::new();
    nodes.insert(node0.clone());
    assert!(!is_quorum_slice(&qs, &nodes, &|_: &NodeId| None));
    assert!(!is_v_blocking(&qs, &nodes));

    nodes.insert(node2.clone());
    assert!(!is_quorum_slice(&qs, &nodes, &|_: &NodeId| None));
    assert!(is_v_blocking(&qs, &nodes));

    nodes.insert(node3.clone());
    assert!(is_quorum_slice(&qs, &nodes, &|_: &NodeId| None));
    assert!(is_v_blocking(&qs, &nodes));

    nodes.insert(node1.clone());
    assert!(is_quorum_slice(&qs, &nodes, &|_: &NodeId| None));
    assert!(is_v_blocking(&qs, &nodes));
}

#[test]
fn test_find_closest_vblocking_distance() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);
    let node4 = make_node_id(4);
    let node5 = make_node_id(5);
    let node6 = make_node_id(6);
    let node7 = make_node_id(7);

    let mut qs = make_simple_quorum_set(2, &[node0.clone(), node1.clone(), node2.clone()]);

    let mut good = HashSet::new();
    good.insert(node0.clone());

    let check = |q: &ScpQuorumSet, s: &HashSet<NodeId>, expected: usize| {
        let result = find_closest_v_blocking(q, s, None);
        assert_eq!(result.len(), expected);
    };

    check(&qs, &good, 0);

    good.insert(node1.clone());
    check(&qs, &good, 1);

    good.insert(node2.clone());
    check(&qs, &good, 2);

    let qsub1 = make_simple_quorum_set(1, &[node3.clone(), node4.clone(), node5.clone()]);
    qs.inner_sets = vec![qsub1].try_into().unwrap_or_default();

    good.insert(node3.clone());
    check(&qs, &good, 3);

    good.insert(node4.clone());
    check(&qs, &good, 3);

    qs.threshold = 1;
    check(&qs, &good, 5);

    good.insert(node5.clone());
    check(&qs, &good, 6);

    let qsub2 = make_simple_quorum_set(2, &[node6.clone(), node7.clone()]);
    let mut inner_sets: Vec<ScpQuorumSet> = qs.inner_sets.iter().cloned().collect();
    inner_sets.push(qsub2);
    qs.inner_sets = inner_sets.try_into().unwrap_or_default();

    check(&qs, &good, 6);

    good.insert(node6.clone());
    check(&qs, &good, 6);

    good.insert(node7.clone());
    check(&qs, &good, 7);

    qs.threshold = 4;
    check(&qs, &good, 2);

    qs.threshold = 3;
    check(&qs, &good, 3);

    qs.threshold = 2;
    check(&qs, &good, 4);
}

#[test]
fn test_find_closest_vblocking_with_excluded() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);

    let qs = make_simple_quorum_set(2, &[node0.clone(), node1.clone(), node2.clone()]);
    let mut nodes = HashSet::new();
    nodes.insert(node0.clone());
    nodes.insert(node1.clone());

    let without_excluded = find_closest_v_blocking(&qs, &nodes, None);
    let with_excluded = find_closest_v_blocking(&qs, &nodes, Some(&node1));

    assert_eq!(without_excluded.len(), 1);
    assert_eq!(with_excluded.len(), 1);
    assert!(!with_excluded.contains(&node1));
}

// ==================== Tests for new parity features ====================

#[test]
fn test_singleton_quorum_set() {
    let node = make_node_id(42);
    let qs = singleton_quorum_set(node.clone());

    assert_eq!(qs.threshold, 1);
    assert_eq!(qs.validators.len(), 1);
    assert_eq!(&qs.validators[0], &node);
    assert!(qs.inner_sets.is_empty());
}

#[test]
fn test_singleton_quorum_set_cache() {
    let cache = SingletonQuorumSetCache::new();
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);

    // First access creates the quorum set
    let qs1a = cache.get_or_create(&node1);
    assert_eq!(qs1a.threshold, 1);
    assert_eq!(qs1a.validators.len(), 1);
    assert_eq!(&qs1a.validators[0], &node1);

    // Second access returns cached version
    let qs1b = cache.get_or_create(&node1);
    assert_eq!(qs1a.threshold, qs1b.threshold);
    assert_eq!(qs1a.validators.len(), qs1b.validators.len());

    // Different node gets different quorum set
    let qs2 = cache.get_or_create(&node2);
    assert_eq!(&qs2.validators[0], &node2);

    // Clear removes all cached entries
    cache.clear();

    // After clear, still creates correctly
    let qs1c = cache.get_or_create(&node1);
    assert_eq!(&qs1c.validators[0], &node1);
}

#[test]
fn test_singleton_quorum_set_cache_thread_safe() {
    use std::sync::Arc;
    use std::thread;

    let cache = Arc::new(SingletonQuorumSetCache::new());
    let mut handles = vec![];

    // Spawn multiple threads accessing the cache concurrently
    for i in 0..10 {
        let cache_clone = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            let node = make_node_id(i);
            for _ in 0..100 {
                let qs = cache_clone.get_or_create(&node);
                assert_eq!(qs.threshold, 1);
                assert_eq!(qs.validators.len(), 1);
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

// ==================== Additional stellar-core parity tests ====================

#[test]
fn test_is_quorum_with_nested_sets() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);

    // Create a quorum set with an inner set:
    // threshold=2, validators=[node0, node1], inner_sets=[{threshold=1, validators=[node2, node3]}]
    let inner = make_simple_quorum_set(1, &[node2.clone(), node3.clone()]);
    let qs = ScpQuorumSet {
        threshold: 2,
        validators: vec![node0.clone(), node1.clone()].try_into().unwrap(),
        inner_sets: vec![inner].try_into().unwrap(),
    };

    let get_qs = |_: &NodeId| -> Option<ScpQuorumSet> { None };

    // node0 + node1 = 2 validators, satisfies threshold
    let mut nodes = HashSet::new();
    nodes.insert(node0.clone());
    nodes.insert(node1.clone());
    assert!(is_quorum_slice(&qs, &nodes, &get_qs));

    // node0 + inner set satisfied = 2, satisfies threshold
    let mut nodes = HashSet::new();
    nodes.insert(node0.clone());
    nodes.insert(node2.clone()); // inner set is satisfied (1-of-2)
    assert!(is_quorum_slice(&qs, &nodes, &get_qs));

    // Only inner set satisfied = 1, doesn't satisfy threshold
    let mut nodes = HashSet::new();
    nodes.insert(node2.clone());
    nodes.insert(node3.clone());
    assert!(!is_quorum_slice(&qs, &nodes, &get_qs));
}

#[test]
fn test_is_quorum_full() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);

    // All nodes have the same 2-of-3 quorum set
    let qs = make_simple_quorum_set(2, &[node0.clone(), node1.clone(), node2.clone()]);

    let get_qs = |_: &NodeId| -> Option<ScpQuorumSet> { Some(qs.clone()) };

    // 2 nodes form a quorum (each has their slice satisfied by the set)
    let mut nodes = HashSet::new();
    nodes.insert(node0.clone());
    nodes.insert(node1.clone());
    assert!(is_quorum(&qs, &nodes, &get_qs));

    // 1 node does not form a quorum
    let mut nodes = HashSet::new();
    nodes.insert(node0.clone());
    assert!(!is_quorum(&qs, &nodes, &get_qs));

    // All 3 nodes form a quorum
    let mut nodes = HashSet::new();
    nodes.insert(node0);
    nodes.insert(node1);
    nodes.insert(node2);
    assert!(is_quorum(&qs, &nodes, &get_qs));
}

#[test]
fn test_is_quorum_asymmetric() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);

    // node0 trusts node1 and node2 (2-of-2)
    let qs0 = make_simple_quorum_set(2, &[node1.clone(), node2.clone()]);
    // node1 trusts node0 and node2 (2-of-2)
    let qs1 = make_simple_quorum_set(2, &[node0.clone(), node2.clone()]);
    // node2 trusts node0 and node1 (2-of-2)
    let qs2 = make_simple_quorum_set(2, &[node0.clone(), node1.clone()]);

    let get_qs = |n: &NodeId| -> Option<ScpQuorumSet> {
        if n == &node0 {
            Some(qs0.clone())
        } else if n == &node1 {
            Some(qs1.clone())
        } else if n == &node2 {
            Some(qs2.clone())
        } else {
            None
        }
    };

    // {node0, node1, node2} forms a quorum
    let mut nodes = HashSet::new();
    nodes.insert(node0.clone());
    nodes.insert(node1.clone());
    nodes.insert(node2.clone());
    assert!(is_quorum(&qs0, &nodes, &get_qs));

    // {node0, node1} doesn't form a quorum (node0's slice requires node2)
    let mut nodes = HashSet::new();
    nodes.insert(node0.clone());
    nodes.insert(node1.clone());
    assert!(!is_quorum(&qs0, &nodes, &get_qs));
}

#[test]
fn test_blocking_set_with_nested() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);

    // threshold=3, validators=[node0, node1], inner_sets=[{threshold=1, [node2, node3]}]
    // Total members = 3, need 3 to pass, so blocking threshold = 3-3+1 = 1
    let inner = make_simple_quorum_set(1, &[node2.clone(), node3.clone()]);
    let qs = ScpQuorumSet {
        threshold: 3,
        validators: vec![node0.clone(), node1.clone()].try_into().unwrap(),
        inner_sets: vec![inner].try_into().unwrap(),
    };

    // Any single validator blocks
    let mut nodes = HashSet::new();
    nodes.insert(node0.clone());
    assert!(is_blocking_set(&qs, &nodes));

    // If inner set is blocked, it blocks the outer
    let mut nodes = HashSet::new();
    nodes.insert(node2.clone());
    nodes.insert(node3.clone());
    assert!(is_blocking_set(&qs, &nodes));
}

#[test]
fn test_hash_quorum_set_deterministic() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);

    let qs1 = make_simple_quorum_set(1, &[node0.clone(), node1.clone()]);
    let qs2 = make_simple_quorum_set(1, &[node0.clone(), node1.clone()]);

    // Same quorum sets should have same hash
    assert_eq!(hash_quorum_set(&qs1), hash_quorum_set(&qs2));

    // Different threshold should have different hash
    let qs3 = make_simple_quorum_set(2, &[node0.clone(), node1.clone()]);
    assert_ne!(hash_quorum_set(&qs1), hash_quorum_set(&qs3));
}

#[test]
fn test_get_all_nodes_with_nested() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);

    let inner = make_simple_quorum_set(1, &[node2.clone(), node3.clone()]);
    let qs = ScpQuorumSet {
        threshold: 2,
        validators: vec![node0.clone(), node1.clone()].try_into().unwrap(),
        inner_sets: vec![inner].try_into().unwrap(),
    };

    let all_nodes = get_all_nodes(&qs);
    assert_eq!(all_nodes.len(), 4);
    assert!(all_nodes.contains(&node0));
    assert!(all_nodes.contains(&node1));
    assert!(all_nodes.contains(&node2));
    assert!(all_nodes.contains(&node3));
}

#[test]
fn test_normalize_preserves_semantics() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);

    // Create an unnormalized quorum set (unsorted)
    let mut qs = ScpQuorumSet {
        threshold: 2,
        validators: vec![node2.clone(), node0.clone(), node1.clone()]
            .try_into()
            .unwrap(),
        inner_sets: vec![].try_into().unwrap(),
    };

    let _hash_before = hash_quorum_set(&qs);
    normalize_quorum_set(&mut qs);
    let _hash_after = hash_quorum_set(&qs);

    // Hash may change due to ordering, but semantics preserved
    // Validators should now be sorted
    let validators: Vec<_> = qs.validators.iter().cloned().collect();
    assert_eq!(validators[0], node0);
    assert_eq!(validators[1], node1);
    assert_eq!(validators[2], node2);

    // But both should function the same way
    let mut nodes = HashSet::new();
    nodes.insert(node0.clone());
    nodes.insert(node1.clone());
    assert!(is_quorum_slice(&qs, &nodes, &|_: &NodeId| None));
}

// ==================== Q1: Iterative pruning quorum tests ====================

#[test]
fn test_is_quorum_iterative_pruning() {
    // Test that is_quorum uses iterative pruning to find quorums
    // within the input set, matching stellar-core behavior.
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3); // node3 has no quorum set (unknown)

    // All known nodes have the same 2-of-3 quorum set
    let qs = make_simple_quorum_set(2, &[node0.clone(), node1.clone(), node2.clone()]);

    let get_qs = |n: &NodeId| -> Option<ScpQuorumSet> {
        if n == &node0 || n == &node1 || n == &node2 {
            Some(qs.clone())
        } else {
            None // node3 is unknown
        }
    };

    // {node0, node1, node3} - node3 is unknown, but after pruning node3,
    // {node0, node1} still forms a quorum. The iterative algorithm should find it.
    let mut nodes = HashSet::new();
    nodes.insert(node0.clone());
    nodes.insert(node1.clone());
    nodes.insert(node3.clone());
    assert!(is_quorum(&qs, &nodes, &get_qs));
}

#[test]
fn test_is_quorum_iterative_pruning_cascade() {
    // Test cascading pruning: removing one node makes another's slice unsatisfied
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);

    // node0 and node1 have 2-of-3 (node0, node1, node2) - they trust each other
    let qs01 = make_simple_quorum_set(2, &[node0.clone(), node1.clone(), node2.clone()]);

    // node2 requires all three nodes (3-of-3) - very strict
    let qs2 = make_simple_quorum_set(3, &[node0.clone(), node1.clone(), node2.clone()]);

    // node3 requires node2 and node3 (unknown quorum set)
    let get_qs = |n: &NodeId| -> Option<ScpQuorumSet> {
        if n == &node0 || n == &node1 {
            Some(qs01.clone())
        } else if n == &node2 {
            Some(qs2.clone())
        } else {
            None
        }
    };

    // {node0, node1, node2, node3}: node3 gets pruned (unknown), then node2's
    // slice (3-of-3 requiring node3) fails, so node2 gets pruned too.
    // Remaining {node0, node1} satisfies the local 2-of-3 slice.
    let mut nodes = HashSet::new();
    nodes.insert(node0.clone());
    nodes.insert(node1.clone());
    nodes.insert(node2.clone());
    nodes.insert(node3.clone());
    assert!(is_quorum(&qs01, &nodes, &get_qs));
}

// ==================== Q2: normalize_quorum_set_with_remove tests ====================

#[test]
fn test_normalize_quorum_set_with_remove_basic() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);

    // 2-of-3 quorum set: removing node1 should give 1-of-2
    let mut qs = make_simple_quorum_set(2, &[node0.clone(), node1.clone(), node2.clone()]);
    normalize_quorum_set_with_remove(&mut qs, Some(&node1));

    assert_eq!(qs.threshold, 1);
    let validators: Vec<NodeId> = qs.validators.iter().cloned().collect();
    assert_eq!(validators.len(), 2);
    assert!(validators.contains(&node0));
    assert!(validators.contains(&node2));
    assert!(!validators.contains(&node1));
}

#[test]
fn test_normalize_quorum_set_with_remove_inner_set() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);

    // Outer: threshold=2, validators=[node0, node1]
    // Inner: threshold=2, validators=[node1, node2, node3]
    // Removing node1 should:
    //   - Outer: threshold=1, validators=[node0]
    //   - Inner: threshold=1, validators=[node2, node3]
    let inner = make_simple_quorum_set(2, &[node1.clone(), node2.clone(), node3.clone()]);
    let mut qs = ScpQuorumSet {
        threshold: 2,
        validators: vec![node0.clone(), node1.clone()].try_into().unwrap(),
        inner_sets: vec![inner].try_into().unwrap(),
    };

    normalize_quorum_set_with_remove(&mut qs, Some(&node1));

    assert_eq!(qs.threshold, 1);
    let validators: Vec<NodeId> = qs.validators.iter().cloned().collect();
    assert!(!validators.contains(&node1));
    assert!(validators.contains(&node0));

    // Inner set should also have node1 removed
    assert_eq!(qs.inner_sets.len(), 1);
    let inner = &qs.inner_sets[0];
    assert_eq!(inner.threshold, 1);
    let inner_validators: Vec<NodeId> = inner.validators.iter().cloned().collect();
    assert!(!inner_validators.contains(&node1));
    assert!(inner_validators.contains(&node2));
    assert!(inner_validators.contains(&node3));
}

#[test]
fn test_normalize_quorum_set_with_remove_none() {
    // Passing None should behave identically to normalize_quorum_set
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);

    let mut qs1 = ScpQuorumSet {
        threshold: 2,
        validators: vec![node2.clone(), node0.clone(), node1.clone()]
            .try_into()
            .unwrap(),
        inner_sets: vec![].try_into().unwrap(),
    };
    let mut qs2 = qs1.clone();

    normalize_quorum_set(&mut qs1);
    normalize_quorum_set_with_remove(&mut qs2, None);

    assert_eq!(hash_quorum_set(&qs1), hash_quorum_set(&qs2));
}

// ==================== Q3: is_v_blocking threshold==0 tests ====================

#[test]
fn test_is_v_blocking_empty_quorum_set() {
    // Empty quorum set (threshold=0) should NOT be v-blocking
    // (matches stellar-core "There is no v-blocking set for {\empty}")
    let qs = ScpQuorumSet {
        threshold: 0,
        validators: vec![].try_into().unwrap(),
        inner_sets: vec![].try_into().unwrap(),
    };

    let nodes = HashSet::new();
    assert!(!is_v_blocking(&qs, &nodes));

    // Even with some nodes, threshold=0 means no v-blocking
    let mut nodes = HashSet::new();
    nodes.insert(make_node_id(1));
    assert!(!is_v_blocking(&qs, &nodes));
}
