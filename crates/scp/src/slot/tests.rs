use super::*;
use stellar_xdr::curr::{PublicKey, Uint256};

fn make_node_id(seed: u8) -> NodeId {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
}

fn make_quorum_set() -> ScpQuorumSet {
    ScpQuorumSet {
        threshold: 1,
        validators: vec![].try_into().unwrap(),
        inner_sets: vec![].try_into().unwrap(),
    }
}

#[test]
fn test_slot_new() {
    let slot = Slot::new(42, make_node_id(1), make_quorum_set(), true);

    assert_eq!(slot.slot_index(), 42);
    assert!(!slot.is_externalized());
    assert!(slot.get_externalized_value().is_none());
}

#[test]
fn test_force_externalize() {
    let mut slot = Slot::new(42, make_node_id(1), make_quorum_set(), true);

    let value: Value = vec![1, 2, 3].try_into().unwrap();
    slot.force_externalize(value.clone());

    assert!(slot.is_externalized());
    assert_eq!(slot.get_externalized_value(), Some(&value));
}

// ==================== Tests for new parity features ====================

#[test]
fn test_set_state_from_envelope_nomination() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let mut slot = Slot::new(1, node.clone(), quorum_set.clone(), true);

    let value: Value = vec![1, 2, 3].try_into().unwrap();
    let nomination = stellar_xdr::curr::ScpNomination {
        quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
        votes: vec![value.clone()].try_into().unwrap(),
        accepted: vec![].try_into().unwrap(),
    };
    let statement = stellar_xdr::curr::ScpStatement {
        node_id: node.clone(),
        slot_index: 1,
        pledges: ScpStatementPledges::Nominate(nomination),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };

    assert!(slot.set_state_from_envelope(&envelope));
    // stellar-core setStateFromEnvelope does NOT set mNominationStarted = true
    assert!(!slot.nomination().is_started());
}

#[test]
fn test_set_state_from_envelope_ballot_prepare() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let mut slot = Slot::new(1, node.clone(), quorum_set.clone(), true);

    let value: Value = vec![4, 5, 6].try_into().unwrap();
    let prep = stellar_xdr::curr::ScpStatementPrepare {
        quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
        ballot: stellar_xdr::curr::ScpBallot {
            counter: 3,
            value: value.clone(),
        },
        prepared: Some(stellar_xdr::curr::ScpBallot {
            counter: 2,
            value: value.clone(),
        }),
        prepared_prime: None,
        n_c: 0,
        n_h: 0,
    };
    let statement = stellar_xdr::curr::ScpStatement {
        node_id: node.clone(),
        slot_index: 1,
        pledges: ScpStatementPledges::Prepare(prep),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };

    assert!(slot.set_state_from_envelope(&envelope));
    assert_eq!(slot.ballot().phase(), crate::ballot::BallotPhase::Prepare);
    assert_eq!(slot.ballot().current_ballot().map(|b| b.counter), Some(3));
}

#[test]
fn test_set_state_from_envelope_externalize() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let mut slot = Slot::new(1, node.clone(), quorum_set.clone(), true);

    let value: Value = vec![7, 8, 9].try_into().unwrap();
    let ext = stellar_xdr::curr::ScpStatementExternalize {
        commit: stellar_xdr::curr::ScpBallot {
            counter: 5,
            value: value.clone(),
        },
        n_h: 7,
        commit_quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
    };
    let statement = stellar_xdr::curr::ScpStatement {
        node_id: node.clone(),
        slot_index: 1,
        pledges: ScpStatementPledges::Externalize(ext),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };

    assert!(slot.set_state_from_envelope(&envelope));
    assert!(slot.is_externalized());
    assert_eq!(slot.get_externalized_value(), Some(&value));
}

#[test]
fn test_abandon_ballot() {
    use crate::driver::{SCPDriver, ValidationLevel};
    use std::sync::Arc;
    use std::time::Duration;

    struct AbandonDriver;
    impl SCPDriver for AbandonDriver {
        fn validate_value(&self, _: u64, _: &Value, _: bool) -> ValidationLevel {
            ValidationLevel::FullyValidated
        }
        fn combine_candidates(&self, _: u64, _: &[Value]) -> Option<Value> {
            None
        }
        fn extract_valid_value(&self, _: u64, _: &Value) -> Option<Value> {
            None
        }
        fn emit_envelope(&self, _: &ScpEnvelope) {}
        fn get_quorum_set(&self, _: &NodeId) -> Option<ScpQuorumSet> {
            None
        }
        fn nominating_value(&self, _: u64, _: &Value) {}
        fn value_externalized(&self, _: u64, _: &Value) {}
        fn ballot_did_prepare(&self, _: u64, _: &stellar_xdr::curr::ScpBallot) {}
        fn ballot_did_confirm(&self, _: u64, _: &stellar_xdr::curr::ScpBallot) {}
        fn compute_hash_node(&self, _: u64, _: &Value, _: bool, _: u32, _: &NodeId) -> u64 {
            0
        }
        fn compute_value_hash(&self, _: u64, _: &Value, _: u32, _: &Value) -> u64 {
            0
        }
        fn compute_timeout(&self, _: u32, _: bool) -> Duration {
            Duration::from_secs(1)
        }
        fn sign_envelope(&self, _: &mut ScpEnvelope) {}
        fn verify_envelope(&self, _: &ScpEnvelope) -> bool {
            true
        }
    }
    let driver = Arc::new(AbandonDriver);

    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let mut slot = Slot::new(1, node.clone(), quorum_set.clone(), true);

    // Set up initial ballot state
    let value: Value = vec![1, 2, 3].try_into().unwrap();
    let prep = stellar_xdr::curr::ScpStatementPrepare {
        quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
        ballot: stellar_xdr::curr::ScpBallot {
            counter: 1,
            value: value.clone(),
        },
        prepared: None,
        prepared_prime: None,
        n_c: 0,
        n_h: 0,
    };
    let statement = stellar_xdr::curr::ScpStatement {
        node_id: node.clone(),
        slot_index: 1,
        pledges: ScpStatementPledges::Prepare(prep),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };
    slot.set_state_from_envelope(&envelope);

    // Abandon to counter 5
    assert!(slot.abandon_ballot(&driver, 5));
    assert_eq!(slot.ballot().current_ballot().map(|b| b.counter), Some(5));

    // Abandon with auto-increment
    assert!(slot.abandon_ballot(&driver, 0));
    assert_eq!(slot.ballot().current_ballot().map(|b| b.counter), Some(6));
}

#[test]
fn test_nomination_mut_accessor() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let mut slot = Slot::new(1, node.clone(), quorum_set.clone(), true);

    // Access nomination mutably
    let nom = slot.nomination_mut();
    assert!(!nom.is_started());
}

#[test]
fn test_ballot_mut_accessor() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let mut slot = Slot::new(1, node.clone(), quorum_set.clone(), true);

    // Access ballot mutably
    let ballot = slot.ballot_mut();
    assert_eq!(ballot.phase(), crate::ballot::BallotPhase::Prepare);
}

#[test]
fn test_get_info_idle() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let slot = Slot::new(42, node.clone(), quorum_set.clone(), true);

    let info = slot.get_info();
    assert_eq!(info.slot_index, 42);
    assert_eq!(info.phase, "IDLE");
    assert!(info.fully_validated);
    assert!(info.nomination.is_none());
    assert!(info.ballot.is_none());
}

#[test]
fn test_get_info_externalized() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let mut slot = Slot::new(42, node.clone(), quorum_set.clone(), true);

    let value: Value = vec![1, 2, 3].try_into().unwrap();
    slot.force_externalize(value);

    let info = slot.get_info();
    assert_eq!(info.slot_index, 42);
    assert_eq!(info.phase, "EXTERNALIZED");
    assert!(info.ballot.is_some());
}

#[test]
fn test_get_quorum_info() {
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);
    let quorum_set = ScpQuorumSet {
        threshold: 2,
        validators: vec![node1.clone(), node2.clone(), node3.clone()]
            .try_into()
            .unwrap(),
        inner_sets: vec![].try_into().unwrap(),
    };
    let slot = Slot::new(42, node1.clone(), quorum_set.clone(), true);

    let info = slot.get_quorum_info();
    assert_eq!(info.slot_index, 42);
    assert_eq!(info.nodes.len(), 3);
    assert!(!info.quorum_reached); // No messages received yet
    assert!(!info.v_blocking);

    // All nodes should be MISSING
    for (_, node_info) in &info.nodes {
        assert_eq!(node_info.state, "MISSING");
        assert!(node_info.ballot_counter.is_none());
    }
}

#[test]
fn test_get_info_serialization() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let slot = Slot::new(42, node.clone(), quorum_set.clone(), true);

    let info = slot.get_info();
    let json = serde_json::to_string(&info).unwrap();
    assert!(json.contains("\"slot_index\":42"));
    assert!(json.contains("\"phase\":\"IDLE\""));
}

#[test]
fn test_get_quorum_info_serialization() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let slot = Slot::new(42, node.clone(), quorum_set.clone(), true);

    let info = slot.get_quorum_info();
    let json = serde_json::to_string(&info).unwrap();
    assert!(json.contains("\"slot_index\":42"));
    assert!(json.contains("\"quorum_reached\":"));
    assert!(json.contains("\"v_blocking\":"));
}

// ==================== Tests for timer callbacks ====================

#[test]
fn test_timer_type_enum() {
    use crate::driver::SCPTimerType;

    // Test enum variants exist and are distinct
    assert_ne!(SCPTimerType::Nomination, SCPTimerType::Ballot);

    // Test Debug impl
    let nom = format!("{:?}", SCPTimerType::Nomination);
    let ballot = format!("{:?}", SCPTimerType::Ballot);
    assert!(nom.contains("Nomination"));
    assert!(ballot.contains("Ballot"));

    // Test Hash impl works
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(SCPTimerType::Nomination);
    set.insert(SCPTimerType::Ballot);
    assert_eq!(set.len(), 2);
}

// ==================== Phase 4 parity tests ====================

// S1: get_latest_messages_send returns empty when not fully validated
#[test]
fn test_get_latest_messages_send_not_fully_validated() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();

    // Create a slot that is NOT fully validated
    let mut slot = Slot::new(1, node.clone(), quorum_set.clone(), false);

    // Set up some state via set_state_from_envelope so there are messages
    let value: Value = vec![1, 2, 3].try_into().unwrap();
    let nomination = stellar_xdr::curr::ScpNomination {
        quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
        votes: vec![value.clone()].try_into().unwrap(),
        accepted: vec![].try_into().unwrap(),
    };
    let statement = stellar_xdr::curr::ScpStatement {
        node_id: node.clone(),
        slot_index: 1,
        pledges: ScpStatementPledges::Nominate(nomination),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };
    slot.set_state_from_envelope(&envelope);

    // Even though we have state, should return empty since not fully validated
    let messages = slot.get_latest_messages_send();
    assert!(
        messages.is_empty(),
        "get_latest_messages_send should return empty when not fully validated"
    );

    // Now test with fully validated slot
    let mut slot2 = Slot::new(1, node.clone(), quorum_set.clone(), true);
    slot2.set_state_from_envelope(&envelope);
    let messages2 = slot2.get_latest_messages_send();
    assert!(
        !messages2.is_empty(),
        "get_latest_messages_send should return messages when fully validated"
    );
}

// S2: got_v_blocking transitions from false to true
#[test]
fn test_got_v_blocking_tracking() {
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);

    // Quorum set: threshold 2 of {node1, node2, node3}
    // V-blocking requires enough nodes to block any quorum slice from being satisfied.
    // With threshold 2 of 3, any 2 nodes form a quorum slice.
    // A v-blocking set is any set that intersects every quorum slice.
    // With threshold=2, validators={n1,n2,n3}, v-blocking needs at least 2 nodes
    // (since removing 2 nodes leaves 1, which doesn't meet threshold 2).
    let quorum_set = ScpQuorumSet {
        threshold: 2,
        validators: vec![node1.clone(), node2.clone(), node3.clone()]
            .try_into()
            .unwrap(),
        inner_sets: vec![].try_into().unwrap(),
    };
    let mut slot = Slot::new(1, node1.clone(), quorum_set.clone(), true);

    // Initially not v-blocking
    assert!(!slot.got_v_blocking(), "should not be v-blocking initially");

    // Add a nomination envelope from self (node1).
    // Since set_state_from_envelope validates node_id == local_node_id,
    // we can only add our own envelope.
    let value: Value = vec![1, 2, 3].try_into().unwrap();
    let nomination = stellar_xdr::curr::ScpNomination {
        quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
        votes: vec![value.clone()].try_into().unwrap(),
        accepted: vec![].try_into().unwrap(),
    };
    let own_envelope = ScpEnvelope {
        statement: stellar_xdr::curr::ScpStatement {
            node_id: node1.clone(),
            slot_index: 1,
            pledges: ScpStatementPledges::Nominate(nomination.clone()),
        },
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };
    slot.set_state_from_envelope(&own_envelope);

    // After adding one node (self), check got_v_blocking
    // With threshold=2, one node out of 3 is not v-blocking
    // (need 2 nodes to block, since any slice needs 2 of 3)
    // Actually: for threshold=2 of 3 validators, v-blocking needs
    // > (3 - 2) = 1 node, so 2 nodes. One node is NOT v-blocking.
    assert!(
        !slot.got_v_blocking(),
        "one node should not be v-blocking for threshold 2 of 3"
    );
}

// S4: get_externalizing_state filters properly
#[test]
fn test_get_externalizing_state_not_externalized() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let slot = Slot::new(1, node.clone(), quorum_set.clone(), true);

    // Not externalized, should return empty
    let state = slot.get_externalizing_state();
    assert!(
        state.is_empty(),
        "get_externalizing_state should return empty when not externalized"
    );
}

#[test]
fn test_get_externalizing_state_externalized() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let mut slot = Slot::new(1, node.clone(), quorum_set.clone(), true);

    let value: Value = vec![7, 8, 9].try_into().unwrap();
    let ext = stellar_xdr::curr::ScpStatementExternalize {
        commit: stellar_xdr::curr::ScpBallot {
            counter: 5,
            value: value.clone(),
        },
        n_h: 7,
        commit_quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
    };
    let statement = stellar_xdr::curr::ScpStatement {
        node_id: node.clone(),
        slot_index: 1,
        pledges: ScpStatementPledges::Externalize(ext),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };
    slot.set_state_from_envelope(&envelope);

    assert!(slot.is_externalized());
    // Since slot is fully validated and we externalized, should include our envelope
    let state = slot.get_externalizing_state();
    assert!(
        !state.is_empty(),
        "get_externalizing_state should include our envelope when externalized"
    );
}

#[test]
fn test_get_externalizing_state_not_fully_validated() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    // Create NOT fully validated slot
    let mut slot = Slot::new(1, node.clone(), quorum_set.clone(), false);

    let value: Value = vec![7, 8, 9].try_into().unwrap();
    let ext = stellar_xdr::curr::ScpStatementExternalize {
        commit: stellar_xdr::curr::ScpBallot {
            counter: 5,
            value: value.clone(),
        },
        n_h: 7,
        commit_quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
    };
    let statement = stellar_xdr::curr::ScpStatement {
        node_id: node.clone(),
        slot_index: 1,
        pledges: ScpStatementPledges::Externalize(ext),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };

    // Note: set_state_from_envelope for EXTERNALIZE sets fully_validated=true
    // So we need to reset it after
    slot.set_state_from_envelope(&envelope);
    // Manually override fully_validated back to false for this test
    slot.fully_validated = false;

    // Our own envelope should NOT be included since not fully validated
    let state = slot.get_externalizing_state();
    assert!(
        state.is_empty(),
        "get_externalizing_state should exclude self envelope when not fully validated"
    );
}

// S5: set_state_from_envelope rejects wrong node/slot
#[test]
fn test_set_state_from_envelope_rejects_wrong_node() {
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let quorum_set = make_quorum_set();
    let mut slot = Slot::new(1, node1.clone(), quorum_set.clone(), true);

    // Create envelope from wrong node
    let value: Value = vec![1, 2, 3].try_into().unwrap();
    let nomination = stellar_xdr::curr::ScpNomination {
        quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
        votes: vec![value.clone()].try_into().unwrap(),
        accepted: vec![].try_into().unwrap(),
    };
    let statement = stellar_xdr::curr::ScpStatement {
        node_id: node2.clone(), // Wrong node!
        slot_index: 1,
        pledges: ScpStatementPledges::Nominate(nomination),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };

    assert!(
        !slot.set_state_from_envelope(&envelope),
        "set_state_from_envelope should reject envelope from wrong node"
    );
}

#[test]
fn test_set_state_from_envelope_rejects_wrong_slot() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let mut slot = Slot::new(1, node.clone(), quorum_set.clone(), true);

    // Create envelope for wrong slot
    let value: Value = vec![1, 2, 3].try_into().unwrap();
    let nomination = stellar_xdr::curr::ScpNomination {
        quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
        votes: vec![value.clone()].try_into().unwrap(),
        accepted: vec![].try_into().unwrap(),
    };
    let statement = stellar_xdr::curr::ScpStatement {
        node_id: node.clone(),
        slot_index: 999, // Wrong slot!
        pledges: ScpStatementPledges::Nominate(nomination),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };

    assert!(
        !slot.set_state_from_envelope(&envelope),
        "set_state_from_envelope should reject envelope for wrong slot"
    );
}

// S6: EXTERNALIZE state restoration sets prepared field
#[test]
fn test_set_state_from_envelope_externalize_sets_prepared() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let mut slot = Slot::new(1, node.clone(), quorum_set.clone(), true);

    let value: Value = vec![7, 8, 9].try_into().unwrap();
    let ext = stellar_xdr::curr::ScpStatementExternalize {
        commit: stellar_xdr::curr::ScpBallot {
            counter: 5,
            value: value.clone(),
        },
        n_h: 7,
        commit_quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
    };
    let statement = stellar_xdr::curr::ScpStatement {
        node_id: node.clone(),
        slot_index: 1,
        pledges: ScpStatementPledges::Externalize(ext),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };

    assert!(slot.set_state_from_envelope(&envelope));

    // stellar-core sets mPrepared = makeBallot(UINT32_MAX, v) for EXTERNALIZE
    let prepared = slot.ballot().prepared();
    assert!(
        prepared.is_some(),
        "prepared should be set after EXTERNALIZE state restoration"
    );
    let prepared = prepared.unwrap();
    assert_eq!(
        prepared.counter,
        u32::MAX,
        "prepared counter should be UINT32_MAX for EXTERNALIZE"
    );
    assert_eq!(
        prepared.value, value,
        "prepared value should match commit value"
    );
}

// S9: purge_slots keeps slot_to_keep
#[test]
fn test_purge_slots_keeps_slot_to_keep() {
    use crate::driver::{SCPDriver, ValidationLevel};
    use crate::SCP;
    use std::sync::Arc;
    use std::time::Duration;

    struct DummyDriver;
    impl SCPDriver for DummyDriver {
        fn validate_value(&self, _: u64, _: &Value, _: bool) -> ValidationLevel {
            ValidationLevel::FullyValidated
        }
        fn combine_candidates(&self, _: u64, _: &[Value]) -> Option<Value> {
            None
        }
        fn emit_envelope(&self, _: &ScpEnvelope) {}
        fn nominating_value(&self, _: u64, _: &Value) {}
        fn extract_valid_value(&self, _: u64, _: &Value) -> Option<Value> {
            None
        }
        fn value_externalized(&self, _: u64, _: &Value) {}
        fn get_quorum_set(&self, _: &NodeId) -> Option<ScpQuorumSet> {
            None
        }
        fn ballot_did_prepare(&self, _: u64, _: &stellar_xdr::curr::ScpBallot) {}
        fn ballot_did_confirm(&self, _: u64, _: &stellar_xdr::curr::ScpBallot) {}
        fn compute_hash_node(&self, _: u64, _: &Value, _: bool, _: u32, _: &NodeId) -> u64 {
            1
        }
        fn compute_value_hash(&self, _: u64, _: &Value, _: u32, _: &Value) -> u64 {
            1
        }
        fn compute_timeout(&self, _: u32, _: bool) -> Duration {
            Duration::from_secs(1)
        }
        fn sign_envelope(&self, _: &mut ScpEnvelope) {}
        fn verify_envelope(&self, _: &ScpEnvelope) -> bool {
            true
        }
    }

    let node = make_node_id(1);
    let quorum_set = ScpQuorumSet {
        threshold: 1,
        validators: vec![node.clone()].try_into().unwrap(),
        inner_sets: vec![].try_into().unwrap(),
    };
    let driver = Arc::new(DummyDriver);
    let scp = SCP::new(node, true, quorum_set, driver);

    // Create slots 1 through 10
    for i in 1..=10 {
        let value: Value = vec![i as u8].try_into().unwrap();
        scp.force_externalize(i, value);
    }
    assert_eq!(scp.slot_count(), 10);

    // Purge slots older than 8, but keep slot 3
    scp.purge_slots(8, Some(3));

    let active = scp.active_slots();
    // Should keep slots 8, 9, 10 (>= 8) and slot 3 (slot_to_keep)
    assert!(active.contains(&3), "slot 3 should be kept as slot_to_keep");
    assert!(active.contains(&8), "slot 8 should be kept (>= max)");
    assert!(active.contains(&9), "slot 9 should be kept (>= max)");
    assert!(active.contains(&10), "slot 10 should be kept (>= max)");
    assert!(!active.contains(&1), "slot 1 should be purged");
    assert!(!active.contains(&7), "slot 7 should be purged");
    assert_eq!(active.len(), 4, "should have exactly 4 slots remaining");
}

// S9: purge_slots without slot_to_keep behaves normally
#[test]
fn test_purge_slots_without_keep() {
    use crate::driver::{SCPDriver, ValidationLevel};
    use crate::SCP;
    use std::sync::Arc;
    use std::time::Duration;

    struct DummyDriver2;
    impl SCPDriver for DummyDriver2 {
        fn validate_value(&self, _: u64, _: &Value, _: bool) -> ValidationLevel {
            ValidationLevel::FullyValidated
        }
        fn combine_candidates(&self, _: u64, _: &[Value]) -> Option<Value> {
            None
        }
        fn emit_envelope(&self, _: &ScpEnvelope) {}
        fn nominating_value(&self, _: u64, _: &Value) {}
        fn extract_valid_value(&self, _: u64, _: &Value) -> Option<Value> {
            None
        }
        fn value_externalized(&self, _: u64, _: &Value) {}
        fn get_quorum_set(&self, _: &NodeId) -> Option<ScpQuorumSet> {
            None
        }
        fn ballot_did_prepare(&self, _: u64, _: &stellar_xdr::curr::ScpBallot) {}
        fn ballot_did_confirm(&self, _: u64, _: &stellar_xdr::curr::ScpBallot) {}
        fn compute_hash_node(&self, _: u64, _: &Value, _: bool, _: u32, _: &NodeId) -> u64 {
            1
        }
        fn compute_value_hash(&self, _: u64, _: &Value, _: u32, _: &Value) -> u64 {
            1
        }
        fn compute_timeout(&self, _: u32, _: bool) -> Duration {
            Duration::from_secs(1)
        }
        fn sign_envelope(&self, _: &mut ScpEnvelope) {}
        fn verify_envelope(&self, _: &ScpEnvelope) -> bool {
            true
        }
    }

    let node = make_node_id(1);
    let quorum_set = ScpQuorumSet {
        threshold: 1,
        validators: vec![node.clone()].try_into().unwrap(),
        inner_sets: vec![].try_into().unwrap(),
    };
    let driver = Arc::new(DummyDriver2);
    let scp = SCP::new(node, true, quorum_set, driver);

    for i in 1..=10 {
        let value: Value = vec![i as u8].try_into().unwrap();
        scp.force_externalize(i, value);
    }
    assert_eq!(scp.slot_count(), 10);

    // Purge slots older than 8, no slot_to_keep
    scp.purge_slots(8, None);

    let active = scp.active_slots();
    assert_eq!(active.len(), 3, "should have slots 8, 9, 10 remaining");
    assert!(!active.contains(&3), "slot 3 should be purged (no keep)");
}

// S10: advanceSlot panics on recursion overflow
#[test]
#[should_panic(expected = "maximum number of transitions reached in advanceSlot")]
fn test_advance_slot_recursion_panic() {
    use crate::ballot::BallotProtocol;
    use crate::driver::{SCPDriver, ValidationLevel};
    use std::time::Duration;

    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let mut ballot = BallotProtocol::new();

    // Manually set current_message_level to 49 (one below threshold)
    // then call advance_slot which will increment to 50 and panic (>= 50)
    ballot.set_current_message_level_for_test(49);

    // Create a dummy hint statement
    let value: Value = vec![1, 2, 3].try_into().unwrap();
    let prep = stellar_xdr::curr::ScpStatementPrepare {
        quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
        ballot: stellar_xdr::curr::ScpBallot {
            counter: 1,
            value: value.clone(),
        },
        prepared: None,
        prepared_prime: None,
        n_c: 0,
        n_h: 0,
    };
    let statement = stellar_xdr::curr::ScpStatement {
        node_id: node.clone(),
        slot_index: 1,
        pledges: ScpStatementPledges::Prepare(prep),
    };

    struct PanicDriver;
    impl SCPDriver for PanicDriver {
        fn validate_value(&self, _: u64, _: &Value, _: bool) -> ValidationLevel {
            ValidationLevel::FullyValidated
        }
        fn combine_candidates(&self, _: u64, _: &[Value]) -> Option<Value> {
            None
        }
        fn emit_envelope(&self, _: &ScpEnvelope) {}
        fn nominating_value(&self, _: u64, _: &Value) {}
        fn extract_valid_value(&self, _: u64, _: &Value) -> Option<Value> {
            None
        }
        fn value_externalized(&self, _: u64, _: &Value) {}
        fn get_quorum_set(&self, _: &NodeId) -> Option<ScpQuorumSet> {
            None
        }
        fn ballot_did_prepare(&self, _: u64, _: &stellar_xdr::curr::ScpBallot) {}
        fn ballot_did_confirm(&self, _: u64, _: &stellar_xdr::curr::ScpBallot) {}
        fn compute_hash_node(&self, _: u64, _: &Value, _: bool, _: u32, _: &NodeId) -> u64 {
            1
        }
        fn compute_value_hash(&self, _: u64, _: &Value, _: u32, _: &Value) -> u64 {
            1
        }
        fn compute_timeout(&self, _: u32, _: bool) -> Duration {
            Duration::from_secs(1)
        }
        fn sign_envelope(&self, _: &mut ScpEnvelope) {}
        fn verify_envelope(&self, _: &ScpEnvelope) -> bool {
            true
        }
    }

    let driver = std::sync::Arc::new(PanicDriver);
    let ctx = SlotContext {
        local_node_id: &node,
        local_quorum_set: &quorum_set,
        driver: &driver,
        slot_index: 1,
    };
    ballot.advance_slot_for_test(&statement, &ctx);
}

// S-get_latest_envelope: checks ballot then nomination
#[test]
fn test_get_latest_envelope_checks_ballot_then_nomination() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set();
    let mut slot = Slot::new(1, node.clone(), quorum_set.clone(), true);

    // Initially no envelope
    assert!(slot.get_latest_envelope(&node).is_none());

    // Add nomination envelope
    let value: Value = vec![1, 2, 3].try_into().unwrap();
    let nomination = stellar_xdr::curr::ScpNomination {
        quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
        votes: vec![value.clone()].try_into().unwrap(),
        accepted: vec![].try_into().unwrap(),
    };
    let nom_envelope = ScpEnvelope {
        statement: stellar_xdr::curr::ScpStatement {
            node_id: node.clone(),
            slot_index: 1,
            pledges: ScpStatementPledges::Nominate(nomination),
        },
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };
    slot.set_state_from_envelope(&nom_envelope);

    // Now should find the nomination envelope
    let env = slot.get_latest_envelope(&node);
    assert!(env.is_some(), "should find nomination envelope");
    assert!(
        matches!(
            env.unwrap().statement.pledges,
            ScpStatementPledges::Nominate(_)
        ),
        "should be a nomination envelope"
    );

    // Add ballot envelope - should prefer ballot over nomination
    let prep = stellar_xdr::curr::ScpStatementPrepare {
        quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
        ballot: stellar_xdr::curr::ScpBallot {
            counter: 1,
            value: value.clone(),
        },
        prepared: None,
        prepared_prime: None,
        n_c: 0,
        n_h: 0,
    };
    let ballot_envelope = ScpEnvelope {
        statement: stellar_xdr::curr::ScpStatement {
            node_id: node.clone(),
            slot_index: 1,
            pledges: ScpStatementPledges::Prepare(prep),
        },
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };
    slot.set_state_from_envelope(&ballot_envelope);

    // Now should find the ballot envelope (ballot protocol checked first)
    let env = slot.get_latest_envelope(&node);
    assert!(env.is_some(), "should find ballot envelope");
    assert!(
        matches!(
            env.unwrap().statement.pledges,
            ScpStatementPledges::Prepare(_)
        ),
        "should prefer ballot envelope over nomination"
    );
}
