use super::*;
use crate::driver::ValidationLevel;
use crate::quorum::hash_quorum_set;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use stellar_xdr::curr::{
    PublicKey, ScpBallot, ScpNomination, ScpStatement, ScpStatementPledges,
    ScpStatementPrepare, Uint256,
};

/// Mock driver for testing.
struct MockDriver {
    emit_count: AtomicU32,
}

impl MockDriver {
    fn new() -> Self {
        Self {
            emit_count: AtomicU32::new(0),
        }
    }
}

impl SCPDriver for MockDriver {
    fn validate_value(
        &self,
        _slot_index: u64,
        _value: &Value,
        _nomination: bool,
    ) -> ValidationLevel {
        ValidationLevel::FullyValidated
    }

    fn combine_candidates(&self, _slot_index: u64, candidates: &[Value]) -> Option<Value> {
        candidates.first().cloned()
    }

    fn extract_valid_value(&self, _slot_index: u64, value: &Value) -> Option<Value> {
        Some(value.clone())
    }

    fn emit_envelope(&self, _envelope: &ScpEnvelope) {
        self.emit_count.fetch_add(1, Ordering::SeqCst);
    }

    fn get_quorum_set(&self, _node_id: &NodeId) -> Option<ScpQuorumSet> {
        None
    }

    fn nominating_value(&self, _slot_index: u64, _value: &Value) {}

    fn value_externalized(&self, _slot_index: u64, _value: &Value) {}

    fn ballot_did_prepare(&self, _slot_index: u64, _ballot: &ScpBallot) {}

    fn ballot_did_confirm(&self, _slot_index: u64, _ballot: &ScpBallot) {}

    fn compute_hash_node(
        &self,
        _slot_index: u64,
        _prev_value: &Value,
        _is_priority: bool,
        _round: u32,
        _node_id: &NodeId,
    ) -> u64 {
        1
    }

    fn compute_value_hash(
        &self,
        _slot_index: u64,
        _prev_value: &Value,
        _round: u32,
        _value: &Value,
    ) -> u64 {
        1
    }

    fn compute_timeout(&self, round: u32, _is_nomination: bool) -> Duration {
        Duration::from_secs(1 + round as u64)
    }

    fn sign_envelope(&self, _envelope: &mut ScpEnvelope) {}

    fn verify_envelope(&self, _envelope: &ScpEnvelope) -> bool {
        true
    }
}

/// Driver that treats all values as MaybeValid.
struct MaybeValidDriver {
    emit_count: AtomicU32,
    quorum_set: ScpQuorumSet,
}

impl MaybeValidDriver {
    fn new(quorum_set: ScpQuorumSet) -> Self {
        Self {
            emit_count: AtomicU32::new(0),
            quorum_set,
        }
    }
}

impl SCPDriver for MaybeValidDriver {
    fn validate_value(
        &self,
        _slot_index: u64,
        _value: &Value,
        _nomination: bool,
    ) -> ValidationLevel {
        ValidationLevel::MaybeValid
    }

    fn combine_candidates(&self, _slot_index: u64, candidates: &[Value]) -> Option<Value> {
        candidates.first().cloned()
    }

    fn extract_valid_value(&self, _slot_index: u64, value: &Value) -> Option<Value> {
        Some(value.clone())
    }

    fn emit_envelope(&self, _envelope: &ScpEnvelope) {
        self.emit_count.fetch_add(1, Ordering::SeqCst);
    }

    fn get_quorum_set(&self, _node_id: &NodeId) -> Option<ScpQuorumSet> {
        Some(self.quorum_set.clone())
    }

    fn nominating_value(&self, _slot_index: u64, _value: &Value) {}

    fn value_externalized(&self, _slot_index: u64, _value: &Value) {}

    fn ballot_did_prepare(&self, _slot_index: u64, _ballot: &ScpBallot) {}

    fn ballot_did_confirm(&self, _slot_index: u64, _ballot: &ScpBallot) {}

    fn compute_hash_node(
        &self,
        _slot_index: u64,
        _prev_value: &Value,
        _is_priority: bool,
        _round: u32,
        _node_id: &NodeId,
    ) -> u64 {
        1
    }

    fn compute_value_hash(
        &self,
        _slot_index: u64,
        _prev_value: &Value,
        _round: u32,
        _value: &Value,
    ) -> u64 {
        1
    }

    fn compute_timeout(&self, round: u32, _is_nomination: bool) -> Duration {
        Duration::from_secs(1 + round as u64)
    }

    fn sign_envelope(&self, _envelope: &mut ScpEnvelope) {}

    fn verify_envelope(&self, _envelope: &ScpEnvelope) -> bool {
        true
    }
}

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

fn make_quorum_set_with(validators: Vec<NodeId>, threshold: u32) -> ScpQuorumSet {
    ScpQuorumSet {
        threshold,
        validators: validators.try_into().unwrap_or_default(),
        inner_sets: vec![].try_into().unwrap(),
    }
}

fn make_value(bytes: &[u8]) -> Value {
    bytes.to_vec().try_into().unwrap()
}

fn make_prepare_envelope(
    node_id: NodeId,
    slot_index: u64,
    quorum_set: &ScpQuorumSet,
    ballot: ScpBallot,
) -> ScpEnvelope {
    let prep = ScpStatementPrepare {
        quorum_set_hash: hash_quorum_set(quorum_set).into(),
        ballot,
        prepared: None,
        prepared_prime: None,
        n_c: 0,
        n_h: 0,
    };
    let statement = ScpStatement {
        node_id,
        slot_index,
        pledges: ScpStatementPledges::Prepare(prep),
    };
    ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    }
}

fn make_nomination_envelope(
    node_id: NodeId,
    slot_index: u64,
    quorum_set: &ScpQuorumSet,
    value: Value,
) -> ScpEnvelope {
    let nomination = ScpNomination {
        quorum_set_hash: hash_quorum_set(quorum_set).into(),
        votes: vec![value].try_into().unwrap(),
        accepted: vec![].try_into().unwrap(),
    };
    let statement = ScpStatement {
        node_id,
        slot_index,
        pledges: ScpStatementPledges::Nominate(nomination),
    };
    ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    }
}

#[test]
fn test_scp_new() {
    let driver = Arc::new(MockDriver::new());
    let scp = SCP::new(make_node_id(1), true, make_quorum_set(), driver);

    assert!(scp.is_validator());
    assert_eq!(scp.slot_count(), 0);
}

#[test]
fn test_force_externalize() {
    let driver = Arc::new(MockDriver::new());
    let scp = SCP::new(make_node_id(1), true, make_quorum_set(), driver);

    let value: Value = vec![1, 2, 3].try_into().unwrap();
    scp.force_externalize(42, value.clone());

    assert!(scp.is_slot_externalized(42));
    assert_eq!(scp.get_externalized_value(42), Some(value));
}

#[test]
fn test_get_scp_state_skips_self_when_not_fully_validated() {
    let node_a = make_node_id(1);
    let node_b = make_node_id(2);
    let node_c = make_node_id(3);
    // Use threshold=2 so that a single PREPARE from node_b doesn't form
    // a quorum for federated_accept (which would cascade to externalization
    // and set fully_validated=true, defeating the purpose of this test).
    let quorum_set =
        make_quorum_set_with(vec![node_a.clone(), node_b.clone(), node_c.clone()], 2);
    let driver = Arc::new(MaybeValidDriver::new(quorum_set.clone()));
    let scp = SCP::new(node_a.clone(), true, quorum_set.clone(), driver.clone());

    let ballot = ScpBallot {
        counter: 1,
        value: make_value(&[7]),
    };
    let env_b = make_prepare_envelope(node_b, 1, &quorum_set, ballot);
    scp.receive_envelope(env_b);

    let value = make_value(&[1, 2, 3]);
    let prev = make_value(&[0]);
    scp.nominate(1, value, &prev);

    let envelopes = scp.get_scp_state(1);
    assert!(!envelopes.is_empty());
    assert!(envelopes.iter().all(|env| env.statement.node_id != node_a));
    assert_eq!(driver.emit_count.load(Ordering::SeqCst), 0);
}

#[test]
fn test_get_scp_state_includes_self_when_fully_validated() {
    let node_a = make_node_id(1);
    let quorum_set = make_quorum_set_with(vec![node_a.clone()], 1);
    let driver = Arc::new(MockDriver::new());
    let scp = SCP::new(node_a.clone(), true, quorum_set.clone(), driver);

    let value = make_value(&[4, 5, 6]);
    let prev = make_value(&[1]);
    scp.nominate(1, value, &prev);

    let envelopes = scp.get_scp_state(1);
    assert!(envelopes.iter().any(|env| env.statement.node_id == node_a));
}

#[test]
fn test_get_scp_state_orders_by_node_id() {
    let node_a = make_node_id(1);
    let node_b = make_node_id(2);
    let quorum_set = make_quorum_set_with(vec![node_a.clone(), node_b.clone()], 1);
    let driver = Arc::new(MockDriver::new());
    let scp = SCP::new(node_a.clone(), true, quorum_set.clone(), driver);

    let value_a = make_value(&[1]);
    let value_b = make_value(&[2]);
    let env_b = make_nomination_envelope(node_b.clone(), 1, &quorum_set, value_b);
    let env_a = make_nomination_envelope(node_a.clone(), 1, &quorum_set, value_a);
    scp.receive_envelope(env_b);
    scp.receive_envelope(env_a);

    let envelopes = scp.get_scp_state(1);
    assert!(envelopes.len() >= 2);
    assert!(envelopes[0].statement.node_id <= envelopes[1].statement.node_id);
}

#[test]
fn test_get_scp_state_orders_by_slot() {
    let node_a = make_node_id(1);
    let node_b = make_node_id(2);
    let quorum_set = make_quorum_set_with(vec![node_a.clone(), node_b.clone()], 1);
    let driver = Arc::new(MockDriver::new());
    let scp = SCP::new(node_a.clone(), true, quorum_set.clone(), driver);

    let env_slot2 = make_nomination_envelope(node_b.clone(), 2, &quorum_set, make_value(&[2]));
    let env_slot1 = make_nomination_envelope(node_a.clone(), 1, &quorum_set, make_value(&[1]));
    scp.receive_envelope(env_slot2);
    scp.receive_envelope(env_slot1);

    let envelopes = scp.get_scp_state(1);
    assert!(envelopes.len() >= 2);
    assert!(envelopes[0].statement.slot_index <= envelopes[1].statement.slot_index);
}

#[test]
fn test_purge_slots() {
    let driver = Arc::new(MockDriver::new());
    let scp = SCP::new(make_node_id(1), true, make_quorum_set(), driver);

    // Create some slots
    for i in 1..=10 {
        let value: Value = vec![i as u8].try_into().unwrap();
        scp.force_externalize(i, value);
    }

    assert_eq!(scp.slot_count(), 10);

    // Purge old slots
    scp.purge_slots(6, None);

    assert_eq!(scp.slot_count(), 5);
    assert!(scp.get_externalized_value(5).is_none());
    assert!(scp.get_externalized_value(6).is_some());
}

// ==================== Tests for new parity features ====================

#[test]
fn test_got_v_blocking() {
    let node_a = make_node_id(1);
    let node_b = make_node_id(2);
    let quorum_set = ScpQuorumSet {
        threshold: 2,
        validators: vec![node_a.clone(), node_b.clone()].try_into().unwrap(),
        inner_sets: vec![].try_into().unwrap(),
    };
    let driver = Arc::new(MaybeValidDriver::new(quorum_set.clone()));
    let scp = SCP::new(node_a.clone(), true, quorum_set.clone(), driver);

    // No slot created yet
    assert!(!scp.got_v_blocking(1));

    // Force externalize to create a slot
    let value: Value = vec![1, 2, 3].try_into().unwrap();
    scp.force_externalize(1, value);

    // No envelopes yet, so no v-blocking
    // (Note: got_v_blocking checks ballot envelopes, not nomination)
    assert!(!scp.got_v_blocking(1));
}

#[test]
fn test_get_cumulative_statement_count() {
    let node_a = make_node_id(1);
    let quorum_set = make_quorum_set();
    let driver = Arc::new(MockDriver::new());
    let scp = SCP::new(node_a.clone(), true, quorum_set.clone(), driver);

    // No slots, count should be 0
    assert_eq!(scp.get_cumulative_statement_count(), 0);

    // Force externalize to create slots
    for i in 1..=3 {
        let value: Value = vec![i as u8].try_into().unwrap();
        scp.force_externalize(i, value);
    }

    // Slots exist but might have no statements (depends on implementation)
    let _count = scp.get_cumulative_statement_count(); // Just verify it doesn't panic
}

#[test]
fn test_get_missing_nodes() {
    let node_a = make_node_id(1);
    let node_b = make_node_id(2);
    let node_c = make_node_id(3);
    let quorum_set = ScpQuorumSet {
        threshold: 2,
        validators: vec![node_a.clone(), node_b.clone(), node_c.clone()]
            .try_into()
            .unwrap(),
        inner_sets: vec![].try_into().unwrap(),
    };
    let driver = Arc::new(MaybeValidDriver::new(quorum_set.clone()));
    let scp = SCP::new(node_a.clone(), true, quorum_set.clone(), driver);

    // No slot yet - all nodes should be missing
    let missing = scp.get_missing_nodes(1);
    assert!(missing.contains(&node_a));
    assert!(missing.contains(&node_b));
    assert!(missing.contains(&node_c));
}

#[test]
fn test_is_newer_statement() {
    let node_a = make_node_id(1);
    let quorum_set = make_quorum_set();
    let driver = Arc::new(MockDriver::new());
    let scp = SCP::new(node_a.clone(), true, quorum_set.clone(), driver);

    // Create a nomination statement
    let nom = ScpNomination {
        quorum_set_hash: hash_quorum_set(&quorum_set).into(),
        votes: vec![make_value(&[1])].try_into().unwrap(),
        accepted: vec![].try_into().unwrap(),
    };
    let statement = ScpStatement {
        node_id: node_a.clone(),
        slot_index: 1,
        pledges: ScpStatementPledges::Nominate(nom),
    };

    // No slot exists yet, any statement is "newer"
    assert!(scp.is_newer_statement(1, &statement));
}

#[test]
fn test_empty() {
    let driver = Arc::new(MockDriver::new());
    let scp = SCP::new(make_node_id(1), true, make_quorum_set(), driver);

    // New SCP should be empty
    assert!(scp.empty());

    // After force_externalize, should not be empty
    let value: Value = vec![1, 2, 3].try_into().unwrap();
    scp.force_externalize(1, value);
    assert!(!scp.empty());
}

#[test]
fn test_get_highest_known_slot() {
    let driver = Arc::new(MockDriver::new());
    let scp = SCP::new(make_node_id(1), true, make_quorum_set(), driver);

    // No slots initially
    assert_eq!(scp.get_highest_known_slot(), None);

    // Add some slots
    for i in [5, 2, 8, 3] {
        let value: Value = vec![i as u8].try_into().unwrap();
        scp.force_externalize(i, value);
    }

    // Should return the highest slot
    assert_eq!(scp.get_highest_known_slot(), Some(8));
}

#[test]
fn test_driver_access() {
    let driver = Arc::new(MockDriver::new());
    let scp = SCP::new(make_node_id(1), true, make_quorum_set(), driver.clone());

    // Should be able to access the driver
    let retrieved = scp.driver();
    assert!(Arc::ptr_eq(&driver, retrieved));
}
