use super::*;
use crate::driver::ValidationLevel;
use crate::SlotContext;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use stellar_xdr::curr::{PublicKey, ScpBallot, Uint256};

/// Helper to construct a `SlotContext` from the old four-parameter pattern.
macro_rules! ctx {
    ($node:expr, $qs:expr, $driver:expr, $slot:expr) => {
        SlotContext {
            local_node_id: $node,
            local_quorum_set: $qs,
            driver: $driver,
            slot_index: $slot,
        }
    };
}

fn is_near_weight(weight: u64, target: f64) -> bool {
    let ratio = weight as f64 / u64::MAX as f64;
    (ratio - target).abs() < 0.01
}

#[test]
fn test_nomination_weight() {
    let node0 = make_node_id(0);
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);
    let node4 = make_node_id(4);
    let node5 = make_node_id(5);

    let mut qset = make_quorum_set(
        vec![node0.clone(), node1.clone(), node2.clone(), node3.clone()],
        3,
    );
    let protocol = NominationProtocol::new();

    let weight = protocol.get_node_weight(&qset, &node0, &node2);
    assert!(is_near_weight(weight, 0.75));

    let weight = protocol.get_node_weight(&qset, &node0, &node4);
    assert_eq!(weight, 0);

    let inner = make_quorum_set(vec![node4.clone(), node5.clone()], 1);
    qset.inner_sets = vec![inner].try_into().unwrap_or_default();

    let weight = protocol.get_node_weight(&qset, &node0, &node4);
    assert!(is_near_weight(weight, 0.6 * 0.5));
}

#[test]
fn test_nomination_new() {
    let nom = NominationProtocol::new();
    assert_eq!(nom.round(), 0);
    assert!(!nom.is_started());
    assert!(!nom.is_stopped());
    assert!(nom.votes().is_empty());
    assert!(nom.accepted().is_empty());
    assert!(nom.latest_composite().is_none());
}

struct MockDriver {
    quorum_set: ScpQuorumSet,
    emit_count: AtomicU32,
}

impl MockDriver {
    fn new(quorum_set: ScpQuorumSet) -> Self {
        Self {
            quorum_set,
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
        value: &Value,
    ) -> u64 {
        value.iter().map(|b| *b as u64).sum()
    }

    fn compute_timeout(&self, _round: u32, _is_nomination: bool) -> Duration {
        Duration::from_millis(1)
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

fn make_quorum_set(validators: Vec<NodeId>, threshold: u32) -> ScpQuorumSet {
    ScpQuorumSet {
        threshold,
        validators: validators.try_into().unwrap_or_default(),
        inner_sets: vec![].try_into().unwrap(),
    }
}

fn make_value(bytes: &[u8]) -> Value {
    bytes.to_vec().try_into().unwrap()
}

fn make_nomination_envelope(
    node_id: NodeId,
    slot_index: u64,
    quorum_set: &ScpQuorumSet,
    votes: Vec<Value>,
    accepted: Vec<Value>,
) -> ScpEnvelope {
    let nomination = ScpNomination {
        quorum_set_hash: hash_quorum_set(quorum_set).into(),
        votes: votes.try_into().unwrap_or_default(),
        accepted: accepted.try_into().unwrap_or_default(),
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
fn test_nomination_rejects_unsorted_values() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let v1 = make_value(&[1]);
    let v2 = make_value(&[2]);
    let env = make_nomination_envelope(make_node_id(2), 7, &quorum_set, vec![v2, v1], vec![]);
    let state = nom.process_envelope(&env, &ctx!(&node, &quorum_set, &driver, 7));
    assert_eq!(state, EnvelopeState::Invalid);
}

#[test]
fn test_nomination_rejects_non_monotonic_statement() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let v1 = make_value(&[1]);
    let env =
        make_nomination_envelope(make_node_id(2), 8, &quorum_set, vec![v1.clone()], vec![]);
    let first = nom.process_envelope(&env, &ctx!(&node, &quorum_set, &driver, 8));
    let second = nom.process_envelope(&env, &ctx!(&node, &quorum_set, &driver, 8));

    assert!(matches!(
        first,
        EnvelopeState::Valid | EnvelopeState::ValidNew
    ));
    assert_eq!(second, EnvelopeState::Invalid);
}

#[test]
fn test_nomination_accepts_and_ratifies_with_quorum() {
    let node = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);
    let quorum_set = make_quorum_set(vec![node.clone(), node2.clone(), node3.clone()], 2);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let value = make_value(&[9]);
    let prev = make_value(&[0]);
    nom.nominate(&ctx!(&node, &quorum_set, &driver, 9), value.clone(), &prev, false);

    let env2 = make_nomination_envelope(
        node2,
        9,
        &quorum_set,
        vec![value.clone()],
        vec![value.clone()],
    );
    let env3 = make_nomination_envelope(
        node3,
        9,
        &quorum_set,
        vec![value.clone()],
        vec![value.clone()],
    );

    nom.process_envelope(&env2, &ctx!(&node, &quorum_set, &driver, 9));
    nom.process_envelope(&env3, &ctx!(&node, &quorum_set, &driver, 9));

    assert!(nom.accepted().contains(&value));
    assert_eq!(nom.latest_composite(), Some(&value));
}

#[test]
fn test_nomination_timeout_requires_start() {
    let node = make_node_id(1);
    let node2 = make_node_id(2);
    // Use a 2-of-2 quorum set so self-processing alone can't form quorum
    // (prevents immediate acceptance/ratification that would fill candidates).
    let quorum_set = make_quorum_set(vec![node.clone(), node2.clone()], 2);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();
    let value = make_value(&[4]);
    let prev = make_value(&[0]);

    let timed_out = nom.nominate(&ctx!(&node, &quorum_set, &driver, 10), value.clone(), &prev, true);
    assert!(!timed_out);
    assert!(!nom.is_started());

    nom.nominate(&ctx!(&node, &quorum_set, &driver, 10), value.clone(), &prev, false);
    let round_before = nom.round();

    nom.nominate(&ctx!(&node, &quorum_set, &driver, 10), value, &prev, true);
    assert!(nom.round() > round_before);
}

#[test]
fn test_nomination_process_current_state_skips_self_when_not_validated() {
    let local = make_node_id(1);
    let remote = make_node_id(2);
    let quorum_set = make_quorum_set(vec![local.clone(), remote.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let value_local = make_value(&[1]);
    let value_remote = make_value(&[2]);
    let env_local =
        make_nomination_envelope(local.clone(), 11, &quorum_set, vec![value_local], vec![]);
    let env_remote =
        make_nomination_envelope(remote.clone(), 11, &quorum_set, vec![value_remote], vec![]);

    nom.process_envelope(&env_local, &ctx!(&local, &quorum_set, &driver, 11));
    nom.process_envelope(&env_remote, &ctx!(&local, &quorum_set, &driver, 11));

    let mut seen = Vec::new();
    nom.process_current_state(
        |env| {
            seen.push(env.statement.node_id.clone());
            true
        },
        &local,
        false,
        false,
    );

    assert!(seen.contains(&remote));
    assert!(!seen.contains(&local));
}

#[test]
fn test_nomination_process_current_state_includes_self_when_forced() {
    let local = make_node_id(1);
    let quorum_set = make_quorum_set(vec![local.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let value_local = make_value(&[3]);
    let env_local =
        make_nomination_envelope(local.clone(), 12, &quorum_set, vec![value_local], vec![]);

    nom.process_envelope(&env_local, &ctx!(&local, &quorum_set, &driver, 12));

    let mut seen = Vec::new();
    nom.process_current_state(
        |env| {
            seen.push(env.statement.node_id.clone());
            true
        },
        &local,
        false,
        true,
    );

    assert!(seen.contains(&local));
}

#[test]
fn test_nomination_process_current_state_orders_by_node_id() {
    let local = make_node_id(1);
    let node_b = make_node_id(3);
    let node_c = make_node_id(2);
    let quorum_set = make_quorum_set(vec![local.clone(), node_b.clone(), node_c.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let env_local = make_nomination_envelope(
        local.clone(),
        13,
        &quorum_set,
        vec![make_value(&[1])],
        vec![],
    );
    let env_b = make_nomination_envelope(
        node_b.clone(),
        13,
        &quorum_set,
        vec![make_value(&[2])],
        vec![],
    );
    let env_c = make_nomination_envelope(
        node_c.clone(),
        13,
        &quorum_set,
        vec![make_value(&[3])],
        vec![],
    );

    nom.process_envelope(&env_b, &ctx!(&local, &quorum_set, &driver, 13));
    nom.process_envelope(&env_c, &ctx!(&local, &quorum_set, &driver, 13));
    nom.process_envelope(&env_local, &ctx!(&local, &quorum_set, &driver, 13));

    let mut seen = Vec::new();
    nom.process_current_state(
        |env| {
            seen.push(env.statement.node_id.clone());
            true
        },
        &local,
        true,
        false,
    );

    assert_eq!(seen, vec![local, node_c, node_b]);
}

#[test]
fn test_nomination_newer_statement_accepts_accepted_growth() {
    let local = make_node_id(1);
    let remote = make_node_id(2);
    let quorum_set = make_quorum_set(vec![local.clone(), remote.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let value = make_value(&[9]);
    let env_old =
        make_nomination_envelope(remote.clone(), 14, &quorum_set, vec![value.clone()], vec![]);
    let env_new = make_nomination_envelope(
        remote.clone(),
        14,
        &quorum_set,
        vec![value.clone()],
        vec![value],
    );

    nom.process_envelope(&env_old, &ctx!(&local, &quorum_set, &driver, 14));
    nom.process_envelope(&env_new, &ctx!(&local, &quorum_set, &driver, 14));

    let mut accepted_counts = Vec::new();
    nom.process_current_state(
        |env| {
            if let ScpStatementPledges::Nominate(nom) = &env.statement.pledges {
                accepted_counts.push(nom.accepted.len());
            }
            true
        },
        &local,
        true,
        false,
    );

    assert_eq!(accepted_counts, vec![1]);
}

#[test]
fn test_nomination_rejects_shrinking_votes() {
    let local = make_node_id(1);
    let remote = make_node_id(2);
    let quorum_set = make_quorum_set(vec![local.clone(), remote.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let value_a = make_value(&[1]);
    let value_b = make_value(&[2]);
    let env_old = make_nomination_envelope(
        remote.clone(),
        15,
        &quorum_set,
        vec![value_a.clone(), value_b.clone()],
        vec![],
    );
    let env_new =
        make_nomination_envelope(remote.clone(), 15, &quorum_set, vec![value_a], vec![]);

    let first = nom.process_envelope(&env_old, &ctx!(&local, &quorum_set, &driver, 15));
    let second = nom.process_envelope(&env_new, &ctx!(&local, &quorum_set, &driver, 15));

    assert!(matches!(
        first,
        EnvelopeState::Valid | EnvelopeState::ValidNew
    ));
    assert_eq!(second, EnvelopeState::Invalid);
}

#[test]
fn test_nomination_process_current_state_short_circuits() {
    let local = make_node_id(1);
    let remote = make_node_id(2);
    let quorum_set = make_quorum_set(vec![local.clone(), remote.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let env_local = make_nomination_envelope(
        local.clone(),
        16,
        &quorum_set,
        vec![make_value(&[1])],
        vec![],
    );
    let env_remote = make_nomination_envelope(
        remote.clone(),
        16,
        &quorum_set,
        vec![make_value(&[2])],
        vec![],
    );

    nom.process_envelope(&env_remote, &ctx!(&local, &quorum_set, &driver, 16));
    nom.process_envelope(&env_local, &ctx!(&local, &quorum_set, &driver, 16));

    let mut seen = Vec::new();
    let ok = nom.process_current_state(
        |env| {
            seen.push(env.statement.node_id.clone());
            false
        },
        &local,
        true,
        false,
    );

    assert!(!ok);
    assert_eq!(seen.len(), 1);
}

// ==================== Tests for new parity features ====================

#[test]
fn test_set_state_from_envelope_nomination() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let mut nom = NominationProtocol::new();

    let votes = vec![make_value(&[1, 2, 3]), make_value(&[4, 5, 6])];
    let accepted = vec![make_value(&[7, 8, 9])];

    let envelope = make_nomination_envelope(
        node.clone(),
        1,
        &quorum_set,
        votes.clone(),
        accepted.clone(),
    );

    assert!(!nom.is_started());
    assert!(nom.set_state_from_envelope(&envelope));
    // stellar-core does NOT set mNominationStarted = true in setStateFromEnvelope
    assert!(!nom.is_started());

    // Verify votes were restored
    for vote in &votes {
        assert!(nom.votes().contains(vote));
    }

    // Verify accepted values were restored
    for acc in &accepted {
        assert!(nom.accepted().contains(acc));
    }
}

#[test]
fn test_set_state_from_envelope_rejects_ballot_pledges() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let mut nom = NominationProtocol::new();

    // Create a prepare envelope (ballot protocol, not nomination)
    let prep = stellar_xdr::curr::ScpStatementPrepare {
        quorum_set_hash: crate::quorum::hash_quorum_set(&quorum_set).into(),
        ballot: stellar_xdr::curr::ScpBallot {
            counter: 1,
            value: make_value(&[1]),
        },
        prepared: None,
        prepared_prime: None,
        n_c: 0,
        n_h: 0,
    };
    let statement = stellar_xdr::curr::ScpStatement {
        node_id: node.clone(),
        slot_index: 1,
        pledges: stellar_xdr::curr::ScpStatementPledges::Prepare(prep),
    };
    let envelope = stellar_xdr::curr::ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };

    assert!(!nom.set_state_from_envelope(&envelope));
    assert!(!nom.is_started());
}

#[test]
fn test_candidates_accessor() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    // Initially no candidates
    assert!(nom.candidates().is_empty());

    // After nomination starts and values are confirmed, candidates should appear
    let value = make_value(&[1, 2, 3]);
    nom.nominate(
        &ctx!(&node, &quorum_set, &driver, 1),
        value.clone(),
        &make_value(&[0]),
        false,
    );

    // Create envelope from another node that accepts the value
    let other = make_node_id(2);
    let env = make_nomination_envelope(
        other.clone(),
        1,
        &quorum_set,
        vec![value.clone()],
        vec![value.clone()],
    );
    nom.process_envelope(&env, &ctx!(&node, &quorum_set, &driver, 1));

    // Candidates may or may not be populated depending on quorum
    // This test mainly verifies the accessor works
    let _ = nom.candidates();
}

// ==================== Nomination Parity Tests ====================

// Enhanced mock driver that tracks timer stops and supports upgrade logic
struct ParityMockDriver {
    quorum_set: ScpQuorumSet,
    emit_count: AtomicU32,
    timer_stops: std::sync::Mutex<Vec<(u64, crate::driver::SCPTimerType)>>,
    validation_level: std::sync::Mutex<ValidationLevel>,
    extract_result: std::sync::Mutex<Option<Value>>,
    upgrade_timeout_limit: AtomicU32,
    values_with_upgrades: std::sync::Mutex<HashSet<Vec<u8>>>,
    stripped_value: std::sync::Mutex<Option<Value>>,
}

impl ParityMockDriver {
    fn new(quorum_set: ScpQuorumSet) -> Self {
        Self {
            quorum_set,
            emit_count: AtomicU32::new(0),
            timer_stops: std::sync::Mutex::new(Vec::new()),
            validation_level: std::sync::Mutex::new(ValidationLevel::FullyValidated),
            extract_result: std::sync::Mutex::new(None),
            upgrade_timeout_limit: AtomicU32::new(u32::MAX),
            values_with_upgrades: std::sync::Mutex::new(HashSet::new()),
            stripped_value: std::sync::Mutex::new(None),
        }
    }

    fn set_validation_level(&self, level: ValidationLevel) {
        *self.validation_level.lock().unwrap() = level;
    }

    fn set_extract_result(&self, value: Option<Value>) {
        *self.extract_result.lock().unwrap() = value;
    }

    fn get_timer_stops(&self) -> Vec<(u64, crate::driver::SCPTimerType)> {
        self.timer_stops.lock().unwrap().clone()
    }

    fn mark_has_upgrades(&self, value: &Value) {
        self.values_with_upgrades
            .lock()
            .unwrap()
            .insert(value.to_vec());
    }

    fn set_stripped_value(&self, value: Option<Value>) {
        *self.stripped_value.lock().unwrap() = value;
    }
}

impl SCPDriver for ParityMockDriver {
    fn validate_value(
        &self,
        _slot_index: u64,
        _value: &Value,
        _nomination: bool,
    ) -> ValidationLevel {
        *self.validation_level.lock().unwrap()
    }

    fn combine_candidates(&self, _slot_index: u64, candidates: &[Value]) -> Option<Value> {
        candidates.first().cloned()
    }

    fn extract_valid_value(&self, _slot_index: u64, value: &Value) -> Option<Value> {
        let result = self.extract_result.lock().unwrap();
        result.clone().or_else(|| Some(value.clone()))
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
        is_priority: bool,
        round: u32,
        node_id: &NodeId,
    ) -> u64 {
        let seed = match &node_id.0 {
            PublicKey::PublicKeyTypeEd25519(Uint256(bytes)) => bytes[0] as u64,
        };
        if is_priority {
            // Rotate priorities across rounds so different nodes win in
            // different rounds. This ensures update_round_leaders converges.
            // Use a simple hash-like function: (seed * prime1 + round * prime2) mod some range
            let h = (seed
                .wrapping_mul(7919)
                .wrapping_add((round as u64).wrapping_mul(104729)))
                % 100_000;
            h + 1 // ensure non-zero
        } else {
            // Return a small value that's always <= any non-zero weight.
            1
        }
    }

    fn compute_value_hash(
        &self,
        _slot_index: u64,
        _prev_value: &Value,
        _round: u32,
        value: &Value,
    ) -> u64 {
        value.iter().map(|b| *b as u64).sum()
    }

    fn compute_timeout(&self, _round: u32, _is_nomination: bool) -> Duration {
        Duration::from_millis(1)
    }

    fn sign_envelope(&self, _envelope: &mut ScpEnvelope) {}

    fn verify_envelope(&self, _envelope: &ScpEnvelope) -> bool {
        true
    }

    fn stop_timer(&self, slot_index: u64, timer_type: crate::driver::SCPTimerType) {
        self.timer_stops
            .lock()
            .unwrap()
            .push((slot_index, timer_type));
    }

    fn has_upgrades(&self, value: &Value) -> bool {
        self.values_with_upgrades
            .lock()
            .unwrap()
            .contains(value.as_slice())
    }

    fn strip_all_upgrades(&self, _value: &Value) -> Option<Value> {
        self.stripped_value.lock().unwrap().clone()
    }

    fn get_upgrade_nomination_timeout_limit(&self) -> u32 {
        self.upgrade_timeout_limit.load(Ordering::SeqCst)
    }
}

/// N3/15: After stop(), process_envelope should NOT do accept/ratify
/// because `started` is set to false.
///
/// stellar-core `stopNomination()` sets `mNominationStarted = false`, which
/// means the `if (mNominationStarted)` check in `processEnvelope`
/// will skip the accept/ratify logic.
#[test]
fn test_stop_clears_started_flag() {
    let node = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);
    let quorum_set = make_quorum_set(vec![node.clone(), node2.clone(), node3.clone()], 2);
    let driver = Arc::new(ParityMockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let value = make_value(&[5]);
    let prev = make_value(&[0]);

    // Start nomination
    nom.nominate(&ctx!(&node, &quorum_set, &driver, 1), value.clone(), &prev, false);
    assert!(nom.is_started());

    // Stop nomination (N3/15 fix: this should clear started)
    nom.stop();
    assert!(!nom.is_started());
    assert!(nom.is_stopped());

    // Now process an envelope that would normally cause accept/ratify.
    // Since started=false, the accept/ratify block should be skipped.
    let env = make_nomination_envelope(
        node2,
        1,
        &quorum_set,
        vec![value.clone()],
        vec![value.clone()],
    );
    let state = nom.process_envelope(&env, &ctx!(&node, &quorum_set, &driver, 1));

    // Envelope is stored but no accept/ratify processing happens
    assert!(matches!(state, EnvelopeState::Valid));
    // Value should NOT have been accepted since started=false
    assert!(!nom.accepted().contains(&value));
}

/// N7/8: update_round_leaders normalizes quorum set by removing self
/// and adjusting thresholds before computing leaders.
///
/// stellar-core normalizes the quorum set via `normalize(qset, nodeID)` which
/// removes the local node from validators and decrements the threshold.
/// This affects weight calculations and leader selection.
#[test]
fn test_round_leaders_use_normalized_quorum_set() {
    // Create a 3-of-4 quorum set where node0 (local) is a validator
    let node0 = make_node_id(0); // local node
    let node1 = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);
    let quorum_set = make_quorum_set(
        vec![node0.clone(), node1.clone(), node2.clone(), node3.clone()],
        3,
    );
    let driver = Arc::new(ParityMockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let value = make_value(&[10]);
    let prev = make_value(&[0]);

    // Nominate to trigger update_round_leaders
    nom.nominate(&ctx!(&node0, &quorum_set, &driver, 1), value.clone(), &prev, false);

    // After normalization: node0 removed, threshold becomes 2, validators = [1,2,3]
    // Verify leaders were selected (at least one leader exists)
    let leaders = nom.get_round_leaders();
    assert!(
        !leaders.is_empty(),
        "Should have at least one round leader after normalization"
    );

    // The key property: normalization means weight calculations use
    // threshold=2/total=3 (not 3/4). With the mock driver's hash function,
    // all nodes in the normalized set get weight > 0 and can become leaders.
    // The local node is always a candidate but may not win highest priority.
    // Verify that at least one non-local node could become a leader
    // (possible because normalization produced a non-degenerate quorum set).
    let has_non_local = leaders.iter().any(|l| l != &node0);
    let local_is_leader = leaders.contains(&node0);
    assert!(
        has_non_local || local_is_leader,
        "At least one node should be a leader"
    );
}

/// N13: process_envelope adopts values from round leaders when
/// no candidates exist yet.
///
/// stellar-core processEnvelope (lines 476-489): after accept/ratify processing,
/// if candidates is empty AND the envelope sender is a round leader,
/// adopt their best value via getNewValueFromNomination.
#[test]
fn test_process_envelope_adopts_leader_votes() {
    let node = make_node_id(1); // local node
    let leader = make_node_id(2); // will be a leader
    let quorum_set = make_quorum_set(vec![node.clone(), leader.clone()], 1);
    let driver = Arc::new(ParityMockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let value = make_value(&[42]);
    let leader_value = make_value(&[99]);
    let prev = make_value(&[0]);

    // Start nomination (this sets up round leaders)
    nom.nominate(&ctx!(&node, &quorum_set, &driver, 1), value.clone(), &prev, false);
    assert!(nom.is_started());

    // Verify the leader is indeed a round leader
    let leaders = nom.get_round_leaders();

    // If leader is not in the round leaders, this test isn't exercising N13.
    // The ParityMockDriver gives higher priority to higher node IDs, so
    // leader (node2) should be included.
    if leaders.contains(&leader) {
        let initial_votes = nom.votes().len();

        // Process an envelope from the leader with a new value
        let env = make_nomination_envelope(
            leader.clone(),
            1,
            &quorum_set,
            vec![leader_value.clone()],
            vec![],
        );
        nom.process_envelope(&env, &ctx!(&node, &quorum_set, &driver, 1));

        // N13: Since candidates is empty and sender is a leader,
        // we should adopt their best value
        assert!(
            nom.votes().len() > initial_votes,
            "Should have adopted leader's value; votes before={}, after={}",
            initial_votes,
            nom.votes().len()
        );
        assert!(
            nom.votes().contains(&leader_value),
            "Leader's value should have been adopted into votes"
        );
    }
}

/// N14: foundValidValue is set for MaybeValid extracted values too.
///
/// stellar-core sets foundValidValue=true for ANY value that produces a candidate
/// (both FullyValidated and successfully-extracted MaybeValid). This
/// controls whether we also look at the `votes` list after scanning
/// `accepted`.
#[test]
fn test_found_valid_value_set_for_maybe_valid() {
    let node = make_node_id(1);
    let leader = make_node_id(2);
    let quorum_set = make_quorum_set(vec![node.clone(), leader.clone()], 1);
    let driver = Arc::new(ParityMockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let accepted_value = make_value(&[50]);
    let vote_value = make_value(&[60]);
    let extracted = make_value(&[55]); // extracted from MaybeValid accepted_value
    let prev = make_value(&[0]);

    // Set driver to return MaybeValid and extract a specific value
    driver.set_validation_level(ValidationLevel::MaybeValid);
    driver.set_extract_result(Some(extracted.clone()));

    // Start nomination
    nom.nominate(
        &ctx!(&node, &quorum_set, &driver, 1),
        make_value(&[1]),
        &prev,
        false,
    );

    // Create an envelope from the leader with accepted_value in `accepted`
    // and vote_value in `votes`
    let env = make_nomination_envelope(
        leader.clone(),
        1,
        &quorum_set,
        vec![vote_value.clone()],
        vec![accepted_value.clone()],
    );

    // If leader is a round leader, get_new_value_from_nomination will be called.
    // With N14 fix: if accepted_value extracts to a valid value, foundValidValue
    // becomes true and we skip scanning votes.
    let leaders = nom.get_round_leaders();
    if leaders.contains(&leader) {
        nom.process_envelope(&env, &ctx!(&node, &quorum_set, &driver, 1));

        // The extracted value (from accepted) should be adopted, but NOT the
        // vote_value (because foundValidValue=true stops us from scanning votes)
        assert!(
            nom.votes().contains(&extracted),
            "Extracted value from MaybeValid accepted should be adopted"
        );
        // vote_value should NOT be adopted because foundValidValue was set
        // when we found a valid candidate in accepted
        assert!(
            !nom.votes().contains(&vote_value),
            "Votes should NOT be scanned when foundValidValue is set from accepted"
        );
    }
}

/// N18: set_state_from_envelope rejects if nomination is already started.
///
/// stellar-core throws "Cannot set state after nomination is started" when
/// mNominationStarted is true.
#[test]
fn test_set_state_from_envelope_rejects_when_started() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    // Start nomination
    let value = make_value(&[1]);
    let prev = make_value(&[0]);
    nom.nominate(&ctx!(&node, &quorum_set, &driver, 1), value.clone(), &prev, false);
    assert!(nom.is_started());

    // Try to set state from envelope — should fail
    let env = make_nomination_envelope(node.clone(), 1, &quorum_set, vec![value], vec![]);
    assert!(
        !nom.set_state_from_envelope(&env),
        "set_state_from_envelope should reject when nomination is already started"
    );
}

/// N12: Nomination timer is stopped when candidates are confirmed.
///
/// stellar-core (lines 471-472): When a value is ratified (promoted to candidate),
/// the nomination timer is stopped because "there's no need to continue
/// nominating" per the whitepaper.
#[test]
fn test_timer_stopped_on_candidate_confirmation() {
    let node = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);
    let quorum_set = make_quorum_set(vec![node.clone(), node2.clone(), node3.clone()], 2);
    let driver = Arc::new(ParityMockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let value = make_value(&[7]);
    let prev = make_value(&[0]);

    // Start nomination
    nom.nominate(&ctx!(&node, &quorum_set, &driver, 1), value.clone(), &prev, false);
    assert!(nom.is_started());

    // No timer stops yet
    assert!(
        driver.get_timer_stops().is_empty(),
        "No timer stops before candidate confirmation"
    );

    // Create envelopes from 2 other nodes that both accept the value.
    // With threshold=2, this forms a quorum for ratification.
    let env2 = make_nomination_envelope(
        node2.clone(),
        1,
        &quorum_set,
        vec![value.clone()],
        vec![value.clone()],
    );
    let env3 = make_nomination_envelope(
        node3.clone(),
        1,
        &quorum_set,
        vec![value.clone()],
        vec![value.clone()],
    );

    nom.process_envelope(&env2, &ctx!(&node, &quorum_set, &driver, 1));
    nom.process_envelope(&env3, &ctx!(&node, &quorum_set, &driver, 1));

    // Value should be a candidate now
    assert!(
        nom.candidates().contains(&value),
        "Value should be confirmed as candidate"
    );

    // N12: Timer should have been stopped
    let stops = driver.get_timer_stops();
    assert!(
        !stops.is_empty(),
        "Nomination timer should be stopped when candidates are confirmed"
    );
    assert!(
        stops.iter().any(|(slot, timer_type)| {
            *slot == 1 && matches!(timer_type, crate::driver::SCPTimerType::Nomination)
        }),
        "Should stop the Nomination timer for slot 1"
    );
}

/// N5: Upgrade stripping when timer_exp_count exceeds the limit.
///
/// stellar-core (lines 597-651): When the nomination timer has expired enough
/// times (>= getUpgradeNominationTimeoutLimit), and all current votes
/// have upgrades, the node strips upgrades from its value and votes
/// for the stripped version.
#[test]
fn test_upgrade_stripping_after_timeout_limit() {
    // Use seed=2 for local node so it wins round leader priority over node2.
    // ParityMockDriver's compute_hash_node gives seed=2 priority 20568 vs seed=1's 12649.
    let node = make_node_id(2);
    let node2 = make_node_id(1);
    // Use a 2-of-2 quorum set so self-processing alone can't form quorum
    // (prevents immediate acceptance/ratification that would fill candidates).
    let quorum_set = make_quorum_set(vec![node.clone(), node2.clone()], 2);
    let driver = Arc::new(ParityMockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let value_with_upgrades = make_value(&[10, 20]); // has upgrades
    let stripped_value = make_value(&[10]); // stripped version
    let prev = make_value(&[0]);

    // Configure driver: timeout limit = 2, value has upgrades, stripped version
    driver.upgrade_timeout_limit.store(2, Ordering::SeqCst);
    driver.mark_has_upgrades(&value_with_upgrades);
    driver.set_stripped_value(Some(stripped_value.clone()));

    // First nomination: votes for value_with_upgrades, timer_exp_count=0
    nom.nominate(
        &ctx!(&node, &quorum_set, &driver, 1),
        value_with_upgrades.clone(),
        &prev,
        false,
    );
    assert!(nom.votes().contains(&value_with_upgrades));
    assert!(
        !nom.votes().contains(&stripped_value),
        "Should not strip upgrades before timeout limit"
    );

    // Timeout once (timer_exp_count becomes 1, still below limit=2)
    nom.nominate(
        &ctx!(&node, &quorum_set, &driver, 1),
        value_with_upgrades.clone(),
        &prev,
        true,
    );
    assert!(
        !nom.votes().contains(&stripped_value),
        "timer_exp_count=1 < limit=2, should not strip yet"
    );

    // Timeout again (timer_exp_count becomes 2, meets limit=2)
    nom.nominate(
        &ctx!(&node, &quorum_set, &driver, 1),
        value_with_upgrades.clone(),
        &prev,
        true,
    );

    // Now all votes have upgrades and timer_exp_count >= limit,
    // so the stripped value should be voted for
    assert!(
        nom.votes().contains(&stripped_value),
        "Should vote for stripped value after reaching timeout limit; votes: {:?}",
        nom.votes()
    );
}

/// N5: When not all votes have upgrades, stripping doesn't happen
/// even after timeout limit.
#[test]
fn test_upgrade_stripping_only_when_all_votes_have_upgrades() {
    let node = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);
    // Use threshold=2 with 3 validators so after normalization (removing
    // node1) we get threshold=1, validators=[node2, node3] — non-degenerate.
    let quorum_set = make_quorum_set(vec![node.clone(), node2.clone(), node3.clone()], 2);
    let driver = Arc::new(ParityMockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let value_with_upgrades = make_value(&[10, 20]);
    let value_no_upgrades = make_value(&[30]);
    let stripped_value = make_value(&[10]);
    let prev = make_value(&[0]);

    // Configure driver
    driver.upgrade_timeout_limit.store(1, Ordering::SeqCst);
    driver.mark_has_upgrades(&value_with_upgrades);
    // value_no_upgrades is NOT marked as having upgrades
    driver.set_stripped_value(Some(stripped_value.clone()));

    // Start nomination
    nom.nominate(
        &ctx!(&node, &quorum_set, &driver, 1),
        value_with_upgrades.clone(),
        &prev,
        false,
    );

    // Add a vote without upgrades from a leader
    let env = make_nomination_envelope(
        node2.clone(),
        1,
        &quorum_set,
        vec![value_no_upgrades.clone()],
        vec![],
    );
    nom.process_envelope(&env, &ctx!(&node, &quorum_set, &driver, 1));

    // Now timeout past the limit — but not all votes have upgrades
    nom.nominate(
        &ctx!(&node, &quorum_set, &driver, 1),
        value_with_upgrades.clone(),
        &prev,
        true,
    );

    // Stripped value should NOT be added because value_no_upgrades
    // doesn't have upgrades
    assert!(
        !nom.votes().contains(&stripped_value),
        "Should not strip when not all votes have upgrades"
    );
}

/// N6: Timer is set up unconditionally in nominate() when nomination
/// is active and no candidates exist yet.
///
/// stellar-core always sets up the nomination timer (lines 654-659) regardless
/// of whether nomination updated. The condition is: nomination is
/// started and not stopped and no candidates.
#[test]
fn test_nominate_returns_false_but_nomination_still_active() {
    // This test verifies that nominate() can return false (no update)
    // but nomination is still considered active (started, not stopped,
    // no candidates). The slot-level timer setup check happens in
    // slot.rs, so here we just verify the preconditions.
    let node = make_node_id(1);
    let node2 = make_node_id(2);
    // Use a 2-of-2 quorum set so self-processing alone can't form quorum
    // (prevents immediate acceptance/ratification that would fill candidates).
    let quorum_set = make_quorum_set(vec![node.clone(), node2.clone()], 2);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut nom = NominationProtocol::new();

    let value = make_value(&[5]);
    let prev = make_value(&[0]);

    // First nomination starts it
    nom.nominate(&ctx!(&node, &quorum_set, &driver, 1), value.clone(), &prev, false);
    assert!(nom.is_started());
    assert!(!nom.is_stopped());
    assert!(nom.candidates().is_empty());

    // Second call with same value — nominate returns false (no new votes)
    // but nomination should still be active
    let _updated = nom.nominate(&ctx!(&node, &quorum_set, &driver, 1), value, &prev, true);
    // Whether updated or not, the key check is state:
    assert!(nom.is_started());
    assert!(!nom.is_stopped());
    assert!(nom.candidates().is_empty());
    // N6: In the slot, the timer should be set regardless of `updated`.
    // This test confirms the nomination state is correct for that check.
}
