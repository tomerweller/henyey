use super::*;
use crate::driver::ValidationLevel;
use crate::SlotContext;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use stellar_xdr::curr::{PublicKey, ScpNomination, Uint256, VecM};

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

#[test]
fn test_ballot_protocol_new() {
    let bp = BallotProtocol::new();
    assert_eq!(bp.phase(), BallotPhase::Prepare);
    assert!(bp.current_ballot().is_none());
    assert!(bp.prepared().is_none());
    assert!(!bp.is_externalized());
}

#[test]
fn test_ballot_compare() {
    let b1 = ScpBallot {
        counter: 1,
        value: vec![1].try_into().unwrap(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: vec![1].try_into().unwrap(),
    };
    let b3 = ScpBallot {
        counter: 1,
        value: vec![2].try_into().unwrap(),
    };

    assert_eq!(ballot_compare(&b1, &b1), std::cmp::Ordering::Equal);
    assert_eq!(ballot_compare(&b1, &b2), std::cmp::Ordering::Less);
    assert_eq!(ballot_compare(&b2, &b1), std::cmp::Ordering::Greater);
    // Same counter, different value - compared by value
    assert_eq!(ballot_compare(&b1, &b3), std::cmp::Ordering::Less);
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

struct QuorumCallbackDriver {
    quorum_set: ScpQuorumSet,
    heard_from_quorum: AtomicU32,
}

impl QuorumCallbackDriver {
    fn new(quorum_set: ScpQuorumSet) -> Self {
        Self {
            quorum_set,
            heard_from_quorum: AtomicU32::new(0),
        }
    }
}

impl SCPDriver for QuorumCallbackDriver {
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

    fn emit_envelope(&self, _envelope: &ScpEnvelope) {}

    fn get_quorum_set(&self, _node_id: &NodeId) -> Option<ScpQuorumSet> {
        Some(self.quorum_set.clone())
    }

    fn nominating_value(&self, _slot_index: u64, _value: &Value) {}

    fn value_externalized(&self, _slot_index: u64, _value: &Value) {}

    fn ballot_did_prepare(&self, _slot_index: u64, _ballot: &ScpBallot) {}

    fn ballot_did_confirm(&self, _slot_index: u64, _ballot: &ScpBallot) {}

    fn ballot_did_hear_from_quorum(&self, _slot_index: u64, _ballot: &ScpBallot) {
        self.heard_from_quorum.fetch_add(1, Ordering::SeqCst);
    }

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

#[allow(clippy::too_many_arguments)]
fn make_prepare_envelope_with_counters(
    node_id: NodeId,
    slot_index: u64,
    quorum_set: &ScpQuorumSet,
    ballot: ScpBallot,
    prepared: Option<ScpBallot>,
    prepared_prime: Option<ScpBallot>,
    n_c: u32,
    n_h: u32,
) -> ScpEnvelope {
    let prep = ScpStatementPrepare {
        quorum_set_hash: hash_quorum_set(quorum_set).into(),
        ballot,
        prepared,
        prepared_prime,
        n_c,
        n_h,
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

fn make_confirm_envelope(
    node_id: NodeId,
    slot_index: u64,
    quorum_set: &ScpQuorumSet,
    ballot: ScpBallot,
) -> ScpEnvelope {
    let conf = ScpStatementConfirm {
        ballot,
        n_prepared: 0,
        n_commit: 0,
        n_h: 0,
        quorum_set_hash: hash_quorum_set(quorum_set).into(),
    };
    let statement = ScpStatement {
        node_id,
        slot_index,
        pledges: ScpStatementPledges::Confirm(conf),
    };
    ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    }
}

fn make_confirm_envelope_with_counters(
    node_id: NodeId,
    slot_index: u64,
    quorum_set: &ScpQuorumSet,
    ballot: ScpBallot,
    n_prepared: u32,
    n_commit: u32,
    n_h: u32,
) -> ScpEnvelope {
    let conf = ScpStatementConfirm {
        ballot,
        n_prepared,
        n_commit,
        n_h,
        quorum_set_hash: hash_quorum_set(quorum_set).into(),
    };
    let statement = ScpStatement {
        node_id,
        slot_index,
        pledges: ScpStatementPledges::Confirm(conf),
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
) -> ScpEnvelope {
    let nomination = ScpNomination {
        quorum_set_hash: hash_quorum_set(quorum_set).into(),
        votes: VecM::default(),
        accepted: VecM::default(),
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

fn make_externalize_envelope(
    node_id: NodeId,
    slot_index: u64,
    quorum_set: &ScpQuorumSet,
    commit: ScpBallot,
    n_h: u32,
) -> ScpEnvelope {
    let ext = ScpStatementExternalize {
        commit,
        n_h,
        commit_quorum_set_hash: hash_quorum_set(quorum_set).into(),
    };
    let statement = ScpStatement {
        node_id,
        slot_index,
        pledges: ScpStatementPledges::Externalize(ext),
    };
    ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    }
}

fn make_quorum_set_hashless_confirm_envelope(
    node_id: NodeId,
    slot_index: u64,
    ballot: ScpBallot,
    n_prepared: u32,
    n_commit: u32,
    n_h: u32,
) -> ScpEnvelope {
    let conf = ScpStatementConfirm {
        ballot,
        n_prepared,
        n_commit,
        n_h,
        quorum_set_hash: stellar_xdr::curr::Hash([0u8; 32]),
    };
    let statement = ScpStatement {
        node_id,
        slot_index,
        pledges: ScpStatementPledges::Confirm(conf),
    };
    ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    }
}

#[test]
fn test_ballot_rejects_non_ballot_pledges() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();

    let env = make_nomination_envelope(make_node_id(2), 1, &quorum_set);
    let state = ballot.process_envelope(&env, &ctx!(&node, &quorum_set, &driver, 1));
    assert_eq!(state, EnvelopeState::Invalid);
}

#[test]
fn test_ballot_heard_from_quorum_callback() {
    let node_a = make_node_id(1);
    let node_b = make_node_id(2);
    let node_c = make_node_id(3);
    let quorum_set = make_quorum_set(vec![node_a.clone(), node_b.clone(), node_c.clone()], 2);
    let driver = Arc::new(QuorumCallbackDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();

    let value = make_value(&[1, 2, 3]);
    assert!(ballot.bump(&ctx!(&node_a, &quorum_set, &driver, 1), value.clone(), false));

    let current = ballot.current_ballot().expect("current ballot").clone();
    let env_b = make_prepare_envelope(node_b, 1, &quorum_set, current.clone());
    let env_c = make_prepare_envelope(node_c, 1, &quorum_set, current);

    ballot.process_envelope(&env_b, &ctx!(&node_a, &quorum_set, &driver, 1));
    ballot.process_envelope(&env_c, &ctx!(&node_a, &quorum_set, &driver, 1));

    assert_eq!(driver.heard_from_quorum.load(Ordering::SeqCst), 1);
}

#[test]
fn test_ballot_statement_ordering() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();
    let value = make_value(&[7]);
    let ballot_value = ScpBallot { counter: 1, value };

    let prepare = make_prepare_envelope(make_node_id(2), 2, &quorum_set, ballot_value.clone());
    let confirm = make_confirm_envelope(make_node_id(2), 2, &quorum_set, ballot_value.clone());

    let first = ballot.process_envelope(&prepare, &ctx!(&node, &quorum_set, &driver, 2));
    let second = ballot.process_envelope(&confirm, &ctx!(&node, &quorum_set, &driver, 2));
    let third = ballot.process_envelope(&prepare, &ctx!(&node, &quorum_set, &driver, 2));

    assert!(matches!(
        first,
        EnvelopeState::Valid | EnvelopeState::ValidNew
    ));
    assert!(matches!(
        second,
        EnvelopeState::Valid | EnvelopeState::ValidNew
    ));
    assert_eq!(third, EnvelopeState::Invalid);
}

#[test]
fn test_ballot_statement_ordering_confirm_counters() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();
    let ballot_value = ScpBallot {
        counter: 2,
        value: make_value(&[9]),
    };

    let older = make_confirm_envelope_with_counters(
        make_node_id(2),
        4,
        &quorum_set,
        ballot_value.clone(),
        1,
        0,
        1,
    );
    let newer = make_confirm_envelope_with_counters(
        make_node_id(2),
        4,
        &quorum_set,
        ballot_value.clone(),
        2,
        0,
        1,
    );

    let first = ballot.process_envelope(&older, &ctx!(&node, &quorum_set, &driver, 4));
    let second = ballot.process_envelope(&newer, &ctx!(&node, &quorum_set, &driver, 4));
    let third = ballot.process_envelope(&older, &ctx!(&node, &quorum_set, &driver, 4));

    assert!(matches!(
        first,
        EnvelopeState::Valid | EnvelopeState::ValidNew
    ));
    assert!(matches!(
        second,
        EnvelopeState::Valid | EnvelopeState::ValidNew
    ));
    assert_eq!(third, EnvelopeState::Invalid);
}

#[test]
fn test_ballot_statement_ordering_prepare_n_h() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();
    let ballot_value = ScpBallot {
        counter: 3,
        value: make_value(&[7]),
    };
    let prepared = Some(ScpBallot {
        counter: 2,
        value: make_value(&[6]),
    });

    let older = make_prepare_envelope_with_counters(
        make_node_id(2),
        5,
        &quorum_set,
        ballot_value.clone(),
        prepared.clone(),
        None,
        0,
        1,
    );
    let newer = make_prepare_envelope_with_counters(
        make_node_id(2),
        5,
        &quorum_set,
        ballot_value.clone(),
        prepared,
        None,
        0,
        2,
    );

    let first = ballot.process_envelope(&older, &ctx!(&node, &quorum_set, &driver, 5));
    let second = ballot.process_envelope(&newer, &ctx!(&node, &quorum_set, &driver, 5));
    let third = ballot.process_envelope(&older, &ctx!(&node, &quorum_set, &driver, 5));

    assert!(matches!(
        first,
        EnvelopeState::Valid | EnvelopeState::ValidNew
    ));
    assert!(matches!(
        second,
        EnvelopeState::Valid | EnvelopeState::ValidNew
    ));
    assert_eq!(third, EnvelopeState::Invalid);
}

#[test]
fn test_ballot_statement_ordering_prepare_prepared() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();
    let ballot_value = ScpBallot {
        counter: 3,
        value: make_value(&[4]),
    };

    let older = make_prepare_envelope_with_counters(
        make_node_id(2),
        6,
        &quorum_set,
        ballot_value.clone(),
        Some(ScpBallot {
            counter: 1,
            value: make_value(&[1]),
        }),
        None,
        0,
        1,
    );
    let newer = make_prepare_envelope_with_counters(
        make_node_id(2),
        6,
        &quorum_set,
        ballot_value.clone(),
        Some(ScpBallot {
            counter: 2,
            value: make_value(&[1]),
        }),
        None,
        0,
        1,
    );

    let first = ballot.process_envelope(&older, &ctx!(&node, &quorum_set, &driver, 6));
    let second = ballot.process_envelope(&newer, &ctx!(&node, &quorum_set, &driver, 6));
    let third = ballot.process_envelope(&older, &ctx!(&node, &quorum_set, &driver, 6));

    assert!(matches!(
        first,
        EnvelopeState::Valid | EnvelopeState::ValidNew
    ));
    assert!(matches!(
        second,
        EnvelopeState::Valid | EnvelopeState::ValidNew
    ));
    assert_eq!(third, EnvelopeState::Invalid);
}

#[test]
fn test_ballot_statement_ordering_prepare_prepared_prime() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();
    let ballot_value = ScpBallot {
        counter: 3,
        value: make_value(&[5]),
    };

    let older = make_prepare_envelope_with_counters(
        make_node_id(2),
        7,
        &quorum_set,
        ballot_value.clone(),
        Some(ScpBallot {
            counter: 2,
            value: make_value(&[2]),
        }),
        Some(ScpBallot {
            counter: 1,
            value: make_value(&[9]),
        }),
        0,
        1,
    );
    let newer = make_prepare_envelope_with_counters(
        make_node_id(2),
        7,
        &quorum_set,
        ballot_value.clone(),
        Some(ScpBallot {
            counter: 2,
            value: make_value(&[2]),
        }),
        Some(ScpBallot {
            counter: 2,
            value: make_value(&[9]),
        }),
        0,
        1,
    );

    let first = ballot.process_envelope(&older, &ctx!(&node, &quorum_set, &driver, 7));
    let second = ballot.process_envelope(&newer, &ctx!(&node, &quorum_set, &driver, 7));
    let third = ballot.process_envelope(&older, &ctx!(&node, &quorum_set, &driver, 7));

    assert!(matches!(
        first,
        EnvelopeState::Valid | EnvelopeState::ValidNew
    ));
    assert!(matches!(
        second,
        EnvelopeState::Valid | EnvelopeState::ValidNew
    ));
    assert_eq!(third, EnvelopeState::Invalid);
}

#[test]
fn test_ballot_statement_ordering_confirm_n_h() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();
    let ballot_value = ScpBallot {
        counter: 4,
        value: make_value(&[8]),
    };

    let older = make_confirm_envelope_with_counters(
        make_node_id(2),
        8,
        &quorum_set,
        ballot_value.clone(),
        1,
        0,
        1,
    );
    let newer = make_confirm_envelope_with_counters(
        make_node_id(2),
        8,
        &quorum_set,
        ballot_value.clone(),
        1,
        0,
        2,
    );

    let first = ballot.process_envelope(&older, &ctx!(&node, &quorum_set, &driver, 8));
    let second = ballot.process_envelope(&newer, &ctx!(&node, &quorum_set, &driver, 8));
    let third = ballot.process_envelope(&older, &ctx!(&node, &quorum_set, &driver, 8));

    assert!(matches!(
        first,
        EnvelopeState::Valid | EnvelopeState::ValidNew
    ));
    assert!(matches!(
        second,
        EnvelopeState::Valid | EnvelopeState::ValidNew
    ));
    assert_eq!(third, EnvelopeState::Invalid);
}

#[test]
fn test_ballot_timeout_bumps_counter() {
    let node = make_node_id(1);
    let other = make_node_id(99);
    let quorum_set = make_quorum_set(vec![node.clone(), other.clone()], 2);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();
    let value = make_value(&[5]);

    assert!(ballot.bump(&ctx!(&node, &quorum_set, &driver, 3), value.clone(), false));
    assert_eq!(ballot.current_ballot_counter(), Some(1));

    assert!(ballot.bump_timeout(&ctx!(&node, &quorum_set, &driver, 3), None));
    assert_eq!(ballot.current_ballot_counter(), Some(2));
}

#[test]
fn test_ballot_process_current_state_skips_self_when_not_validated() {
    let local = make_node_id(1);
    let remote = make_node_id(2);
    let quorum_set = make_quorum_set(vec![local.clone(), remote.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();

    let ballot_local = ScpBallot {
        counter: 1,
        value: make_value(&[1]),
    };
    let ballot_remote = ScpBallot {
        counter: 1,
        value: make_value(&[2]),
    };
    let env_local = make_prepare_envelope(local.clone(), 13, &quorum_set, ballot_local);
    let env_remote = make_prepare_envelope(remote.clone(), 13, &quorum_set, ballot_remote);

    ballot.process_envelope(&env_local, &ctx!(&local, &quorum_set, &driver, 13));
    ballot.process_envelope(&env_remote, &ctx!(&local, &quorum_set, &driver, 13));

    let mut seen = Vec::new();
    ballot.process_current_state(
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
fn test_ballot_process_current_state_includes_self_when_forced() {
    let local = make_node_id(1);
    let quorum_set = make_quorum_set(vec![local.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();

    let ballot_local = ScpBallot {
        counter: 1,
        value: make_value(&[3]),
    };
    let env_local = make_prepare_envelope(local.clone(), 14, &quorum_set, ballot_local);
    ballot.process_envelope(&env_local, &ctx!(&local, &quorum_set, &driver, 14));

    let mut seen = Vec::new();
    ballot.process_current_state(
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
fn test_ballot_rejects_bumps_after_externalize() {
    let node = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);
    let node4 = make_node_id(4);
    let node5 = make_node_id(5);
    let quorum_set = make_quorum_set(
        vec![
            node.clone(),
            node2.clone(),
            node3.clone(),
            node4.clone(),
            node5.clone(),
        ],
        4,
    );
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();

    let value = make_value(&[1]);
    assert!(ballot.bump(&ctx!(&node, &quorum_set, &driver, 15), value.clone(), false));

    let current = ballot.current_ballot().expect("current ballot").clone();
    let env2 = make_confirm_envelope_with_counters(
        node2.clone(),
        15,
        &quorum_set,
        current.clone(),
        current.counter,
        current.counter,
        current.counter,
    );
    let env3 = make_confirm_envelope_with_counters(
        node3.clone(),
        15,
        &quorum_set,
        current.clone(),
        current.counter,
        current.counter,
        current.counter,
    );
    let env4 = make_confirm_envelope_with_counters(
        node4.clone(),
        15,
        &quorum_set,
        current.clone(),
        current.counter,
        current.counter,
        current.counter,
    );

    ballot.process_envelope(&env2, &ctx!(&node, &quorum_set, &driver, 15));
    ballot.process_envelope(&env3, &ctx!(&node, &quorum_set, &driver, 15));
    ballot.process_envelope(&env4, &ctx!(&node, &quorum_set, &driver, 15));

    assert!(ballot.is_externalized());
    let externalized_value = ballot.get_externalized_value().expect("value").clone();

    let bump_ballot = ScpBallot {
        counter: 2,
        value: make_value(&[2]),
    };
    let bump_env2 = make_quorum_set_hashless_confirm_envelope(
        node2,
        15,
        bump_ballot.clone(),
        bump_ballot.counter,
        bump_ballot.counter,
        bump_ballot.counter,
    );
    let bump_env3 = make_quorum_set_hashless_confirm_envelope(
        node3,
        15,
        bump_ballot.clone(),
        bump_ballot.counter,
        bump_ballot.counter,
        bump_ballot.counter,
    );
    let bump_env4 = make_quorum_set_hashless_confirm_envelope(
        node4,
        15,
        bump_ballot.clone(),
        bump_ballot.counter,
        bump_ballot.counter,
        bump_ballot.counter,
    );

    assert_eq!(
        ballot.process_envelope(&bump_env2, &ctx!(&node, &quorum_set, &driver, 15)),
        EnvelopeState::Invalid
    );
    assert_eq!(
        ballot.process_envelope(&bump_env3, &ctx!(&node, &quorum_set, &driver, 15)),
        EnvelopeState::Invalid
    );
    assert_eq!(
        ballot.process_envelope(&bump_env4, &ctx!(&node, &quorum_set, &driver, 15)),
        EnvelopeState::Invalid
    );

    assert_eq!(
        ballot.get_externalized_value().cloned(),
        Some(externalized_value)
    );
}

#[test]
fn test_ballot_commit_range_externalizes() {
    let node = make_node_id(1);
    let node2 = make_node_id(2);
    let node3 = make_node_id(3);
    let node4 = make_node_id(4);
    let node5 = make_node_id(5);
    let quorum_set = make_quorum_set(
        vec![
            node.clone(),
            node2.clone(),
            node3.clone(),
            node4.clone(),
            node5.clone(),
        ],
        4,
    );
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();

    let value = make_value(&[9]);
    assert!(ballot.bump(&ctx!(&node, &quorum_set, &driver, 16), value.clone(), false));

    let current = ballot.current_ballot().expect("current ballot").clone();
    let prep2 = make_prepare_envelope(node2.clone(), 16, &quorum_set, current.clone());
    let prep3 = make_prepare_envelope(node3.clone(), 16, &quorum_set, current.clone());
    let prep4 = make_prepare_envelope(node4.clone(), 16, &quorum_set, current.clone());
    let prep5 = make_prepare_envelope(node5.clone(), 16, &quorum_set, current.clone());

    ballot.process_envelope(&prep2, &ctx!(&node, &quorum_set, &driver, 16));
    ballot.process_envelope(&prep3, &ctx!(&node, &quorum_set, &driver, 16));
    ballot.process_envelope(&prep4, &ctx!(&node, &quorum_set, &driver, 16));
    ballot.process_envelope(&prep5, &ctx!(&node, &quorum_set, &driver, 16));

    let prepared2 = make_prepare_envelope_with_counters(
        node2.clone(),
        16,
        &quorum_set,
        current.clone(),
        Some(current.clone()),
        None,
        current.counter,
        current.counter,
    );
    let prepared3 = make_prepare_envelope_with_counters(
        node3.clone(),
        16,
        &quorum_set,
        current.clone(),
        Some(current.clone()),
        None,
        current.counter,
        current.counter,
    );
    let prepared4 = make_prepare_envelope_with_counters(
        node4.clone(),
        16,
        &quorum_set,
        current.clone(),
        Some(current.clone()),
        None,
        current.counter,
        current.counter,
    );
    let prepared5 = make_prepare_envelope_with_counters(
        node5.clone(),
        16,
        &quorum_set,
        current.clone(),
        Some(current.clone()),
        None,
        current.counter,
        current.counter,
    );

    ballot.process_envelope(&prepared2, &ctx!(&node, &quorum_set, &driver, 16));
    ballot.process_envelope(&prepared3, &ctx!(&node, &quorum_set, &driver, 16));
    ballot.process_envelope(&prepared4, &ctx!(&node, &quorum_set, &driver, 16));
    ballot.process_envelope(&prepared5, &ctx!(&node, &quorum_set, &driver, 16));

    assert!(matches!(ballot.phase(), BallotPhase::Confirm));
    assert_eq!(ballot.commit().map(|b| b.counter), Some(1));

    let confirm1 = make_confirm_envelope_with_counters(
        node2.clone(),
        16,
        &quorum_set,
        ScpBallot {
            counter: 4,
            value: value.clone(),
        },
        2,
        2,
        4,
    );
    let confirm2 = make_confirm_envelope_with_counters(
        node3.clone(),
        16,
        &quorum_set,
        ScpBallot {
            counter: 6,
            value: value.clone(),
        },
        2,
        2,
        6,
    );
    let confirm4 = make_confirm_envelope_with_counters(
        node5,
        16,
        &quorum_set,
        ScpBallot {
            counter: 6,
            value: value.clone(),
        },
        3,
        3,
        6,
    );

    ballot.process_envelope(&confirm1, &ctx!(&node, &quorum_set, &driver, 16));
    ballot.process_envelope(&confirm2, &ctx!(&node, &quorum_set, &driver, 16));

    assert!(!ballot.is_externalized());

    ballot.process_envelope(&confirm4, &ctx!(&node, &quorum_set, &driver, 16));

    assert!(ballot.is_externalized());
    assert_eq!(ballot.get_externalized_value(), Some(&value));
    assert_eq!(ballot.commit().map(|b| b.counter), Some(3));
}

#[test]
fn test_ballot_statement_sanity_prepare_constraints() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let ballot = BallotProtocol::new();

    let prepared = ScpBallot {
        counter: 2,
        value: make_value(&[1]),
    };
    let prepared_prime = ScpBallot {
        counter: 1,
        value: make_value(&[1]),
    };
    let prep = ScpStatementPrepare {
        quorum_set_hash: hash_quorum_set(&quorum_set).into(),
        ballot: ScpBallot {
            counter: 3,
            value: make_value(&[2]),
        },
        prepared: Some(prepared),
        prepared_prime: Some(prepared_prime),
        n_c: 0,
        n_h: 0,
    };
    let statement = ScpStatement {
        node_id: node.clone(),
        slot_index: 7,
        pledges: ScpStatementPledges::Prepare(prep),
    };

    assert!(!ballot.is_statement_sane(&statement, &node, &quorum_set, &driver));

    let prep_bad_h = ScpStatementPrepare {
        quorum_set_hash: hash_quorum_set(&quorum_set).into(),
        ballot: ScpBallot {
            counter: 3,
            value: make_value(&[3]),
        },
        prepared: Some(ScpBallot {
            counter: 2,
            value: make_value(&[4]),
        }),
        prepared_prime: None,
        n_c: 0,
        n_h: 5,
    };
    let statement_bad_h = ScpStatement {
        node_id: node.clone(),
        slot_index: 8,
        pledges: ScpStatementPledges::Prepare(prep_bad_h),
    };
    assert!(!ballot.is_statement_sane(&statement_bad_h, &node, &quorum_set, &driver));

    let prep_bad_c = ScpStatementPrepare {
        quorum_set_hash: hash_quorum_set(&quorum_set).into(),
        ballot: ScpBallot {
            counter: 3,
            value: make_value(&[5]),
        },
        prepared: Some(ScpBallot {
            counter: 3,
            value: make_value(&[6]),
        }),
        prepared_prime: None,
        n_c: 1,
        n_h: 0,
    };
    let statement_bad_c = ScpStatement {
        node_id: node.clone(),
        slot_index: 9,
        pledges: ScpStatementPledges::Prepare(prep_bad_c),
    };
    assert!(!ballot.is_statement_sane(&statement_bad_c, &node, &quorum_set, &driver));
}

#[test]
fn test_ballot_statement_sanity_confirm_constraints() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let ballot = BallotProtocol::new();

    let conf = ScpStatementConfirm {
        ballot: ScpBallot {
            counter: 0,
            value: make_value(&[1]),
        },
        n_prepared: 0,
        n_commit: 0,
        n_h: 0,
        quorum_set_hash: hash_quorum_set(&quorum_set).into(),
    };
    let statement = ScpStatement {
        node_id: node.clone(),
        slot_index: 10,
        pledges: ScpStatementPledges::Confirm(conf),
    };

    assert!(!ballot.is_statement_sane(&statement, &node, &quorum_set, &driver));
}

#[test]
fn test_ballot_statement_sanity_externalize_constraints() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let ballot = BallotProtocol::new();

    let env = make_externalize_envelope(
        node.clone(),
        11,
        &quorum_set,
        ScpBallot {
            counter: 2,
            value: make_value(&[1]),
        },
        1,
    );

    assert!(!ballot.is_statement_sane(&env.statement, &node, &quorum_set, &driver));
}

struct ValidationDriver {
    quorum_set: ScpQuorumSet,
    invalid_value: Value,
}

impl ValidationDriver {
    fn new(quorum_set: ScpQuorumSet, invalid_value: Value) -> Self {
        Self {
            quorum_set,
            invalid_value,
        }
    }
}

impl SCPDriver for ValidationDriver {
    fn validate_value(
        &self,
        _slot_index: u64,
        value: &Value,
        _nomination: bool,
    ) -> ValidationLevel {
        if value == &self.invalid_value {
            ValidationLevel::Invalid
        } else {
            ValidationLevel::FullyValidated
        }
    }

    fn combine_candidates(&self, _slot_index: u64, _candidates: &[Value]) -> Option<Value> {
        None
    }

    fn extract_valid_value(&self, _slot_index: u64, _value: &Value) -> Option<Value> {
        None
    }

    fn emit_envelope(&self, _envelope: &ScpEnvelope) {}

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
        0
    }

    fn compute_value_hash(
        &self,
        _slot_index: u64,
        _prev_value: &Value,
        _round: u32,
        _value: &Value,
    ) -> u64 {
        0
    }

    fn compute_timeout(&self, _round: u32, _is_nomination: bool) -> Duration {
        Duration::from_millis(1)
    }

    fn sign_envelope(&self, _envelope: &mut ScpEnvelope) {}

    fn verify_envelope(&self, _envelope: &ScpEnvelope) -> bool {
        true
    }
}

#[test]
fn test_ballot_value_validation_rejects_invalid() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let invalid_value = make_value(&[0]);
    let driver = Arc::new(ValidationDriver::new(
        quorum_set.clone(),
        invalid_value.clone(),
    ));
    let ballot = BallotProtocol::new();

    let env = make_prepare_envelope(
        make_node_id(2),
        12,
        &quorum_set,
        ScpBallot {
            counter: 1,
            value: invalid_value,
        },
    );

    let result = ballot.validate_statement_values(&env.statement, &driver, 12);
    assert_eq!(result, ValidationLevel::Invalid);
}

#[test]
fn test_ballot_rejects_unknown_quorum_set_hash() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let ballot = BallotProtocol::new();

    let other_qset = make_quorum_set(vec![make_node_id(2)], 1);
    let prep = ScpStatementPrepare {
        quorum_set_hash: hash_quorum_set(&other_qset).into(),
        ballot: ScpBallot {
            counter: 1,
            value: make_value(&[9]),
        },
        prepared: None,
        prepared_prime: None,
        n_c: 0,
        n_h: 0,
    };
    let statement = ScpStatement {
        node_id: make_node_id(3),
        slot_index: 13,
        pledges: ScpStatementPledges::Prepare(prep),
    };

    assert!(!ballot.is_statement_sane(&statement, &node, &quorum_set, &driver));
}

// ==================== Tests for new parity features ====================

#[test]
fn test_set_state_from_envelope_prepare() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let mut ballot = BallotProtocol::new();

    let value = make_value(&[1, 2, 3]);
    let ballot_val = ScpBallot {
        counter: 5,
        value: value.clone(),
    };
    let prepared = ScpBallot {
        counter: 3,
        value: value.clone(),
    };

    let prep = ScpStatementPrepare {
        quorum_set_hash: hash_quorum_set(&quorum_set).into(),
        ballot: ballot_val.clone(),
        prepared: Some(prepared.clone()),
        prepared_prime: None,
        n_c: 2,
        n_h: 3,
    };
    let statement = ScpStatement {
        node_id: node.clone(),
        slot_index: 1,
        pledges: ScpStatementPledges::Prepare(prep),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };

    assert!(ballot.set_state_from_envelope(&envelope));
    assert_eq!(ballot.phase(), BallotPhase::Prepare);
    assert_eq!(ballot.current_ballot(), Some(&ballot_val));
    assert_eq!(ballot.prepared(), Some(&prepared));
    assert_eq!(ballot.commit().map(|b| b.counter), Some(2));
    assert_eq!(ballot.high_ballot().map(|b| b.counter), Some(3));
}

#[test]
fn test_set_state_from_envelope_confirm() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let mut ballot = BallotProtocol::new();

    let value = make_value(&[4, 5, 6]);
    let ballot_val = ScpBallot {
        counter: 10,
        value: value.clone(),
    };

    let conf = ScpStatementConfirm {
        ballot: ballot_val.clone(),
        n_prepared: 8,
        n_commit: 5,
        n_h: 9,
        quorum_set_hash: hash_quorum_set(&quorum_set).into(),
    };
    let statement = ScpStatement {
        node_id: node.clone(),
        slot_index: 2,
        pledges: ScpStatementPledges::Confirm(conf),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };

    assert!(ballot.set_state_from_envelope(&envelope));
    assert_eq!(ballot.phase(), BallotPhase::Confirm);
    assert_eq!(ballot.current_ballot(), Some(&ballot_val));
    assert_eq!(ballot.prepared().map(|b| b.counter), Some(8));
    assert_eq!(ballot.commit().map(|b| b.counter), Some(5));
    assert_eq!(ballot.high_ballot().map(|b| b.counter), Some(9));
}

#[test]
fn test_set_state_from_envelope_externalize() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let mut ballot = BallotProtocol::new();

    let value = make_value(&[7, 8, 9]);
    let commit = ScpBallot {
        counter: 3,
        value: value.clone(),
    };

    let ext = ScpStatementExternalize {
        commit: commit.clone(),
        n_h: 5,
        commit_quorum_set_hash: hash_quorum_set(&quorum_set).into(),
    };
    let statement = ScpStatement {
        node_id: node.clone(),
        slot_index: 3,
        pledges: ScpStatementPledges::Externalize(ext),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };

    assert!(ballot.set_state_from_envelope(&envelope));
    assert_eq!(ballot.phase(), BallotPhase::Externalize);
    assert!(ballot.is_externalized());
    assert_eq!(ballot.commit(), Some(&commit));
    assert_eq!(ballot.high_ballot().map(|b| b.counter), Some(5));
    assert_eq!(ballot.get_externalized_value(), Some(&value));
}

#[test]
fn test_set_state_from_envelope_rejects_nomination() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let mut ballot = BallotProtocol::new();

    let nomination = ScpNomination {
        quorum_set_hash: hash_quorum_set(&quorum_set).into(),
        votes: vec![make_value(&[1])].try_into().unwrap(),
        accepted: vec![].try_into().unwrap(),
    };
    let statement = ScpStatement {
        node_id: node.clone(),
        slot_index: 4,
        pledges: ScpStatementPledges::Nominate(nomination),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };

    assert!(!ballot.set_state_from_envelope(&envelope));
    assert_eq!(ballot.phase(), BallotPhase::Prepare);
    assert!(ballot.current_ballot().is_none());
}

#[test]
fn test_bump_state_specific_counter() {
    let node = make_node_id(1);
    let other = make_node_id(99);
    let quorum_set = make_quorum_set(vec![node.clone(), other.clone()], 2);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();

    let value = make_value(&[1, 2, 3]);

    // First bump to counter 1
    assert!(ballot.bump(&ctx!(&node, &quorum_set, &driver, 1), value.clone(), false));
    assert_eq!(ballot.current_ballot().map(|b| b.counter), Some(1));

    // Now bump to specific counter 5
    assert!(ballot.bump_state(&ctx!(&node, &quorum_set, &driver, 1), value.clone(), 5));
    assert_eq!(ballot.current_ballot().map(|b| b.counter), Some(5));

    // Cannot go backwards
    assert!(!ballot.bump_state(&ctx!(&node, &quorum_set, &driver, 1), value.clone(), 3));
    assert_eq!(ballot.current_ballot().map(|b| b.counter), Some(5));

    // Can go forwards
    assert!(ballot.bump_state(&ctx!(&node, &quorum_set, &driver, 1), value.clone(), 10));
    assert_eq!(ballot.current_ballot().map(|b| b.counter), Some(10));
}

#[test]
fn test_bump_state_fails_when_externalized() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();

    // Externalize via set_state_from_envelope
    let value = make_value(&[1, 2, 3]);
    let commit = ScpBallot {
        counter: 3,
        value: value.clone(),
    };
    let ext = ScpStatementExternalize {
        commit: commit.clone(),
        n_h: 5,
        commit_quorum_set_hash: hash_quorum_set(&quorum_set).into(),
    };
    let statement = ScpStatement {
        node_id: node.clone(),
        slot_index: 1,
        pledges: ScpStatementPledges::Externalize(ext),
    };
    let envelope = ScpEnvelope {
        statement,
        signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
    };
    ballot.set_state_from_envelope(&envelope);

    // Cannot bump when externalized
    assert!(!ballot.bump_state(&ctx!(&node, &quorum_set, &driver, 1), value.clone(), 10));
}

#[test]
fn test_abandon_ballot_public() {
    let node = make_node_id(1);
    let other = make_node_id(99);
    let quorum_set = make_quorum_set(vec![node.clone(), other.clone()], 2);
    let driver = Arc::new(MockDriver::new(quorum_set.clone()));
    let mut ballot = BallotProtocol::new();

    let value = make_value(&[1, 2, 3]);

    // Start with ballot counter 1
    assert!(ballot.bump(&ctx!(&node, &quorum_set, &driver, 1), value.clone(), false));
    assert_eq!(ballot.current_ballot().map(|b| b.counter), Some(1));

    // Abandon to counter 5
    assert!(ballot.abandon_ballot_public(5, &ctx!(&node, &quorum_set, &driver, 1)));
    assert_eq!(ballot.current_ballot().map(|b| b.counter), Some(5));

    // Abandon with counter 0 should auto-increment
    assert!(ballot.abandon_ballot_public(0, &ctx!(&node, &quorum_set, &driver, 1)));
    assert_eq!(ballot.current_ballot().map(|b| b.counter), Some(6));
}

#[test]
fn test_check_invariants_valid() {
    let mut ballot = BallotProtocol::new();

    // Empty state is valid
    assert!(ballot.check_invariants().is_ok());

    // Set up valid Prepare state
    let value = make_value(&[1, 2, 3]);
    ballot.current_ballot = Some(ScpBallot {
        counter: 5,
        value: value.clone(),
    });
    ballot.prepared = Some(ScpBallot {
        counter: 3,
        value: value.clone(),
    });
    ballot.high_ballot = Some(ScpBallot {
        counter: 4,
        value: value.clone(),
    });
    ballot.commit = Some(ScpBallot {
        counter: 2,
        value: value.clone(),
    });
    ballot.phase = BallotPhase::Prepare;

    assert!(ballot.check_invariants().is_ok());
}

#[test]
fn test_check_invariants_prepared_prime_must_be_less() {
    let mut ballot = BallotProtocol::new();
    let value1 = make_value(&[1]);
    let value2 = make_value(&[2]);

    ballot.prepared = Some(ScpBallot {
        counter: 3,
        value: value1.clone(),
    });
    // prepared_prime has higher counter than prepared - invalid
    ballot.prepared_prime = Some(ScpBallot {
        counter: 5,
        value: value2.clone(),
    });

    assert!(ballot.check_invariants().is_err());
}

#[test]
fn test_get_local_state_formatting() {
    let mut ballot = BallotProtocol::new();
    let value = make_value(&[0xab, 0xcd, 0xef, 0x12]);

    ballot.current_ballot = Some(ScpBallot {
        counter: 5,
        value: value.clone(),
    });
    ballot.prepared = Some(ScpBallot {
        counter: 3,
        value: value.clone(),
    });
    ballot.phase = BallotPhase::Prepare;

    let state = ballot.get_local_state();
    assert!(state.contains("phase=Prepare"));
    assert!(state.contains("b=(5,"));
    assert!(state.contains("p=(3,"));
    assert!(state.contains("heard_from_quorum=false"));
}

#[test]
fn test_get_working_ballot_prepare() {
    let node_id = make_node_id(1);
    let value = make_value(&[1, 2, 3]);
    let ballot = ScpBallot {
        counter: 5,
        value: value.clone(),
    };
    let quorum_set = make_quorum_set(vec![node_id.clone()], 1);
    let env = make_prepare_envelope(node_id, 1, &quorum_set, ballot.clone());

    let working = get_working_ballot(&env.statement);
    assert!(working.is_some());
    let working = working.unwrap();
    assert_eq!(working.counter, 5);
    assert_eq!(working.value, value);
}

#[test]
fn test_get_working_ballot_confirm() {
    let node_id = make_node_id(1);
    let value = make_value(&[1, 2, 3]);
    let ballot = ScpBallot {
        counter: 5,
        value: value.clone(),
    };
    let quorum_set = make_quorum_set(vec![node_id.clone()], 1);
    let env =
        make_confirm_envelope_with_counters(node_id, 1, &quorum_set, ballot.clone(), 3, 2, 4);

    // For CONFIRM, working ballot uses n_commit as counter
    let working = get_working_ballot(&env.statement);
    assert!(working.is_some());
    let working = working.unwrap();
    assert_eq!(working.counter, 2); // n_commit
    assert_eq!(working.value, value);
}

#[test]
fn test_get_working_ballot_externalize() {
    let node_id = make_node_id(1);
    let value = make_value(&[1, 2, 3]);
    let commit = ScpBallot {
        counter: 3,
        value: value.clone(),
    };
    let ext = ScpStatementExternalize {
        commit: commit.clone(),
        n_h: 5,
        commit_quorum_set_hash: [0u8; 32].into(),
    };
    let statement = ScpStatement {
        node_id,
        slot_index: 1,
        pledges: ScpStatementPledges::Externalize(ext),
    };

    // For EXTERNALIZE, working ballot uses u32::MAX as counter
    let working = get_working_ballot(&statement);
    assert!(working.is_some());
    let working = working.unwrap();
    assert_eq!(working.counter, u32::MAX);
    assert_eq!(working.value, value);
}

#[test]
fn test_get_working_ballot_nominate() {
    let node_id = make_node_id(1);
    let nom = ScpNomination {
        quorum_set_hash: [0u8; 32].into(),
        votes: vec![make_value(&[1])].try_into().unwrap(),
        accepted: vec![].try_into().unwrap(),
    };
    let statement = ScpStatement {
        node_id,
        slot_index: 1,
        pledges: ScpStatementPledges::Nominate(nom),
    };

    // Nomination statements don't have a working ballot
    let working = get_working_ballot(&statement);
    assert!(working.is_none());
}

// =========================================================================
// Ballot Protocol Parity Tests (Phase 3)
// =========================================================================

/// Mock driver that tracks timer operations, externalized values, etc.
struct BallotParityDriver {
    quorum_set: ScpQuorumSet,
    emit_count: AtomicU32,
    timer_setups: std::sync::Mutex<Vec<(u64, crate::driver::SCPTimerType)>>,
    timer_stops: std::sync::Mutex<Vec<(u64, crate::driver::SCPTimerType)>>,
    externalized_values: std::sync::Mutex<Vec<(u64, Value)>>,
}

impl BallotParityDriver {
    fn new(quorum_set: ScpQuorumSet) -> Self {
        Self {
            quorum_set,
            emit_count: AtomicU32::new(0),
            timer_setups: std::sync::Mutex::new(Vec::new()),
            timer_stops: std::sync::Mutex::new(Vec::new()),
            externalized_values: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn get_timer_setups(&self) -> Vec<(u64, crate::driver::SCPTimerType)> {
        self.timer_setups.lock().unwrap().clone()
    }

    fn get_timer_stops(&self) -> Vec<(u64, crate::driver::SCPTimerType)> {
        self.timer_stops.lock().unwrap().clone()
    }

    fn get_externalized_values(&self) -> Vec<(u64, Value)> {
        self.externalized_values.lock().unwrap().clone()
    }
}

impl SCPDriver for BallotParityDriver {
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

    fn value_externalized(&self, slot_index: u64, value: &Value) {
        self.externalized_values
            .lock()
            .unwrap()
            .push((slot_index, value.clone()));
    }

    fn ballot_did_prepare(&self, _slot_index: u64, _ballot: &ScpBallot) {}
    fn ballot_did_confirm(&self, _slot_index: u64, _ballot: &ScpBallot) {}
    fn ballot_did_hear_from_quorum(&self, _slot_index: u64, _ballot: &ScpBallot) {}

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
        Duration::from_millis(1000)
    }

    fn sign_envelope(&self, _envelope: &mut ScpEnvelope) {}

    fn verify_envelope(&self, _envelope: &ScpEnvelope) -> bool {
        true
    }

    fn setup_timer(
        &self,
        slot_index: u64,
        timer_type: crate::driver::SCPTimerType,
        _timeout: Duration,
    ) {
        self.timer_setups
            .lock()
            .unwrap()
            .push((slot_index, timer_type));
    }

    fn stop_timer(&self, slot_index: u64, timer_type: crate::driver::SCPTimerType) {
        self.timer_stops
            .lock()
            .unwrap()
            .push((slot_index, timer_type));
    }
}

/// B-bump parity test: bump_to_ballot resets high/commit when value is incompatible.
///
/// stellar-core invariant: h.value == b.value. When bumping to a ballot with an
/// incompatible value, high_ballot and commit must be cleared.
#[test]
fn test_bump_to_ballot_resets_incompatible_high_commit() {
    let mut bp = BallotProtocol::new();
    let value_a = make_value(&[1]);
    let value_b = make_value(&[2]);

    // Set up state: current ballot with value_a, high and commit set
    bp.current_ballot = Some(ScpBallot {
        counter: 1,
        value: value_a.clone(),
    });
    bp.high_ballot = Some(ScpBallot {
        counter: 1,
        value: value_a.clone(),
    });
    bp.commit = Some(ScpBallot {
        counter: 1,
        value: value_a.clone(),
    });
    bp.value = Some(value_a.clone());

    // Bump to a ballot with incompatible value
    let new_ballot = ScpBallot {
        counter: 2,
        value: value_b.clone(),
    };
    assert!(bp.bump_to_ballot(&new_ballot, false));

    // h and c should be cleared because value_b != value_a
    assert!(
        bp.high_ballot.is_none(),
        "high_ballot should be cleared on incompatible bump"
    );
    assert!(
        bp.commit.is_none(),
        "commit should be cleared on incompatible bump"
    );
    assert_eq!(bp.current_ballot.as_ref().unwrap().value, value_b);
}

/// B-bump parity test: bump_to_ballot preserves high/commit when value is compatible.
#[test]
fn test_bump_to_ballot_preserves_compatible_high_commit() {
    let mut bp = BallotProtocol::new();
    let value_a = make_value(&[1]);

    // Set up state with high and commit
    bp.current_ballot = Some(ScpBallot {
        counter: 1,
        value: value_a.clone(),
    });
    bp.high_ballot = Some(ScpBallot {
        counter: 1,
        value: value_a.clone(),
    });
    bp.commit = Some(ScpBallot {
        counter: 1,
        value: value_a.clone(),
    });
    bp.value = Some(value_a.clone());

    // Bump to higher counter with same value (compatible)
    let new_ballot = ScpBallot {
        counter: 2,
        value: value_a.clone(),
    };
    assert!(bp.bump_to_ballot(&new_ballot, false));

    // h and c should be preserved because same value
    assert!(
        bp.high_ballot.is_some(),
        "high_ballot should be preserved on compatible bump"
    );
    assert!(
        bp.commit.is_some(),
        "commit should be preserved on compatible bump"
    );
}

/// B-bump parity test: heard_from_quorum only resets when counter changes.
#[test]
fn test_bump_to_ballot_heard_from_quorum_counter_change() {
    let mut bp = BallotProtocol::new();
    let value_a = make_value(&[1]);

    // Set initial ballot and heard_from_quorum
    bp.current_ballot = Some(ScpBallot {
        counter: 1,
        value: value_a.clone(),
    });
    bp.heard_from_quorum = true;

    // Bump with same counter (different value) - should NOT reset heard_from_quorum
    let same_counter_ballot = ScpBallot {
        counter: 1,
        value: make_value(&[2]),
    };
    bp.bump_to_ballot(&same_counter_ballot, false);
    assert!(
        bp.heard_from_quorum,
        "heard_from_quorum should not reset when counter stays the same"
    );

    // Bump with different counter - SHOULD reset heard_from_quorum
    let new_counter_ballot = ScpBallot {
        counter: 2,
        value: make_value(&[2]),
    };
    bp.bump_to_ballot(&new_counter_ballot, false);
    assert!(
        !bp.heard_from_quorum,
        "heard_from_quorum should reset when counter changes"
    );
}

/// B-override parity test: bump_state uses value_override when set.
///
/// stellar-core bumpState checks mValueOverride and uses that instead of the
/// passed-in value when it's set (e.g., after confirming prepared).
#[test]
fn test_bump_state_uses_value_override() {
    let node = make_node_id(1);
    let other = make_node_id(99);
    let quorum_set = make_quorum_set(vec![node.clone(), other.clone()], 2);
    let driver = Arc::new(BallotParityDriver::new(quorum_set.clone()));
    let mut bp = BallotProtocol::new();

    let value_a = make_value(&[1]);
    let value_override = make_value(&[99]);

    // Start with a ballot
    assert!(bp.bump(&ctx!(&node, &quorum_set, &driver, 1), value_a.clone(), false));
    assert_eq!(bp.current_ballot().unwrap().counter, 1);
    assert_eq!(bp.current_ballot().unwrap().value, value_a);

    // Set value_override (as would happen during confirm phase)
    bp.value_override = Some(value_override.clone());

    // Now bump_state with value_a - should use value_override instead
    assert!(bp.bump_state(&ctx!(&node, &quorum_set, &driver, 1), value_a.clone(), 2));
    assert_eq!(
        bp.current_ballot().unwrap().value,
        value_override,
        "bump_state should use value_override when set"
    );
}

/// B-override parity test: bump_state goes through update_current_value.
///
/// stellar-core bumpState(value, n) calls updateCurrentValue which checks phase
/// and commit compatibility. Verify that bump_state rejects incompatible
/// commit values.
#[test]
fn test_bump_state_rejects_incompatible_with_commit() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(BallotParityDriver::new(quorum_set.clone()));
    let mut bp = BallotProtocol::new();

    let value_a = make_value(&[1]);
    let value_b = make_value(&[2]);

    // Start with a ballot
    assert!(bp.bump(&ctx!(&node, &quorum_set, &driver, 1), value_a.clone(), false));

    // Set a commit ballot with value_a
    bp.commit = Some(ScpBallot {
        counter: 1,
        value: value_a.clone(),
    });

    // bump_state with incompatible value_b should be rejected
    assert!(
        !bp.bump_state(&ctx!(&node, &quorum_set, &driver, 1), value_b.clone(), 5),
        "bump_state should reject value incompatible with commit"
    );
}

/// B-abandon parity test: abandon_ballot uses composite candidate over current ballot.
///
/// stellar-core abandonBallot first checks mSlot.getLatestCompositeCandidate(),
/// then falls back to mCurrentBallot->value.
#[test]
fn test_abandon_ballot_uses_composite_candidate() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(BallotParityDriver::new(quorum_set.clone()));
    let mut bp = BallotProtocol::new();
    let value_current = make_value(&[1]);
    let value_composite = make_value(&[99]);

    // Set up current ballot
    bp.current_ballot = Some(ScpBallot {
        counter: 1,
        value: value_current.clone(),
    });
    bp.value = Some(value_current.clone());

    // Set composite candidate (simulating nomination output)
    bp.set_composite_candidate(Some(value_composite.clone()));

    // Abandon should use composite candidate value
    assert!(bp.abandon_ballot_public(0, &ctx!(&node, &quorum_set, &driver, 1)));
    assert_eq!(
        bp.current_ballot.as_ref().unwrap().value,
        value_composite,
        "abandon_ballot should prefer composite candidate value"
    );
    assert_eq!(bp.current_ballot.as_ref().unwrap().counter, 2);
}

/// B-abandon parity test: abandon_ballot falls back to current ballot value.
#[test]
fn test_abandon_ballot_falls_back_to_current_value() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(BallotParityDriver::new(quorum_set.clone()));
    let mut bp = BallotProtocol::new();
    let value_current = make_value(&[1]);

    // Set up current ballot, no composite candidate
    bp.current_ballot = Some(ScpBallot {
        counter: 1,
        value: value_current.clone(),
    });
    bp.value = Some(value_current.clone());

    // No composite candidate set
    assert!(bp.abandon_ballot_public(0, &ctx!(&node, &quorum_set, &driver, 1)));
    assert_eq!(
        bp.current_ballot.as_ref().unwrap().value,
        value_current,
        "abandon_ballot should fall back to current ballot value"
    );
    assert_eq!(bp.current_ballot.as_ref().unwrap().counter, 2);
}

/// B-abandon parity test: abandon_ballot with specific counter.
#[test]
fn test_abandon_ballot_with_specific_counter() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(BallotParityDriver::new(quorum_set.clone()));
    let mut bp = BallotProtocol::new();
    let value_current = make_value(&[1]);

    bp.current_ballot = Some(ScpBallot {
        counter: 1,
        value: value_current.clone(),
    });
    bp.value = Some(value_current.clone());

    // Abandon with specific counter
    assert!(bp.abandon_ballot_public(10, &ctx!(&node, &quorum_set, &driver, 1)));
    assert_eq!(
        bp.current_ballot.as_ref().unwrap().counter,
        10,
        "abandon_ballot should use specified counter"
    );
}

/// B-stopnom parity test: set_confirm_commit signals nomination stop.
///
/// stellar-core setConfirmCommit calls mSlot.stopNomination() between
/// emitCurrentStateStatement() and valueExternalized().
#[test]
fn test_set_confirm_commit_signals_stop_nomination() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(BallotParityDriver::new(quorum_set.clone()));
    let mut bp = BallotProtocol::new();

    let value = make_value(&[1]);

    // Must have a current ballot first
    bp.current_ballot = Some(ScpBallot {
        counter: 1,
        value: value.clone(),
    });
    bp.value = Some(value.clone());

    let c = ScpBallot {
        counter: 1,
        value: value.clone(),
    };
    let h = ScpBallot {
        counter: 1,
        value: value.clone(),
    };

    bp.set_confirm_commit(c, h, &ctx!(&node, &quorum_set, &driver, 1));

    // Should signal that nomination needs to stop
    assert!(
        bp.needs_stop_nomination,
        "set_confirm_commit should signal nomination stop"
    );

    // And take_needs_stop_nomination should clear the flag
    assert!(bp.take_needs_stop_nomination());
    assert!(!bp.take_needs_stop_nomination());
}

/// B-stopnom parity test: set_confirm_commit uses commit value for externalize.
///
/// stellar-core uses mCommit->getBallot().value (c.value) for valueExternalized,
/// not h.value.
#[test]
fn test_set_confirm_commit_externalizes_commit_value() {
    let node = make_node_id(1);
    let quorum_set = make_quorum_set(vec![node.clone()], 1);
    let driver = Arc::new(BallotParityDriver::new(quorum_set.clone()));
    let mut bp = BallotProtocol::new();

    let value = make_value(&[42]);

    bp.current_ballot = Some(ScpBallot {
        counter: 1,
        value: value.clone(),
    });
    bp.value = Some(value.clone());

    let c = ScpBallot {
        counter: 1,
        value: value.clone(),
    };
    let h = ScpBallot {
        counter: 3,
        value: value.clone(),
    };

    bp.set_confirm_commit(c.clone(), h, &ctx!(&node, &quorum_set, &driver, 1));

    let externalized = driver.get_externalized_values();
    assert_eq!(externalized.len(), 1);
    assert_eq!(
        externalized[0].1, c.value,
        "valueExternalized should be called with c.value"
    );
}

/// B-timer parity test: check_heard_from_quorum starts ballot timer on transition.
///
/// stellar-core starts the ballot protocol timer when heard_from_quorum transitions
/// from false to true and phase is not Externalize.
#[test]
fn test_check_heard_from_quorum_starts_timer() {
    let local = make_node_id(1);
    let remote = make_node_id(2);
    let quorum_set = make_quorum_set(vec![local.clone(), remote.clone()], 2);
    let driver = Arc::new(BallotParityDriver::new(quorum_set.clone()));
    let mut bp = BallotProtocol::new();

    let value = make_value(&[1]);
    let ballot = ScpBallot {
        counter: 1,
        value: value.clone(),
    };

    // Start with a ballot
    bp.current_ballot = Some(ballot.clone());
    bp.value = Some(value.clone());
    bp.heard_from_quorum = false;

    // Add envelopes from both nodes (need quorum)
    let env_local = make_prepare_envelope(local.clone(), 1, &quorum_set, ballot.clone());
    let env_remote = make_prepare_envelope(remote.clone(), 1, &quorum_set, ballot.clone());
    bp.latest_envelopes.insert(local.clone(), env_local);
    bp.latest_envelopes.insert(remote.clone(), env_remote);

    // Check heard from quorum
    bp.check_heard_from_quorum(&ctx!(&local, &quorum_set, &driver, 1));

    assert!(bp.heard_from_quorum);

    // Ballot timer should have been set up
    let setups = driver.get_timer_setups();
    assert!(
        setups
            .iter()
            .any(|(_, t)| *t == crate::driver::SCPTimerType::Ballot),
        "Ballot timer should be started when heard_from_quorum transitions to true"
    );
}

/// B-timer parity test: check_heard_from_quorum stops timer when not quorum.
///
/// stellar-core stops the ballot timer when heard_from_quorum is false.
#[test]
fn test_check_heard_from_quorum_stops_timer_no_quorum() {
    let local = make_node_id(1);
    let remote = make_node_id(2);
    let quorum_set = make_quorum_set(vec![local.clone(), remote.clone()], 2);
    let driver = Arc::new(BallotParityDriver::new(quorum_set.clone()));
    let mut bp = BallotProtocol::new();

    let value = make_value(&[1]);
    let ballot = ScpBallot {
        counter: 1,
        value: value.clone(),
    };

    bp.current_ballot = Some(ballot.clone());
    bp.value = Some(value.clone());
    bp.heard_from_quorum = true; // Was previously true

    // Only local envelope (not a quorum for threshold=2)
    let env_local = make_prepare_envelope(local.clone(), 1, &quorum_set, ballot.clone());
    bp.latest_envelopes.insert(local.clone(), env_local);

    bp.check_heard_from_quorum(&ctx!(&local, &quorum_set, &driver, 1));

    assert!(!bp.heard_from_quorum);

    // Timer should have been stopped
    let stops = driver.get_timer_stops();
    assert!(
        stops
            .iter()
            .any(|(_, t)| *t == crate::driver::SCPTimerType::Ballot),
        "Ballot timer should be stopped when quorum is lost"
    );
}

/// B-timer parity test: check_heard_from_quorum stops timer in Externalize phase.
///
/// stellar-core stops the ballot timer when heard_from_quorum is true but phase is Externalize.
#[test]
fn test_check_heard_from_quorum_stops_timer_externalize() {
    let local = make_node_id(1);
    let remote = make_node_id(2);
    let quorum_set = make_quorum_set(vec![local.clone(), remote.clone()], 2);
    let driver = Arc::new(BallotParityDriver::new(quorum_set.clone()));
    let mut bp = BallotProtocol::new();

    let value = make_value(&[1]);
    let ballot = ScpBallot {
        counter: 1,
        value: value.clone(),
    };

    bp.current_ballot = Some(ballot.clone());
    bp.value = Some(value.clone());
    bp.phase = BallotPhase::Externalize;
    bp.heard_from_quorum = false; // Will transition to true

    // Add quorum of envelopes
    let env_local = make_prepare_envelope(local.clone(), 1, &quorum_set, ballot.clone());
    let env_remote = make_prepare_envelope(remote.clone(), 1, &quorum_set, ballot.clone());
    bp.latest_envelopes.insert(local.clone(), env_local);
    bp.latest_envelopes.insert(remote.clone(), env_remote);

    bp.check_heard_from_quorum(&ctx!(&local, &quorum_set, &driver, 1));

    assert!(bp.heard_from_quorum);

    // Timer should NOT have been started (phase is Externalize)
    let setups = driver.get_timer_setups();
    assert!(
        !setups
            .iter()
            .any(|(_, t)| *t == crate::driver::SCPTimerType::Ballot),
        "Ballot timer should NOT be started in Externalize phase"
    );

    // Timer should have been stopped
    let stops = driver.get_timer_stops();
    assert!(
        stops
            .iter()
            .any(|(_, t)| *t == crate::driver::SCPTimerType::Ballot),
        "Ballot timer should be stopped in Externalize phase"
    );
}

/// B-override parity test: update_current_value checks phase.
#[test]
fn test_update_current_value_rejects_externalize_phase() {
    let mut bp = BallotProtocol::new();
    let value = make_value(&[1]);

    bp.phase = BallotPhase::Externalize;

    let ballot = ScpBallot {
        counter: 1,
        value: value.clone(),
    };

    assert!(
        !bp.update_current_value(&ballot),
        "update_current_value should reject in Externalize phase"
    );
}

/// B-override parity test: update_current_value rejects commit-incompatible ballots.
#[test]
fn test_update_current_value_rejects_commit_incompatible() {
    let mut bp = BallotProtocol::new();
    let value_a = make_value(&[1]);
    let value_b = make_value(&[2]);

    bp.current_ballot = Some(ScpBallot {
        counter: 1,
        value: value_a.clone(),
    });
    bp.commit = Some(ScpBallot {
        counter: 1,
        value: value_a.clone(),
    });

    let incompatible_ballot = ScpBallot {
        counter: 2,
        value: value_b,
    };

    assert!(
        !bp.update_current_value(&incompatible_ballot),
        "update_current_value should reject ballot incompatible with commit"
    );
}

/// B-bump parity test: bump delegates to bump_state.
///
/// Since bump now delegates to bump_state, it inherits value_override
/// checking and update_current_value logic.
#[test]
fn test_bump_delegates_to_bump_state() {
    let node = make_node_id(1);
    let other = make_node_id(99);
    let quorum_set = make_quorum_set(vec![node.clone(), other.clone()], 2);
    let driver = Arc::new(BallotParityDriver::new(quorum_set.clone()));
    let mut bp = BallotProtocol::new();

    let value_a = make_value(&[1]);
    let value_override = make_value(&[99]);

    // Start with a ballot
    assert!(bp.bump(&ctx!(&node, &quorum_set, &driver, 1), value_a.clone(), false));
    assert_eq!(bp.current_ballot().unwrap().value, value_a);

    // Set value_override
    bp.value_override = Some(value_override.clone());

    // Force bump should use value_override
    assert!(bp.bump(&ctx!(&node, &quorum_set, &driver, 1), value_a.clone(), true));
    assert_eq!(
        bp.current_ballot().unwrap().value,
        value_override,
        "bump with force should use value_override"
    );
}
