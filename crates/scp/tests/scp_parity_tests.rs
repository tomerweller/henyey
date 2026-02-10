//! SCP parity tests ported from SCPTests.cpp.
//!
//! These tests mirror the exact test scenarios from stellar-core v25's
//! src/scp/test/SCPTests.cpp, ensuring behavioral parity between the
//! stellar-core and Rust implementations of the SCP consensus protocol.
//!
//! The test harness (`TestSCP`) matches the stellar-core `TestSCP` class:
//! - Single-node focus with controllable quorum/v-blocking delivery
//! - Append-only envelope tracking for assertion counting
//! - Simulated timer system
//! - Controllable nomination leader priority

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use henyey_common::Hash256;
use henyey_scp::{EnvelopeState, SCPDriver, SCPTimerType, ValidationLevel, SCP};
use stellar_xdr::curr::{
    Hash, NodeId, PublicKey, ScpBallot, ScpEnvelope, ScpNomination, ScpQuorumSet, ScpStatement,
    ScpStatementConfirm, ScpStatementExternalize, ScpStatementPledges, ScpStatementPrepare,
    Signature, Uint256, Value,
};

// ---------------------------------------------------------------------------
// Test harness: TestSCP (mirrors stellar-core TestSCP class)
// ---------------------------------------------------------------------------

/// Timer data for simulated timers.
struct TimerData {
    absolute_timeout: u64,
    // We don't store the callback; we just track existence and timing.
}

/// Test SCP driver that mirrors the stellar-core TestSCP class.
///
/// Key differences from the production driver:
/// - Append-only `envs` vector (never cleared) — tests assert on `.len()`
/// - Configurable priority lookup for nomination leader control
/// - Simulated timer system with `bump_timer_offset()`
/// - Pre-settable expected candidates and composite value
#[allow(dead_code)]
struct TestSCPDriver {
    node_id: NodeId,
    quorum_set: ScpQuorumSet,
    quorum_set_hash: Hash256,

    /// All emitted envelopes (append-only, matching stellar-core mEnvs).
    envs: RwLock<Vec<ScpEnvelope>>,

    /// Externalized values per slot.
    externalized_values: RwLock<HashMap<u64, Value>>,

    /// Ballots heard from quorum per slot.
    heard_from_quorums: RwLock<HashMap<u64, Vec<ScpBallot>>>,

    /// Stored quorum sets by hash.
    quorum_sets: RwLock<HashMap<Hash256, ScpQuorumSet>>,

    /// Expected candidates for combine_candidates assertion.
    expected_candidates: RwLock<BTreeSet<Value>>,

    /// Composite value to return from combine_candidates.
    composite_value: RwLock<Value>,

    /// Simulated timers.
    timers: RwLock<HashMap<(u64, SCPTimerType), TimerData>>,

    /// Simulated clock offset in milliseconds.
    current_timer_offset: RwLock<u64>,

    /// Custom priority lookup: returns priority for a given node.
    /// Default: local node gets 1000, others get 1.
    /// Mutable via RwLock so tests can change the priority node at runtime
    /// (matching stellar-core mPriorityLookup which is a mutable std::function).
    priority_node: RwLock<NodeId>,

    /// Timeout parameters (matching stellar-core TestSCP).
    initial_ballot_timeout_ms: u32,
    increment_ballot_timeout_ms: u32,
    initial_nomination_timeout_ms: u32,
    increment_nomination_timeout_ms: u32,
}

impl TestSCPDriver {
    fn new(node_id: NodeId, quorum_set: ScpQuorumSet) -> Self {
        let qs_hash = Hash256::hash_xdr(&quorum_set).unwrap_or(Hash256::ZERO);
        let mut quorum_sets = HashMap::new();
        quorum_sets.insert(qs_hash, quorum_set.clone());
        Self {
            node_id: node_id.clone(),
            quorum_set,
            quorum_set_hash: qs_hash,
            envs: RwLock::new(Vec::new()),
            externalized_values: RwLock::new(HashMap::new()),
            heard_from_quorums: RwLock::new(HashMap::new()),
            quorum_sets: RwLock::new(quorum_sets),
            expected_candidates: RwLock::new(BTreeSet::new()),
            composite_value: RwLock::new(Value(vec![].try_into().unwrap())),
            timers: RwLock::new(HashMap::new()),
            current_timer_offset: RwLock::new(0),
            priority_node: RwLock::new(node_id),
            initial_ballot_timeout_ms: 1000,
            increment_ballot_timeout_ms: 1000,
            initial_nomination_timeout_ms: 1000,
            increment_nomination_timeout_ms: 1000,
        }
    }

    fn store_quorum_set(&self, qs: &ScpQuorumSet) {
        let hash = Hash256::hash_xdr(qs).unwrap_or(Hash256::ZERO);
        self.quorum_sets.write().unwrap().insert(hash, qs.clone());
    }

    fn envs_len(&self) -> usize {
        self.envs.read().unwrap().len()
    }

    fn get_env(&self, index: usize) -> ScpEnvelope {
        self.envs.read().unwrap()[index].clone()
    }

    fn heard_from_quorum_count(&self, slot: u64) -> usize {
        self.heard_from_quorums
            .read()
            .unwrap()
            .get(&slot)
            .map_or(0, |v| v.len())
    }

    fn heard_from_quorum_ballot(&self, slot: u64, index: usize) -> ScpBallot {
        self.heard_from_quorums.read().unwrap()[&slot][index].clone()
    }

    fn set_expected_candidates(&self, candidates: BTreeSet<Value>) {
        *self.expected_candidates.write().unwrap() = candidates;
    }

    fn set_composite_value(&self, value: Value) {
        *self.composite_value.write().unwrap() = value;
    }

    fn has_ballot_timer(&self) -> bool {
        self.timers
            .read()
            .unwrap()
            .contains_key(&(0, SCPTimerType::Ballot))
    }

    fn has_ballot_timer_upcoming(&self) -> bool {
        let timers = self.timers.read().unwrap();
        let offset = *self.current_timer_offset.read().unwrap();
        if let Some(td) = timers.get(&(0, SCPTimerType::Ballot)) {
            td.absolute_timeout > offset
        } else {
            false
        }
    }

    fn bump_timer_offset(&self) {
        // Advance simulated time by 5 hours (matching stellar-core)
        let mut offset = self.current_timer_offset.write().unwrap();
        *offset += 5 * 3600 * 1000;
    }

    fn externalized_value(&self, slot: u64) -> Option<Value> {
        self.externalized_values.read().unwrap().get(&slot).cloned()
    }

    /// Change which node has highest priority (1000) in compute_hash_node.
    /// Matches stellar-core `scp.mPriorityLookup = [&](NodeID const& n) { ... }`.
    fn set_priority_node(&self, node: NodeId) {
        *self.priority_node.write().unwrap() = node;
    }
}

impl SCPDriver for TestSCPDriver {
    fn validate_value(
        &self,
        _slot_index: u64,
        _value: &Value,
        _nomination: bool,
    ) -> ValidationLevel {
        ValidationLevel::FullyValidated
    }

    fn combine_candidates(&self, _slot_index: u64, candidates: &[Value]) -> Option<Value> {
        let expected = self.expected_candidates.read().unwrap();
        if !expected.is_empty() {
            let actual: BTreeSet<Value> = candidates.iter().cloned().collect();
            assert_eq!(
                *expected, actual,
                "combine_candidates: unexpected candidates"
            );
        }
        Some(self.composite_value.read().unwrap().clone())
    }

    fn extract_valid_value(&self, _slot_index: u64, value: &Value) -> Option<Value> {
        Some(value.clone())
    }

    fn emit_envelope(&self, envelope: &ScpEnvelope) {
        self.envs.write().unwrap().push(envelope.clone());
    }

    fn get_quorum_set(&self, node_id: &NodeId) -> Option<ScpQuorumSet> {
        // All nodes share the same quorum set in these tests
        let _ = node_id;
        Some(self.quorum_set.clone())
    }

    fn get_quorum_set_by_hash(&self, hash: &Hash256) -> Option<ScpQuorumSet> {
        self.quorum_sets.read().unwrap().get(hash).cloned()
    }

    fn nominating_value(&self, _slot_index: u64, _value: &Value) {}

    fn value_externalized(&self, slot_index: u64, value: &Value) {
        let mut ext = self.externalized_values.write().unwrap();
        assert!(
            !ext.contains_key(&slot_index),
            "value already externalized for slot {}",
            slot_index
        );
        ext.insert(slot_index, value.clone());
    }

    fn ballot_did_prepare(&self, _slot_index: u64, _ballot: &ScpBallot) {}

    fn ballot_did_confirm(&self, _slot_index: u64, _ballot: &ScpBallot) {}

    fn ballot_did_hear_from_quorum(&self, slot_index: u64, ballot: &ScpBallot) {
        self.heard_from_quorums
            .write()
            .unwrap()
            .entry(slot_index)
            .or_default()
            .push(ballot.clone());
    }

    fn compute_hash_node(
        &self,
        _slot_index: u64,
        _prev_value: &Value,
        is_priority: bool,
        _round: u32,
        node_id: &NodeId,
    ) -> u64 {
        if is_priority {
            // Priority node gets highest priority (1000), others get 1
            if node_id == &*self.priority_node.read().unwrap() {
                1000
            } else {
                1
            }
        } else {
            0
        }
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

    fn compute_timeout(&self, round: u32, is_nomination: bool) -> Duration {
        let (initial, increment) = if is_nomination {
            (
                self.initial_nomination_timeout_ms,
                self.increment_nomination_timeout_ms,
            )
        } else {
            (
                self.initial_ballot_timeout_ms,
                self.increment_ballot_timeout_ms,
            )
        };
        let ms = initial as u64 + (round.saturating_sub(1) as u64) * increment as u64;
        let max_timeout_ms = 30 * 60 * 1000; // 30 minutes
        Duration::from_millis(ms.min(max_timeout_ms))
    }

    fn sign_envelope(&self, _envelope: &mut ScpEnvelope) {
        // No-op for tests (matching stellar-core)
    }

    fn verify_envelope(&self, _envelope: &ScpEnvelope) -> bool {
        true
    }

    fn setup_timer(&self, slot_index: u64, timer_type: SCPTimerType, timeout: Duration) {
        let offset = *self.current_timer_offset.read().unwrap();
        let absolute = offset + timeout.as_millis() as u64;
        self.timers.write().unwrap().insert(
            (slot_index, timer_type),
            TimerData {
                absolute_timeout: absolute,
            },
        );
    }

    fn stop_timer(&self, slot_index: u64, timer_type: SCPTimerType) {
        self.timers
            .write()
            .unwrap()
            .remove(&(slot_index, timer_type));
    }
}

// ---------------------------------------------------------------------------
// Wrapper for TestSCP that owns SCP + driver
// ---------------------------------------------------------------------------

struct TestSCP {
    scp: SCP<TestSCPDriver>,
}

impl TestSCP {
    fn new(node_id: NodeId, quorum_set: ScpQuorumSet) -> Self {
        let driver = TestSCPDriver::new(node_id.clone(), quorum_set.clone());
        let scp = SCP::new(node_id, true, quorum_set, Arc::new(driver));
        Self { scp }
    }

    fn new_non_validator(node_id: NodeId, quorum_set: ScpQuorumSet) -> Self {
        let driver = TestSCPDriver::new(node_id.clone(), quorum_set.clone());
        let scp = SCP::new(node_id, false, quorum_set, Arc::new(driver));
        Self { scp }
    }

    fn new_with_priority(node_id: NodeId, quorum_set: ScpQuorumSet, priority_node: NodeId) -> Self {
        let driver = TestSCPDriver::new(node_id.clone(), quorum_set.clone());
        driver.set_priority_node(priority_node);
        let scp = SCP::new(node_id, true, quorum_set, Arc::new(driver));
        Self { scp }
    }

    fn driver(&self) -> &TestSCPDriver {
        &self.scp.driver()
    }

    fn bump_state(&self, slot: u64, value: Value) -> bool {
        self.scp.force_bump_state(slot, value)
    }

    fn receive_envelope(&self, envelope: ScpEnvelope) -> EnvelopeState {
        self.scp.receive_envelope(envelope)
    }

    fn envs_len(&self) -> usize {
        self.driver().envs_len()
    }

    fn get_env(&self, index: usize) -> ScpEnvelope {
        self.driver().get_env(index)
    }

    fn has_ballot_timer(&self) -> bool {
        self.driver().has_ballot_timer()
    }

    fn has_ballot_timer_upcoming(&self) -> bool {
        self.driver().has_ballot_timer_upcoming()
    }

    fn bump_timer_offset(&self) {
        self.driver().bump_timer_offset()
    }

    fn heard_from_quorum_count(&self, slot: u64) -> usize {
        self.driver().heard_from_quorum_count(slot)
    }

    fn heard_from_quorum_ballot(&self, slot: u64, index: usize) -> ScpBallot {
        self.driver().heard_from_quorum_ballot(slot, index)
    }

    fn externalized_value(&self, slot: u64) -> Option<Value> {
        self.driver().externalized_value(slot)
    }

    fn externalized_value_count(&self) -> usize {
        self.driver().externalized_values.read().unwrap().len()
    }

    fn fire_ballot_timer(&self) {
        // Matches stellar-core getBallotProtocolTimer().mCallback() which calls abandonBallot(0)
        self.scp.abandon_ballot(0, 0);
    }

    fn store_quorum_set(&self, qs: &ScpQuorumSet) {
        self.driver().store_quorum_set(qs);
    }

    fn set_priority_node(&self, node: NodeId) {
        self.driver().set_priority_node(node);
    }

    fn nominate(&self, slot: u64, value: Value, prev_value: &Value) -> bool {
        self.scp.nominate(slot, value, prev_value)
    }

    fn nominate_timeout(&self, slot: u64, value: Value, prev_value: &Value) -> bool {
        self.scp.nominate_timeout(slot, value, prev_value)
    }

    /// Get the current envelope for a specific node in a slot, including self
    /// even when not fully validated. Matches stellar-core `getCurrentEnvelope(index, nodeID)`.
    fn get_current_envelope(&self, slot_index: u64, node_id: &NodeId) -> ScpEnvelope {
        let envs = self.scp.get_entire_current_state(slot_index);
        envs.into_iter()
            .find(|e| &e.statement.node_id == node_id)
            .expect("getCurrentEnvelope: envelope not found for node")
    }

    /// Set SCP state from a saved envelope (for crash recovery testing).
    /// Matches stellar-core `mSCP.setStateFromEnvelope(slotIndex, envelope)`.
    fn set_state_from_envelope(&self, envelope: &ScpEnvelope) {
        self.scp.set_state_from_envelope(envelope);
    }

    /// Get the nomination leaders for slot 0.
    /// Matches stellar-core `scp.getNominationLeaders(0)`.
    #[allow(dead_code)]
    fn get_nomination_leaders(&self) -> std::collections::HashSet<NodeId> {
        self.scp.get_nomination_leaders(0)
    }

    /// Get the latest composite candidate value for a slot.
    /// Matches stellar-core `scp.getLatestCompositeCandidate(slotIndex)`.
    #[allow(dead_code)]
    fn get_latest_composite_candidate(&self, slot_index: u64) -> Option<Value> {
        self.scp.get_latest_composite_candidate(slot_index)
    }

    /// Check if a nomination timer is currently set for slot 0.
    /// Matches stellar-core `scp.mTimers.find(Slot::NOMINATION_TIMER) != scp.mTimers.end()`.
    #[allow(dead_code)]
    fn has_nomination_timer(&self) -> bool {
        self.driver()
            .timers
            .read()
            .unwrap()
            .contains_key(&(0, SCPTimerType::Nomination))
    }
}

// ---------------------------------------------------------------------------
// Node identity helpers
// ---------------------------------------------------------------------------

/// Create a deterministic node ID from a seed byte.
fn make_node_id(seed: u8) -> NodeId {
    // Matches stellar-core SIMULATION_CREATE_NODE pattern with deterministic bytes
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
}

// Fixed node IDs for the 5-node test topology
fn v0_id() -> NodeId {
    make_node_id(0)
}
fn v1_id() -> NodeId {
    make_node_id(1)
}
fn v2_id() -> NodeId {
    make_node_id(2)
}
fn v3_id() -> NodeId {
    make_node_id(3)
}
fn v4_id() -> NodeId {
    make_node_id(4)
}

// ---------------------------------------------------------------------------
// Value setup (matching stellar-core setupValues)
// ---------------------------------------------------------------------------

/// Create deterministic test values where x_value < y_value < z_value < zz_value.
fn setup_values() -> (Value, Value, Value, Value) {
    let mut values: Vec<Value> = (0u8..4)
        .map(|i| {
            let mut bytes = vec![0u8; 32];
            bytes[0] = i + 1; // 1, 2, 3, 4 — ensures distinct values
            Value(bytes.try_into().unwrap())
        })
        .collect();
    values.sort();
    let x = values[0].clone();
    let y = values[1].clone();
    let z = values[2].clone();
    let zz = values[3].clone();
    assert!(x < y);
    assert!(y < z);
    assert!(z < zz);
    (x, y, z, zz)
}

// ---------------------------------------------------------------------------
// Quorum set helpers
// ---------------------------------------------------------------------------

/// Create the standard 5-node quorum set with threshold 4.
fn make_core5_quorum_set() -> ScpQuorumSet {
    ScpQuorumSet {
        threshold: 4,
        validators: vec![v0_id(), v1_id(), v2_id(), v3_id(), v4_id()]
            .try_into()
            .unwrap(),
        inner_sets: vec![].try_into().unwrap(),
    }
}

/// Create a 3-node quorum set with threshold 2.
fn make_core3_quorum_set() -> ScpQuorumSet {
    ScpQuorumSet {
        threshold: 2,
        validators: vec![v0_id(), v1_id(), v2_id()].try_into().unwrap(),
        inner_sets: vec![].try_into().unwrap(),
    }
}

fn quorum_set_hash(qs: &ScpQuorumSet) -> Hash256 {
    Hash256::hash_xdr(qs).unwrap_or(Hash256::ZERO)
}

// ---------------------------------------------------------------------------
// Envelope construction helpers (matching stellar-core makePrepare, etc.)
// ---------------------------------------------------------------------------

fn make_prepare(
    node_id: &NodeId,
    q_set_hash: Hash256,
    slot_index: u64,
    ballot: &ScpBallot,
    prepared: Option<&ScpBallot>,
    n_c: u32,
    n_h: u32,
    prepared_prime: Option<&ScpBallot>,
) -> ScpEnvelope {
    ScpEnvelope {
        statement: ScpStatement {
            node_id: node_id.clone(),
            slot_index,
            pledges: ScpStatementPledges::Prepare(ScpStatementPrepare {
                quorum_set_hash: Hash(q_set_hash.0),
                ballot: ballot.clone(),
                prepared: prepared.cloned(),
                prepared_prime: prepared_prime.cloned(),
                n_c,
                n_h,
            }),
        },
        signature: Signature(vec![0u8; 64].try_into().unwrap()),
    }
}

fn make_confirm(
    node_id: &NodeId,
    q_set_hash: Hash256,
    slot_index: u64,
    n_prepared: u32,
    ballot: &ScpBallot,
    n_c: u32,
    n_h: u32,
) -> ScpEnvelope {
    ScpEnvelope {
        statement: ScpStatement {
            node_id: node_id.clone(),
            slot_index,
            pledges: ScpStatementPledges::Confirm(ScpStatementConfirm {
                ballot: ballot.clone(),
                n_prepared,
                n_commit: n_c,
                n_h,
                quorum_set_hash: Hash(q_set_hash.0),
            }),
        },
        signature: Signature(vec![0u8; 64].try_into().unwrap()),
    }
}

fn make_externalize(
    node_id: &NodeId,
    q_set_hash: Hash256,
    slot_index: u64,
    commit_ballot: &ScpBallot,
    n_h: u32,
) -> ScpEnvelope {
    ScpEnvelope {
        statement: ScpStatement {
            node_id: node_id.clone(),
            slot_index,
            pledges: ScpStatementPledges::Externalize(ScpStatementExternalize {
                commit: commit_ballot.clone(),
                n_h,
                commit_quorum_set_hash: Hash(q_set_hash.0),
            }),
        },
        signature: Signature(vec![0u8; 64].try_into().unwrap()),
    }
}

fn make_nominate(
    node_id: &NodeId,
    q_set_hash: Hash256,
    slot_index: u64,
    votes: Vec<Value>,
    accepted: Vec<Value>,
) -> ScpEnvelope {
    let mut sorted_votes = votes;
    sorted_votes.sort();
    let mut sorted_accepted = accepted;
    sorted_accepted.sort();

    ScpEnvelope {
        statement: ScpStatement {
            node_id: node_id.clone(),
            slot_index,
            pledges: ScpStatementPledges::Nominate(ScpNomination {
                quorum_set_hash: Hash(q_set_hash.0),
                votes: sorted_votes.try_into().unwrap(),
                accepted: sorted_accepted.try_into().unwrap(),
            }),
        },
        signature: Signature(vec![0u8; 64].try_into().unwrap()),
    }
}

// ---------------------------------------------------------------------------
// Verification helpers (matching stellar-core verifyPrepare, etc.)
// ---------------------------------------------------------------------------

fn verify_prepare(
    actual: &ScpEnvelope,
    expected_node: &NodeId,
    q_set_hash: Hash256,
    slot_index: u64,
    ballot: &ScpBallot,
    prepared: Option<&ScpBallot>,
    n_c: u32,
    n_h: u32,
    prepared_prime: Option<&ScpBallot>,
) {
    let expected = make_prepare(
        expected_node,
        q_set_hash,
        slot_index,
        ballot,
        prepared,
        n_c,
        n_h,
        prepared_prime,
    );
    assert_eq!(
        actual.statement, expected.statement,
        "PREPARE verification failed.\nActual:   {:?}\nExpected: {:?}",
        actual.statement.pledges, expected.statement.pledges
    );
}

fn verify_confirm(
    actual: &ScpEnvelope,
    expected_node: &NodeId,
    q_set_hash: Hash256,
    slot_index: u64,
    n_prepared: u32,
    ballot: &ScpBallot,
    n_c: u32,
    n_h: u32,
) {
    let expected = make_confirm(
        expected_node,
        q_set_hash,
        slot_index,
        n_prepared,
        ballot,
        n_c,
        n_h,
    );
    assert_eq!(
        actual.statement, expected.statement,
        "CONFIRM verification failed.\nActual:   {:?}\nExpected: {:?}",
        actual.statement.pledges, expected.statement.pledges
    );
}

fn verify_externalize(
    actual: &ScpEnvelope,
    expected_node: &NodeId,
    q_set_hash: Hash256,
    slot_index: u64,
    commit_ballot: &ScpBallot,
    n_h: u32,
) {
    let expected = make_externalize(expected_node, q_set_hash, slot_index, commit_ballot, n_h);
    assert_eq!(
        actual.statement, expected.statement,
        "EXTERNALIZE verification failed.\nActual:   {:?}\nExpected: {:?}",
        actual.statement.pledges, expected.statement.pledges
    );
}

fn verify_nominate(
    actual: &ScpEnvelope,
    expected_node: &NodeId,
    q_set_hash: Hash256,
    slot_index: u64,
    votes: Vec<Value>,
    accepted: Vec<Value>,
) {
    let expected = make_nominate(expected_node, q_set_hash, slot_index, votes, accepted);
    assert_eq!(
        actual.statement, expected.statement,
        "NOMINATE verification failed.\nActual:   {:?}\nExpected: {:?}",
        actual.statement.pledges, expected.statement.pledges
    );
}

// ---------------------------------------------------------------------------
// Envelope generator type (matching stellar-core genEnvelope)
// ---------------------------------------------------------------------------

/// A generator that takes a node ID and produces an envelope.
/// This mirrors the stellar-core `genEnvelope` typedef.
type GenEnvelope = Box<dyn Fn(&NodeId) -> ScpEnvelope>;

/// Create a PREPARE envelope generator with pre-bound parameters.
fn make_prepare_gen(
    q_set_hash: Hash256,
    ballot: ScpBallot,
    prepared: Option<ScpBallot>,
    n_c: u32,
    n_h: u32,
    prepared_prime: Option<ScpBallot>,
) -> GenEnvelope {
    Box::new(move |node_id: &NodeId| {
        make_prepare(
            node_id,
            q_set_hash,
            0,
            &ballot,
            prepared.as_ref(),
            n_c,
            n_h,
            prepared_prime.as_ref(),
        )
    })
}

/// Create a CONFIRM envelope generator with pre-bound parameters.
fn make_confirm_gen(
    q_set_hash: Hash256,
    n_prepared: u32,
    ballot: ScpBallot,
    n_c: u32,
    n_h: u32,
) -> GenEnvelope {
    Box::new(move |node_id: &NodeId| {
        make_confirm(node_id, q_set_hash, 0, n_prepared, &ballot, n_c, n_h)
    })
}

/// Create an EXTERNALIZE envelope generator with pre-bound parameters.
fn make_externalize_gen(q_set_hash: Hash256, commit_ballot: ScpBallot, n_h: u32) -> GenEnvelope {
    Box::new(move |node_id: &NodeId| make_externalize(node_id, q_set_hash, 0, &commit_ballot, n_h))
}

// ---------------------------------------------------------------------------
// Multi-node message delivery helpers (matching stellar-core recvQuorum/recvVBlocking)
// ---------------------------------------------------------------------------

/// Deliver envelopes from a v-blocking set (v1, v2) to the test SCP node.
/// In a 5-node quorum with threshold=4, any 2 nodes form a v-blocking set.
///
/// After delivery, asserts exactly 1 new envelope was emitted (if with_checks).
fn recv_v_blocking_checks(scp: &TestSCP, gen: &GenEnvelope, with_checks: bool) {
    let e1 = gen(&v1_id());
    let e2 = gen(&v2_id());

    scp.bump_timer_offset();

    let i = scp.envs_len();
    scp.receive_envelope(e1);
    if with_checks {
        assert_eq!(
            scp.envs_len(),
            i,
            "v-blocking: first message should not emit"
        );
    }
    scp.receive_envelope(e2);
    if with_checks {
        assert_eq!(
            scp.envs_len(),
            i + 1,
            "v-blocking: second message should emit exactly 1"
        );
    }
}

fn recv_v_blocking(scp: &TestSCP, gen: &GenEnvelope) {
    recv_v_blocking_checks(scp, gen, true);
}

/// Deliver envelopes from a quorum (v1, v2, v3, v4) to the test SCP node.
/// In a 5-node quorum with threshold=4: v0 (self) + v1 + v2 + v3 = quorum after 3 messages.
///
/// Asserts exactly 1 new envelope was emitted after quorum is reached (if with_checks).
fn recv_quorum_checks_ex(
    scp: &TestSCP,
    gen: &GenEnvelope,
    with_checks: bool,
    delayed_quorum: bool,
    check_upcoming: bool,
) {
    let e1 = gen(&v1_id());
    let e2 = gen(&v2_id());
    let e3 = gen(&v3_id());
    let e4 = gen(&v4_id());

    scp.bump_timer_offset();

    scp.receive_envelope(e1);
    scp.receive_envelope(e2);
    let i = scp.envs_len() + 1;
    scp.receive_envelope(e3);
    if with_checks && !delayed_quorum {
        assert_eq!(
            scp.envs_len(),
            i,
            "quorum: 3rd message should produce exactly 1 new envelope"
        );
    }
    if check_upcoming && !delayed_quorum {
        assert!(
            scp.has_ballot_timer_upcoming(),
            "quorum: ballot timer should be upcoming"
        );
    }
    // 4th message: nothing extra (unless delayed quorum)
    scp.receive_envelope(e4);
    if with_checks && delayed_quorum {
        assert_eq!(
            scp.envs_len(),
            i,
            "delayed quorum: 4th message should produce exactly 1 new envelope"
        );
    }
    if check_upcoming && delayed_quorum {
        assert!(
            scp.has_ballot_timer_upcoming(),
            "delayed quorum: ballot timer should be upcoming"
        );
    }
}

fn recv_quorum_ex(scp: &TestSCP, gen: &GenEnvelope, check_upcoming: bool) {
    recv_quorum_checks_ex(scp, gen, true, false, check_upcoming);
}

fn recv_quorum(scp: &TestSCP, gen: &GenEnvelope) {
    recv_quorum_checks_ex(scp, gen, true, false, false);
}

// ---------------------------------------------------------------------------
// Common test setup: nodesAllPledgeToCommit
// ---------------------------------------------------------------------------

/// Drive the ballot protocol through the sequence where all nodes pledge to
/// commit value x. After this, `scp.envs` has 3 entries:
/// 0: PREPARE(1,x)
/// 1: PREPARE(1,x) prepared=(1,x)
/// 2: PREPARE(1,x) prepared=(1,x) nC=1 nH=1
fn nodes_all_pledge_to_commit(scp: &TestSCP, x_value: &Value, qs_hash: Hash256) {
    let qs_hash0 = quorum_set_hash(&scp.scp.local_quorum_set());
    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    assert!(scp.bump_state(0, x_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    verify_prepare(&scp.get_env(0), &v0_id(), qs_hash0, 0, &b, None, 0, 0, None);

    // Receive PREPARE from v1, v2, v3 (quorum)
    let prepare1 = make_prepare(&v1_id(), qs_hash, 0, &b, None, 0, 0, None);
    let prepare2 = make_prepare(&v2_id(), qs_hash, 0, &b, None, 0, 0, None);
    let prepare3 = make_prepare(&v3_id(), qs_hash, 0, &b, None, 0, 0, None);
    let prepare4 = make_prepare(&v4_id(), qs_hash, 0, &b, None, 0, 0, None);

    scp.receive_envelope(prepare1);
    assert_eq!(scp.envs_len(), 1);
    assert_eq!(scp.heard_from_quorum_count(0), 0);

    scp.receive_envelope(prepare2);
    assert_eq!(scp.envs_len(), 1);
    assert_eq!(scp.heard_from_quorum_count(0), 0);

    scp.receive_envelope(prepare3);
    assert_eq!(scp.envs_len(), 2);
    assert_eq!(scp.heard_from_quorum_count(0), 1);
    assert_eq!(scp.heard_from_quorum_ballot(0, 0), b);

    // Quorum including us → emits PREPARE with prepared set
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &b,
        Some(&b),
        0,
        0,
        None,
    );

    scp.receive_envelope(prepare4);
    assert_eq!(scp.envs_len(), 2);

    // Now receive PREPARE-with-prepared from quorum to confirm prepared
    let prepared2 = make_prepare(&v2_id(), qs_hash, 0, &b, Some(&b), 0, 0, None);
    let prepared3 = make_prepare(&v3_id(), qs_hash, 0, &b, Some(&b), 0, 0, None);
    let prepared4 = make_prepare(&v4_id(), qs_hash, 0, &b, Some(&b), 0, 0, None);

    scp.receive_envelope(prepared4);
    scp.receive_envelope(prepared3);
    assert_eq!(scp.envs_len(), 2);

    scp.receive_envelope(prepared2);
    assert_eq!(scp.envs_len(), 3);

    // Confirms prepared: nC=1, nH=1
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
}

// ===========================================================================
// TEST CASES
// ===========================================================================

// ---------------------------------------------------------------------------
// ballot protocol core5 > "bumpState x"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_bump_state_x() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash0 = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    assert!(scp.bump_state(0, x_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    let expected_ballot = ScpBallot {
        counter: 1,
        value: x_value,
    };

    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        &expected_ballot,
        None,
        0,
        0,
        None,
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "start <1,x>" > "prepared A1"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_start_1x_prepared_a1() {
    let (x_value, _y_value, z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let _b_value = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);
    assert!(!scp.has_ballot_timer());

    // Receive quorum PREPARE for A1 → should emit PREPARE with prepared=A1
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );

    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&a1),
        0,
        0,
        None,
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "start <1,x>" > "prepared A1" > "bump prepared A2"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_bump_prepared_a2() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    // Start and get A1 prepared
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);

    // Bump to (2,a)
    scp.bump_timer_offset();
    assert!(scp.scp.force_bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&a1),
        0,
        0,
        None,
    );
    assert!(!scp.has_ballot_timer());

    // Receive quorum PREPARE for A2
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 4);
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&a2),
        0,
        0,
        None,
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "start <1,x>" > prepared A1 > bump A2 > "Confirm prepared A2"
// ---------------------------------------------------------------------------

/// Helper: set up scp through "Confirm prepared A2" state.
/// Returns the scp instance positioned for the "Accept commit" or other branches.
#[allow(clippy::type_complexity)]
fn setup_confirm_prepared_a2() -> (TestSCP, Value, Value, Value, Value, Hash256) {
    let (x_value, y_value, z_value, zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value.clone();
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    // Start → prepared A1 → bump → prepared A2
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    scp.bump_timer_offset();
    scp.scp.force_bump_state(0, a_value.clone());
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), None, 0, 0, None),
        true,
    );

    // Confirm prepared A2: receive quorum PREPARE with prepared=A2
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 5);
    let qs_hash0 = qs_hash;
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&a2),
        2,
        2,
        None,
    );
    assert!(!scp.has_ballot_timer_upcoming());

    (scp, x_value, y_value, z_value, zz_value, qs_hash)
}

#[test]
fn test_ballot_core5_confirm_prepared_a2() {
    let (_scp, _x, _y, _z, _zz, _qs_hash) = setup_confirm_prepared_a2();
    // Just verifying setup completes without panic
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > Accept commit > Quorum A2
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_accept_commit_quorum_a2() {
    let (scp, x_value, _y_value, _z_value, _zz_value, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;

    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    // Receive quorum PREPARE with nC=2 nH=2 → should emit CONFIRM
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash0, 0, 2, &a2, 2, 2);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > Accept commit > Quorum A2 > Quorum prepared A3
// > Accept more commit A3 > Quorum externalize A3
// (Full happy path to externalization)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_full_externalization_path() {
    let (scp, x_value, _y_value, _z_value, _zz_value, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;

    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    // Accept commit: quorum PREPARE with nC=2 nH=2
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash0, 0, 2, &a2, 2, 2);

    // Quorum prepared A3: v-blocking PREPARE with A3
    // First send manually to debug
    let gen_a3_prep = make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None);
    let e1 = gen_a3_prep(&v1_id());
    let e2 = gen_a3_prep(&v2_id());
    scp.bump_timer_offset();
    let before = scp.envs_len();
    eprintln!("Before v-blocking PREPARE(A3): envs_len={}", before);
    let r1 = scp.receive_envelope(e1);
    eprintln!(
        "After v1 PREPARE(A3): envs_len={}, result={:?}",
        scp.envs_len(),
        r1
    );
    assert_eq!(
        scp.envs_len(),
        before,
        "v-blocking: first message should not emit"
    );
    let r2 = scp.receive_envelope(e2);
    eprintln!(
        "After v2 PREPARE(A3): envs_len={}, result={:?}",
        scp.envs_len(),
        r2
    );
    assert_eq!(
        scp.envs_len(),
        before + 1,
        "v-blocking: second message should emit exactly 1"
    );
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 2, &a3, 2, 2);

    // Now quorum PREPARE A3 prepared=A2 nC=2 nH=2 to bump nPrepared to 3
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
        true,
    );
    assert_eq!(scp.envs_len(), 8);
    verify_confirm(&scp.get_env(7), &v0_id(), qs_hash0, 0, 3, &a3, 2, 2);

    // Accept more commit A3: quorum PREPARE with A3 nC=2 nH=3
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a3.clone()), 2, 3, None),
    );
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(&scp.get_env(8), &v0_id(), qs_hash0, 0, 3, &a3, 2, 3);

    // Quorum externalize A3
    recv_quorum(&scp, &make_confirm_gen(qs_hash, 3, a3.clone(), 2, 3));
    assert_eq!(scp.envs_len(), 10);
    verify_externalize(&scp.get_env(9), &v0_id(), qs_hash0, 0, &a2, 3);
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > Accept commit > v-blocking CONFIRM
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_accept_commit_vblocking_confirm_a2() {
    let (scp, x_value, _y_value, _z_value, _zz_value, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;

    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    // v-blocking CONFIRM for A2 → should emit CONFIRM
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 2, a2.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash0, 0, 2, &a2, 2, 2);
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > Accept commit > v-blocking EXTERNALIZE
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_accept_commit_vblocking_externalize_a2() {
    let (scp, x_value, _y_value, _z_value, _zz_value, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;

    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    // v-blocking EXTERNALIZE for A2 → should emit CONFIRM with infinite ballot
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a2.clone(), 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        u32::MAX,
        &ScpBallot {
            counter: u32::MAX,
            value: a_value.clone(),
        },
        2,
        u32::MAX,
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "normal round (1,x)" — full happy path
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_normal_round() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    nodes_all_pledge_to_commit(&scp, &x_value, qs_hash);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // At this point envs has 3 entries:
    // 0: PREPARE(1,x)
    // 1: PREPARE(1,x) prepared=(1,x)
    // 2: PREPARE(1,x) prepared=(1,x) nC=1 nH=1

    // Receive quorum PREPARE with nC=1 nH=1 → should emit CONFIRM
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, b.clone(), Some(b.clone()), 1, 1, None),
    );
    assert_eq!(scp.envs_len(), 4);
    verify_confirm(&scp.get_env(3), &v0_id(), qs_hash0, 0, 1, &b, 1, 1);

    // Receive quorum CONFIRM → should emit EXTERNALIZE
    recv_quorum(&scp, &make_confirm_gen(qs_hash, 1, b.clone(), 1, 1));
    assert_eq!(scp.envs_len(), 5);
    verify_externalize(&scp.get_env(4), &v0_id(), qs_hash0, 0, &b, 1);
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "non validator watching the network"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_non_validator_watching() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new_non_validator(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // In stellar-core, bumpState returns true for non-validators (internal state is
    // updated via emitCurrentStateStatement, but sendLatestEnvelope is a no-op).
    assert!(scp.bump_state(0, x_value.clone()));
    // No envelopes emitted (non-validator doesn't broadcast)
    assert_eq!(scp.envs_len(), 0);

    // Receive quorum EXTERNALIZE messages
    let ext1 = make_externalize(&v1_id(), qs_hash, 0, &b, 1);
    let ext2 = make_externalize(&v2_id(), qs_hash, 0, &b, 1);
    let ext3 = make_externalize(&v3_id(), qs_hash, 0, &b, 1);
    let ext4 = make_externalize(&v4_id(), qs_hash, 0, &b, 1);

    scp.receive_envelope(ext1);
    scp.receive_envelope(ext2);
    scp.receive_envelope(ext3);
    // After quorum EXTERNALIZE, still no emitted envelopes (non-validator)
    assert_eq!(scp.envs_len(), 0);
    // stellar-core verifies internal CONFIRM state here via getCurrentEnvelope

    scp.receive_envelope(ext4);
    // Still no emitted envelopes
    assert_eq!(scp.envs_len(), 0);

    // Value should be externalized
    assert_eq!(scp.externalized_value(0), Some(x_value));
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "restore ballot protocol"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_restore_prepare() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // Create a PREPARE envelope from self
    let prepare = make_prepare(&v0_id(), qs_hash, 0, &b, Some(&b), 0, 0, None);

    // Restore state from this envelope
    let result = scp.scp.set_state_from_envelope(&prepare);
    assert!(result, "set_state_from_envelope should succeed for PREPARE");

    // Should be able to receive further messages
    assert_eq!(scp.envs_len(), 0); // No new emissions from restore
}

#[test]
fn test_ballot_core5_restore_confirm() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    let confirm = make_confirm(&v0_id(), qs_hash, 0, 1, &b, 1, 1);
    let result = scp.scp.set_state_from_envelope(&confirm);
    assert!(result, "set_state_from_envelope should succeed for CONFIRM");
}

#[test]
fn test_ballot_core5_restore_externalize() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    let externalize = make_externalize(&v0_id(), qs_hash, 0, &b, 1);
    let result = scp.scp.set_state_from_envelope(&externalize);
    assert!(
        result,
        "set_state_from_envelope should succeed for EXTERNALIZE"
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "start <1,x>" > "prepared B (v-blocking)"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_prepared_b_vblocking() {
    let (x_value, _y_value, z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let b_value = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    // Start with aValue
    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // v-blocking PREPARE for B1 with prepared=B1
    // Since B > A, this should update our prepared' to B1
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 2);
    // Should emit PREPARE(1,a) with prepared'=B1
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        None,
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "start <1,x>" > "confirm (v-blocking)" > "via CONFIRM"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_confirm_vblocking_via_confirm() {
    let (x_value, _y_value, z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let _b_value = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };

    // Start with aValue
    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // v-blocking CONFIRM for A1 → should emit CONFIRM
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 1, a1.clone(), 1, 1));
    assert_eq!(scp.envs_len(), 2);
    verify_confirm(&scp.get_env(1), &v0_id(), qs_hash0, 0, 1, &a1, 1, 1);
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "start <1,x>" > "confirm (v-blocking)" > "via EXTERNALIZE"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_confirm_vblocking_via_externalize() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };

    // Start with aValue
    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // v-blocking EXTERNALIZE for A1 → should emit CONFIRM with nPrepared=MAX, nH=MAX
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a1.clone(), 1));
    assert_eq!(scp.envs_len(), 2);
    verify_confirm(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        u32::MAX,
        &ScpBallot {
            counter: u32::MAX,
            value: a_value.clone(),
        },
        1,
        u32::MAX,
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "start <1,x>" > "prepare B (quorum)"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_prepare_b_quorum() {
    let (x_value, _y_value, z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let b_value = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    // Start with aValue
    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // Quorum PREPARE for B1 → should accept B1 as prepared.
    // delayedQuorum=true because v0 voted for A1, not B1, so quorum for B1
    // isn't reached until the 4th external node (v1+v2+v3+v4 = 4 nodes).
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), None, 0, 0, None),
        true,
        true, // delayedQuorum
        true, // checkUpcoming
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        None,
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "start <1,x>" > "prepared A1" >
// "switch prepared B1 from A1" > "v-blocking switches to previous value of p"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_switch_prepared_b1_from_a1() {
    let (x_value, _y_value, z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let b_value = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    // Start and get A1 prepared
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&a1),
        0,
        0,
        None,
    );

    // v-blocking PREPARE for B1 with prepared=B1
    // Should switch p to B1, p' to A1
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        Some(&a1),
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core3 tests
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core3_prepared_b1_quorum_votes_b1() {
    let (x_value, _y_value, z_value, _zz_value) = setup_values();
    let qs = make_core3_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    // In core3 with threshold=2:
    // v-blocking set size = 1 (3 - 2 + 1 = 2, but actually min = 1 for t=2,n=3...
    // actually n-t+1 = 3-2+1 = 2, so v-blocking needs 2 nodes.)
    // quorum needs 2 nodes

    let a_value = &x_value; // aValue = xValue (smaller)
    let b_value = &z_value; // bValue = zValue (larger)
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    // Start with aValue
    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);
    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        None,
        0,
        0,
        None,
    );

    // In a 3-node quorum with threshold=2:
    // v0 voted A1, v1 votes B1, v2 votes B1.
    // v0 did NOT vote for B1 (incompatible value), so v0 is excluded from the
    // "voted to prepare B1" set. We need {v1, v2} to form a quorum for B1.
    // stellar-core uses recvQuorumChecks which sends from both v1 and v2.
    let prepare1 = make_prepare(&v1_id(), qs_hash, 0, &b1, None, 0, 0, None);
    let prepare2 = make_prepare(&v2_id(), qs_hash, 0, &b1, None, 0, 0, None);
    scp.receive_envelope(prepare1);
    // After v1 alone, quorum may not be reached yet (v0 didn't vote B1)
    scp.receive_envelope(prepare2);
    // Now {v1, v2} forms a quorum for B1 (threshold=2, both voted B1)
    assert_eq!(scp.envs_len(), 2);
    // Should have B1 as prepared (since quorum voted for B1)
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        None,
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "range check"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_range_check() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let _qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    nodes_all_pledge_to_commit(&scp, &x_value, qs_hash);

    let _b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // envs[0..3] from nodes_all_pledge_to_commit

    // Receive CONFIRM messages with different commit ranges
    // nC=2, nH=4 (commit range [2,4])
    let c1 = make_confirm(
        &v1_id(),
        qs_hash,
        0,
        2,
        &ScpBallot {
            counter: 4,
            value: x_value.clone(),
        },
        2,
        4,
    );
    let c2 = make_confirm(
        &v2_id(),
        qs_hash,
        0,
        2,
        &ScpBallot {
            counter: 4,
            value: x_value.clone(),
        },
        2,
        4,
    );
    let c3 = make_confirm(
        &v3_id(),
        qs_hash,
        0,
        2,
        &ScpBallot {
            counter: 4,
            value: x_value.clone(),
        },
        2,
        4,
    );
    let c4 = make_confirm(
        &v4_id(),
        qs_hash,
        0,
        2,
        &ScpBallot {
            counter: 4,
            value: x_value.clone(),
        },
        2,
        4,
    );

    scp.receive_envelope(c1);
    scp.receive_envelope(c2);
    scp.receive_envelope(c3);
    // After quorum CONFIRM, should emit CONFIRM
    assert!(scp.envs_len() >= 4);
    scp.receive_envelope(c4);
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "timeout when h is set -> stay locked on h"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_timeout_stay_locked_on_h() {
    let (x_value, y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let _qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };

    // Start with aValue
    assert!(scp.bump_state(0, a_value.clone()));

    // Get A1 prepared
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );

    // Confirm prepared A1 (quorum says prepared=A1)
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), Some(a1.clone()), 0, 0, None),
    );

    // Now we have nC=1 nH=1 (confirmed prepared A1, h is set)
    // Timeout with value y should stay locked on h (= A1 value = x)
    scp.bump_timer_offset();
    scp.scp.force_bump_state(0, y_value.clone());

    // The bumped ballot should use x (locked on h), not y
    let last = scp.get_env(scp.envs_len() - 1);
    if let ScpStatementPledges::Prepare(prep) = &last.statement.pledges {
        assert_eq!(
            prep.ballot.value, *a_value,
            "should stay locked on h value (x), not switch to y"
        );
    } else {
        panic!("expected PREPARE envelope after bump");
    }
}

// ---------------------------------------------------------------------------
// Nomination tests core5
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_v0_is_top_nominates_x() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // v0 is top (priority=1000 in our driver)
    // Nominate x
    assert!(scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);
    verify_nominate(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        vec![x_value.clone()],
        vec![],
    );
}

// ---------------------------------------------------------------------------
// Nomination tests core5 > "v0 is top" > "others nominate x → prepare x" setup
// C++ SCPTests.cpp lines 2805-2866
// ---------------------------------------------------------------------------

/// Shared setup: drives nomination through "others nominate x → prepare x".
///
/// At exit:
/// - env[0] = NOMINATE(votes=[x], accepted=[])
/// - env[1] = NOMINATE(votes=[x], accepted=[x])
/// - env[2] = PREPARE(1, x)
/// - Total: 3 envelopes
///
/// Returns (scp, x_value, y_value, k_value, qs_hash, qs_hash0) ready for
/// the nested SECTION tests that extend this state.
#[allow(clippy::type_complexity)]
fn setup_nomination_others_nominate_x_prepare_x() -> (TestSCP, Value, Value, Value, Hash256, Hash256)
{
    let (x_value, y_value, _z_value, _zz_value) = setup_values();
    let k_value = Value(vec![0xFFu8; 32].try_into().unwrap());
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // v0 nominates x
    assert!(scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);
    verify_nominate(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        vec![x_value.clone()],
        vec![],
    );

    // Others vote for x
    let nom1 = make_nominate(&v1_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom3 = make_nominate(&v3_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom4 = make_nominate(&v4_id(), qs_hash, 0, vec![x_value.clone()], vec![]);

    // nothing happens yet
    scp.receive_envelope(nom1);
    scp.receive_envelope(nom2);
    assert_eq!(scp.envs_len(), 1);

    // this causes 'x' to be accepted (quorum)
    scp.receive_envelope(nom3);
    assert_eq!(scp.envs_len(), 2);

    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    scp.driver().set_expected_candidates(expected);
    scp.driver().set_composite_value(x_value.clone());

    verify_nominate(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );

    // extra message doesn't do anything
    scp.receive_envelope(nom4);
    assert_eq!(scp.envs_len(), 2);

    // Others accept x
    let acc1 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc2 = make_nominate(
        &v2_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc3 = make_nominate(
        &v3_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc4 = make_nominate(
        &v4_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );

    // nothing happens yet
    scp.receive_envelope(acc1);
    scp.receive_envelope(acc2);
    assert_eq!(scp.envs_len(), 2);

    scp.driver().set_composite_value(x_value.clone());
    // this causes the node to send a prepare message (quorum)
    scp.receive_envelope(acc3);
    assert_eq!(scp.envs_len(), 3);

    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &ScpBallot {
            counter: 1,
            value: x_value.clone(),
        },
        None,
        0,
        0,
        None,
    );

    scp.receive_envelope(acc4);
    assert_eq!(scp.envs_len(), 3);

    (scp, x_value, y_value, k_value, qs_hash, qs_hash0)
}

#[test]
fn test_nomination_core5_others_nominate_x_prepare_x() {
    // Just verify the setup completes successfully
    let (_scp, _x, _y, _k, _qs_hash, _qs_hash0) = setup_nomination_others_nominate_x_prepare_x();
}

// ---------------------------------------------------------------------------
// "nominate x → accept x → prepare (x) ; others accepted y → update latest to (z=x+y)"
// C++ SCPTests.cpp lines 2871-2904
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_others_accepted_y_update_latest() {
    let (scp, x_value, y_value, k_value, qs_hash, qs_hash0) =
        setup_nomination_others_nominate_x_prepare_x();

    // votes2 = [x, y]
    let votes2 = vec![x_value.clone(), y_value.clone()];

    let acc1_2 = make_nominate(&v1_id(), qs_hash, 0, votes2.clone(), votes2.clone());
    let acc2_2 = make_nominate(&v2_id(), qs_hash, 0, votes2.clone(), votes2.clone());
    let acc3_2 = make_nominate(&v3_id(), qs_hash, 0, votes2.clone(), votes2.clone());
    let acc4_2 = make_nominate(&v4_id(), qs_hash, 0, votes2.clone(), votes2.clone());

    scp.receive_envelope(acc1_2);
    assert_eq!(scp.envs_len(), 3);

    // v-blocking
    scp.receive_envelope(acc2_2);
    assert_eq!(scp.envs_len(), 4);
    verify_nominate(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        votes2.clone(),
        votes2.clone(),
    );

    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    expected.insert(y_value.clone());
    scp.driver().set_expected_candidates(expected);
    scp.driver().set_composite_value(k_value.clone());

    // this updates the composite value to use next time
    // but does not prepare it
    scp.receive_envelope(acc3_2);
    assert_eq!(scp.envs_len(), 4);

    assert_eq!(scp.get_latest_composite_candidate(0), Some(k_value.clone()));

    scp.receive_envelope(acc4_2);
    assert_eq!(scp.envs_len(), 4);
}

// ---------------------------------------------------------------------------
// "nomination - restored state / ballot protocol not started"
// C++ SCPTests.cpp lines 2956-2964
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_restored_state_ballot_not_started() {
    let (_scp, x_value, _y_value, _k_value, qs_hash, qs_hash0) =
        setup_nomination_others_nominate_x_prepare_x();

    // Create a fresh SCP (scp2) and restore from the original's nomination state
    let qs = make_core5_quorum_set();
    let scp2 = TestSCP::new(v0_id(), qs.clone());
    scp2.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // At this point: votes = { x }, accepted = { x }
    let votes = vec![x_value.clone()];
    let accepted = vec![x_value.clone()];

    // Restore from the previous state
    let restore_env = make_nominate(&v0_id(), qs_hash0, 0, votes.clone(), accepted.clone());
    scp2.set_state_from_envelope(&restore_env);

    // tries to start nomination with yValue, but picks
    // xValue since it was already in the votes
    let (_, y_value, _, _) = setup_values();
    assert!(!scp2.nominate(0, y_value, &empty_value));
    assert_eq!(scp2.envs_len(), 0);

    // Recreate the nominate envelopes from the original setup
    let nom1 = make_nominate(&v1_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom3 = make_nominate(&v3_id(), qs_hash, 0, vec![x_value.clone()], vec![]);

    // other nodes vote for 'x'
    scp2.receive_envelope(nom1);
    scp2.receive_envelope(nom2);
    assert_eq!(scp2.envs_len(), 0);

    // 'x' is accepted (quorum)
    // but because the restored state already included
    // 'x' in the accepted set, no new message is emitted
    scp2.receive_envelope(nom3);

    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    scp2.driver().set_expected_candidates(expected);
    scp2.driver().set_composite_value(x_value.clone());

    // other nodes emit 'x' as accepted
    let acc1 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc2 = make_nominate(
        &v2_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc3 = make_nominate(
        &v3_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );

    scp2.receive_envelope(acc1);
    scp2.receive_envelope(acc2);
    assert_eq!(scp2.envs_len(), 0);

    scp2.driver().set_composite_value(x_value.clone());
    // this causes the node to update its composite value to x
    scp2.receive_envelope(acc3);

    // nomination ended up starting the ballot protocol
    assert_eq!(scp2.envs_len(), 1);

    verify_prepare(
        &scp2.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        &ScpBallot {
            counter: 1,
            value: x_value.clone(),
        },
        None,
        0,
        0,
        None,
    );
}

// ---------------------------------------------------------------------------
// "nomination - restored state / ballot protocol started (on value k)"
// C++ SCPTests.cpp lines 2965-2975
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_restored_state_ballot_started() {
    let (_scp, x_value, _y_value, k_value, qs_hash, qs_hash0) =
        setup_nomination_others_nominate_x_prepare_x();

    // Create a fresh SCP (scp2) and restore from the original's nomination state
    let qs = make_core5_quorum_set();
    let scp2 = TestSCP::new(v0_id(), qs.clone());
    scp2.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // At this point: votes = { x }, accepted = { x }
    let votes = vec![x_value.clone()];
    let accepted = vec![x_value.clone()];

    // First restore ballot protocol state (on value k)
    let ballot_restore_env = make_prepare(
        &v0_id(),
        qs_hash0,
        0,
        &ScpBallot {
            counter: 1,
            value: k_value.clone(),
        },
        None,
        0,
        0,
        None,
    );
    scp2.set_state_from_envelope(&ballot_restore_env);

    // Then do the nomination restore
    let nom_restore_env = make_nominate(&v0_id(), qs_hash0, 0, votes.clone(), accepted.clone());
    scp2.set_state_from_envelope(&nom_restore_env);

    // tries to start nomination with yValue, but picks
    // xValue since it was already in the votes
    let (_, y_value, _, _) = setup_values();
    assert!(!scp2.nominate(0, y_value, &empty_value));
    assert_eq!(scp2.envs_len(), 0);

    // Recreate the nominate envelopes from the original setup
    let nom1 = make_nominate(&v1_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom3 = make_nominate(&v3_id(), qs_hash, 0, vec![x_value.clone()], vec![]);

    // other nodes vote for 'x'
    scp2.receive_envelope(nom1);
    scp2.receive_envelope(nom2);
    assert_eq!(scp2.envs_len(), 0);
    scp2.receive_envelope(nom3);

    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    scp2.driver().set_expected_candidates(expected);
    scp2.driver().set_composite_value(x_value.clone());

    // other nodes emit 'x' as accepted
    let acc1 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc2 = make_nominate(
        &v2_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc3 = make_nominate(
        &v3_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );

    scp2.receive_envelope(acc1);
    scp2.receive_envelope(acc2);
    assert_eq!(scp2.envs_len(), 0);

    scp2.driver().set_composite_value(x_value.clone());
    scp2.receive_envelope(acc3);

    // nomination didn't do anything (already working on k)
    assert_eq!(scp2.envs_len(), 0);
}

// ---------------------------------------------------------------------------
// "receive more messages, then v0 switches to a different leader"
// C++ SCPTests.cpp lines 2978-3005
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_switch_leader() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let k_value = Value(vec![0xFFu8; 32].try_into().unwrap());
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // v0 nominates x (v0 is top)
    assert!(scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);

    // Receive messages from non-leaders
    let nom1 = make_nominate(&v1_id(), qs_hash, 0, vec![k_value.clone()], vec![]);
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, vec![_y_value.clone()], vec![]);

    // nothing more happens
    scp.receive_envelope(nom1);
    scp.receive_envelope(nom2);
    assert_eq!(scp.envs_len(), 1);

    // switch leader to v1
    scp.set_priority_node(v1_id());
    assert!(scp.nominate_timeout(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 2);

    // votesXK sorted
    let mut votes_xk = vec![x_value.clone(), k_value.clone()];
    votes_xk.sort();

    verify_nominate(&scp.get_env(1), &v0_id(), qs_hash0, 0, votes_xk, vec![]);
}

// ---------------------------------------------------------------------------
// "select accepted value from leader / receive accepted before timeout"
// C++ SCPTests.cpp lines 3020-3055
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_select_accepted_before_timeout() {
    let (x_value, y_value, z_value, zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // v0 nominates x
    assert!(scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);

    // Update round leader to v1
    scp.set_priority_node(v1_id());

    let nom1 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![y_value.clone(), z_value.clone()],
        vec![y_value.clone()],
    );

    // receive accepted before timeout
    // nothing more happens, v0 is leader
    scp.receive_envelope(nom1);
    assert_eq!(scp.envs_len(), 1);

    // Update round leaders, vote for accepted value (y)
    assert!(scp.nominate_timeout(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 2);

    // Common tail: verify nominate envelope and test additional nom2
    let votes_xy = vec![x_value.clone(), y_value.clone()];
    verify_nominate(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        votes_xy.clone(),
        vec![],
    );

    let nom2 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![y_value.clone(), z_value.clone(), zz_value.clone()],
        vec![y_value.clone()],
    );
    scp.receive_envelope(nom2);
    // Nothing happens, as v0 already voted for the accepted value (y)
    assert_eq!(scp.envs_len(), 2);
    verify_nominate(&scp.get_env(1), &v0_id(), qs_hash0, 0, votes_xy, vec![]);
}

// ---------------------------------------------------------------------------
// "select accepted value from leader / receive accepted after timeout"
// C++ SCPTests.cpp lines 3030-3055
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_select_accepted_after_timeout() {
    let (x_value, y_value, z_value, zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // v0 nominates x
    assert!(scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);

    // Update round leader to v1
    scp.set_priority_node(v1_id());

    let nom1 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![y_value.clone(), z_value.clone()],
        vec![y_value.clone()],
    );

    // receive accepted after timeout
    assert!(!scp.nominate_timeout(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);

    // Vote for accepted value (y)
    scp.receive_envelope(nom1);
    assert_eq!(scp.envs_len(), 2);

    // Common tail: verify nominate envelope and test additional nom2
    let votes_xy = vec![x_value.clone(), y_value.clone()];
    verify_nominate(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        votes_xy.clone(),
        vec![],
    );

    let nom2 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![y_value.clone(), z_value.clone(), zz_value.clone()],
        vec![y_value.clone()],
    );
    scp.receive_envelope(nom2);
    // Nothing happens, as v0 already voted for the accepted value (y)
    assert_eq!(scp.envs_len(), 2);
    verify_nominate(&scp.get_env(1), &v0_id(), qs_hash0, 0, votes_xy, vec![]);
}

// ---------------------------------------------------------------------------
// "self nominates 'x', others nominate y → prepare y / others only vote for y"
// C++ SCPTests.cpp lines 3078-3101
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_others_vote_y() {
    let (x_value, y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    let mut my_votes = vec![x_value.clone()];

    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    scp.driver().set_expected_candidates(expected);
    scp.driver().set_composite_value(x_value.clone());

    assert!(scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);
    verify_nominate(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        my_votes.clone(),
        vec![],
    );

    let votes = vec![y_value.clone()];

    // Others only vote for y (no accepted)
    let nom1 = make_nominate(&v1_id(), qs_hash, 0, votes.clone(), vec![]);
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, votes.clone(), vec![]);
    let nom3 = make_nominate(&v3_id(), qs_hash, 0, votes.clone(), vec![]);
    let nom4 = make_nominate(&v4_id(), qs_hash, 0, votes.clone(), vec![]);

    // nothing happens yet
    scp.receive_envelope(nom1);
    scp.receive_envelope(nom2);
    scp.receive_envelope(nom3);
    assert_eq!(scp.envs_len(), 1);

    // 'y' is accepted (quorum)
    scp.receive_envelope(nom4);
    assert_eq!(scp.envs_len(), 2);
    my_votes.push(y_value.clone());
    verify_nominate(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        my_votes,
        vec![y_value.clone()],
    );
}

// ---------------------------------------------------------------------------
// "self nominates 'x', others nominate y → prepare y / others accepted y"
// C++ SCPTests.cpp lines 3102-3136
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_others_accepted_y() {
    let (x_value, y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    let mut my_votes = vec![x_value.clone()];

    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    scp.driver().set_expected_candidates(expected);
    scp.driver().set_composite_value(x_value.clone());

    assert!(scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);
    verify_nominate(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        my_votes.clone(),
        vec![],
    );

    let votes = vec![y_value.clone()];
    let accepted_y = vec![y_value.clone()];

    // Others accepted y
    let acc1 = make_nominate(&v1_id(), qs_hash, 0, votes.clone(), accepted_y.clone());
    let acc2 = make_nominate(&v2_id(), qs_hash, 0, votes.clone(), accepted_y.clone());
    let acc3 = make_nominate(&v3_id(), qs_hash, 0, votes.clone(), accepted_y.clone());
    let acc4 = make_nominate(&v4_id(), qs_hash, 0, votes.clone(), accepted_y.clone());

    scp.receive_envelope(acc1);
    assert_eq!(scp.envs_len(), 1);

    // this causes 'y' to be accepted (v-blocking)
    scp.receive_envelope(acc2);
    assert_eq!(scp.envs_len(), 2);

    my_votes.push(y_value.clone());
    verify_nominate(&scp.get_env(1), &v0_id(), qs_hash0, 0, my_votes, accepted_y);

    let mut expected2 = BTreeSet::new();
    expected2.insert(y_value.clone());
    scp.driver().set_expected_candidates(expected2);
    scp.driver().set_composite_value(y_value.clone());

    // this causes the node to send a prepare message (quorum)
    scp.receive_envelope(acc3);
    assert_eq!(scp.envs_len(), 3);

    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &ScpBallot {
            counter: 1,
            value: y_value.clone(),
        },
        None,
        0,
        0,
        None,
    );

    scp.receive_envelope(acc4);
    assert_eq!(scp.envs_len(), 3);
}

// ---------------------------------------------------------------------------
// "value from v1 is a candidate, self should not introduce new value on timeout"
// C++ SCPTests.cpp lines 3191-3244
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_v1_candidate_no_new_value_on_timeout() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let k_value = Value(vec![0xFFu8; 32].try_into().unwrap());
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;

    // v1 is top node
    let scp = TestSCP::new_with_priority(v0_id(), qs.clone(), v1_id());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // v0 is not leader (v1 is), so nominate returns false
    assert!(!scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 0);

    // Receive x from v1, vote for it
    let nom1 = make_nominate(&v1_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom3 = make_nominate(&v3_id(), qs_hash, 0, vec![x_value.clone()], vec![]);

    scp.receive_envelope(nom1);
    assert_eq!(scp.envs_len(), 1);
    verify_nominate(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        vec![x_value.clone()],
        vec![],
    );

    scp.receive_envelope(nom2);
    scp.receive_envelope(nom3);
    assert_eq!(scp.envs_len(), 2);
    verify_nominate(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );

    let acc1 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc2 = make_nominate(
        &v2_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc3 = make_nominate(
        &v3_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );

    scp.receive_envelope(acc1);
    scp.receive_envelope(acc2);
    assert_eq!(scp.envs_len(), 2);

    // Receive accept from quorum, ratify and generate a candidate value
    assert!(scp.has_nomination_timer());
    scp.driver().set_composite_value(x_value.clone());
    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    scp.driver().set_expected_candidates(expected);
    scp.receive_envelope(acc3);
    assert_eq!(scp.envs_len(), 3);
    // Timer is cancelled
    assert!(!scp.has_nomination_timer());

    // v0 is the new leader, but we already have a candidate
    scp.set_priority_node(v0_id());
    assert!(!scp.nominate_timeout(0, k_value, &empty_value));
}

// ---------------------------------------------------------------------------
// "nomination waits for v1"
// C++ SCPTests.cpp lines 3245-3290
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_nomination_waits_for_v1() {
    let (x_value, y_value, _z_value, _zz_value) = setup_values();
    let k_value = Value(vec![0xFFu8; 32].try_into().unwrap());
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;

    // v1 is top node
    let scp = TestSCP::new_with_priority(v0_id(), qs.clone(), v1_id());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    let votes_xy = vec![x_value.clone(), y_value.clone()];
    let mut votes_xk = vec![x_value.clone(), k_value.clone()];
    votes_xk.sort();

    let nom1 = make_nominate(&v1_id(), qs_hash, 0, votes_xy.clone(), vec![]);
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, votes_xk.clone(), vec![]);

    assert!(!scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 0);

    let nom4 = make_nominate(&v4_id(), qs_hash, 0, votes_xk.clone(), vec![]);

    // nothing happens with non top nodes
    scp.receive_envelope(nom2);
    // (note: don't receive anything from node3 - we want to pick
    // another dead node)
    assert_eq!(scp.envs_len(), 0);

    // v1 is leader -> nominate the first value from its message
    // that's "y" (the value with highest hash from v1's votes that
    // v0 hasn't already voted for)
    scp.receive_envelope(nom1);
    assert_eq!(scp.envs_len(), 1);
    verify_nominate(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        vec![y_value.clone()],
        vec![],
    );

    scp.receive_envelope(nom4);
    assert_eq!(scp.envs_len(), 1);

    // "timeout -> pick another value from v1"
    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    scp.driver().set_expected_candidates(expected);
    scp.driver().set_composite_value(x_value.clone());

    // allows to pick another leader,
    // pick another dead node v3 as to force picking up
    // a new value from v1
    scp.set_priority_node(v3_id());

    // note: value passed in here should be ignored
    assert!(scp.nominate_timeout(0, k_value, &empty_value));
    // picks up 'x' from v1 (as we already have 'y')
    // which also happens to cause 'x' to be accepted
    assert_eq!(scp.envs_len(), 2);
    verify_nominate(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        votes_xy.clone(),
        vec![x_value.clone()],
    );
}

// ---------------------------------------------------------------------------
// Nomination tests core5 > v1 is top > "v1 dead, timeout" > "v0 is new top node"
// C++ SCPTests.cpp line 3291-3314
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_v1_dead_timeout_v0_becomes_top() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    // k_value is independent (matches stellar-core kValue = sha256(d))
    let k_value = Value(vec![0xFFu8; 32].try_into().unwrap());
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;

    // Create SCP where v1 has highest priority (matching stellar-core line 3150)
    let scp = TestSCP::new_with_priority(v0_id(), qs.clone(), v1_id());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // votesXK = sorted [x, k]
    let mut votes_xk = vec![x_value.clone(), k_value.clone()];
    votes_xk.sort();

    // nom2 = NOMINATE from v2 with votes [x, k] (stellar-core line 3188)
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, votes_xk, vec![]);

    // stellar-core line 3293: v0 is not leader (v1 is), so nominate returns false
    assert!(!scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 0);

    // stellar-core line 3297: receive nom2 from v2 (not leader, so no new envelopes)
    scp.receive_envelope(nom2);
    assert_eq!(scp.envs_len(), 0);

    // stellar-core line 3304: change priority to v0
    scp.set_priority_node(v0_id());

    // stellar-core line 3308: timeout nomination — v0 is now top, should emit
    assert!(scp.nominate_timeout(0, x_value.clone(), &empty_value));

    // stellar-core line 3312: exactly 1 envelope emitted
    assert_eq!(scp.envs_len(), 1);

    // stellar-core line 3313: NOMINATE(votes=[x], accepted=[])
    verify_nominate(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        vec![x_value.clone()],
        vec![],
    );
}

// ---------------------------------------------------------------------------
// Nomination tests core5 > v1 is top > "v1 dead, timeout" > "v2 is new top node"
// C++ SCPTests.cpp line 3316-3333
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_v1_dead_timeout_v2_becomes_top() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let k_value = Value(vec![0xFFu8; 32].try_into().unwrap());
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;

    let scp = TestSCP::new_with_priority(v0_id(), qs.clone(), v1_id());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    let mut votes_xk = vec![x_value.clone(), k_value.clone()];
    votes_xk.sort();

    let nom2 = make_nominate(&v2_id(), qs_hash, 0, votes_xk, vec![]);

    // Same setup as v0 test
    assert!(!scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 0);
    scp.receive_envelope(nom2);
    assert_eq!(scp.envs_len(), 0);

    // stellar-core line 3318: change priority to v2
    scp.set_priority_node(v2_id());

    // stellar-core line 3322: timeout nomination — v2 is now top leader
    assert!(scp.nominate_timeout(0, x_value.clone(), &empty_value));

    // stellar-core line 3326: exactly 1 envelope emitted
    assert_eq!(scp.envs_len(), 1);

    // stellar-core line 3327-3332: v2 votes for XK, but nomination only picks the highest value
    // std::max(xValue, kValue) — pick the larger of x and k
    let v2_top = std::cmp::max(x_value.clone(), k_value.clone());
    verify_nominate(&scp.get_env(0), &v0_id(), qs_hash0, 0, vec![v2_top], vec![]);
}

// ---------------------------------------------------------------------------
// Nomination tests core5 > v1 is top > "v1 dead, timeout" > "v3 is new top node"
// C++ SCPTests.cpp line 3334-3345
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_v1_dead_timeout_v3_becomes_top() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let k_value = Value(vec![0xFFu8; 32].try_into().unwrap());
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new_with_priority(v0_id(), qs.clone(), v1_id());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    let mut votes_xk = vec![x_value.clone(), k_value.clone()];
    votes_xk.sort();

    let nom2 = make_nominate(&v2_id(), qs_hash, 0, votes_xk, vec![]);

    // Same setup
    assert!(!scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 0);
    scp.receive_envelope(nom2);
    assert_eq!(scp.envs_len(), 0);

    // stellar-core line 3336: change priority to v3
    scp.set_priority_node(v3_id());

    // stellar-core line 3340: nothing happens — we don't have any message for v3
    assert!(!scp.nominate_timeout(0, x_value.clone(), &empty_value));

    // stellar-core line 3344: no envelopes emitted
    assert_eq!(scp.envs_len(), 0);
}

// ===========================================================================
// Helper: set up through "Accept commit > Quorum A2" (6 envelopes)
// ===========================================================================

/// Drive SCP through Confirm prepared A2 → Accept commit (Quorum A2).
/// Returns scp at env[5] = CONFIRM(nP=2, b=A2, nC=2, nH=2).
#[allow(clippy::type_complexity)]
fn setup_accept_commit_quorum_a2() -> (TestSCP, Value, Value, Value, Value, Hash256) {
    let (scp, x_value, y_value, z_value, zz_value, qs_hash) = setup_confirm_prepared_a2();
    let a_value = x_value.clone();
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash, 0, 2, &a2, 2, 2);
    assert!(!scp.has_ballot_timer_upcoming());

    (scp, x_value, y_value, z_value, zz_value, qs_hash)
}

// ===========================================================================
// Ballot core5 > Accept commit > Quorum A2 > deep branches
// ===========================================================================

// ---------------------------------------------------------------------------
// v-blocking prepared A3 (stellar-core line 1054)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_vblocking_prepared_a3() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a3.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 3, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// v-blocking prepared A3+B3 (stellar-core line 1063)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_vblocking_prepared_a3_b3() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let b_value = z_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(b3), 2, 2, Some(a3)),
    );
    assert_eq!(scp.envs_len(), 7);
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 3, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// v-blocking confirm A3 (stellar-core line 1072)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_vblocking_confirm_a3() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, a3.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 3, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// Hang - does not switch to B in CONFIRM > Network EXTERNALIZE (stellar-core line 1084)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_hang_no_switch_externalize() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let b_value = z_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    // v-blocking EXTERNALIZE with B2 → bumps to AInf but stays on A
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, b2.clone(), 3));
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 2, &a_inf, 2, 2);
    assert!(!scp.has_ballot_timer());

    // stuck: quorum EXTERNALIZE with B2 doesn't externalize
    recv_quorum_checks_ex(
        &scp,
        &make_externalize_gen(qs_hash, b2, 3),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 7);
    assert!(scp.externalized_value(0).is_none());
    // timer scheduled as there is a quorum with (2, *)
    assert!(scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// Hang > Network CONFIRMS other ballot > at same counter (stellar-core line 1110)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_hang_confirm_same_counter() {
    let (scp, _x_value, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let b_value = z_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // nothing should happen, node should not switch p
    recv_quorum_checks_ex(
        &scp,
        &make_confirm_gen(qs_hash, 3, b2, 2, 3),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 6);
    assert!(scp.externalized_value(0).is_none());
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// Hang > Network CONFIRMS other ballot > at a different counter (stellar-core line 1125)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_hang_confirm_different_counter() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let b_value = z_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    // v-blocking CONFIRM B3 → bumps to A3 but keeps nC=2 nH=2
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, b3.clone(), 3, 3));
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 2, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());

    // quorum CONFIRM B3 → stuck, no externalization
    recv_quorum_checks_ex(
        &scp,
        &make_confirm_gen(qs_hash, 3, b3, 3, 3),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 7);
    assert!(scp.externalized_value(0).is_none());
    // timer scheduled as there is a quorum with (3, *)
    assert!(scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// v-blocking after Quorum prepared A3 > Confirm A3 (stellar-core line 1004)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_vblocking_accept_more_a3_confirm() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    // Quorum prepared A3 (same as full ext path, lines 957-969)
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 2, &a3, 2, 2);

    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
        true,
    );
    assert_eq!(scp.envs_len(), 8);
    verify_confirm(&scp.get_env(7), &v0_id(), qs_hash0, 0, 3, &a3, 2, 2);

    // v-blocking CONFIRM A3 with nC=2 nH=3 → updates nH
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, a3.clone(), 2, 3));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(&scp.get_env(8), &v0_id(), qs_hash0, 0, 3, &a3, 2, 3);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// v-blocking after Quorum prepared A3 > Externalize A3 (stellar-core line 1015)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_vblocking_accept_more_a3_externalize() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    // Quorum prepared A3
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
    );
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
        true,
    );
    assert_eq!(scp.envs_len(), 8);

    // v-blocking EXTERNALIZE A2 with nH=3 → bumps to infinite
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a2, 3));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(
        &scp.get_env(8),
        &v0_id(),
        qs_hash0,
        0,
        u32::MAX,
        &a_inf,
        2,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// v-blocking accept more A3 > other nodes moved to c=A4 h=A5 > Confirm A4..5 (stellar-core line 1029)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_vblocking_accept_more_a3_confirm_a4_a5() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let a5 = ScpBallot {
        counter: 5,
        value: a_value.clone(),
    };

    // Quorum prepared A3
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
    );
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
        true,
    );
    assert_eq!(scp.envs_len(), 8);

    // v-blocking CONFIRM A5 nC=4 nH=5
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, a5.clone(), 4, 5));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(&scp.get_env(8), &v0_id(), qs_hash0, 0, 3, &a5, 4, 5);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// v-blocking accept more A3 > other nodes moved to c=A4 h=A5 > Externalize A4..5 (stellar-core line 1039)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_vblocking_accept_more_a3_externalize_a4_a5() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    // Quorum prepared A3
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
    );
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
        true,
    );
    assert_eq!(scp.envs_len(), 8);

    // v-blocking EXTERNALIZE A4 nH=5
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a4, 5));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(
        &scp.get_env(8),
        &v0_id(),
        qs_hash0,
        0,
        u32::MAX,
        &a_inf,
        4,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// Accept commit > v-blocking > CONFIRM A3..4 (stellar-core line 1164)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_accept_commit_vblocking_confirm_a3_a4() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 4, a4.clone(), 3, 4));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash0, 0, 4, &a4, 3, 4);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// Accept commit > v-blocking > CONFIRM B2 (stellar-core line 1174)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_accept_commit_vblocking_confirm_b2() {
    let (scp, _x_value, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;
    let b_value = z_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 2, b2.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash0, 0, 2, &b2, 2, 2);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// Accept commit > v-blocking > EXTERNALIZE B2 (stellar-core line 1197)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_accept_commit_vblocking_externalize_b2() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;
    let b_value = z_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let b_inf = ScpBallot {
        counter: u32::MAX,
        value: b_value.clone(),
    };

    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, b2, 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        u32::MAX,
        &b_inf,
        2,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// get conflicting prepared B > same counter (stellar-core line 1212)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_conflicting_prepared_b_same_counter() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let b_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // v-blocking PREPARE B2 prepared=B2 → sets p=B2, p'=A2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&b2),
        0,
        2,
        Some(&a2),
    );
    assert!(!scp.has_ballot_timer_upcoming());

    // quorum PREPARE B2 nC=2 nH=2 → CONFIRM B2
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 2, &b2, 2, 2);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// get conflicting prepared B > higher counter (stellar-core line 1228)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_conflicting_prepared_b_higher_counter() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let b_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    // v-blocking PREPARE B3 prepared=B2 nC=2 nH=2 → bumps to A3, p=B2, p'=A2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b3.clone(), Some(b2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &a3,
        Some(&b2),
        0,
        2,
        Some(&a2),
    );
    assert!(!scp.has_ballot_timer());

    // delayed quorum PREPARE B3 → CONFIRM
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b3.clone(), Some(b2.clone()), 2, 2, None),
        true,
        true,
        true,
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 3, &b3, 2, 2);
}

// ---------------------------------------------------------------------------
// get conflicting prepared B > higher counter mixed (stellar-core line 1244)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_conflicting_prepared_b_higher_counter_mixed() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let b_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    // v-blocking PREPARE A3 prepared=B3 nC=0 nH=2 p'=A2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(
            qs_hash,
            a3.clone(),
            Some(b3.clone()),
            0,
            2,
            Some(a2.clone()),
        ),
    );
    assert_eq!(scp.envs_len(), 6);
    // p=B3, p'=A2, counter=3, b=A3 (same value as h), c=0
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &a3,
        Some(&b3),
        0,
        2,
        Some(&a2),
    );

    // quorum PREPARE same → p=B3, p'=A3, computed_h=B3, b=B3, h=B3, c=3
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(b3.clone()), 0, 2, Some(a2)),
        true,
    );
    assert_eq!(scp.envs_len(), 7);
    verify_prepare(
        &scp.get_env(6),
        &v0_id(),
        qs_hash0,
        0,
        &b3,
        Some(&b3),
        3,
        3,
        Some(&a3),
    );
}

// ---------------------------------------------------------------------------
// Confirm prepared mixed > mixed A2 (stellar-core line 1280)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_confirm_prepared_mixed_a2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();

    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // Start → prepared A1 → bump → prepared A2
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    scp.bump_timer_offset();
    scp.scp.force_bump_state(0, a_value.clone());
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), None, 0, 0, None),
        true,
    );

    // v-blocking prepared B2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(
            qs_hash,
            b2.clone(),
            Some(b2.clone()),
            0,
            0,
            Some(a2.clone()),
        ),
    );
    assert_eq!(scp.envs_len(), 5);
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&b2),
        0,
        0,
        Some(&a2),
    );

    // mixed B2: causes h=B2, c=B2
    scp.bump_timer_offset();
    scp.receive_envelope(make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &b2,
        Some(&b2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 6);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &b2,
        Some(&b2),
        2,
        2,
        Some(&a2),
    );
    assert!(!scp.has_ballot_timer_upcoming());

    scp.bump_timer_offset();
    scp.receive_envelope(make_prepare(
        &v4_id(),
        qs_hash,
        0,
        &b2,
        Some(&b2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 6);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// switch prepared B1 from A1 > v-blocking switches to previous value of p (stellar-core line 1344)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_switch_prepared_no_downgrade_p() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    // Start → prepared A1
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);

    // switch to B1 prepared
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        Some(&a1),
    );

    // bump counter to 2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), None, 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 4);
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&b1),
        0,
        0,
        Some(&a1),
    );

    // update p to B2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 5);
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&b2),
        0,
        0,
        Some(&a1),
    );

    // bump counter to 3
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b3.clone(), None, 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 6);
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &a3,
        Some(&b2),
        0,
        0,
        Some(&a1),
    );
    assert!(!scp.has_ballot_timer());

    // v-blocking says B1 is prepared — but we already have p=B2, should not downgrade
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, b3.clone(), Some(b1), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 6);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// switch prepared B1 from A1 > switch p' to Mid2 (stellar-core line 1361)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_switch_prepared_pprime_to_mid2() {
    let (x_value, y_value, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let mid_value = y_value; // midValue = yValue
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let mid2 = ScpBallot {
        counter: 2,
        value: mid_value.clone(),
    };

    // Start → prepared A1 → switch to B1 → bump to 2 → update p to B2
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
    );
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), None, 0, 0, None),
    );
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 5);

    // (p,p') = (B2, Mid2)
    recv_v_blocking(
        &scp,
        &make_prepare_gen(
            qs_hash,
            b2.clone(),
            Some(b2.clone()),
            0,
            0,
            Some(mid2.clone()),
        ),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&b2),
        0,
        0,
        Some(&mid2),
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// switch prepared B1 from A1 > switch again Big2 (stellar-core line 1371)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_switch_prepared_big2() {
    let (x_value, _y, z_value, zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let big_value = zz_value; // bigValue = zzValue
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let big2 = ScpBallot {
        counter: 2,
        value: big_value.clone(),
    };

    // Start → prepared A1 → switch to B1 → bump to 2 → update p to B2
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
    );
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), None, 0, 0, None),
    );
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 5);

    // both p and p' get updated: (p,p') = (Big2, B2)
    recv_v_blocking(
        &scp,
        &make_prepare_gen(
            qs_hash,
            b2.clone(),
            Some(big2.clone()),
            0,
            0,
            Some(b2.clone()),
        ),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&big2),
        0,
        0,
        Some(&b2),
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// switch prepare B1 (quorum, delayed) (stellar-core line 1383)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_switch_prepare_b1_quorum() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    // Start → prepared A1
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);

    // Quorum PREPARE B1 (delayed quorum — local voted A1 not B1)
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), None, 0, 0, None),
        true,
        true,
        false,
    );
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        Some(&a1),
    );
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// prepare higher counter (v-blocking) (stellar-core line 1391)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_prepare_higher_counter_vblocking() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    // Start → prepared A1
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);

    // v-blocking PREPARE B2 → bumps counter to 2
    recv_v_blocking(&scp, &make_prepare_gen(qs_hash, b2, None, 0, 0, None));
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&a1),
        0,
        0,
        None,
    );
    assert!(!scp.has_ballot_timer());

    // v-blocking PREPARE B3 → bumps counter to 3
    recv_v_blocking(&scp, &make_prepare_gen(qs_hash, b3, None, 0, 0, None));
    assert_eq!(scp.envs_len(), 4);
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        &a3,
        Some(&a1),
        0,
        0,
        None,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// prepared B (v-blocking) — no prior prepared (stellar-core line 1407)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_prepared_b_vblocking_from_start() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // v-blocking PREPARE B1 prepared=B1 → sets p=B1
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        None,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// prepare B (quorum) — no prior prepared (stellar-core line 1414)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_prepare_b_quorum_from_start() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // quorum PREPARE B1 (delayed — local voted A1)
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), None, 0, 0, None),
        true,
        true,
        true,
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        None,
    );
}

// ---------------------------------------------------------------------------
// confirm (v-blocking) > via CONFIRM (stellar-core line 1423)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_confirm_vblocking_via_confirm_higher() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // v-blocking via two CONFIRM messages with different counters
    scp.bump_timer_offset();
    scp.receive_envelope(make_confirm(&v1_id(), qs_hash, 0, 3, &a3, 3, 3));
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };
    scp.receive_envelope(make_confirm(&v2_id(), qs_hash, 0, 4, &a4, 2, 4));
    assert_eq!(scp.envs_len(), 2);
    verify_confirm(&scp.get_env(1), &v0_id(), qs_hash0, 0, 3, &a3, 3, 3);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// confirm (v-blocking) > via EXTERNALIZE (stellar-core line 1435)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_confirm_vblocking_via_externalize_higher() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // v-blocking via two EXTERNALIZE messages
    scp.receive_envelope(make_externalize(&v1_id(), qs_hash, 0, &a2, 4));
    scp.receive_envelope(make_externalize(&v2_id(), qs_hash, 0, &a3, 5));
    assert_eq!(scp.envs_len(), 2);
    verify_confirm(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        u32::MAX,
        &a_inf,
        3,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ===========================================================================
// "start <1,z>" branch — stellar-core lines 1452-1975
//
// This is the mirror of "start <1,x>" with inverted value ordering:
//   aValue = zValue (larger), bValue = xValue (smaller)
// So B < A at the same counter, which changes conflicting prepared behavior.
// ===========================================================================

// ---------------------------------------------------------------------------
// Setup helpers for <1,z> branch
// ---------------------------------------------------------------------------

/// Setup for "start <1,z>" → prepared A1 → bump prepared A2.
///
/// Returns scp at env[3] = PREPARE(A2, p=A2)
/// where aValue = zValue, bValue = xValue.
fn setup_bump_prepared_a2_z() -> (TestSCP, Value, Value, Value, Value, Hash256) {
    let (x_value, y_value, z_value, zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    // In <1,z>: aValue = zValue, bValue = xValue
    let a_value = z_value.clone();
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    // Start → env[0] = PREPARE(A1)
    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);
    assert!(!scp.has_ballot_timer());

    // prepared A1: quorum PREPARE(A1) → env[1] = PREPARE(A1, p=A1)
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash,
        0,
        &a1,
        Some(&a1),
        0,
        0,
        None,
    );

    // bump to (2,a) → env[2] = PREPARE(A2, p=A1)
    scp.bump_timer_offset();
    scp.scp.force_bump_state(0, a_value.clone());
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a1),
        0,
        0,
        None,
    );
    assert!(!scp.has_ballot_timer());

    // quorum PREPARE(A2) → env[3] = PREPARE(A2, p=A2)
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 4);
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        0,
        0,
        None,
    );

    (scp, x_value, y_value, z_value, zz_value, qs_hash)
}

/// Setup for "start <1,z>" → prepared A1 → bump prepared A2 → Confirm prepared A2.
///
/// Returns scp at env[4] = PREPARE(A2, p=A2, nC=2, nH=2)
/// where aValue = zValue, bValue = xValue.
fn setup_confirm_prepared_a2_z() -> (TestSCP, Value, Value, Value, Value, Hash256) {
    let (scp, x_value, y_value, z_value, zz_value, qs_hash) = setup_bump_prepared_a2_z();
    let a_value = z_value.clone();
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    // Confirm prepared A2: receive quorum PREPARE with prepared=A2
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 5);
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        2,
        2,
        None,
    );
    assert!(!scp.has_ballot_timer_upcoming());

    (scp, x_value, y_value, z_value, zz_value, qs_hash)
}

/// Setup for "start <1,z>" → Accept commit > Quorum A2.
///
/// Returns scp at env[5] = CONFIRM(nP=2, b=A2, nC=2, nH=2)
/// where aValue = zValue, bValue = xValue.
fn setup_accept_commit_quorum_a2_z() -> (TestSCP, Value, Value, Value, Value, Hash256) {
    let (scp, x_value, y_value, z_value, zz_value, qs_hash) = setup_confirm_prepared_a2_z();
    let a_value = z_value.clone();
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash, 0, 2, &a2, 2, 2);
    assert!(!scp.has_ballot_timer_upcoming());

    (scp, x_value, y_value, z_value, zz_value, qs_hash)
}

// ---------------------------------------------------------------------------
// start <1,z> > prepared A1 > bump prepared A2 > Confirm prepared A2 (stellar-core line 1513)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_confirm_prepared_a2() {
    let (_scp, _x, _y, _z, _zz, _qs_hash) = setup_confirm_prepared_a2_z();
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept commit > Quorum A2 (stellar-core line 1523)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_accept_commit_quorum_a2() {
    let (_scp, _x, _y, _z, _zz, _qs_hash) = setup_accept_commit_quorum_a2_z();
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept commit > Quorum A2 > Quorum prepared A3 (stellar-core line 1532)
// ---------------------------------------------------------------------------

/// Helper: drives from accept_commit_quorum_a2_z through "Quorum prepared A3"
/// arriving at env[7] = CONFIRM(nP=3, b=A3, nC=2, nH=2)
fn setup_quorum_prepared_a3_z() -> (TestSCP, Value, Value, Value, Value, Hash256) {
    let (scp, x_value, y_value, z_value, zz_value, qs_hash) = setup_accept_commit_quorum_a2_z();
    let a_value = z_value.clone();
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    // v-blocking PREPARE(A3, p=A2, nC=2, nH=2)
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash, 0, 2, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());

    // quorum PREPARE(A3, p=A2, nC=2, nH=2)
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
        true,
    );
    assert_eq!(scp.envs_len(), 8);
    verify_confirm(&scp.get_env(7), &v0_id(), qs_hash, 0, 3, &a3, 2, 2);

    (scp, x_value, y_value, z_value, zz_value, qs_hash)
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept more commit A3 > Quorum externalize A3 (stellar-core line 1562)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_quorum_externalize_a3() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_quorum_prepared_a3_z();
    let a_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    // Accept more commit A3
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a3.clone()), 2, 3, None),
    );
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(&scp.get_env(8), &v0_id(), qs_hash, 0, 3, &a3, 2, 3);
    assert!(!scp.has_ballot_timer_upcoming());
    assert_eq!(scp.externalized_value_count(), 0);

    // Quorum externalize A3
    recv_quorum(&scp, &make_confirm_gen(qs_hash, 3, a3.clone(), 2, 3));
    assert_eq!(scp.envs_len(), 10);
    verify_externalize(&scp.get_env(9), &v0_id(), qs_hash, 0, &a2, 3);
    assert!(!scp.has_ballot_timer());
    assert_eq!(scp.externalized_value_count(), 1);
    assert_eq!(scp.externalized_value(0), Some(a_value));
}

// ---------------------------------------------------------------------------
// start <1,z> > v-blocking accept more A3 > Confirm A3 (stellar-core line 1581)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_vblocking_accept_more_a3_confirm() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_quorum_prepared_a3_z();
    let a_value = z_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, a3.clone(), 2, 3));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(&scp.get_env(8), &v0_id(), qs_hash, 0, 3, &a3, 2, 3);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > v-blocking accept more A3 > Externalize A3 (stellar-core line 1592)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_vblocking_accept_more_a3_externalize() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_quorum_prepared_a3_z();
    let a_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a2.clone(), 3));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(
        &scp.get_env(8),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &a_inf,
        2,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > v-blocking accept more A3 > other nodes c=A4 h=A5 > Confirm (stellar-core line 1606)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_vblocking_accept_more_a3_confirm_a4_a5() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_quorum_prepared_a3_z();
    let a_value = z_value;
    let a5 = ScpBallot {
        counter: 5,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, a5.clone(), 4, 5));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(&scp.get_env(8), &v0_id(), qs_hash, 0, 3, &a5, 4, 5);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > v-blocking accept more A3 > other nodes c=A4 h=A5 > Externalize (stellar-core line 1616)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_vblocking_accept_more_a3_externalize_a4_a5() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_quorum_prepared_a3_z();
    let a_value = z_value;
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a4.clone(), 5));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(
        &scp.get_env(8),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &a_inf,
        4,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > v-blocking prepared A3 (stellar-core line 1631)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_vblocking_prepared_a3() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2_z();
    let a_value = z_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a3.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash, 0, 3, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > v-blocking prepared A3+B3 (stellar-core line 1640)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_vblocking_prepared_a3_b3() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2_z();
    let a_value = z_value;
    let b_value = x_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a3.clone()), 2, 2, Some(b3)),
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash, 0, 3, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > v-blocking confirm A3 (stellar-core line 1649)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_vblocking_confirm_a3() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2_z();
    let a_value = z_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, a3.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash, 0, 3, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > Hang - does not switch to B in CONFIRM > Network EXTERNALIZE (stellar-core line 1661)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_hang_no_switch_externalize() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2_z();
    let a_value = z_value;
    let b_value = x_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    // externalize messages have a counter at infinite
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, b2.clone(), 3));
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash, 0, 2, &a_inf, 2, 2);
    assert!(!scp.has_ballot_timer());

    // stuck
    recv_quorum_checks_ex(
        &scp,
        &make_externalize_gen(qs_hash, b2.clone(), 3),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 7);
    assert_eq!(scp.externalized_value_count(), 0);
    // timer scheduled as there is a quorum with (inf, *)
    assert!(scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > Hang > Network CONFIRMS other ballot > at same counter (stellar-core line 1687)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_hang_confirm_same_counter() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_accept_commit_quorum_a2_z();
    let b_value = x_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // nothing should happen here, node should not attempt to switch 'p'
    recv_quorum_checks_ex(
        &scp,
        &make_confirm_gen(qs_hash, 3, b2.clone(), 2, 3),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 6);
    assert_eq!(scp.externalized_value_count(), 0);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > Hang > Network CONFIRMS other ballot > at a different counter (stellar-core line 1702)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_hang_confirm_different_counter() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2_z();
    let a_value = z_value;
    let b_value = x_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, b3.clone(), 3, 3));
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash, 0, 2, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());

    recv_quorum_checks_ex(
        &scp,
        &make_confirm_gen(qs_hash, 3, b3.clone(), 3, 3),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 7);
    assert_eq!(scp.externalized_value_count(), 0);
    // timer scheduled as there is a quorum with (3, *)
    assert!(scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept commit > v-blocking > CONFIRM A2 (stellar-core line 1731)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_accept_commit_vblocking_confirm_a2() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let a_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 2, a2.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash, 0, 2, &a2, 2, 2);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept commit > v-blocking > CONFIRM A3..4 (stellar-core line 1741)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_accept_commit_vblocking_confirm_a3_a4() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let a_value = z_value;
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 4, a4.clone(), 3, 4));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash, 0, 4, &a4, 3, 4);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept commit > v-blocking > CONFIRM B2 (stellar-core line 1751)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_accept_commit_vblocking_confirm_b2() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let b_value = x_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 2, b2.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash, 0, 2, &b2, 2, 2);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept commit > v-blocking > EXTERNALIZE A2 (stellar-core line 1764)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_accept_commit_vblocking_externalize_a2() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let a_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a2.clone(), 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(
        &scp.get_env(5),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &a_inf,
        2,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept commit > v-blocking > EXTERNALIZE B2 (stellar-core line 1774)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_accept_commit_vblocking_externalize_b2() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let b_value = x_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let b_inf = ScpBallot {
        counter: u32::MAX,
        value: b_value.clone(),
    };

    // can switch to B2 with externalize (higher counter)
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, b2.clone(), 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(
        &scp.get_env(5),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &b_inf,
        2,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > Conflicting prepared B > same counter (stellar-core line 1791)
// messages are ignored as B2 < A2
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_conflicting_prepared_b_same_counter() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let b_value = x_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // messages are ignored as B2 < A2
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 0, 0, None),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 5);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > Conflicting prepared B > higher counter (stellar-core line 1800)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_conflicting_prepared_b_higher_counter() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let a_value = z_value;
    let b_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b3.clone(), Some(b2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 6);
    // A2 > B2 -> p = A2, p'=B2
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash,
        0,
        &a3,
        Some(&a2),
        2,
        2,
        Some(&b2),
    );
    assert!(!scp.has_ballot_timer());

    // node is trying to commit A2 but rest of quorum is trying to commit B2
    // we end up with a delayed quorum
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b3.clone(), Some(b2.clone()), 2, 2, None),
        true,
        true,
        true,
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash, 0, 3, &b3, 2, 2);
}

// ---------------------------------------------------------------------------
// start <1,z> > Conflicting prepared B > higher counter mixed (stellar-core line 1820)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_conflicting_prepared_b_higher_counter_mixed() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let a_value = z_value;
    let b_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };
    let b4 = ScpBallot {
        counter: 4,
        value: b_value.clone(),
    };

    recv_v_blocking(
        &scp,
        &make_prepare_gen(
            qs_hash,
            a3.clone(),
            Some(b3.clone()),
            0,
            2,
            Some(a2.clone()),
        ),
    );
    assert_eq!(scp.envs_len(), 6);
    // h still A2
    // v-blocking: prepared B3 -> p=B3, p'=A2 (1), counter 3, b=A3 (same value as h), c=0
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash,
        0,
        &a3,
        Some(&b3),
        0,
        2,
        Some(&a2),
    );

    recv_quorum_ex(
        &scp,
        &make_prepare_gen(
            qs_hash,
            a3.clone(),
            Some(b3.clone()),
            0,
            2,
            Some(a2.clone()),
        ),
        true,
    );
    // p=A3, p'=B3 (1)
    // computed_h = B3 (2) z = B - cannot update b
    assert_eq!(scp.envs_len(), 7);
    verify_prepare(
        &scp.get_env(6),
        &v0_id(),
        qs_hash,
        0,
        &a3,
        Some(&a3),
        0,
        2,
        Some(&b3),
    );
    // timeout, bump to B4
    assert!(scp.has_ballot_timer_upcoming());
    scp.fire_ballot_timer();
    // computed_h = B3, h = B3 (2), c = 0
    assert_eq!(scp.envs_len(), 8);
    verify_prepare(
        &scp.get_env(7),
        &v0_id(),
        qs_hash,
        0,
        &b4,
        Some(&a3),
        0,
        3,
        Some(&b3),
    );
}

// ---------------------------------------------------------------------------
// start <1,z> > Confirm prepared mixed > mixed A2 (stellar-core line 1864)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_confirm_prepared_mixed_a2() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_bump_prepared_a2_z();
    let a_value = z_value;
    let b_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // a few nodes prepared B2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(
            qs_hash,
            a2.clone(),
            Some(a2.clone()),
            0,
            0,
            Some(b2.clone()),
        ),
    );
    assert_eq!(scp.envs_len(), 5);
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        0,
        0,
        Some(&b2),
    );
    assert!(!scp.has_ballot_timer_upcoming());

    // causes h=A2, c=A2
    scp.bump_timer_offset();
    scp.receive_envelope(make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 6);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        2,
        2,
        Some(&b2),
    );
    assert!(!scp.has_ballot_timer_upcoming());

    scp.bump_timer_offset();
    scp.receive_envelope(make_prepare(
        &v4_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 6);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > Confirm prepared mixed > mixed B2 (stellar-core line 1883)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_confirm_prepared_mixed_b2() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_bump_prepared_a2_z();
    let a_value = z_value;
    let b_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // a few nodes prepared B2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(
            qs_hash,
            a2.clone(),
            Some(a2.clone()),
            0,
            0,
            Some(b2.clone()),
        ),
    );
    assert_eq!(scp.envs_len(), 5);
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        0,
        0,
        Some(&b2),
    );
    assert!(!scp.has_ballot_timer_upcoming());

    // causes computed_h=B2 ~ not set as h ~!= b → noop
    scp.bump_timer_offset();
    scp.receive_envelope(make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &a2,
        Some(&b2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 5);
    assert!(!scp.has_ballot_timer_upcoming());

    scp.bump_timer_offset();
    scp.receive_envelope(make_prepare(
        &v4_id(),
        qs_hash,
        0,
        &b2,
        Some(&b2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 5);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > switch prepared B1 from A1 (stellar-core line 1903)
// can't switch to B1 because B1 < A1
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_switch_prepared_b1_from_a1() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = z_value;
    let b_value = x_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));

    // prepared A1
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash,
        0,
        &a1,
        Some(&a1),
        0,
        0,
        None,
    );

    // can't switch to B1
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 2);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > switch prepare B1 (stellar-core line 1911)
// doesn't switch as B1 < A1
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_switch_prepare_b1_quorum() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = z_value;
    let b_value = x_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));

    // prepared A1
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);

    // doesn't switch as B1 < A1
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), None, 0, 0, None),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 2);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > prepare higher counter (v-blocking) (stellar-core line 1919)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_prepare_higher_counter_vblocking() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = z_value;
    let b_value = x_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));

    // prepared A1
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);

    // v-blocking PREPARE(B2) → bump to A2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), None, 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a1),
        0,
        0,
        None,
    );
    assert!(!scp.has_ballot_timer());

    // more timeout from vBlocking set → bump to A3
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b3.clone(), None, 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 4);
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash,
        0,
        &a3,
        Some(&a1),
        0,
        0,
        None,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > prepared B (v-blocking) (stellar-core line 1935)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_prepared_b_vblocking_from_start() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = z_value;
    let b_value = x_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        None,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > prepare B (quorum) (stellar-core line 1942)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_prepare_b_quorum_from_start() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = z_value;
    let b_value = x_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), None, 0, 0, None),
        true,
        true,
        true,
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        None,
    );
}

// ---------------------------------------------------------------------------
// start <1,z> > confirm (v-blocking) > via CONFIRM (stellar-core line 1951)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_confirm_vblocking_via_confirm() {
    let (_x, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = z_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    scp.bump_timer_offset();
    scp.receive_envelope(make_confirm(&v1_id(), qs_hash, 0, 3, &a3, 3, 3));
    scp.receive_envelope(make_confirm(&v2_id(), qs_hash, 0, 4, &a4, 2, 4));
    assert_eq!(scp.envs_len(), 2);
    verify_confirm(&scp.get_env(1), &v0_id(), qs_hash, 0, 3, &a3, 3, 3);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > confirm (v-blocking) > via EXTERNALIZE (stellar-core line 1963)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_confirm_vblocking_via_externalize() {
    let (_x, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    scp.receive_envelope(make_externalize(&v1_id(), qs_hash, 0, &a2, 4));
    scp.receive_envelope(make_externalize(&v2_id(), qs_hash, 0, &a3, 5));
    assert_eq!(scp.envs_len(), 2);
    verify_confirm(
        &scp.get_env(1),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &a_inf,
        3,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ===========================================================================
// "start from pristine" tests (stellar-core lines 1979-2199)
// Same test suite as "start <1,x>" but only keeping transitions observable
// when starting from empty (no bumpState call).
// aValue = xValue (smaller), bValue = zValue (larger)
// ===========================================================================

/// Helper: receives quorum of PREPARE(A1) from pristine state (no bumpState).
/// No envelope expected since we're starting from empty.
fn setup_pristine_prepared_a1(scp: &TestSCP, qs_hash: Hash256, a1: &ScpBallot) {
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 0);
}

/// Helper: extends setup_pristine_prepared_a1, receives v-blocking PREPARE(A2, p=A2).
/// No envelope expected.
fn setup_pristine_confirm_prepared_a2(
    scp: &TestSCP,
    qs_hash: Hash256,
    a1: &ScpBallot,
    a2: &ScpBallot,
) {
    setup_pristine_prepared_a1(scp, qs_hash, a1);
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 0);
}

// -- "Confirm prepared A2" -> "Quorum A2"
#[test]
fn test_ballot_pristine_confirm_prepared_a2_quorum_a2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let _ = &b_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // extra v-blocking PREPARE(A2, p=A2) -> no-op
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 0);

    // quorum PREPARE(A2, p=A2) -> emit PREPARE(A2, p=A2, nC=1, nH=2)
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 1);
    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        1,
        2,
        None,
    );
}

// -- "Confirm prepared A2" -> "Quorum B2"
#[test]
fn test_ballot_pristine_confirm_prepared_a2_quorum_b2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value.clone();
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // v-blocking PREPARE(B2, p=B2) -> no-op
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 0);

    // quorum PREPARE(B2, p=B2) -> emit PREPARE(B2, p=B2, nC=2, nH=2, p'=A2)
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 1);
    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash,
        0,
        &b2,
        Some(&b2),
        2,
        2,
        Some(&a2),
    );
}

// -- "Accept commit" -> "Quorum A2"
#[test]
fn test_ballot_pristine_accept_commit_quorum_a2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let _ = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // quorum PREPARE(A2, p=A2, nC=2, nH=2) -> emit CONFIRM(2, A2, 2, 2)
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(&scp.get_env(0), &v0_id(), qs_hash, 0, 2, &a2, 2, 2);
}

// -- "Accept commit" -> "Quorum B2"
#[test]
fn test_ballot_pristine_accept_commit_quorum_b2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value.clone();
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // quorum PREPARE(B2, p=B2, nC=2, nH=2) -> emit CONFIRM(2, B2, 2, 2)
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(&scp.get_env(0), &v0_id(), qs_hash, 0, 2, &b2, 2, 2);
}

// -- "Accept commit" -> "v-blocking" -> "CONFIRM A2"
#[test]
fn test_ballot_pristine_accept_commit_vblocking_confirm_a2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let _ = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // v-blocking CONFIRM(2, A2, 2, 2) -> emit CONFIRM(2, A2, 2, 2)
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 2, a2.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(&scp.get_env(0), &v0_id(), qs_hash, 0, 2, &a2, 2, 2);
}

// -- "Accept commit" -> "v-blocking" -> "CONFIRM A3..4"
#[test]
fn test_ballot_pristine_accept_commit_vblocking_confirm_a3_a4() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let _ = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // v-blocking CONFIRM(4, A4, 3, 4) -> emit CONFIRM(4, A4, 3, 4)
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 4, a4.clone(), 3, 4));
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(&scp.get_env(0), &v0_id(), qs_hash, 0, 4, &a4, 3, 4);
}

// -- "Accept commit" -> "v-blocking" -> "CONFIRM B2"
#[test]
fn test_ballot_pristine_accept_commit_vblocking_confirm_b2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let _ = &x_value;
    let b_value = z_value.clone();
    let a1 = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // v-blocking CONFIRM(2, B2, 2, 2) -> emit CONFIRM(2, B2, 2, 2)
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 2, b2.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(&scp.get_env(0), &v0_id(), qs_hash, 0, 2, &b2, 2, 2);
}

// -- "Accept commit" -> "v-blocking" -> "EXTERNALIZE A2"
#[test]
fn test_ballot_pristine_accept_commit_vblocking_externalize_a2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let _ = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // v-blocking EXTERNALIZE(A2, 2) -> emit CONFIRM(MAX, AInf, 2, MAX)
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a2.clone(), 2));
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(
        &scp.get_env(0),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &a_inf,
        2,
        u32::MAX,
    );
}

// -- "Accept commit" -> "v-blocking" -> "EXTERNALIZE B2"
#[test]
fn test_ballot_pristine_accept_commit_vblocking_externalize_b2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let _ = &x_value;
    let b_value = z_value.clone();
    let a1 = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let b_inf = ScpBallot {
        counter: u32::MAX,
        value: b_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // v-blocking EXTERNALIZE(B2, 2) -> emit CONFIRM(MAX, BInf, 2, MAX)
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, b2.clone(), 2));
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(
        &scp.get_env(0),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &b_inf,
        2,
        u32::MAX,
    );
}

// -- "Confirm prepared mixed" -> "mixed A2"
#[test]
fn test_ballot_pristine_confirm_prepared_mixed_a2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value.clone();
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    setup_pristine_prepared_a1(&scp, qs_hash, &a1);

    // a few nodes prepared A2 => causes p=A2
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 0);

    // a few nodes prepared B2 => causes p=B2, p'=A2
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(
            qs_hash,
            a2.clone(),
            Some(b2.clone()),
            0,
            0,
            Some(a2.clone()),
        ),
        false,
    );
    assert_eq!(scp.envs_len(), 0);

    // causes h=A2, but c=0 as p >!~ h
    scp.receive_envelope(make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 1);
    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&b2),
        0,
        2,
        Some(&a2),
    );

    scp.receive_envelope(make_prepare(
        &v4_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 1);
}

// -- "Confirm prepared mixed" -> "mixed B2"
#[test]
fn test_ballot_pristine_confirm_prepared_mixed_b2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value.clone();
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    setup_pristine_prepared_a1(&scp, qs_hash, &a1);

    // a few nodes prepared A2 => causes p=A2
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 0);

    // a few nodes prepared B2 => causes p=B2, p'=A2
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(
            qs_hash,
            a2.clone(),
            Some(b2.clone()),
            0,
            0,
            Some(a2.clone()),
        ),
        false,
    );
    assert_eq!(scp.envs_len(), 0);

    // causes h=B2, c=B2
    scp.receive_envelope(make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &b2,
        Some(&b2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 1);
    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash,
        0,
        &b2,
        Some(&b2),
        2,
        2,
        Some(&a2),
    );

    scp.receive_envelope(make_prepare(
        &v4_id(),
        qs_hash,
        0,
        &b2,
        Some(&b2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 1);
}

// -- "switch prepared B1"
#[test]
fn test_ballot_pristine_switch_prepared_b1() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value.clone();
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    setup_pristine_prepared_a1(&scp, qs_hash, &a1);

    // v-blocking PREPARE(B1, p=B1) -> no envelope
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 0);
}

// -- "prepared B (v-blocking)"
#[test]
fn test_ballot_pristine_prepared_b_vblocking() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let _ = &x_value;
    let b_value = z_value.clone();
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    // v-blocking PREPARE(B1, p=B1) from pristine -> no envelope
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 0);
}

// -- "confirm (v-blocking)" -> "via CONFIRM"
#[test]
fn test_ballot_pristine_confirm_vblocking_via_confirm() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };

    // from pristine, receive v-blocking CONFIRMs
    scp.receive_envelope(make_confirm(&v1_id(), qs_hash, 0, 3, &a3, 3, 3));
    scp.receive_envelope(make_confirm(&v2_id(), qs_hash, 0, 4, &a4, 2, 4));
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(&scp.get_env(0), &v0_id(), qs_hash, 0, 3, &a3, 3, 3);
}

// -- "confirm (v-blocking)" -> "via EXTERNALIZE"
#[test]
fn test_ballot_pristine_confirm_vblocking_via_externalize() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    // from pristine, receive v-blocking EXTERNALIZEs
    scp.receive_envelope(make_externalize(&v1_id(), qs_hash, 0, &a2, 4));
    scp.receive_envelope(make_externalize(&v2_id(), qs_hash, 0, &a3, 5));
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(
        &scp.get_env(0),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &a_inf,
        3,
        u32::MAX,
    );
}

// ===========================================================================
// "normal round (1,x)" — stellar-core lines 2201-2301
// ===========================================================================

#[test]
fn test_ballot_normal_round_1x() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);
    let qs_hash0 = quorum_set_hash(&scp.scp.local_quorum_set());

    nodes_all_pledge_to_commit(&scp, &x_value, qs_hash);
    assert_eq!(scp.envs_len(), 3);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // bunch of prepare messages with "commit b"
    let prepared_c1 = make_prepare(
        &v1_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
    let prepared_c2 = make_prepare(
        &v2_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
    let prepared_c3 = make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
    let _prepared_c4 = make_prepare(
        &v4_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );

    // those should not trigger anything just yet
    scp.receive_envelope(prepared_c1);
    scp.receive_envelope(prepared_c2);
    assert_eq!(scp.envs_len(), 3);

    // this should cause the node to accept 'commit b' (quorum)
    // and therefore send a "CONFIRM" message
    scp.receive_envelope(prepared_c3);
    assert_eq!(scp.envs_len(), 4);

    verify_confirm(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        1,
        &b,
        b.counter,
        b.counter,
    );

    // bunch of confirm messages
    let confirm1 = make_confirm(&v1_id(), qs_hash, 0, b.counter, &b, b.counter, b.counter);
    let confirm2 = make_confirm(&v2_id(), qs_hash, 0, b.counter, &b, b.counter, b.counter);
    let confirm3 = make_confirm(&v3_id(), qs_hash, 0, b.counter, &b, b.counter, b.counter);
    let confirm4 = make_confirm(&v4_id(), qs_hash, 0, b.counter, &b, b.counter, b.counter);

    // those should not trigger anything just yet
    scp.receive_envelope(confirm1);
    scp.receive_envelope(confirm2.clone());
    assert_eq!(scp.envs_len(), 4);

    scp.receive_envelope(confirm3);
    // this causes our node to externalize (confirm commit c)
    assert_eq!(scp.envs_len(), 5);

    // The slot should have externalized the value
    assert_eq!(scp.externalized_value_count(), 1);
    assert_eq!(scp.externalized_value(0), Some(x_value.clone()));

    verify_externalize(&scp.get_env(4), &v0_id(), qs_hash0, 0, &b, b.counter);

    // extra vote should not do anything
    scp.receive_envelope(confirm4);
    assert_eq!(scp.envs_len(), 5);
    assert_eq!(scp.externalized_value_count(), 1);

    // duplicate should just no-op
    scp.receive_envelope(confirm2);
    assert_eq!(scp.envs_len(), 5);
    assert_eq!(scp.externalized_value_count(), 1);
}

/// Helper to set up a fully externalized normal round, returning the TestSCP.
fn setup_normal_round_externalized(
    x_value: &Value,
    qs: &ScpQuorumSet,
    qs_hash: Hash256,
) -> TestSCP {
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(qs);

    nodes_all_pledge_to_commit(&scp, x_value, qs_hash);
    assert_eq!(scp.envs_len(), 3);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // Accept commit via quorum of prepares with commit
    let prepared_c1 = make_prepare(
        &v1_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
    let prepared_c2 = make_prepare(
        &v2_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
    let prepared_c3 = make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );

    scp.receive_envelope(prepared_c1);
    scp.receive_envelope(prepared_c2);
    scp.receive_envelope(prepared_c3);
    assert_eq!(scp.envs_len(), 4);
    verify_confirm(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        1,
        &b,
        b.counter,
        b.counter,
    );

    // Externalize via quorum of confirms
    let confirm1 = make_confirm(&v1_id(), qs_hash, 0, b.counter, &b, b.counter, b.counter);
    let confirm2 = make_confirm(&v2_id(), qs_hash, 0, b.counter, &b, b.counter, b.counter);
    let confirm3 = make_confirm(&v3_id(), qs_hash, 0, b.counter, &b, b.counter, b.counter);

    scp.receive_envelope(confirm1);
    scp.receive_envelope(confirm2);
    scp.receive_envelope(confirm3);
    assert_eq!(scp.envs_len(), 5);
    assert_eq!(scp.externalized_value_count(), 1);
    assert_eq!(scp.externalized_value(0), Some(x_value.clone()));
    verify_externalize(&scp.get_env(4), &v0_id(), qs_hash0, 0, &b, b.counter);

    scp
}

/// Helper to verify that bumpToBallot is prevented after externalization.
fn verify_bump_to_ballot_prevented(
    scp: &TestSCP,
    _x_value: &Value,
    _z_value: &Value,
    b2: &ScpBallot,
    qs_hash: Hash256,
) {
    let confirm1b2 = make_confirm(&v1_id(), qs_hash, 0, b2.counter, b2, b2.counter, b2.counter);
    let confirm2b2 = make_confirm(&v2_id(), qs_hash, 0, b2.counter, b2, b2.counter, b2.counter);
    let confirm3b2 = make_confirm(&v3_id(), qs_hash, 0, b2.counter, b2, b2.counter, b2.counter);
    let confirm4b2 = make_confirm(&v4_id(), qs_hash, 0, b2.counter, b2, b2.counter, b2.counter);

    scp.receive_envelope(confirm1b2);
    scp.receive_envelope(confirm2b2);
    scp.receive_envelope(confirm3b2);
    scp.receive_envelope(confirm4b2);
    assert_eq!(scp.envs_len(), 5);
    assert_eq!(scp.externalized_value_count(), 1);
}

#[test]
fn test_ballot_bump_to_ballot_prevented_by_value() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = setup_normal_round_externalized(&x_value, &qs, qs_hash);

    // b2 = (1, zValue) — different value, same counter
    let b2 = ScpBallot {
        counter: 1,
        value: z_value.clone(),
    };
    verify_bump_to_ballot_prevented(&scp, &x_value, &z_value, &b2, qs_hash);
}

#[test]
fn test_ballot_bump_to_ballot_prevented_by_counter() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = setup_normal_round_externalized(&x_value, &qs, qs_hash);

    // b2 = (2, xValue) — same value, higher counter
    let b2 = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };
    verify_bump_to_ballot_prevented(&scp, &x_value, &z_value, &b2, qs_hash);
}

#[test]
fn test_ballot_bump_to_ballot_prevented_by_value_and_counter() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = setup_normal_round_externalized(&x_value, &qs, qs_hash);

    // b2 = (2, zValue) — different value and higher counter
    let b2 = ScpBallot {
        counter: 2,
        value: z_value.clone(),
    };
    verify_bump_to_ballot_prevented(&scp, &x_value, &z_value, &b2, qs_hash);
}

// ===========================================================================
// "range check" — stellar-core lines 2304-2368
// ===========================================================================

#[test]
fn test_ballot_range_check() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);
    let qs_hash0 = quorum_set_hash(&scp.scp.local_quorum_set());

    nodes_all_pledge_to_commit(&scp, &x_value, qs_hash);
    assert_eq!(scp.envs_len(), 3);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // bunch of prepare messages with "commit b"
    let prepared_c1 = make_prepare(
        &v1_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
    let prepared_c2 = make_prepare(
        &v2_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
    let prepared_c3 = make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );

    // those should not trigger anything just yet
    scp.receive_envelope(prepared_c1);
    scp.receive_envelope(prepared_c2);
    assert_eq!(scp.envs_len(), 3);

    // this should cause the node to accept 'commit b' (quorum)
    // and therefore send a "CONFIRM" message
    scp.receive_envelope(prepared_c3);
    assert_eq!(scp.envs_len(), 4);

    verify_confirm(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        1,
        &b,
        b.counter,
        b.counter,
    );

    // bunch of confirm messages with different ranges
    let confirm1 = make_confirm(
        &v1_id(),
        qs_hash,
        0,
        4,
        &ScpBallot {
            counter: 4,
            value: x_value.clone(),
        },
        2,
        4,
    );
    let confirm2 = make_confirm(
        &v2_id(),
        qs_hash,
        0,
        6,
        &ScpBallot {
            counter: 6,
            value: x_value.clone(),
        },
        2,
        6,
    );
    let _confirm3 = make_confirm(
        &v3_id(),
        qs_hash,
        0,
        5,
        &ScpBallot {
            counter: 5,
            value: x_value.clone(),
        },
        3,
        5,
    );
    let confirm4 = make_confirm(
        &v4_id(),
        qs_hash,
        0,
        6,
        &ScpBallot {
            counter: 6,
            value: x_value.clone(),
        },
        3,
        6,
    );

    // this should not trigger anything just yet
    scp.receive_envelope(confirm1);

    // v-blocking
    //   * b gets bumped to (4,x)
    //   * p gets bumped to (4,x)
    //   * (c,h) gets bumped to (2,4)
    scp.receive_envelope(confirm2);
    assert_eq!(scp.envs_len(), 5);
    verify_confirm(
        &scp.get_env(4),
        &v0_id(),
        qs_hash0,
        0,
        4,
        &ScpBallot {
            counter: 4,
            value: x_value.clone(),
        },
        2,
        4,
    );

    // this causes to externalize
    // range is [3,4]
    scp.receive_envelope(confirm4);
    assert_eq!(scp.envs_len(), 6);

    // The slot should have externalized the value
    assert_eq!(scp.externalized_value_count(), 1);
    assert_eq!(scp.externalized_value(0), Some(x_value.clone()));

    verify_externalize(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &ScpBallot {
            counter: 3,
            value: x_value.clone(),
        },
        4,
    );
}

// ===========================================================================
// "timeout when h is set -> stay locked on h" — stellar-core lines 2370-2389
// ===========================================================================

#[test]
fn test_ballot_timeout_h_set_stay_locked() {
    let (x_value, y_value, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);
    let qs_hash0 = quorum_set_hash(&scp.scp.local_quorum_set());

    let bx = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };
    assert!(scp.bump_state(0, x_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // v-blocking -> prepared
    // quorum -> confirm prepared
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, bx.clone(), Some(bx.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &bx,
        Some(&bx),
        bx.counter,
        bx.counter,
        None,
    );

    // now, see if we can timeout and move to a different value
    assert!(scp.bump_state(0, y_value.clone()));
    assert_eq!(scp.envs_len(), 4);
    let newbx = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        &newbx,
        Some(&bx),
        bx.counter,
        bx.counter,
        None,
    );
}

// ===========================================================================
// "timeout when h exists but can't be set -> vote for h" — stellar-core lines 2390-2415
// ===========================================================================

#[test]
fn test_ballot_timeout_h_cant_be_set_vote_for_h() {
    let (x_value, y_value, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);
    let qs_hash0 = quorum_set_hash(&scp.scp.local_quorum_set());

    // start with (1,y)
    let by = ScpBallot {
        counter: 1,
        value: y_value.clone(),
    };
    assert!(scp.bump_state(0, y_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    let bx = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };
    // but quorum goes with (1,x)
    // v-blocking -> prepared
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, bx.clone(), Some(bx.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &by,
        Some(&bx),
        0,
        0,
        None,
    );
    // quorum -> confirm prepared (no-op as b > h)
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, bx.clone(), Some(bx.clone()), 0, 0, None),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 2);

    assert!(scp.bump_state(0, y_value.clone()));
    assert_eq!(scp.envs_len(), 3);
    let newbx = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };
    // on timeout:
    // * we should move to the quorum's h value
    // * c can't be set yet as b > h
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &newbx,
        Some(&bx),
        0,
        bx.counter,
        None,
    );
}

// ===========================================================================
// "timeout from multiple nodes" — stellar-core lines 2417-2460
// ===========================================================================

#[test]
fn test_ballot_timeout_from_multiple_nodes() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);
    let qs_hash0 = quorum_set_hash(&scp.scp.local_quorum_set());

    assert!(scp.bump_state(0, x_value.clone()));

    let x1 = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    assert_eq!(scp.envs_len(), 1);
    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        &x1,
        None,
        0,
        0,
        None,
    );

    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, x1.clone(), None, 0, 0, None),
    );
    // quorum -> prepared (1,x)
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &x1,
        Some(&x1),
        0,
        0,
        None,
    );

    let x2 = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };
    // timeout from local node
    assert!(scp.bump_state(0, x_value.clone()));
    // prepares (2,x)
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &x2,
        Some(&x1),
        0,
        0,
        None,
    );

    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, x1.clone(), Some(x1.clone()), 0, 0, None),
    );
    // quorum -> set nH=1
    assert_eq!(scp.envs_len(), 4);
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        &x2,
        Some(&x1),
        0,
        1,
        None,
    );
    assert_eq!(scp.envs_len(), 4);

    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, x2.clone(), Some(x2.clone()), 1, 1, None),
    );
    // v-blocking prepared (2,x) -> prepared (2,x)
    assert_eq!(scp.envs_len(), 5);
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash0,
        0,
        &x2,
        Some(&x2),
        0,
        1,
        None,
    );

    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, x2.clone(), Some(x2.clone()), 1, 1, None),
    );
    // quorum (including us) confirms (2,x) prepared -> set h=c=x2
    // we also get extra message: a quorum not including us confirms
    // (1,x) prepared
    //  -> we confirm c=h=x1
    assert_eq!(scp.envs_len(), 7);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &x2,
        Some(&x2),
        2,
        2,
        None,
    );
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 2, &x2, 1, 1);
}

// ===========================================================================
// "timeout after prepare, receive old messages to prepare" — stellar-core lines 2462-2508
// ===========================================================================

#[test]
fn test_ballot_timeout_after_prepare_receive_old_messages() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);
    let qs_hash0 = quorum_set_hash(&scp.scp.local_quorum_set());

    assert!(scp.bump_state(0, x_value.clone()));

    let x1 = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    assert_eq!(scp.envs_len(), 1);
    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        &x1,
        None,
        0,
        0,
        None,
    );

    scp.receive_envelope(make_prepare(&v1_id(), qs_hash, 0, &x1, None, 0, 0, None));
    scp.receive_envelope(make_prepare(&v2_id(), qs_hash, 0, &x1, None, 0, 0, None));
    scp.receive_envelope(make_prepare(&v3_id(), qs_hash, 0, &x1, None, 0, 0, None));

    // quorum -> prepared (1,x)
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &x1,
        Some(&x1),
        0,
        0,
        None,
    );

    let x2 = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };
    // timeout from local node
    assert!(scp.bump_state(0, x_value.clone()));
    // prepares (2,x)
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &x2,
        Some(&x1),
        0,
        0,
        None,
    );

    let x3 = ScpBallot {
        counter: 3,
        value: x_value.clone(),
    };
    // timeout again
    assert!(scp.bump_state(0, x_value.clone()));
    // prepares (3,x)
    assert_eq!(scp.envs_len(), 4);
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        &x3,
        Some(&x1),
        0,
        0,
        None,
    );

    // other nodes moved on with x2
    scp.receive_envelope(make_prepare(
        &v1_id(),
        qs_hash,
        0,
        &x2,
        Some(&x2),
        1,
        2,
        None,
    ));
    scp.receive_envelope(make_prepare(
        &v2_id(),
        qs_hash,
        0,
        &x2,
        Some(&x2),
        1,
        2,
        None,
    ));
    // v-blocking -> prepared x2
    assert_eq!(scp.envs_len(), 5);
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash0,
        0,
        &x3,
        Some(&x2),
        0,
        0,
        None,
    );

    scp.receive_envelope(make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &x2,
        Some(&x2),
        1,
        2,
        None,
    ));
    // quorum -> set nH=2
    assert_eq!(scp.envs_len(), 6);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &x3,
        Some(&x2),
        0,
        2,
        None,
    );
}

// ===========================================================================
// "non validator watching the network" — stellar-core lines 2510-2538
// ===========================================================================

#[test]
fn test_non_validator_watching_the_network() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    // Create a non-validator node (NV) using a distinct node ID
    let nv_id = make_node_id(10); // distinct from v0-v4
    let scp = TestSCP::new_non_validator(nv_id.clone(), qs.clone());
    scp.store_quorum_set(&qs);
    let qs_hash_nv = quorum_set_hash(&scp.scp.local_quorum_set());

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // Non-validator bumps state — no envelopes emitted
    assert!(scp.bump_state(0, x_value.clone()));
    assert_eq!(scp.envs_len(), 0);

    // But internally it should have moved to PREPARE
    verify_prepare(
        &scp.get_current_envelope(0, &nv_id),
        &nv_id,
        qs_hash_nv,
        0,
        &b,
        None,
        0,
        0,
        None,
    );

    // Receive 4 EXTERNALIZE envelopes from v1-v4
    let ext1 = make_externalize(&v1_id(), qs_hash, 0, &b, 1);
    let ext2 = make_externalize(&v2_id(), qs_hash, 0, &b, 1);
    let ext3 = make_externalize(&v3_id(), qs_hash, 0, &b, 1);
    let ext4 = make_externalize(&v4_id(), qs_hash, 0, &b, 1);

    scp.receive_envelope(ext1);
    scp.receive_envelope(ext2);
    scp.receive_envelope(ext3);
    // After 3 EXTERNALIZE envelopes: no emitted envelopes (non-validator)
    assert_eq!(scp.envs_len(), 0);

    // Internal state should be CONFIRM (accept commit via v-blocking,
    // quorum confirms -> CONFIRM with UINT32_MAX)
    let b_inf = ScpBallot {
        counter: u32::MAX,
        value: x_value.clone(),
    };
    verify_confirm(
        &scp.get_current_envelope(0, &nv_id),
        &nv_id,
        qs_hash_nv,
        0,
        u32::MAX,
        &b_inf,
        1,
        u32::MAX,
    );

    scp.receive_envelope(ext4);
    // Still no emitted envelopes
    assert_eq!(scp.envs_len(), 0);

    // Internal state should be EXTERNALIZE
    verify_externalize(
        &scp.get_current_envelope(0, &nv_id),
        &nv_id,
        qs_hash_nv,
        0,
        &b,
        u32::MAX,
    );

    // Value should be externalized
    assert_eq!(scp.externalized_value(0), Some(x_value.clone()));
}

// ===========================================================================
// "restore ballot protocol" — stellar-core lines 2540-2563
// Tests that setStateFromEnvelope doesn't crash for PREPARE/CONFIRM/EXTERNALIZE
// ===========================================================================

#[test]
fn test_restore_ballot_protocol_prepare() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let b = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };

    let envelope = make_prepare(&v0_id(), qs_hash, 0, &b, None, 0, 0, None);
    scp.set_state_from_envelope(&envelope);
}

#[test]
fn test_restore_ballot_protocol_confirm() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let b = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };

    let envelope = make_confirm(&v0_id(), qs_hash, 0, 2, &b, 1, 2);
    scp.set_state_from_envelope(&envelope);
}

#[test]
fn test_restore_ballot_protocol_externalize() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let b = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };

    let envelope = make_externalize(&v0_id(), qs_hash, 0, &b, 2);
    scp.set_state_from_envelope(&envelope);
}

// ===========================================================================
// "ballot protocol core3" — stellar-core lines 2569-2757
// Core3 has an edge case where v-blocking and quorum can be the same
// v-blocking set size: 2, threshold: 2 = 1 + self or 2 others
// ===========================================================================

/// Core3 helper: recv_quorum for a 3-node quorum where receiving from v1
/// alone forms a quorum (with self). The `min_quorum` flag skips sending e2.
fn recv_quorum_checks_ex_core3(
    scp: &TestSCP,
    gen: &dyn Fn(&NodeId) -> ScpEnvelope,
    with_checks: bool,
    delayed_quorum: bool,
    check_upcoming: bool,
    min_quorum: bool,
) {
    let e1 = gen(&v1_id());
    let e2 = gen(&v2_id());

    scp.bump_timer_offset();

    let i = scp.envs_len() + 1;
    scp.receive_envelope(e1);
    if with_checks && !delayed_quorum {
        assert_eq!(scp.envs_len(), i);
    }
    if check_upcoming {
        assert!(scp.has_ballot_timer_upcoming());
    }
    if !min_quorum {
        // nothing happens with an extra vote (unless we're in delayedQuorum)
        scp.receive_envelope(e2);
        if with_checks {
            assert_eq!(scp.envs_len(), i);
        }
    }
}

/// Core3 helper: standard quorum check (no min_quorum)
fn recv_quorum_checks_core3(
    scp: &TestSCP,
    gen: &dyn Fn(&NodeId) -> ScpEnvelope,
    with_checks: bool,
    delayed_quorum: bool,
) {
    recv_quorum_checks_ex_core3(scp, gen, with_checks, delayed_quorum, false, false);
}

// ---------------------------------------------------------------------------
// "prepared B1 (quorum votes B1) local aValue" — stellar-core lines 2659-2703
// ---------------------------------------------------------------------------

#[test]
fn test_core3_prepared_b1_quorum_votes_b1_local_a_value() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core3_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    // core3: aValue = zValue, bValue = xValue
    let a_value = &z_value;
    let b_value = &x_value;

    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    // no timer is set
    assert!(!scp.has_ballot_timer());

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);
    assert!(!scp.has_ballot_timer());

    // quorum votes B1 -> prepared B1
    scp.bump_timer_offset();
    recv_quorum_checks_core3(
        &scp,
        &|node_id| make_prepare(node_id, qs_hash, 0, &b1, None, 0, 0, None),
        true,
        true,
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        None,
    );
    assert!(scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// "prepared B1 (quorum votes B1) -> quorum prepared B1 -> quorum bumps to A1"
// stellar-core lines 2670-2701
// ---------------------------------------------------------------------------

#[test]
fn test_core3_quorum_prepared_b1_then_bumps_to_a1() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core3_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &z_value;
    let b_value = &x_value;

    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // quorum votes B1 -> prepared B1
    scp.bump_timer_offset();
    recv_quorum_checks_core3(
        &scp,
        &|node_id| make_prepare(node_id, qs_hash, 0, &b1, None, 0, 0, None),
        true,
        true,
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        None,
    );
    assert!(scp.has_ballot_timer_upcoming());

    // quorum prepared B1
    scp.bump_timer_offset();
    recv_quorum_checks_core3(
        &scp,
        &|node_id| make_prepare(node_id, qs_hash, 0, &b1, Some(&b1), 0, 0, None),
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 2);
    // nothing happens:
    // computed_h = B1 (2)
    //    does not actually update h as b > computed_h
    //    also skips (3)
    assert!(!scp.has_ballot_timer_upcoming());

    // quorum bumps to A1 (min_quorum = true)
    scp.bump_timer_offset();
    recv_quorum_checks_ex_core3(
        &scp,
        &|node_id| make_prepare(node_id, qs_hash, 0, &a1, Some(&b1), 0, 0, None),
        false,
        false,
        false,
        true,
    );
    assert_eq!(scp.envs_len(), 3);
    // still does not set h as b > computed_h
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&a1),
        0,
        0,
        Some(&b1),
    );
    assert!(!scp.has_ballot_timer_upcoming());

    // quorum commits A1
    scp.bump_timer_offset();
    recv_quorum_checks_ex_core3(
        &scp,
        &|node_id| make_prepare(node_id, qs_hash, 0, &a2, Some(&a1), 1, 1, Some(&b1)),
        false,
        false,
        false,
        true,
    );
    assert_eq!(scp.envs_len(), 4);
    verify_confirm(&scp.get_env(3), &v0_id(), qs_hash0, 0, 2, &a1, 1, 1);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// "prepared A1 with timeout" — stellar-core lines 2705-2730
// ---------------------------------------------------------------------------

#[test]
fn test_core3_prepared_a1_with_timeout() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core3_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &z_value;
    let b_value = &x_value;

    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // starts with bValue (smallest)
    assert!(scp.bump_state(0, b_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // setup: quorum votes prepare A1 with p'=A1, nC=0, nH=1
    recv_quorum_checks_core3(
        &scp,
        &|node_id| make_prepare(node_id, qs_hash, 0, &a1, Some(&a1), 0, 1, None),
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&a1),
        1,
        1,
        None,
    );

    // now, receive bumped votes
    recv_quorum_checks_core3(
        &scp,
        &|node_id| make_prepare(node_id, qs_hash, 0, &a2, Some(&b2), 0, 1, Some(&a1)),
        true,
        true,
    );
    assert_eq!(scp.envs_len(), 3);
    // p=B2, p'=A1 (1)
    // computed_h = B2 (2)
    //   does not update h as b < computed_h
    // v-blocking ahead -> b = computed_h = B2 (9)
    // h = B2 (2) (now possible)
    // c = 0 (1)
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &b2,
        Some(&a2),
        0,
        2,
        Some(&b2),
    );
}

// ---------------------------------------------------------------------------
// "node without self - quorum timeout" — stellar-core lines 2731-2754
// ---------------------------------------------------------------------------

#[test]
fn test_core3_node_without_self_quorum_timeout() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core3_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let a_value = &z_value;

    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };

    // Create a node that is NOT in the quorum set (NodeNS)
    let ns_id = make_node_id(20); // distinct from v0-v2
    let scp_nns = TestSCP::new(ns_id.clone(), qs.clone());
    scp_nns.store_quorum_set(&qs);
    let qs_hash_ns = quorum_set_hash(&scp_nns.scp.local_quorum_set());

    // Receive envelopes from v1 and v2 (forms quorum without self since
    // NodeNS is not in the quorum set, so threshold is met by v1+v2 alone)
    scp_nns.receive_envelope(make_prepare(
        &v1_id(),
        qs_hash,
        0,
        &a2,
        Some(&b2),
        0,
        1,
        Some(&a1),
    ));
    scp_nns.receive_envelope(make_prepare(
        &v2_id(),
        qs_hash,
        0,
        &a1,
        Some(&a1),
        1,
        1,
        None,
    ));

    assert_eq!(scp_nns.envs_len(), 1);
    verify_prepare(
        &scp_nns.get_env(0),
        &ns_id,
        qs_hash_ns,
        0,
        &a1,
        Some(&a1),
        1,
        1,
        None,
    );

    scp_nns.receive_envelope(make_prepare(
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&b2),
        0,
        1,
        Some(&a1),
    ));

    assert_eq!(scp_nns.envs_len(), 2);
    verify_prepare(
        &scp_nns.get_env(1),
        &ns_id,
        qs_hash_ns,
        0,
        &b2,
        Some(&a2),
        0,
        2,
        Some(&b2),
    );
}
