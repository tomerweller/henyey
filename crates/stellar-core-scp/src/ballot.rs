//! Ballot protocol implementation for SCP.
//!
//! The ballot protocol is the second phase of SCP consensus, following the
//! nomination phase. After nomination produces a composite value, nodes use
//! the ballot protocol to achieve Byzantine agreement on that exact value.
//!
//! # Protocol Phases
//!
//! The ballot protocol progresses through three phases:
//!
//! 1. **PREPARE**: Nodes vote to prepare ballots. A ballot is "prepared" when
//!    nodes agree it's safe to commit (no conflicting ballot can be committed).
//!
//! 2. **CONFIRM**: Nodes confirm that a ballot is prepared. This phase ensures
//!    the network agrees that a particular ballot is prepared.
//!
//! 3. **EXTERNALIZE**: Once a ballot is confirmed prepared, nodes commit to
//!    its value. This is the final state where consensus is reached.
//!
//! # Ballot Structure
//!
//! A ballot `<n, x>` consists of:
//! - `n`: A counter (increases on timeout to try new ballots)
//! - `x`: The consensus value
//!
//! Ballots with the same value but different counters are "compatible".
//! The protocol ensures only compatible ballots can be committed.
//!
//! # Key State Variables
//!
//! Following the SCP whitepaper notation:
//! - `b`: Current ballot we're working on
//! - `p`: Highest prepared ballot
//! - `p'`: Second-highest prepared ballot (if incompatible with p)
//! - `h`: Highest ballot we can confirm prepared
//! - `c`: Commit ballot (lowest ballot we can commit)
//!
//! # Safety Guarantees
//!
//! The ballot protocol ensures that if any node externalizes a value,
//! all other nodes will externalize the same value (or not externalize at all).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use stellar_xdr::curr::{
    Limits, NodeId, ScpBallot, ScpEnvelope, ScpQuorumSet, ScpStatement, ScpStatementConfirm,
    ScpStatementExternalize, ScpStatementPledges, ScpStatementPrepare, Value, WriteXdr,
};

use crate::driver::{SCPDriver, ValidationLevel};
use crate::quorum::{
    hash_quorum_set, is_blocking_set, is_quorum, is_quorum_set_sane, simple_quorum_set,
};
use crate::EnvelopeState;

/// Extract the "working ballot" from an SCP statement.
///
/// The working ballot is the ballot a node is actively working on:
/// - For PREPARE statements: returns the `ballot` field
/// - For CONFIRM statements: returns a ballot with `(n_commit, value)`
/// - For EXTERNALIZE statements: returns a ballot with `(UINT32_MAX, value)`
///
/// This is useful for comparing the progress of different nodes in the
/// ballot protocol.
///
/// # Arguments
/// * `statement` - The SCP statement to extract the working ballot from
///
/// # Returns
/// The working ballot if the statement is a ballot statement (PREPARE/CONFIRM/EXTERNALIZE),
/// or None if it's a nomination statement.
pub fn get_working_ballot(statement: &ScpStatement) -> Option<ScpBallot> {
    match &statement.pledges {
        ScpStatementPledges::Prepare(prep) => Some(prep.ballot.clone()),
        ScpStatementPledges::Confirm(conf) => Some(ScpBallot {
            counter: conf.n_commit,
            value: conf.ballot.value.clone(),
        }),
        ScpStatementPledges::Externalize(ext) => Some(ScpBallot {
            counter: u32::MAX,
            value: ext.commit.value.clone(),
        }),
        ScpStatementPledges::Nominate(_) => None,
    }
}

/// Phase of the ballot protocol.
///
/// The ballot protocol progresses through these phases in order.
/// Once in the Externalize phase, the slot has reached consensus
/// and the value is final.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BallotPhase {
    /// Preparing ballots - voting to confirm a ballot is safe to commit.
    ///
    /// In this phase, nodes exchange PREPARE messages to establish
    /// which ballots are prepared (safe to commit).
    Prepare,

    /// Confirming a prepared ballot - agreeing on which ballot to commit.
    ///
    /// In this phase, nodes exchange CONFIRM messages to agree on
    /// a commit range. Transition occurs when accept-commit is achieved.
    Confirm,

    /// Externalized - consensus has been reached.
    ///
    /// This is the terminal state. The committed value is final and
    /// will not change. Nodes broadcast EXTERNALIZE messages.
    Externalize,
}

/// State machine for the ballot protocol phase.
///
/// The `BallotProtocol` implements the second phase of SCP consensus,
/// tracking all state needed to progress from PREPARE through CONFIRM
/// to EXTERNALIZE.
///
/// # Whitepaper Correspondence
///
/// This implementation follows the SCP whitepaper. Key state variables:
/// - `current_ballot` corresponds to `b` (current ballot)
/// - `prepared` corresponds to `p` (highest prepared ballot)
/// - `prepared_prime` corresponds to `p'` (second-highest prepared, incompatible with p)
/// - `high_ballot` corresponds to `h` (highest confirmable ballot)
/// - `commit` corresponds to `c` (commit ballot)
#[derive(Debug)]
pub struct BallotProtocol {
    /// Current ballot we're working on (`b` in the whitepaper).
    ///
    /// The ballot counter increases on timeout; the value comes from nomination.
    current_ballot: Option<ScpBallot>,

    /// Highest prepared ballot (`p` in the whitepaper).
    ///
    /// A ballot is prepared when we've accepted it as prepared.
    prepared: Option<ScpBallot>,

    /// Second-highest prepared ballot (`p'` in the whitepaper).
    ///
    /// Only set if it's incompatible with `prepared`. Used to prevent
    /// committing conflicting values.
    prepared_prime: Option<ScpBallot>,

    /// Highest ballot we can confirm prepared (`h` in the whitepaper).
    ///
    /// When h is set and c <= h, we can move to confirm phase.
    high_ballot: Option<ScpBallot>,

    /// Commit ballot (`c` in the whitepaper).
    ///
    /// The lowest ballot counter at which we can commit the value.
    commit: Option<ScpBallot>,

    /// Current protocol phase.
    phase: BallotPhase,

    /// Latest ballot envelope from each node.
    latest_envelopes: HashMap<NodeId, ScpEnvelope>,

    /// The consensus value (from the current or commit ballot).
    value: Option<Value>,

    /// Override value set when confirming prepared/commit.
    ///
    /// Used to ensure we commit the correct value when switching ballots.
    value_override: Option<Value>,

    /// Whether we've heard from a quorum for the current ballot.
    heard_from_quorum: bool,

    /// Recursion depth counter for `advance_slot` (prevents infinite loops).
    current_message_level: u32,

    /// Last envelope we constructed locally.
    last_envelope: Option<ScpEnvelope>,

    /// Last envelope we actually emitted to the network.
    last_envelope_emit: Option<ScpEnvelope>,

    /// Whether values are fully validated (affects envelope emission).
    fully_validated: bool,
}

impl BallotProtocol {
    /// Create a new ballot protocol state.
    pub fn new() -> Self {
        Self {
            current_ballot: None,
            prepared: None,
            prepared_prime: None,
            high_ballot: None,
            commit: None,
            phase: BallotPhase::Prepare,
            latest_envelopes: HashMap::new(),
            value: None,
            value_override: None,
            heard_from_quorum: false,
            current_message_level: 0,
            last_envelope: None,
            last_envelope_emit: None,
            fully_validated: true,
        }
    }

    /// Get the current phase.
    pub fn phase(&self) -> BallotPhase {
        self.phase
    }

    /// Get the current ballot.
    pub fn current_ballot(&self) -> Option<&ScpBallot> {
        self.current_ballot.as_ref()
    }

    /// Get the current ballot counter, if any.
    pub fn current_ballot_counter(&self) -> Option<u32> {
        self.current_ballot.as_ref().map(|ballot| ballot.counter)
    }

    /// Get the prepared ballot.
    pub fn prepared(&self) -> Option<&ScpBallot> {
        self.prepared.as_ref()
    }

    /// Get the commit ballot.
    pub fn commit(&self) -> Option<&ScpBallot> {
        self.commit.as_ref()
    }

    /// Check if we're externalized.
    pub fn is_externalized(&self) -> bool {
        self.phase == BallotPhase::Externalize
    }

    /// Process the latest ballot envelopes with a callback.
    pub fn process_current_state<F>(
        &self,
        mut f: F,
        local_node_id: &NodeId,
        fully_validated: bool,
        force_self: bool,
    ) -> bool
    where
        F: FnMut(&ScpEnvelope) -> bool,
    {
        let mut nodes: Vec<_> = self.latest_envelopes.keys().collect();
        nodes.sort();

        for node_id in nodes {
            if !force_self && node_id == local_node_id && !fully_validated {
                continue;
            }

            if let Some(envelope) = self.latest_envelopes.get(node_id) {
                if !f(envelope) {
                    return false;
                }
            }
        }

        true
    }

    /// Update fully-validated state for local emission gating.
    pub fn set_fully_validated(&mut self, fully_validated: bool) {
        self.fully_validated = fully_validated;
    }

    /// Check whether we've heard from quorum for the current ballot.
    pub fn heard_from_quorum(&self) -> bool {
        self.heard_from_quorum
    }

    /// Get the externalized value if we've reached consensus.
    pub fn get_externalized_value(&self) -> Option<&Value> {
        if self.phase == BallotPhase::Externalize {
            self.value.as_ref()
        } else {
            None
        }
    }

    /// Force the ballot protocol to the externalized state with the given value.
    ///
    /// This is used when fast-forwarding via EXTERNALIZE messages from the network.
    /// It ensures that subsequent envelopes for this slot are properly validated
    /// against the externalized value.
    pub fn force_externalize(&mut self, value: Value) {
        let ballot = ScpBallot {
            counter: u32::MAX, // Infinite ballot for externalize
            value: value.clone(),
        };
        self.commit = Some(ballot.clone());
        self.high_ballot = Some(ballot.clone());
        self.current_ballot = Some(ballot);
        self.value = Some(value);
        self.phase = BallotPhase::Externalize;
    }

    /// Get the last envelope constructed by this node.
    pub fn get_last_envelope(&self) -> Option<&ScpEnvelope> {
        self.last_envelope.as_ref()
    }

    /// Get the latest envelope from a specific node.
    pub fn get_latest_envelope(&self, node_id: &NodeId) -> Option<&ScpEnvelope> {
        self.latest_envelopes.get(node_id)
    }

    /// Get the high ballot (highest confirmable).
    pub fn high_ballot(&self) -> Option<&ScpBallot> {
        self.high_ballot.as_ref()
    }

    /// Get the prepared' ballot.
    pub fn prepared_prime(&self) -> Option<&ScpBallot> {
        self.prepared_prime.as_ref()
    }

    /// Get the current consensus value.
    pub fn value(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    /// Check protocol invariants for debugging.
    ///
    /// Returns Ok(()) if invariants hold, Err with description otherwise.
    pub fn check_invariants(&self) -> Result<(), String> {
        // In PREPARE phase, c == 0 (no commit yet)
        if self.phase == BallotPhase::Prepare && self.commit.is_some() {
            // Actually in prepare phase, c is only set when we have h set
            // The invariant is: c != 0 => h != 0
            if self.high_ballot.is_none() {
                return Err("commit set but high_ballot not set in Prepare phase".to_string());
            }
        }

        // If we have prepared' it must be < prepared and incompatible
        if let (Some(prepared), Some(prepared_prime)) = (&self.prepared, &self.prepared_prime) {
            if ballot_compare(prepared_prime, prepared) != std::cmp::Ordering::Less {
                return Err("prepared_prime must be less than prepared".to_string());
            }
            if ballot_compatible(prepared_prime, prepared) {
                return Err("prepared_prime must be incompatible with prepared".to_string());
            }
        }

        // c <= h (commit counter <= high counter)
        if let (Some(commit), Some(high)) = (&self.commit, &self.high_ballot) {
            if commit.counter > high.counter {
                return Err("commit counter exceeds high counter".to_string());
            }
            // c and h must have same value
            if commit.value != high.value {
                return Err("commit and high have different values".to_string());
            }
        }

        // In EXTERNALIZE, we must have commit and high
        if self.phase == BallotPhase::Externalize
            && (self.commit.is_none() || self.high_ballot.is_none())
        {
            return Err("externalize phase requires commit and high".to_string());
        }

        Ok(())
    }

    /// Get a string representation of the local state for debugging.
    pub fn get_local_state(&self) -> String {
        let mut state = format!("phase={:?}", self.phase);

        if let Some(b) = &self.current_ballot {
            state.push_str(&format!(
                " b=({},{})",
                b.counter,
                hex::encode(&b.value.as_slice()[..4.min(b.value.len())])
            ));
        }

        if let Some(p) = &self.prepared {
            state.push_str(&format!(
                " p=({},{})",
                p.counter,
                hex::encode(&p.value.as_slice()[..4.min(p.value.len())])
            ));
        }

        if let Some(pp) = &self.prepared_prime {
            state.push_str(&format!(
                " p'=({},{})",
                pp.counter,
                hex::encode(&pp.value.as_slice()[..4.min(pp.value.len())])
            ));
        }

        if let Some(h) = &self.high_ballot {
            state.push_str(&format!(
                " h=({},{})",
                h.counter,
                hex::encode(&h.value.as_slice()[..4.min(h.value.len())])
            ));
        }

        if let Some(c) = &self.commit {
            state.push_str(&format!(
                " c=({},{})",
                c.counter,
                hex::encode(&c.value.as_slice()[..4.min(c.value.len())])
            ));
        }

        state.push_str(&format!(" heard_from_quorum={}", self.heard_from_quorum));

        state
    }

    /// Get the latest envelopes received from each node.
    ///
    /// Returns a map from node ID to the most recent envelope from that node.
    pub fn latest_envelopes(&self) -> &HashMap<NodeId, ScpEnvelope> {
        &self.latest_envelopes
    }

    /// Get the count of nodes we've heard from.
    pub fn get_node_count(&self) -> usize {
        self.latest_envelopes.len()
    }

    /// Get the state of a node in the ballot protocol.
    ///
    /// Returns the QuorumInfoNodeState for a given node based on their
    /// latest ballot envelope, or Missing if we haven't heard from them.
    pub fn get_node_state(&self, node_id: &NodeId) -> crate::QuorumInfoNodeState {
        if let Some(envelope) = self.latest_envelopes.get(node_id) {
            crate::QuorumInfoNodeState::from_pledges(&envelope.statement.pledges)
        } else {
            crate::QuorumInfoNodeState::Missing
        }
    }

    /// Get a summary string of the ballot state for debugging.
    pub fn get_state_string(&self) -> String {
        let mut state = format!("phase={:?}", self.phase);

        if let Some(b) = &self.current_ballot {
            state.push_str(&format!(" b={}", b.counter));
        }

        if let Some(p) = &self.prepared {
            state.push_str(&format!(" p={}", p.counter));
        }

        if let Some(h) = &self.high_ballot {
            state.push_str(&format!(" h={}", h.counter));
        }

        if let Some(c) = &self.commit {
            state.push_str(&format!(" c={}", c.counter));
        }

        state.push_str(&format!(
            " heard={} nodes={}",
            self.heard_from_quorum,
            self.latest_envelopes.len()
        ));

        state
    }

    /// Get JSON-serializable ballot information.
    ///
    /// Returns a BallotInfo struct that can be serialized to JSON
    /// for debugging and monitoring purposes.
    pub fn get_info(&self) -> crate::BallotInfo {
        let ballot_to_info = |b: &ScpBallot| crate::BallotValue {
            counter: b.counter,
            value: crate::value_to_str(&b.value),
        };

        crate::BallotInfo {
            phase: format!("{:?}", self.phase),
            ballot_counter: self.current_ballot.as_ref().map(|b| b.counter).unwrap_or(0),
            ballot_value: self
                .current_ballot
                .as_ref()
                .map(|b| crate::value_to_str(&b.value)),
            prepared: self.prepared.as_ref().map(ballot_to_info),
            prepared_prime: self.prepared_prime.as_ref().map(ballot_to_info),
            commit: self.commit.as_ref().map(|c| crate::CommitBounds {
                low: c.counter,
                high: self
                    .high_ballot
                    .as_ref()
                    .map(|h| h.counter)
                    .unwrap_or(c.counter),
            }),
            high: self.high_ballot.as_ref().map(|h| h.counter).unwrap_or(0),
            node_count: self.latest_envelopes.len(),
            heard_from_quorum: self.heard_from_quorum,
        }
    }

    /// Start the ballot protocol with a value from nomination.
    pub fn bump<D: SCPDriver>(
        &mut self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
        value: Value,
        force: bool,
    ) -> bool {
        if self.phase == BallotPhase::Externalize {
            return false;
        }

        if !force && self.current_ballot.is_some() {
            return false;
        }

        // Calculate new ballot counter
        let counter = self
            .current_ballot
            .as_ref()
            .map(|current| current.counter + 1)
            .unwrap_or(1);

        let ballot = ScpBallot {
            counter,
            value: value.clone(),
        };

        self.current_ballot = Some(ballot.clone());
        self.value = Some(value);
        self.heard_from_quorum = false;

        // Emit prepare statement
        self.emit_prepare(local_node_id, local_quorum_set, driver, slot_index);
        self.check_heard_from_quorum(local_node_id, local_quorum_set, driver, slot_index);

        true
    }

    /// Bump ballot counter on timeout.
    pub fn bump_timeout<D: SCPDriver>(
        &mut self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> bool {
        if self.phase == BallotPhase::Externalize {
            return false;
        }

        if let Some(ref mut ballot) = self.current_ballot {
            ballot.counter += 1;
            self.heard_from_quorum = false;
            self.emit_current_state(local_node_id, local_quorum_set, driver, slot_index);
            self.check_heard_from_quorum(local_node_id, local_quorum_set, driver, slot_index);
            true
        } else {
            false
        }
    }

    /// Process a ballot protocol envelope.
    pub fn process_envelope<D: SCPDriver>(
        &mut self,
        envelope: &ScpEnvelope,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> EnvelopeState {
        let node_id = &envelope.statement.node_id;

        match &envelope.statement.pledges {
            ScpStatementPledges::Prepare(_)
            | ScpStatementPledges::Confirm(_)
            | ScpStatementPledges::Externalize(_) => {}
            _ => return EnvelopeState::Invalid,
        }

        if !self.is_newer_statement(node_id, &envelope.statement) {
            return EnvelopeState::Invalid;
        }

        if self.phase == BallotPhase::Externalize {
            if self.statement_value_matches_commit(&envelope.statement) {
                self.latest_envelopes
                    .insert(node_id.clone(), envelope.clone());
                return EnvelopeState::Valid;
            }
            return EnvelopeState::Invalid;
        }

        // Store the envelope
        self.latest_envelopes
            .insert(node_id.clone(), envelope.clone());

        self.advance_slot(
            &envelope.statement,
            local_node_id,
            local_quorum_set,
            driver,
            slot_index,
        )
    }

    pub fn is_newer_statement(&self, node_id: &NodeId, statement: &ScpStatement) -> bool {
        match self.latest_envelopes.get(node_id) {
            None => true,
            Some(existing) => self.is_newer_statement_pair(&existing.statement, statement),
        }
    }

    fn is_newer_statement_pair(&self, old: &ScpStatement, new: &ScpStatement) -> bool {
        let old_rank = self.pledge_rank(&old.pledges);
        let new_rank = self.pledge_rank(&new.pledges);

        if old_rank != new_rank {
            return old_rank < new_rank;
        }

        match (&old.pledges, &new.pledges) {
            (ScpStatementPledges::Externalize(_), ScpStatementPledges::Externalize(_)) => false,
            (ScpStatementPledges::Confirm(old_c), ScpStatementPledges::Confirm(new_c)) => {
                let cmp = self.compare_ballots(&old_c.ballot, &new_c.ballot);
                if cmp < 0 {
                    return true;
                }
                if cmp == 0 {
                    if old_c.n_prepared == new_c.n_prepared {
                        return old_c.n_h < new_c.n_h;
                    }
                    return old_c.n_prepared < new_c.n_prepared;
                }
                false
            }
            (ScpStatementPledges::Prepare(old_p), ScpStatementPledges::Prepare(new_p)) => {
                let cmp = self.compare_ballots(&old_p.ballot, &new_p.ballot);
                if cmp < 0 {
                    return true;
                }
                if cmp == 0 {
                    let cmp_prepared =
                        self.compare_optional_ballots(&old_p.prepared, &new_p.prepared);
                    if cmp_prepared < 0 {
                        return true;
                    }
                    if cmp_prepared == 0 {
                        let cmp_prime = self
                            .compare_optional_ballots(&old_p.prepared_prime, &new_p.prepared_prime);
                        if cmp_prime < 0 {
                            return true;
                        }
                        if cmp_prime == 0 {
                            return old_p.n_h < new_p.n_h;
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    fn pledge_rank(&self, pledges: &ScpStatementPledges) -> u8 {
        match pledges {
            ScpStatementPledges::Prepare(_) => 0,
            ScpStatementPledges::Confirm(_) => 1,
            ScpStatementPledges::Externalize(_) => 2,
            _ => 3,
        }
    }

    pub(crate) fn is_statement_sane<D: SCPDriver>(
        &self,
        statement: &ScpStatement,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
    ) -> bool {
        let quorum_set =
            match self.statement_quorum_set(statement, local_node_id, local_quorum_set, driver) {
                Some(qset) => qset,
                None => return false,
            };

        if is_quorum_set_sane(&quorum_set, false).is_err() {
            return false;
        }

        match &statement.pledges {
            ScpStatementPledges::Prepare(prep) => {
                let is_self = statement.node_id == *local_node_id;
                if !is_self && prep.ballot.counter == 0 {
                    return false;
                }

                if let (Some(prepared_prime), Some(prepared)) =
                    (&prep.prepared_prime, &prep.prepared)
                {
                    if ballot_compare(prepared_prime, prepared) != std::cmp::Ordering::Less
                        || ballot_compatible(prepared_prime, prepared)
                    {
                        return false;
                    }
                }

                if prep.n_h != 0 {
                    if let Some(prepared) = &prep.prepared {
                        if prep.n_h > prepared.counter {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }

                if prep.n_c != 0 {
                    if prep.n_h == 0 {
                        return false;
                    }
                    if prep.ballot.counter < prep.n_h || prep.n_h < prep.n_c {
                        return false;
                    }
                }
            }
            ScpStatementPledges::Confirm(conf) => {
                if conf.ballot.counter == 0 {
                    return false;
                }
                if conf.n_h > conf.ballot.counter {
                    return false;
                }
                if conf.n_commit > conf.n_h {
                    return false;
                }
            }
            ScpStatementPledges::Externalize(ext) => {
                if ext.commit.counter == 0 {
                    return false;
                }
                if ext.n_h < ext.commit.counter {
                    return false;
                }
            }
            _ => return false,
        }

        true
    }

    pub(crate) fn validate_statement_values<D: SCPDriver>(
        &self,
        statement: &ScpStatement,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> ValidationLevel {
        let values = self.statement_values(statement);
        if values.is_empty() {
            return ValidationLevel::Invalid;
        }

        let mut level = ValidationLevel::FullyValidated;
        for value in values {
            let next = driver.validate_value(slot_index, &value, false);
            level = min_validation_level(level, next);
            if level == ValidationLevel::Invalid {
                break;
            }
        }
        level
    }

    fn statement_quorum_set<D: SCPDriver>(
        &self,
        statement: &ScpStatement,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
    ) -> Option<ScpQuorumSet> {
        match &statement.pledges {
            ScpStatementPledges::Externalize(_) => {
                Some(simple_quorum_set(1, vec![statement.node_id.clone()]))
            }
            ScpStatementPledges::Prepare(prep) => {
                let provided = stellar_core_common::Hash256::from(prep.quorum_set_hash.clone());
                if &statement.node_id == local_node_id {
                    let expected = hash_quorum_set(local_quorum_set);
                    if expected == provided {
                        return Some(local_quorum_set.clone());
                    }
                }
                if let Some(qset) = driver.get_quorum_set_by_hash(&provided) {
                    return Some(qset);
                }
                driver.get_quorum_set(&statement.node_id).and_then(|qset| {
                    let expected = hash_quorum_set(&qset);
                    if expected == provided {
                        Some(qset)
                    } else {
                        None
                    }
                })
            }
            ScpStatementPledges::Confirm(conf) => {
                let provided = stellar_core_common::Hash256::from(conf.quorum_set_hash.clone());
                if &statement.node_id == local_node_id {
                    let expected = hash_quorum_set(local_quorum_set);
                    if expected == provided {
                        return Some(local_quorum_set.clone());
                    }
                }
                if let Some(qset) = driver.get_quorum_set_by_hash(&provided) {
                    return Some(qset);
                }
                driver.get_quorum_set(&statement.node_id).and_then(|qset| {
                    let expected = hash_quorum_set(&qset);
                    if expected == provided {
                        Some(qset)
                    } else {
                        None
                    }
                })
            }
            _ => None,
        }
    }

    fn statement_values(&self, statement: &ScpStatement) -> Vec<Value> {
        let mut values = Vec::new();
        match &statement.pledges {
            ScpStatementPledges::Prepare(prep) => {
                if prep.ballot.counter != 0 {
                    values.push(prep.ballot.value.clone());
                }
                if let Some(prepared) = &prep.prepared {
                    values.push(prepared.value.clone());
                }
                if let Some(prepared_prime) = &prep.prepared_prime {
                    values.push(prepared_prime.value.clone());
                }
            }
            ScpStatementPledges::Confirm(conf) => {
                values.push(conf.ballot.value.clone());
            }
            ScpStatementPledges::Externalize(ext) => {
                values.push(ext.commit.value.clone());
            }
            _ => {}
        }
        values
    }

    fn statement_value_matches_commit(&self, statement: &ScpStatement) -> bool {
        let commit = match self.commit.as_ref() {
            Some(commit) => commit,
            None => return false,
        };

        match &statement.pledges {
            ScpStatementPledges::Prepare(prep) => commit.value == prep.ballot.value,
            ScpStatementPledges::Confirm(conf) => commit.value == conf.ballot.value,
            ScpStatementPledges::Externalize(ext) => commit.value == ext.commit.value,
            _ => false,
        }
    }

    fn compare_optional_ballots(&self, left: &Option<ScpBallot>, right: &Option<ScpBallot>) -> i32 {
        match (left, right) {
            (Some(a), Some(b)) => self.compare_ballots(a, b),
            (Some(_), None) => 1,
            (None, Some(_)) => -1,
            (None, None) => 0,
        }
    }

    fn compare_ballots(&self, left: &ScpBallot, right: &ScpBallot) -> i32 {
        if left.counter < right.counter {
            return -1;
        }
        if right.counter < left.counter {
            return 1;
        }

        let cmp = self.compare_values(&left.value, &right.value);
        if cmp.is_lt() {
            -1
        } else if cmp.is_gt() {
            1
        } else {
            0
        }
    }

    fn compare_values(&self, left: &Value, right: &Value) -> std::cmp::Ordering {
        let left_bytes = left.to_xdr(Limits::none()).unwrap_or_default();
        let right_bytes = right.to_xdr(Limits::none()).unwrap_or_default();
        left_bytes.cmp(&right_bytes)
    }

    /// Try to advance the slot state based on received messages.
    fn advance_slot<D: SCPDriver>(
        &mut self,
        hint: &ScpStatement,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> EnvelopeState {
        self.current_message_level = self.current_message_level.saturating_add(1);
        if self.current_message_level > 50 {
            self.current_message_level = 0;
            return EnvelopeState::Invalid;
        }
        let mut did_work = false;

        did_work =
            self.attempt_accept_prepared(hint, local_node_id, local_quorum_set, driver, slot_index)
                || did_work;
        did_work = self.attempt_confirm_prepared(
            hint,
            local_node_id,
            local_quorum_set,
            driver,
            slot_index,
        ) || did_work;
        did_work =
            self.attempt_accept_commit(hint, local_node_id, local_quorum_set, driver, slot_index)
                || did_work;
        did_work =
            self.attempt_confirm_commit(hint, local_node_id, local_quorum_set, driver, slot_index)
                || did_work;

        if self.current_message_level == 1 {
            loop {
                let bumped = self.attempt_bump(local_node_id, local_quorum_set, driver, slot_index);
                did_work = bumped || did_work;
                if !bumped {
                    break;
                }
            }
            self.check_heard_from_quorum(local_node_id, local_quorum_set, driver, slot_index);
        }

        self.current_message_level = self.current_message_level.saturating_sub(1);
        if did_work {
            self.send_latest_envelope(driver);
            EnvelopeState::ValidNew
        } else {
            EnvelopeState::Valid
        }
    }

    fn attempt_accept_prepared<D: SCPDriver>(
        &mut self,
        hint: &ScpStatement,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> bool {
        if !matches!(self.phase, BallotPhase::Prepare | BallotPhase::Confirm) {
            return false;
        }

        let candidates = self.get_prepare_candidates(hint);

        for ballot in candidates.iter().rev() {
            if self.phase == BallotPhase::Confirm {
                if let Some(prepared) = &self.prepared {
                    if !are_ballots_less_and_compatible(prepared, ballot) {
                        continue;
                    }
                }
                if let Some(commit) = &self.commit {
                    if !ballot_compatible(commit, ballot) {
                        continue;
                    }
                }
            }

            if let Some(prepared_prime) = &self.prepared_prime {
                if ballot_compare(ballot, prepared_prime) != std::cmp::Ordering::Greater {
                    continue;
                }
            }

            if let Some(prepared) = &self.prepared {
                if are_ballots_less_and_compatible(ballot, prepared) {
                    continue;
                }
            }

            let accepted = self.federated_accept(
                |st| self.statement_votes_for_ballot(ballot, st),
                |st| self.has_prepared_ballot(ballot, st),
                local_node_id,
                local_quorum_set,
                driver,
            );

            if accepted
                && self.set_accept_prepared(
                    ballot.clone(),
                    local_node_id,
                    local_quorum_set,
                    driver,
                    slot_index,
                )
            {
                return true;
            }
        }

        false
    }

    fn set_accept_prepared<D: SCPDriver>(
        &mut self,
        ballot: ScpBallot,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> bool {
        let mut did_work = self.set_prepared(ballot.clone(), driver, slot_index);

        if self.commit.is_some() && self.high_ballot.is_some() {
            let high = self.high_ballot.as_ref().unwrap();
            let incompatible = self
                .prepared
                .as_ref()
                .map(|p| are_ballots_less_and_incompatible(high, p))
                .unwrap_or(false)
                || self
                    .prepared_prime
                    .as_ref()
                    .map(|p| are_ballots_less_and_incompatible(high, p))
                    .unwrap_or(false);
            if incompatible {
                self.commit = None;
                did_work = true;
            }
        }

        if did_work {
            self.emit_current_state(local_node_id, local_quorum_set, driver, slot_index);
        }

        did_work
    }

    fn attempt_confirm_prepared<D: SCPDriver>(
        &mut self,
        hint: &ScpStatement,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> bool {
        if self.phase != BallotPhase::Prepare {
            return false;
        }
        if self.prepared.is_none() {
            return false;
        }

        let candidates = self.get_prepare_candidates(hint);
        let mut new_h: Option<ScpBallot> = None;
        let mut new_h_index: Option<usize> = None;

        for (idx, ballot) in candidates.iter().enumerate().rev() {
            if let Some(high) = &self.high_ballot {
                if ballot_compare(high, ballot) != std::cmp::Ordering::Less {
                    break;
                }
            }

            if self.federated_ratify(
                |st| self.has_prepared_ballot(ballot, st),
                local_node_id,
                local_quorum_set,
                driver,
            ) {
                new_h = Some(ballot.clone());
                new_h_index = Some(idx);
                break;
            }
        }

        let Some(new_h_ballot) = new_h else {
            return false;
        };

        let mut new_c = ScpBallot {
            counter: 0,
            value: new_h_ballot.value.clone(),
        };

        let current = self.current_ballot.clone().unwrap_or(ScpBallot {
            counter: 0,
            value: new_h_ballot.value.clone(),
        });

        if self.commit.is_none()
            && self
                .prepared
                .as_ref()
                .map(|p| !are_ballots_less_and_incompatible(&new_h_ballot, p))
                .unwrap_or(true)
            && self
                .prepared_prime
                .as_ref()
                .map(|p| !are_ballots_less_and_incompatible(&new_h_ballot, p))
                .unwrap_or(true)
        {
            if let Some(start_idx) = new_h_index {
                for ballot in candidates[..=start_idx].iter().rev() {
                    if ballot_compare(ballot, &current) == std::cmp::Ordering::Less {
                        break;
                    }
                    if !are_ballots_less_and_compatible(ballot, &new_h_ballot) {
                        continue;
                    }
                    if self.federated_ratify(
                        |st| self.has_prepared_ballot(ballot, st),
                        local_node_id,
                        local_quorum_set,
                        driver,
                    ) {
                        new_c = ballot.clone();
                    } else {
                        break;
                    }
                }
            }
        }

        self.set_confirm_prepared(
            new_c,
            new_h_ballot,
            local_node_id,
            local_quorum_set,
            driver,
            slot_index,
        )
    }

    fn set_confirm_prepared<D: SCPDriver>(
        &mut self,
        new_c: ScpBallot,
        new_h: ScpBallot,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> bool {
        let mut did_work = false;
        self.value_override = Some(new_h.value.clone());

        if self
            .current_ballot
            .as_ref()
            .map(|b| ballot_compatible(b, &new_h))
            .unwrap_or(true)
        {
            if self
                .high_ballot
                .as_ref()
                .map(|b| ballot_compare(&new_h, b) == std::cmp::Ordering::Greater)
                .unwrap_or(true)
            {
                self.high_ballot = Some(new_h.clone());
                did_work = true;
            }

            if new_c.counter != 0 && self.commit.is_none() {
                self.commit = Some(new_c);
                did_work = true;
            }

            if did_work {
                driver.confirmed_ballot_prepared(slot_index, &new_h);
            }
        }

        did_work = self.update_current_if_needed(&new_h) || did_work;
        if did_work {
            self.emit_current_state(local_node_id, local_quorum_set, driver, slot_index);
        }

        did_work
    }

    fn attempt_accept_commit<D: SCPDriver>(
        &mut self,
        hint: &ScpStatement,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> bool {
        if !matches!(self.phase, BallotPhase::Prepare | BallotPhase::Confirm) {
            return false;
        }

        let Some(ballot) = self.hint_ballot_for_commit(hint) else {
            return false;
        };
        if self.phase == BallotPhase::Confirm {
            if let Some(high) = &self.high_ballot {
                if !ballot_compatible(&ballot, high) {
                    return false;
                }
            }
        }

        let boundaries = self.get_commit_boundaries_from_statements(&ballot);
        if boundaries.is_empty() {
            return false;
        }

        let mut candidate = (0u32, 0u32);
        self.find_extended_interval(&mut candidate, &boundaries, |interval| {
            self.federated_accept(
                |st| self.statement_votes_commit(&ballot, interval, st),
                |st| self.commit_predicate(&ballot, interval, st),
                local_node_id,
                local_quorum_set,
                driver,
            )
        });

        if candidate.0 == 0 {
            return false;
        }

        if self.phase != BallotPhase::Confirm
            || candidate.1 > self.high_ballot.as_ref().map(|b| b.counter).unwrap_or(0)
        {
            let c = ScpBallot {
                counter: candidate.0,
                value: ballot.value.clone(),
            };
            let h = ScpBallot {
                counter: candidate.1,
                value: ballot.value.clone(),
            };
            return self.set_accept_commit(
                c,
                h,
                local_node_id,
                local_quorum_set,
                driver,
                slot_index,
            );
        }

        false
    }

    fn set_accept_commit<D: SCPDriver>(
        &mut self,
        c: ScpBallot,
        h: ScpBallot,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> bool {
        let mut did_work = false;
        self.value_override = Some(h.value.clone());

        if self
            .high_ballot
            .as_ref()
            .map(|b| ballot_compare(b, &h) != std::cmp::Ordering::Equal)
            .unwrap_or(true)
            || self
                .commit
                .as_ref()
                .map(|b| ballot_compare(b, &c) != std::cmp::Ordering::Equal)
                .unwrap_or(true)
        {
            self.commit = Some(c.clone());
            self.high_ballot = Some(h.clone());
            did_work = true;
        }

        if self.phase == BallotPhase::Prepare {
            self.phase = BallotPhase::Confirm;
            if let Some(current) = &self.current_ballot {
                if !are_ballots_less_and_compatible(&h, current) {
                    self.bump_to_ballot(&h, false);
                }
            }
            self.prepared_prime = None;
            did_work = true;
        }

        if did_work {
            self.update_current_if_needed(&h);
            driver.accepted_commit(slot_index, &h);
            self.emit_current_state(local_node_id, local_quorum_set, driver, slot_index);
        }

        did_work
    }

    fn attempt_confirm_commit<D: SCPDriver>(
        &mut self,
        hint: &ScpStatement,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> bool {
        if self.phase != BallotPhase::Confirm {
            return false;
        }
        if self.high_ballot.is_none() || self.commit.is_none() {
            return false;
        }

        let Some(ballot) = self.hint_ballot_for_commit(hint) else {
            return false;
        };
        if !ballot_compatible(&ballot, self.commit.as_ref().unwrap()) {
            return false;
        }

        let boundaries = self.get_commit_boundaries_from_statements(&ballot);
        let mut candidate = (0u32, 0u32);
        self.find_extended_interval(&mut candidate, &boundaries, |interval| {
            self.federated_ratify(
                |st| self.commit_predicate(&ballot, interval, st),
                local_node_id,
                local_quorum_set,
                driver,
            )
        });

        if candidate.0 == 0 {
            return false;
        }

        let c = ScpBallot {
            counter: candidate.0,
            value: ballot.value.clone(),
        };
        let h = ScpBallot {
            counter: candidate.1,
            value: ballot.value.clone(),
        };
        self.set_confirm_commit(c, h, local_node_id, local_quorum_set, driver, slot_index)
    }

    fn set_confirm_commit<D: SCPDriver>(
        &mut self,
        c: ScpBallot,
        h: ScpBallot,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> bool {
        self.commit = Some(c.clone());
        self.high_ballot = Some(h.clone());
        self.update_current_if_needed(&h);
        self.phase = BallotPhase::Externalize;

        self.emit_current_state(local_node_id, local_quorum_set, driver, slot_index);
        driver.value_externalized(slot_index, &h.value);
        true
    }

    fn attempt_bump<D: SCPDriver>(
        &mut self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        _slot_index: u64,
    ) -> bool {
        if !matches!(self.phase, BallotPhase::Prepare | BallotPhase::Confirm) {
            return false;
        }

        let local_counter = self.current_ballot.as_ref().map(|b| b.counter).unwrap_or(0);
        if !self.has_vblocking_subset_strictly_ahead_of(
            local_counter,
            local_node_id,
            local_quorum_set,
            driver,
        ) {
            return false;
        }

        let mut counters = std::collections::BTreeSet::new();
        for envelope in self.latest_envelopes.values() {
            let counter = self.statement_ballot_counter(&envelope.statement);
            if counter > local_counter {
                counters.insert(counter);
            }
        }

        for counter in counters {
            if !self.has_vblocking_subset_strictly_ahead_of(
                counter,
                local_node_id,
                local_quorum_set,
                driver,
            ) {
                return self.abandon_ballot(counter);
            }
        }

        false
    }

    fn abandon_ballot(&mut self, counter: u32) -> bool {
        if let Some(value) = self
            .value_override
            .clone()
            .or_else(|| self.current_ballot.as_ref().map(|b| b.value.clone()))
        {
            return self.bump_to_ballot(
                &ScpBallot {
                    counter: if counter == 0 {
                        self.current_ballot
                            .as_ref()
                            .map(|b| b.counter + 1)
                            .unwrap_or(1)
                    } else {
                        counter
                    },
                    value,
                },
                true,
            );
        }
        false
    }

    fn update_current_if_needed(&mut self, ballot: &ScpBallot) -> bool {
        if self
            .current_ballot
            .as_ref()
            .map(|b| ballot_compare(b, ballot) == std::cmp::Ordering::Less)
            .unwrap_or(true)
        {
            return self.bump_to_ballot(ballot, true);
        }
        false
    }

    fn bump_to_ballot(&mut self, ballot: &ScpBallot, check: bool) -> bool {
        if check {
            if let Some(current) = &self.current_ballot {
                if ballot_compare(ballot, current) != std::cmp::Ordering::Greater {
                    return false;
                }
            }
        }

        self.current_ballot = Some(ballot.clone());
        self.value = Some(ballot.value.clone());
        self.heard_from_quorum = false;
        true
    }

    fn get_prepare_candidates(&self, hint: &ScpStatement) -> Vec<ScpBallot> {
        let mut hint_ballots: Vec<ScpBallot> = Vec::new();
        match &hint.pledges {
            ScpStatementPledges::Prepare(prep) => {
                hint_ballots.push(prep.ballot.clone());
                if let Some(prepared) = &prep.prepared {
                    hint_ballots.push(prepared.clone());
                }
                if let Some(prepared_prime) = &prep.prepared_prime {
                    hint_ballots.push(prepared_prime.clone());
                }
            }
            ScpStatementPledges::Confirm(conf) => {
                hint_ballots.push(ScpBallot {
                    counter: conf.n_prepared,
                    value: conf.ballot.value.clone(),
                });
                hint_ballots.push(ScpBallot {
                    counter: u32::MAX,
                    value: conf.ballot.value.clone(),
                });
            }
            ScpStatementPledges::Externalize(ext) => {
                hint_ballots.push(ScpBallot {
                    counter: u32::MAX,
                    value: ext.commit.value.clone(),
                });
            }
            _ => {}
        }

        let mut candidates: Vec<ScpBallot> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        hint_ballots.sort_by(ballot_compare);

        for top_vote in hint_ballots.iter().rev() {
            for envelope in self.latest_envelopes.values() {
                match &envelope.statement.pledges {
                    ScpStatementPledges::Prepare(prep) => {
                        if are_ballots_less_and_compatible(&prep.ballot, top_vote) {
                            self.push_candidate(&mut candidates, &mut seen, prep.ballot.clone());
                        }
                        if let Some(prepared) = &prep.prepared {
                            if are_ballots_less_and_compatible(prepared, top_vote) {
                                self.push_candidate(&mut candidates, &mut seen, prepared.clone());
                            }
                        }
                        if let Some(prepared_prime) = &prep.prepared_prime {
                            if are_ballots_less_and_compatible(prepared_prime, top_vote) {
                                self.push_candidate(
                                    &mut candidates,
                                    &mut seen,
                                    prepared_prime.clone(),
                                );
                            }
                        }
                    }
                    ScpStatementPledges::Confirm(conf) => {
                        if ballot_compatible(top_vote, &conf.ballot) {
                            self.push_candidate(&mut candidates, &mut seen, top_vote.clone());
                            if conf.n_prepared < top_vote.counter {
                                self.push_candidate(
                                    &mut candidates,
                                    &mut seen,
                                    ScpBallot {
                                        counter: conf.n_prepared,
                                        value: top_vote.value.clone(),
                                    },
                                );
                            }
                        }
                    }
                    ScpStatementPledges::Externalize(ext) => {
                        if ballot_compatible(top_vote, &ext.commit) {
                            self.push_candidate(&mut candidates, &mut seen, top_vote.clone());
                        }
                    }
                    _ => {}
                }
            }
        }

        candidates.sort_by(ballot_compare);
        candidates
    }

    fn push_candidate(
        &self,
        candidates: &mut Vec<ScpBallot>,
        seen: &mut std::collections::HashSet<(u32, Vec<u8>)>,
        ballot: ScpBallot,
    ) {
        let key = (
            ballot.counter,
            ballot.value.to_xdr(Limits::none()).unwrap_or_default(),
        );
        if seen.insert(key) {
            candidates.push(ballot);
        }
    }

    fn commit_predicate(
        &self,
        ballot: &ScpBallot,
        interval: (u32, u32),
        statement: &ScpStatement,
    ) -> bool {
        match &statement.pledges {
            ScpStatementPledges::Confirm(conf) => {
                if ballot_compatible(ballot, &conf.ballot) {
                    conf.n_commit <= interval.0 && interval.1 <= conf.n_h
                } else {
                    false
                }
            }
            ScpStatementPledges::Externalize(ext) => {
                if ballot_compatible(ballot, &ext.commit) {
                    ext.commit.counter <= interval.0
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn get_commit_boundaries_from_statements(
        &self,
        ballot: &ScpBallot,
    ) -> std::collections::BTreeSet<u32> {
        let mut res = std::collections::BTreeSet::new();
        for envelope in self.latest_envelopes.values() {
            match &envelope.statement.pledges {
                ScpStatementPledges::Prepare(prep) => {
                    if ballot_compatible(ballot, &prep.ballot) && prep.n_c != 0 {
                        res.insert(prep.n_c);
                        res.insert(prep.n_h);
                    }
                }
                ScpStatementPledges::Confirm(conf) => {
                    if ballot_compatible(ballot, &conf.ballot) {
                        res.insert(conf.n_commit);
                        res.insert(conf.n_h);
                    }
                }
                ScpStatementPledges::Externalize(ext) => {
                    if ballot_compatible(ballot, &ext.commit) {
                        res.insert(ext.commit.counter);
                        res.insert(ext.n_h);
                        res.insert(u32::MAX);
                    }
                }
                _ => {}
            }
        }
        res
    }

    fn find_extended_interval<F>(
        &self,
        candidate: &mut (u32, u32),
        boundaries: &std::collections::BTreeSet<u32>,
        pred: F,
    ) where
        F: Fn((u32, u32)) -> bool,
    {
        for boundary in boundaries.iter().rev() {
            let current = if candidate.0 == 0 {
                (*boundary, *boundary)
            } else if *boundary > candidate.1 {
                continue;
            } else {
                (*boundary, candidate.1)
            };

            if pred(current) {
                *candidate = current;
            } else if candidate.0 != 0 {
                break;
            }
        }
    }

    fn hint_ballot_for_commit(&self, hint: &ScpStatement) -> Option<ScpBallot> {
        match &hint.pledges {
            ScpStatementPledges::Prepare(prep) => {
                if prep.n_c != 0 {
                    Some(ScpBallot {
                        counter: prep.n_h,
                        value: prep.ballot.value.clone(),
                    })
                } else {
                    None
                }
            }
            ScpStatementPledges::Confirm(conf) => Some(ScpBallot {
                counter: conf.n_h,
                value: conf.ballot.value.clone(),
            }),
            ScpStatementPledges::Externalize(ext) => Some(ScpBallot {
                counter: ext.n_h,
                value: ext.commit.value.clone(),
            }),
            _ => None,
        }
    }

    fn statement_ballot_counter(&self, statement: &ScpStatement) -> u32 {
        match &statement.pledges {
            ScpStatementPledges::Prepare(prep) => prep.ballot.counter,
            ScpStatementPledges::Confirm(conf) => conf.ballot.counter,
            ScpStatementPledges::Externalize(_) => u32::MAX,
            _ => 0,
        }
    }

    fn has_vblocking_subset_strictly_ahead_of<D: SCPDriver>(
        &self,
        counter: u32,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
    ) -> bool {
        let mut nodes = HashSet::new();
        for (node_id, envelope) in &self.latest_envelopes {
            if self.statement_ballot_counter(&envelope.statement) > counter {
                nodes.insert(node_id.clone());
            }
        }
        is_blocking_set(local_quorum_set, &nodes)
            && !self
                .statement_quorum_set_map(local_node_id, local_quorum_set, driver)
                .is_empty()
    }

    fn statement_quorum_set_map<D: SCPDriver>(
        &self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
    ) -> HashMap<NodeId, ScpQuorumSet> {
        let mut map = HashMap::new();
        for (node_id, envelope) in &self.latest_envelopes {
            if let Some(qset) = self.statement_quorum_set(
                &envelope.statement,
                local_node_id,
                local_quorum_set,
                driver,
            ) {
                map.insert(node_id.clone(), qset);
            }
        }
        if !map.contains_key(local_node_id) {
            map.insert(local_node_id.clone(), local_quorum_set.clone());
        }
        map
    }

    fn federated_accept<D: SCPDriver, V, A>(
        &self,
        voted: V,
        accepted: A,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
    ) -> bool
    where
        V: Fn(&ScpStatement) -> bool,
        A: Fn(&ScpStatement) -> bool,
    {
        let mut accepted_nodes = HashSet::new();
        let mut supporters = HashSet::new();
        for (node_id, envelope) in &self.latest_envelopes {
            let statement = &envelope.statement;
            if accepted(statement) {
                accepted_nodes.insert(node_id.clone());
                supporters.insert(node_id.clone());
            } else if voted(statement) {
                supporters.insert(node_id.clone());
            }
        }

        if is_blocking_set(local_quorum_set, &accepted_nodes) {
            return true;
        }

        let qsets = self.statement_quorum_set_map(local_node_id, local_quorum_set, driver);
        let get_qs = |node_id: &NodeId| -> Option<ScpQuorumSet> { qsets.get(node_id).cloned() };
        is_quorum(local_quorum_set, &supporters, get_qs)
    }

    fn federated_ratify<D: SCPDriver, V>(
        &self,
        voted: V,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
    ) -> bool
    where
        V: Fn(&ScpStatement) -> bool,
    {
        let mut supporters = HashSet::new();
        for (node_id, envelope) in &self.latest_envelopes {
            if voted(&envelope.statement) {
                supporters.insert(node_id.clone());
            }
        }

        let qsets = self.statement_quorum_set_map(local_node_id, local_quorum_set, driver);
        let get_qs = |node_id: &NodeId| -> Option<ScpQuorumSet> { qsets.get(node_id).cloned() };
        is_quorum(local_quorum_set, &supporters, get_qs)
    }

    fn statement_votes_for_ballot(&self, ballot: &ScpBallot, statement: &ScpStatement) -> bool {
        match &statement.pledges {
            ScpStatementPledges::Prepare(prep) => {
                are_ballots_less_and_compatible(ballot, &prep.ballot)
            }
            ScpStatementPledges::Confirm(conf) => ballot_compatible(ballot, &conf.ballot),
            ScpStatementPledges::Externalize(ext) => ballot_compatible(ballot, &ext.commit),
            _ => false,
        }
    }

    fn statement_votes_commit(
        &self,
        ballot: &ScpBallot,
        interval: (u32, u32),
        statement: &ScpStatement,
    ) -> bool {
        match &statement.pledges {
            ScpStatementPledges::Prepare(prep) => {
                if ballot_compatible(ballot, &prep.ballot) && prep.n_c != 0 {
                    prep.n_c <= interval.0 && interval.1 <= prep.n_h
                } else {
                    false
                }
            }
            ScpStatementPledges::Confirm(conf) => {
                ballot_compatible(ballot, &conf.ballot) && conf.n_commit <= interval.0
            }
            ScpStatementPledges::Externalize(ext) => {
                ballot_compatible(ballot, &ext.commit) && ext.commit.counter <= interval.0
            }
            _ => false,
        }
    }

    fn has_prepared_ballot(&self, ballot: &ScpBallot, statement: &ScpStatement) -> bool {
        match &statement.pledges {
            ScpStatementPledges::Prepare(prep) => {
                prep.prepared
                    .as_ref()
                    .map(|p| are_ballots_less_and_compatible(ballot, p))
                    .unwrap_or(false)
                    || prep
                        .prepared_prime
                        .as_ref()
                        .map(|p| are_ballots_less_and_compatible(ballot, p))
                        .unwrap_or(false)
            }
            ScpStatementPledges::Confirm(conf) => {
                let prepared = ScpBallot {
                    counter: conf.n_prepared,
                    value: conf.ballot.value.clone(),
                };
                are_ballots_less_and_compatible(ballot, &prepared)
            }
            ScpStatementPledges::Externalize(ext) => ballot_compatible(ballot, &ext.commit),
            _ => false,
        }
    }

    /// Set prepared ballot.
    fn set_prepared<D: SCPDriver>(
        &mut self,
        ballot: ScpBallot,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> bool {
        let mut did_work = false;
        if let Some(ref current_prepared) = self.prepared {
            match ballot_compare(current_prepared, &ballot) {
                std::cmp::Ordering::Less => {
                    if !ballot_compatible(current_prepared, &ballot) {
                        self.prepared_prime = Some(current_prepared.clone());
                    }
                    self.prepared = Some(ballot.clone());
                    did_work = true;
                }
                std::cmp::Ordering::Greater => {
                    let should_update_prime = match &self.prepared_prime {
                        None => true,
                        Some(prepared_prime) => {
                            ballot_compare(prepared_prime, &ballot) == std::cmp::Ordering::Less
                                && !ballot_compatible(current_prepared, &ballot)
                        }
                    };
                    if should_update_prime {
                        self.prepared_prime = Some(ballot.clone());
                        did_work = true;
                    }
                }
                std::cmp::Ordering::Equal => {}
            }
        } else {
            self.prepared = Some(ballot.clone());
            did_work = true;
        }

        if did_work {
            driver.accepted_ballot_prepared(slot_index, &ballot);
            driver.ballot_did_prepare(slot_index, &ballot);
        }

        did_work
    }

    fn check_heard_from_quorum<D: SCPDriver>(
        &mut self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) {
        let current = match self.current_ballot.as_ref() {
            Some(ballot) => ballot.clone(),
            None => return,
        };

        let mut nodes = HashSet::new();
        let mut quorum_sets = HashMap::new();

        for (node_id, envelope) in &self.latest_envelopes {
            let include = match &envelope.statement.pledges {
                ScpStatementPledges::Prepare(prep) => current.counter <= prep.ballot.counter,
                ScpStatementPledges::Confirm(_) | ScpStatementPledges::Externalize(_) => true,
                _ => false,
            };
            if !include {
                continue;
            }

            nodes.insert(node_id.clone());
            if let Some(qs) = self.statement_quorum_set(
                &envelope.statement,
                local_node_id,
                local_quorum_set,
                driver,
            ) {
                quorum_sets.insert(node_id.clone(), qs);
            }
        }

        let get_qs =
            |node_id: &NodeId| -> Option<ScpQuorumSet> { quorum_sets.get(node_id).cloned() };

        if is_quorum(local_quorum_set, &nodes, get_qs) {
            let old = self.heard_from_quorum;
            self.heard_from_quorum = true;
            if !old {
                driver.ballot_did_hear_from_quorum(slot_index, &current);
            }
        } else {
            self.heard_from_quorum = false;
        }
    }

    fn send_latest_envelope<D: SCPDriver>(&mut self, driver: &Arc<D>) {
        if self.current_message_level != 0 {
            return;
        }

        if !self.fully_validated {
            return;
        }

        let Some(envelope) = self.last_envelope.as_ref() else {
            return;
        };

        if self.last_envelope_emit.as_ref() == Some(envelope) {
            return;
        }

        self.last_envelope_emit = Some(envelope.clone());
        driver.emit_envelope(envelope);
    }

    /// Emit prepare statement.
    fn emit_prepare<D: SCPDriver>(
        &mut self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) {
        if let Some(ref ballot) = self.current_ballot {
            let prep = ScpStatementPrepare {
                quorum_set_hash: hash_quorum_set(local_quorum_set).into(),
                ballot: ballot.clone(),
                prepared: self.prepared.clone(),
                prepared_prime: self.prepared_prime.clone(),
                n_c: self.commit.as_ref().map(|b| b.counter).unwrap_or(0),
                n_h: self.high_ballot.as_ref().map(|b| b.counter).unwrap_or(0),
            };

            let statement = ScpStatement {
                node_id: local_node_id.clone(),
                slot_index,
                pledges: ScpStatementPledges::Prepare(prep),
            };

            let mut envelope = ScpEnvelope {
                statement,
                signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
            };

            driver.sign_envelope(&mut envelope);
            if self.record_local_envelope(local_node_id, envelope.clone()) {
                self.last_envelope = Some(envelope.clone());
                self.send_latest_envelope(driver);
            }
        }
    }

    /// Emit confirm statement.
    fn emit_confirm<D: SCPDriver>(
        &mut self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) {
        if let Some(ref ballot) = self.current_ballot {
            let conf = ScpStatementConfirm {
                ballot: ballot.clone(),
                n_prepared: self.prepared.as_ref().map(|b| b.counter).unwrap_or(0),
                n_commit: self.commit.as_ref().map(|b| b.counter).unwrap_or(0),
                n_h: self.high_ballot.as_ref().map(|b| b.counter).unwrap_or(0),
                quorum_set_hash: hash_quorum_set(local_quorum_set).into(),
            };

            let statement = ScpStatement {
                node_id: local_node_id.clone(),
                slot_index,
                pledges: ScpStatementPledges::Confirm(conf),
            };

            let mut envelope = ScpEnvelope {
                statement,
                signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
            };

            driver.sign_envelope(&mut envelope);
            if self.record_local_envelope(local_node_id, envelope.clone()) {
                self.last_envelope = Some(envelope.clone());
                self.send_latest_envelope(driver);
            }
        }
    }

    /// Emit externalize statement.
    fn emit_externalize<D: SCPDriver>(
        &mut self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) {
        if let Some(ref commit) = self.commit {
            let ext = ScpStatementExternalize {
                commit: commit.clone(),
                n_h: self.high_ballot.as_ref().map(|b| b.counter).unwrap_or(0),
                commit_quorum_set_hash: hash_quorum_set(local_quorum_set).into(),
            };

            let statement = ScpStatement {
                node_id: local_node_id.clone(),
                slot_index,
                pledges: ScpStatementPledges::Externalize(ext),
            };

            let mut envelope = ScpEnvelope {
                statement,
                signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
            };

            driver.sign_envelope(&mut envelope);
            if self.record_local_envelope(local_node_id, envelope.clone()) {
                self.last_envelope = Some(envelope.clone());
                self.send_latest_envelope(driver);
            }
        }
    }

    /// Emit current state (used after timeout).
    fn emit_current_state<D: SCPDriver>(
        &mut self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) {
        match self.phase {
            BallotPhase::Prepare => {
                self.emit_prepare(local_node_id, local_quorum_set, driver, slot_index)
            }
            BallotPhase::Confirm => {
                self.emit_confirm(local_node_id, local_quorum_set, driver, slot_index)
            }
            BallotPhase::Externalize => {
                self.emit_externalize(local_node_id, local_quorum_set, driver, slot_index)
            }
        }
    }

    fn record_local_envelope(&mut self, local_node_id: &NodeId, envelope: ScpEnvelope) -> bool {
        if !self.is_newer_statement(local_node_id, &envelope.statement) {
            return false;
        }
        self.latest_envelopes
            .insert(local_node_id.clone(), envelope);
        true
    }

    /// Restore state from a saved envelope (for crash recovery).
    ///
    /// This method is used to restore the ballot protocol state from a previously
    /// saved envelope when restarting after a crash. It sets up the internal state
    /// to match what it would have been after processing that envelope.
    ///
    /// # Arguments
    /// * `envelope` - The envelope to restore state from
    ///
    /// # Returns
    /// True if state was successfully restored, false if the envelope is invalid
    /// for state restoration.
    pub fn set_state_from_envelope(&mut self, envelope: &ScpEnvelope) -> bool {
        match &envelope.statement.pledges {
            ScpStatementPledges::Prepare(prep) => {
                self.current_ballot = Some(prep.ballot.clone());
                self.prepared = prep.prepared.clone();
                self.prepared_prime = prep.prepared_prime.clone();
                if prep.n_c != 0 {
                    self.commit = Some(ScpBallot {
                        counter: prep.n_c,
                        value: prep.ballot.value.clone(),
                    });
                }
                if prep.n_h != 0 {
                    self.high_ballot = Some(ScpBallot {
                        counter: prep.n_h,
                        value: prep.ballot.value.clone(),
                    });
                }
                self.value = Some(prep.ballot.value.clone());
                self.phase = BallotPhase::Prepare;
                self.latest_envelopes
                    .insert(envelope.statement.node_id.clone(), envelope.clone());
                self.last_envelope = Some(envelope.clone());
                true
            }
            ScpStatementPledges::Confirm(conf) => {
                self.current_ballot = Some(conf.ballot.clone());
                self.prepared = Some(ScpBallot {
                    counter: conf.n_prepared,
                    value: conf.ballot.value.clone(),
                });
                self.prepared_prime = None;
                self.commit = Some(ScpBallot {
                    counter: conf.n_commit,
                    value: conf.ballot.value.clone(),
                });
                self.high_ballot = Some(ScpBallot {
                    counter: conf.n_h,
                    value: conf.ballot.value.clone(),
                });
                self.value = Some(conf.ballot.value.clone());
                self.phase = BallotPhase::Confirm;
                self.latest_envelopes
                    .insert(envelope.statement.node_id.clone(), envelope.clone());
                self.last_envelope = Some(envelope.clone());
                true
            }
            ScpStatementPledges::Externalize(ext) => {
                self.commit = Some(ext.commit.clone());
                self.high_ballot = Some(ScpBallot {
                    counter: ext.n_h,
                    value: ext.commit.value.clone(),
                });
                self.current_ballot = Some(ScpBallot {
                    counter: u32::MAX,
                    value: ext.commit.value.clone(),
                });
                self.value = Some(ext.commit.value.clone());
                self.phase = BallotPhase::Externalize;
                self.latest_envelopes
                    .insert(envelope.statement.node_id.clone(), envelope.clone());
                self.last_envelope = Some(envelope.clone());
                true
            }
            _ => false,
        }
    }

    /// Bump the ballot to a specific counter value.
    ///
    /// This is used when we need to bump to a specific ballot counter,
    /// for example when catching up to a higher ballot counter seen on the network.
    ///
    /// # Arguments
    /// * `local_node_id` - Our node ID
    /// * `local_quorum_set` - Our quorum set
    /// * `driver` - The SCP driver
    /// * `slot_index` - The slot index
    /// * `value` - The value for the ballot
    /// * `counter` - The specific counter to bump to
    ///
    /// # Returns
    /// True if the ballot was bumped, false if the operation failed.
    pub fn bump_state<D: SCPDriver>(
        &mut self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
        value: Value,
        counter: u32,
    ) -> bool {
        if self.phase == BallotPhase::Externalize {
            return false;
        }

        // Don't go backwards
        if let Some(current) = &self.current_ballot {
            if counter <= current.counter {
                return false;
            }
        }

        let ballot = ScpBallot {
            counter,
            value: value.clone(),
        };

        self.current_ballot = Some(ballot.clone());
        self.value = Some(value);
        self.heard_from_quorum = false;

        self.emit_current_state(local_node_id, local_quorum_set, driver, slot_index);
        self.check_heard_from_quorum(local_node_id, local_quorum_set, driver, slot_index);

        true
    }

    /// Abandon the current ballot and move to a new one.
    ///
    /// This is a public wrapper around the internal abandon logic,
    /// used when we need to give up on the current ballot and try a new one.
    ///
    /// # Arguments
    /// * `counter` - The counter for the new ballot (0 to auto-increment)
    ///
    /// # Returns
    /// True if the ballot was abandoned successfully.
    pub fn abandon_ballot_public(&mut self, counter: u32) -> bool {
        self.abandon_ballot(counter)
    }
}

fn min_validation_level(left: ValidationLevel, right: ValidationLevel) -> ValidationLevel {
    match (left, right) {
        (ValidationLevel::Invalid, _) | (_, ValidationLevel::Invalid) => ValidationLevel::Invalid,
        (ValidationLevel::MaybeValid, _) | (_, ValidationLevel::MaybeValid) => {
            ValidationLevel::MaybeValid
        }
        _ => ValidationLevel::FullyValidated,
    }
}

impl Default for BallotProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Compare two ballots.
/// Returns Greater if a > b, Less if a < b, Equal if a == b.
fn ballot_compare(a: &ScpBallot, b: &ScpBallot) -> std::cmp::Ordering {
    match a.counter.cmp(&b.counter) {
        std::cmp::Ordering::Equal => a.value.cmp(&b.value),
        other => other,
    }
}

/// Check if two ballots are compatible (same value).
fn ballot_compatible(a: &ScpBallot, b: &ScpBallot) -> bool {
    a.value == b.value
}

fn are_ballots_less_and_compatible(a: &ScpBallot, b: &ScpBallot) -> bool {
    ballot_compare(a, b) != std::cmp::Ordering::Greater && ballot_compatible(a, b)
}

fn are_ballots_less_and_incompatible(a: &ScpBallot, b: &ScpBallot) -> bool {
    ballot_compare(a, b) != std::cmp::Ordering::Greater && !ballot_compatible(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::ValidationLevel;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use stellar_xdr::curr::{PublicKey, ScpNomination, Uint256, VecM};

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
        let state = ballot.process_envelope(&env, &node, &quorum_set, &driver, 1);
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
        assert!(ballot.bump(&node_a, &quorum_set, &driver, 1, value.clone(), false));

        let current = ballot.current_ballot().expect("current ballot").clone();
        let env_b = make_prepare_envelope(node_b, 1, &quorum_set, current.clone());
        let env_c = make_prepare_envelope(node_c, 1, &quorum_set, current);

        ballot.process_envelope(&env_b, &node_a, &quorum_set, &driver, 1);
        ballot.process_envelope(&env_c, &node_a, &quorum_set, &driver, 1);

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

        let first = ballot.process_envelope(&prepare, &node, &quorum_set, &driver, 2);
        let second = ballot.process_envelope(&confirm, &node, &quorum_set, &driver, 2);
        let third = ballot.process_envelope(&prepare, &node, &quorum_set, &driver, 2);

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

        let first = ballot.process_envelope(&older, &node, &quorum_set, &driver, 4);
        let second = ballot.process_envelope(&newer, &node, &quorum_set, &driver, 4);
        let third = ballot.process_envelope(&older, &node, &quorum_set, &driver, 4);

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

        let first = ballot.process_envelope(&older, &node, &quorum_set, &driver, 5);
        let second = ballot.process_envelope(&newer, &node, &quorum_set, &driver, 5);
        let third = ballot.process_envelope(&older, &node, &quorum_set, &driver, 5);

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

        let first = ballot.process_envelope(&older, &node, &quorum_set, &driver, 6);
        let second = ballot.process_envelope(&newer, &node, &quorum_set, &driver, 6);
        let third = ballot.process_envelope(&older, &node, &quorum_set, &driver, 6);

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

        let first = ballot.process_envelope(&older, &node, &quorum_set, &driver, 7);
        let second = ballot.process_envelope(&newer, &node, &quorum_set, &driver, 7);
        let third = ballot.process_envelope(&older, &node, &quorum_set, &driver, 7);

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

        let first = ballot.process_envelope(&older, &node, &quorum_set, &driver, 8);
        let second = ballot.process_envelope(&newer, &node, &quorum_set, &driver, 8);
        let third = ballot.process_envelope(&older, &node, &quorum_set, &driver, 8);

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
        let quorum_set = make_quorum_set(vec![node.clone()], 1);
        let driver = Arc::new(MockDriver::new(quorum_set.clone()));
        let mut ballot = BallotProtocol::new();
        let value = make_value(&[5]);

        assert!(ballot.bump(&node, &quorum_set, &driver, 3, value, false));
        assert_eq!(ballot.current_ballot_counter(), Some(1));

        assert!(ballot.bump_timeout(&node, &quorum_set, &driver, 3));
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

        ballot.process_envelope(&env_local, &local, &quorum_set, &driver, 13);
        ballot.process_envelope(&env_remote, &local, &quorum_set, &driver, 13);

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
        ballot.process_envelope(&env_local, &local, &quorum_set, &driver, 14);

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
        assert!(ballot.bump(&node, &quorum_set, &driver, 15, value.clone(), false));

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

        ballot.process_envelope(&env2, &node, &quorum_set, &driver, 15);
        ballot.process_envelope(&env3, &node, &quorum_set, &driver, 15);
        ballot.process_envelope(&env4, &node, &quorum_set, &driver, 15);

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
            ballot.process_envelope(&bump_env2, &node, &quorum_set, &driver, 15),
            EnvelopeState::Invalid
        );
        assert_eq!(
            ballot.process_envelope(&bump_env3, &node, &quorum_set, &driver, 15),
            EnvelopeState::Invalid
        );
        assert_eq!(
            ballot.process_envelope(&bump_env4, &node, &quorum_set, &driver, 15),
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
        assert!(ballot.bump(&node, &quorum_set, &driver, 16, value.clone(), false));

        let current = ballot.current_ballot().expect("current ballot").clone();
        let prep2 = make_prepare_envelope(node2.clone(), 16, &quorum_set, current.clone());
        let prep3 = make_prepare_envelope(node3.clone(), 16, &quorum_set, current.clone());
        let prep4 = make_prepare_envelope(node4.clone(), 16, &quorum_set, current.clone());
        let prep5 = make_prepare_envelope(node5.clone(), 16, &quorum_set, current.clone());

        ballot.process_envelope(&prep2, &node, &quorum_set, &driver, 16);
        ballot.process_envelope(&prep3, &node, &quorum_set, &driver, 16);
        ballot.process_envelope(&prep4, &node, &quorum_set, &driver, 16);
        ballot.process_envelope(&prep5, &node, &quorum_set, &driver, 16);

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

        ballot.process_envelope(&prepared2, &node, &quorum_set, &driver, 16);
        ballot.process_envelope(&prepared3, &node, &quorum_set, &driver, 16);
        ballot.process_envelope(&prepared4, &node, &quorum_set, &driver, 16);
        ballot.process_envelope(&prepared5, &node, &quorum_set, &driver, 16);

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

        ballot.process_envelope(&confirm1, &node, &quorum_set, &driver, 16);
        ballot.process_envelope(&confirm2, &node, &quorum_set, &driver, 16);

        assert!(!ballot.is_externalized());

        ballot.process_envelope(&confirm4, &node, &quorum_set, &driver, 16);

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
        let quorum_set = make_quorum_set(vec![node.clone()], 1);
        let driver = Arc::new(MockDriver::new(quorum_set.clone()));
        let mut ballot = BallotProtocol::new();

        let value = make_value(&[1, 2, 3]);

        // First bump to counter 1
        assert!(ballot.bump(&node, &quorum_set, &driver, 1, value.clone(), false));
        assert_eq!(ballot.current_ballot().map(|b| b.counter), Some(1));

        // Now bump to specific counter 5
        assert!(ballot.bump_state(&node, &quorum_set, &driver, 1, value.clone(), 5));
        assert_eq!(ballot.current_ballot().map(|b| b.counter), Some(5));

        // Cannot go backwards
        assert!(!ballot.bump_state(&node, &quorum_set, &driver, 1, value.clone(), 3));
        assert_eq!(ballot.current_ballot().map(|b| b.counter), Some(5));

        // Can go forwards
        assert!(ballot.bump_state(&node, &quorum_set, &driver, 1, value.clone(), 10));
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
        assert!(!ballot.bump_state(&node, &quorum_set, &driver, 1, value.clone(), 10));
    }

    #[test]
    fn test_abandon_ballot_public() {
        let node = make_node_id(1);
        let quorum_set = make_quorum_set(vec![node.clone()], 1);
        let driver = Arc::new(MockDriver::new(quorum_set.clone()));
        let mut ballot = BallotProtocol::new();

        let value = make_value(&[1, 2, 3]);

        // Start with ballot counter 1
        assert!(ballot.bump(&node, &quorum_set, &driver, 1, value.clone(), false));
        assert_eq!(ballot.current_ballot().map(|b| b.counter), Some(1));

        // Abandon to counter 5
        assert!(ballot.abandon_ballot_public(5));
        assert_eq!(ballot.current_ballot().map(|b| b.counter), Some(5));

        // Abandon with counter 0 should auto-increment
        assert!(ballot.abandon_ballot_public(0));
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
}
