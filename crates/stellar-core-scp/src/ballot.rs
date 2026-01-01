//! Ballot protocol implementation for SCP.
//!
//! The ballot protocol is the second phase of SCP consensus.
//! After nomination produces a composite value, nodes use the
//! ballot protocol to agree on that exact value through:
//! - PREPARE: Vote to prepare a ballot
//! - CONFIRM: Confirm a ballot is prepared
//! - EXTERNALIZE: Commit to the value

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use stellar_xdr::curr::{
    Limits, NodeId, ScpBallot, ScpEnvelope, ScpQuorumSet, ScpStatement,
    ScpStatementConfirm, ScpStatementExternalize, ScpStatementPledges, ScpStatementPrepare,
    Value, WriteXdr,
};

use crate::driver::SCPDriver;
use crate::quorum::{hash_quorum_set, is_blocking_set, is_quorum};
use crate::EnvelopeState;

/// Phase of the ballot protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BallotPhase {
    /// Preparing a ballot.
    Prepare,
    /// Confirming a prepared ballot.
    Confirm,
    /// Externalized (consensus reached).
    Externalize,
}

/// State of the ballot protocol for a slot.
#[derive(Debug)]
pub struct BallotProtocol {
    /// Current ballot we're working on.
    current_ballot: Option<ScpBallot>,
    /// Highest prepared ballot (p in the whitepaper).
    prepared: Option<ScpBallot>,
    /// Second highest prepared ballot (p' in the whitepaper).
    prepared_prime: Option<ScpBallot>,
    /// Highest ballot we can confirm prepare (h in the whitepaper).
    high_ballot: Option<ScpBallot>,
    /// Commit ballot (c in the whitepaper).
    commit: Option<ScpBallot>,
    /// Current phase.
    phase: BallotPhase,
    /// Latest envelopes from each node.
    latest_envelopes: HashMap<NodeId, ScpEnvelope>,
    /// Value being confirmed/externalized.
    value: Option<Value>,
    /// Whether we've heard from quorum in current round.
    heard_from_quorum: bool,
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
            heard_from_quorum: false,
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

    /// Get the externalized value if we've reached consensus.
    pub fn get_externalized_value(&self) -> Option<&Value> {
        if self.phase == BallotPhase::Externalize {
            self.value.as_ref()
        } else {
            None
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

        // Calculate new ballot counter
        let counter = if let Some(ref current) = self.current_ballot {
            if force {
                current.counter + 1
            } else if current.value == value {
                // Same value, no need to bump
                return false;
            } else {
                current.counter + 1
            }
        } else {
            1
        };

        let ballot = ScpBallot {
            counter,
            value: value.clone(),
        };

        self.current_ballot = Some(ballot.clone());
        self.value = Some(value);

        // Emit prepare statement
        self.emit_prepare(local_node_id, local_quorum_set, driver, slot_index);

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
            self.emit_current_state(local_node_id, local_quorum_set, driver, slot_index);
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

        // Store the envelope
        self.latest_envelopes
            .insert(node_id.clone(), envelope.clone());

        // Process based on statement type
        match &envelope.statement.pledges {
            ScpStatementPledges::Prepare(_) => {
                self.advance_slot(local_node_id, local_quorum_set, driver, slot_index)
            }
            ScpStatementPledges::Confirm(_) => {
                self.advance_slot(local_node_id, local_quorum_set, driver, slot_index)
            }
            ScpStatementPledges::Externalize(ext) => {
                // If we receive externalize from enough nodes, we should externalize too
                self.try_accept_externalize(
                    ext,
                    local_node_id,
                    local_quorum_set,
                    driver,
                    slot_index,
                )
            }
            _ => EnvelopeState::Invalid,
        }
    }

    fn is_newer_statement(&self, node_id: &NodeId, statement: &ScpStatement) -> bool {
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
                    let cmp_prepared = self.compare_optional_ballots(&old_p.prepared, &new_p.prepared);
                    if cmp_prepared < 0 {
                        return true;
                    }
                    if cmp_prepared == 0 {
                        let cmp_prime =
                            self.compare_optional_ballots(&old_p.prepared_prime, &new_p.prepared_prime);
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
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> EnvelopeState {
        match self.phase {
            BallotPhase::Prepare => {
                self.try_advance_prepare(
                    local_node_id,
                    local_quorum_set,
                    driver,
                    slot_index,
                )
            }
            BallotPhase::Confirm => {
                self.try_advance_confirm(
                    local_node_id,
                    local_quorum_set,
                    driver,
                    slot_index,
                )
            }
            BallotPhase::Externalize => EnvelopeState::Valid,
        }
    }

    /// Try to advance from prepare phase.
    fn try_advance_prepare<D: SCPDriver>(
        &mut self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> EnvelopeState {
        // Check if we can accept "prepare(b)" for any ballot b
        if let Some(ref current) = self.current_ballot.clone() {
            // Get nodes that have voted or accepted prepare for this ballot
            let preparers = self.get_nodes_that_prepared_or_better(current);

            let get_qs = |node_id: &NodeId| -> Option<ScpQuorumSet> {
                driver.get_quorum_set(node_id)
            };

            // Check if quorum has prepared
            if is_quorum(local_quorum_set, &preparers, get_qs) {
                // Accept prepare
                self.set_prepared(current.clone(), driver, slot_index);

                // Check if we can move to confirm
                let confirmers = self.get_nodes_that_confirmed_or_better(current);
                let get_qs = |node_id: &NodeId| -> Option<ScpQuorumSet> {
                    driver.get_quorum_set(node_id)
                };
                if is_quorum(local_quorum_set, &confirmers, get_qs) {
                    self.phase = BallotPhase::Confirm;
                    self.emit_confirm(local_node_id, local_quorum_set, driver, slot_index);
                    driver.ballot_did_confirm(slot_index, current);
                } else {
                    self.emit_prepare(local_node_id, local_quorum_set, driver, slot_index);
                }
            } else if is_blocking_set(local_quorum_set, &preparers) {
                // Blocking set has prepared - we should too
                self.set_prepared(current.clone(), driver, slot_index);
                self.emit_prepare(local_node_id, local_quorum_set, driver, slot_index);
            }
        }

        EnvelopeState::ValidNew
    }

    /// Try to advance from confirm phase.
    fn try_advance_confirm<D: SCPDriver>(
        &mut self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> EnvelopeState {
        if let Some(ref current) = self.current_ballot.clone() {
            // Get nodes that have externalized
            let externalizers = self.get_nodes_that_externalized(&current.value);

            let get_qs = |node_id: &NodeId| -> Option<ScpQuorumSet> {
                driver.get_quorum_set(node_id)
            };

            // Check if quorum has externalized
            if is_quorum(local_quorum_set, &externalizers, get_qs) {
                // We can externalize
                self.do_externalize(
                    &current.value.clone(),
                    local_node_id,
                    local_quorum_set,
                    driver,
                    slot_index,
                );
            } else if is_blocking_set(local_quorum_set, &externalizers) {
                // Blocking set has externalized - we should too
                self.do_externalize(
                    &current.value.clone(),
                    local_node_id,
                    local_quorum_set,
                    driver,
                    slot_index,
                );
            }
        }

        EnvelopeState::ValidNew
    }

    /// Try to accept externalize from received envelope.
    fn try_accept_externalize<D: SCPDriver>(
        &mut self,
        ext: &ScpStatementExternalize,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> EnvelopeState {
        let value = &ext.commit.value;

        // Get nodes that have externalized this value
        let externalizers = self.get_nodes_that_externalized(value);

        let get_qs = |node_id: &NodeId| -> Option<ScpQuorumSet> {
            driver.get_quorum_set(node_id)
        };

        // If quorum or blocking set has externalized, we should too
        if is_quorum(local_quorum_set, &externalizers, get_qs)
            || is_blocking_set(local_quorum_set, &externalizers)
        {
            self.do_externalize(
                value,
                local_node_id,
                local_quorum_set,
                driver,
                slot_index,
            );
        }

        EnvelopeState::ValidNew
    }

    /// Set prepared ballot.
    fn set_prepared<D: SCPDriver>(
        &mut self,
        ballot: ScpBallot,
        driver: &Arc<D>,
        slot_index: u64,
    ) {
        // Update prepared and prepared_prime
        if let Some(ref current_prepared) = self.prepared {
            if ballot_compare(&ballot, current_prepared) == std::cmp::Ordering::Greater {
                self.prepared_prime = self.prepared.take();
                self.prepared = Some(ballot.clone());
                driver.ballot_did_prepare(slot_index, &ballot);
            }
        } else {
            self.prepared = Some(ballot.clone());
            driver.ballot_did_prepare(slot_index, &ballot);
        }
    }

    /// Finalize externalization.
    fn do_externalize<D: SCPDriver>(
        &mut self,
        value: &Value,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) {
        if self.phase == BallotPhase::Externalize {
            return;
        }

        self.phase = BallotPhase::Externalize;
        self.value = Some(value.clone());

        // Set commit ballot
        if self.commit.is_none() {
            if let Some(ref current) = self.current_ballot {
                self.commit = Some(current.clone());
            } else {
                // Create a commit ballot with counter 1
                self.commit = Some(ScpBallot {
                    counter: 1,
                    value: value.clone(),
                });
            }
        }

        // Emit externalize statement
        self.emit_externalize(local_node_id, local_quorum_set, driver, slot_index);

        // Notify driver
        driver.value_externalized(slot_index, value);
    }

    /// Get nodes that have prepared or confirmed/externalized a ballot.
    fn get_nodes_that_prepared_or_better(&self, ballot: &ScpBallot) -> HashSet<NodeId> {
        let mut nodes = HashSet::new();

        for (node_id, envelope) in &self.latest_envelopes {
            match &envelope.statement.pledges {
                ScpStatementPledges::Prepare(prep) => {
                    // Check if prepared ballot is >= our ballot
                    if ballot_compatible(&prep.ballot, ballot) {
                        nodes.insert(node_id.clone());
                    }
                }
                ScpStatementPledges::Confirm(conf) => {
                    if ballot_compatible(&conf.ballot, ballot) {
                        nodes.insert(node_id.clone());
                    }
                }
                ScpStatementPledges::Externalize(ext) => {
                    if ext.commit.value == ballot.value {
                        nodes.insert(node_id.clone());
                    }
                }
                _ => {}
            }
        }

        nodes
    }

    /// Get nodes that have confirmed or externalized a ballot.
    fn get_nodes_that_confirmed_or_better(&self, ballot: &ScpBallot) -> HashSet<NodeId> {
        let mut nodes = HashSet::new();

        for (node_id, envelope) in &self.latest_envelopes {
            match &envelope.statement.pledges {
                ScpStatementPledges::Confirm(conf) => {
                    if ballot_compatible(&conf.ballot, ballot) {
                        nodes.insert(node_id.clone());
                    }
                }
                ScpStatementPledges::Externalize(ext) => {
                    if ext.commit.value == ballot.value {
                        nodes.insert(node_id.clone());
                    }
                }
                _ => {}
            }
        }

        nodes
    }

    /// Get nodes that have externalized a specific value.
    fn get_nodes_that_externalized(&self, value: &Value) -> HashSet<NodeId> {
        let mut nodes = HashSet::new();

        for (node_id, envelope) in &self.latest_envelopes {
            if let ScpStatementPledges::Externalize(ext) = &envelope.statement.pledges {
                if &ext.commit.value == value {
                    nodes.insert(node_id.clone());
                }
            }
        }

        nodes
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
                signature: stellar_xdr::curr::Signature(
                    Vec::new().try_into().unwrap_or_default(),
                ),
            };

            driver.sign_envelope(&mut envelope);
            self.record_local_envelope(local_node_id, envelope.clone());
            driver.emit_envelope(&envelope);
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
                signature: stellar_xdr::curr::Signature(
                    Vec::new().try_into().unwrap_or_default(),
                ),
            };

            driver.sign_envelope(&mut envelope);
            self.record_local_envelope(local_node_id, envelope.clone());
            driver.emit_envelope(&envelope);
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
                signature: stellar_xdr::curr::Signature(
                    Vec::new().try_into().unwrap_or_default(),
                ),
            };

            driver.sign_envelope(&mut envelope);
            self.record_local_envelope(local_node_id, envelope.clone());
            driver.emit_envelope(&envelope);
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

    fn record_local_envelope(&mut self, local_node_id: &NodeId, envelope: ScpEnvelope) {
        if !self.is_newer_statement(local_node_id, &envelope.statement) {
            return;
        }
        self.latest_envelopes
            .insert(local_node_id.clone(), envelope);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::ValidationLevel;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
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

        fn combine_candidates(
            &self,
            _slot_index: u64,
            candidates: &[Value],
        ) -> Option<Value> {
            candidates.first().cloned()
        }

        fn extract_valid_value(
            &self,
            _slot_index: u64,
            value: &Value,
        ) -> Option<Value> {
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
    fn test_ballot_statement_ordering() {
        let node = make_node_id(1);
        let quorum_set = make_quorum_set(vec![node.clone()], 1);
        let driver = Arc::new(MockDriver::new(quorum_set.clone()));
        let mut ballot = BallotProtocol::new();
        let value = make_value(&[7]);
        let ballot_value = ScpBallot {
            counter: 1,
            value,
        };

        let prepare = make_prepare_envelope(make_node_id(2), 2, &quorum_set, ballot_value.clone());
        let confirm = make_confirm_envelope(make_node_id(2), 2, &quorum_set, ballot_value.clone());

        let first = ballot.process_envelope(&prepare, &node, &quorum_set, &driver, 2);
        let second = ballot.process_envelope(&confirm, &node, &quorum_set, &driver, 2);
        let third = ballot.process_envelope(&prepare, &node, &quorum_set, &driver, 2);

        assert!(matches!(first, EnvelopeState::Valid | EnvelopeState::ValidNew));
        assert!(matches!(second, EnvelopeState::Valid | EnvelopeState::ValidNew));
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
}
