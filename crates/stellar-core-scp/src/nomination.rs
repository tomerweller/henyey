//! Nomination protocol implementation for SCP.
//!
//! The nomination protocol is the first phase of SCP consensus.
//! Nodes propose candidate values and vote to accept them. Once
//! a quorum accepts a set of values, they are combined into a
//! composite value that enters the ballot protocol.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use stellar_xdr::curr::{
    Limits, NodeId, ScpEnvelope, ScpNomination, ScpQuorumSet, ScpStatement,
    ScpStatementPledges, Value, WriteXdr,
};

use crate::driver::{SCPDriver, ValidationLevel};
use crate::quorum::{hash_quorum_set, is_blocking_set, is_quorum};
use crate::EnvelopeState;

/// State of the nomination protocol for a slot.
#[derive(Debug)]
pub struct NominationProtocol {
    /// Current nomination round.
    round: u32,
    /// Values we've voted for.
    votes: Vec<Value>,
    /// Values we've accepted.
    accepted: Vec<Value>,
    /// Values that have been ratified by a quorum.
    candidates: Vec<Value>,
    /// Nomination started flag.
    started: bool,
    /// Nomination stopped flag (moving to ballot).
    stopped: bool,
    /// Latest composite value (combination of accepted values).
    latest_composite: Option<Value>,
    /// Previous slot value (for priority hashing).
    previous_value: Option<Value>,
    /// Number of nomination timeouts.
    timer_exp_count: u32,
    /// Latest nomination envelopes from each node.
    latest_nominations: HashMap<NodeId, ScpEnvelope>,
    /// Round leaders (nodes we're nominating values from).
    round_leaders: HashSet<NodeId>,
    /// Last local envelope we built.
    last_envelope: Option<ScpEnvelope>,
    /// Last local envelope we emitted.
    last_envelope_emit: Option<ScpEnvelope>,
    /// Whether the slot is fully validated.
    fully_validated: bool,
}

impl NominationProtocol {
    /// Create a new nomination protocol state.
    pub fn new() -> Self {
        Self {
            round: 0,
            votes: Vec::new(),
            accepted: Vec::new(),
            candidates: Vec::new(),
            started: false,
            stopped: false,
            latest_composite: None,
            previous_value: None,
            timer_exp_count: 0,
            latest_nominations: HashMap::new(),
            round_leaders: HashSet::new(),
            last_envelope: None,
            last_envelope_emit: None,
            fully_validated: true,
        }
    }

    /// Get the current nomination round.
    pub fn round(&self) -> u32 {
        self.round
    }

    /// Check if nomination has started.
    pub fn is_started(&self) -> bool {
        self.started
    }

    /// Check if nomination has stopped.
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Update fully-validated state for local emission gating.
    pub fn set_fully_validated(&mut self, fully_validated: bool) {
        self.fully_validated = fully_validated;
    }

    /// Get the voted values.
    pub fn votes(&self) -> &[Value] {
        &self.votes
    }

    /// Get the accepted values.
    pub fn accepted(&self) -> &[Value] {
        &self.accepted
    }

    /// Get the latest composite value.
    pub fn latest_composite(&self) -> Option<&Value> {
        self.latest_composite.as_ref()
    }

    /// Process the latest nomination envelopes with a callback.
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
        let mut nodes: Vec<_> = self.latest_nominations.keys().collect();
        nodes.sort();

        for node_id in nodes {
            if !force_self && node_id == local_node_id && !fully_validated {
                continue;
            }

            if let Some(envelope) = self.latest_nominations.get(node_id) {
                if !f(envelope) {
                    return false;
                }
            }
        }

        true
    }

    /// Nominate a value for this slot.
    ///
    /// # Arguments
    /// * `local_node_id` - Our node ID
    /// * `local_quorum_set` - Our quorum set
    /// * `driver` - The SCP driver for callbacks
    /// * `slot_index` - The slot index
    /// * `value` - The value to nominate
    /// * `prev_value` - The previous slot's value (for priority calculation)
    /// * `timedout` - Whether this is a timeout-triggered nomination
    ///
    /// # Returns
    /// True if nomination was updated.
    pub fn nominate<D: SCPDriver>(
        &mut self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
        value: Value,
        prev_value: &Value,
        timedout: bool,
    ) -> bool {
        if self.stopped {
            return false;
        }

        // No need to continue nominating if we already have candidates.
        if !self.candidates.is_empty() {
            return false;
        }

        if timedout {
            self.timer_exp_count = self.timer_exp_count.saturating_add(1);
            if !self.started {
                return false;
            }
        }

        self.started = true;
        self.previous_value = Some(prev_value.clone());
        self.round = self.round.saturating_add(1);

        // Update round leaders
        self.update_round_leaders(
            local_node_id,
            local_quorum_set,
            driver,
            slot_index,
            prev_value,
        );

        let mut updated = false;

        // Add a few more values from other leaders
        for leader in self.round_leaders.clone() {
            if let Some(env) = self.latest_nominations.get(&leader) {
                if let ScpStatementPledges::Nominate(nom) = &env.statement.pledges {
                    if let Some(new_vote) =
                        self.get_new_value_from_nomination(nom, driver, slot_index)
                    {
                        if Self::insert_unique(&mut self.votes, new_vote.clone()) {
                            updated = true;
                            driver.nominating_value(slot_index, &new_vote);
                        }
                    }
                }
            }
        }

        // If we're a leader and haven't voted yet, add our value.
        if self.round_leaders.contains(local_node_id) && self.votes.is_empty() {
            let validation = driver.validate_value(slot_index, &value, true);
            if validation != ValidationLevel::Invalid
                && Self::insert_unique(&mut self.votes, value.clone())
            {
                updated = true;
                driver.nominating_value(slot_index, &value);
            }
        }

        // Emit nomination envelope
        if updated {
            self.emit_nomination(local_node_id, local_quorum_set, driver, slot_index);
        }

        updated
    }

    /// Process a nomination envelope from the network.
    ///
    /// # Returns
    /// The state of the envelope after processing.
    pub fn process_envelope<D: SCPDriver>(
        &mut self,
        envelope: &ScpEnvelope,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> EnvelopeState {
        let node_id = &envelope.statement.node_id;

        let nomination = match &envelope.statement.pledges {
            ScpStatementPledges::Nominate(nom) => nom,
            _ => return EnvelopeState::Invalid,
        };

        if !self.is_newer_statement(node_id, nomination) {
            return EnvelopeState::Invalid;
        }

        if !self.is_sane_statement(nomination) {
            return EnvelopeState::Invalid;
        }

        // Store the envelope
        self.latest_nominations
            .insert(node_id.clone(), envelope.clone());

        let mut state_changed = false;

        if self.started {
            let mut modified = false;
            let mut new_candidates = false;

            // Attempt to promote votes to accepted.
            for value in nomination.votes.iter() {
                if self.accepted.contains(value) {
                    continue;
                }

                if self.should_accept_value(value, local_quorum_set, driver, slot_index) {
                    match driver.validate_value(slot_index, value, true) {
                        ValidationLevel::FullyValidated => {
                            if Self::insert_unique(&mut self.accepted, value.clone()) {
                                Self::insert_unique(&mut self.votes, value.clone());
                                modified = true;
                            }
                        }
                        ValidationLevel::MaybeValid => {
                            if let Some(extracted) =
                                driver.extract_valid_value(slot_index, value)
                            {
                                if Self::insert_unique(&mut self.votes, extracted) {
                                    modified = true;
                                }
                            }
                        }
                        ValidationLevel::Invalid => {}
                    }
                }
            }

            // Attempt to promote accepted values to candidates.
            for value in self.accepted.clone() {
                if self.candidates.contains(&value) {
                    continue;
                }

                if self.should_ratify_value(&value, local_quorum_set, driver) {
                    if Self::insert_unique(&mut self.candidates, value.clone()) {
                        new_candidates = true;
                    }
                }
            }

            if new_candidates {
                self.update_composite(driver, slot_index);
                state_changed = true;
            }

            if modified {
                self.emit_nomination(local_node_id, local_quorum_set, driver, slot_index);
                state_changed = true;
            }
        }

        if state_changed {
            EnvelopeState::ValidNew
        } else {
            EnvelopeState::Valid
        }
    }

    /// Stop nomination (transition to ballot protocol).
    pub fn stop(&mut self) {
        self.stopped = true;
    }

    /// Get the nodes that have voted for a value.
    fn get_nodes_that_voted(&self, value: &Value) -> HashSet<NodeId> {
        let mut nodes = HashSet::new();

        for (node_id, envelope) in &self.latest_nominations {
            if let ScpStatementPledges::Nominate(nom) = &envelope.statement.pledges {
                for voted in nom.votes.iter() {
                    if voted == value {
                        nodes.insert(node_id.clone());
                        break;
                    }
                }
            }
        }

        nodes
    }

    /// Get the nodes that have accepted a value.
    fn get_nodes_that_accepted(&self, value: &Value) -> HashSet<NodeId> {
        let mut nodes = HashSet::new();

        for (node_id, envelope) in &self.latest_nominations {
            if let ScpStatementPledges::Nominate(nom) = &envelope.statement.pledges {
                for accepted in nom.accepted.iter() {
                    if accepted == value {
                        nodes.insert(node_id.clone());
                        break;
                    }
                }
            }
        }

        nodes
    }

    /// Update the composite value from accepted values.
    fn update_composite<D: SCPDriver>(&mut self, driver: &Arc<D>, slot_index: u64) {
        if self.candidates.is_empty() {
            return;
        }

        // Combine all candidates
        if let Some(composite) = driver.combine_candidates(slot_index, &self.candidates) {
            if self.latest_composite.as_ref() != Some(&composite) {
                self.latest_composite = Some(composite);
            }
        }
    }

    /// Emit a nomination envelope.
    fn emit_nomination<D: SCPDriver>(
        &mut self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) {
        let votes = self.sorted_values(&self.votes);
        let accepted = self.sorted_values(&self.accepted);
        let nomination = ScpNomination {
            quorum_set_hash: hash_quorum_set(local_quorum_set).into(),
            votes: votes.try_into().unwrap_or_default(),
            accepted: accepted.try_into().unwrap_or_default(),
        };

        let statement = ScpStatement {
            node_id: local_node_id.clone(),
            slot_index,
            pledges: ScpStatementPledges::Nominate(nomination),
        };

        let mut envelope = ScpEnvelope {
            statement: statement.clone(),
            signature: stellar_xdr::curr::Signature(
                Vec::new().try_into().unwrap_or_default(),
            ),
        };

        driver.sign_envelope(&mut envelope);
        if self.record_local_nomination(local_node_id, &statement, envelope.clone()) {
            self.last_envelope = Some(envelope.clone());
            self.send_latest_envelope(driver);
        }
    }

    fn send_latest_envelope<D: SCPDriver>(&mut self, driver: &Arc<D>) {
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

    fn record_local_nomination(
        &mut self,
        local_node_id: &NodeId,
        statement: &ScpStatement,
        envelope: ScpEnvelope,
    ) -> bool {
        let nomination = match &statement.pledges {
            ScpStatementPledges::Nominate(nom) => nom,
            _ => return false,
        };
        if !self.is_newer_statement(local_node_id, nomination) {
            return false;
        }
        // Safe to insert: we only store nominations here.
        // This keeps local state in the same envelope stream as remote peers.
        self.latest_nominations
            .insert(local_node_id.clone(), envelope);
        true
    }

    fn is_newer_statement(&self, node_id: &NodeId, nomination: &ScpNomination) -> bool {
        match self.latest_nominations.get(node_id) {
            None => true,
            Some(existing) => {
                if let ScpStatementPledges::Nominate(existing_nom) =
                    &existing.statement.pledges
                {
                    self.is_newer_nomination(existing_nom, nomination)
                } else {
                    true
                }
            }
        }
    }

    fn is_newer_nomination(&self, old_nom: &ScpNomination, new_nom: &ScpNomination) -> bool {
        let old_votes = self.value_set(&old_nom.votes);
        let old_accepted = self.value_set(&old_nom.accepted);
        let new_votes = self.value_set(&new_nom.votes);
        let new_accepted = self.value_set(&new_nom.accepted);

        let votes_grew = old_votes.is_subset(&new_votes) && old_votes.len() < new_votes.len();
        let accepted_grew =
            old_accepted.is_subset(&new_accepted) && old_accepted.len() < new_accepted.len();

        (old_votes.is_subset(&new_votes) && old_accepted.is_subset(&new_accepted))
            && (votes_grew || accepted_grew)
    }

    fn is_sane_statement(&self, nomination: &ScpNomination) -> bool {
        if nomination.votes.is_empty() && nomination.accepted.is_empty() {
            return false;
        }

        self.is_sorted_unique(&nomination.votes) && self.is_sorted_unique(&nomination.accepted)
    }

    fn is_sorted_unique(&self, values: &[Value]) -> bool {
        if values.is_empty() {
            return true;
        }
        let mut prev = self.value_key(&values[0]);
        for value in values.iter().skip(1) {
            let key = self.value_key(value);
            if key <= prev {
                return false;
            }
            prev = key;
        }
        true
    }

    fn value_set(&self, values: &[Value]) -> HashSet<Vec<u8>> {
        values.iter().map(|v| self.value_key(v)).collect()
    }

    fn value_key(&self, value: &Value) -> Vec<u8> {
        value.to_xdr(Limits::none()).unwrap_or_default()
    }

    fn sorted_values(&self, values: &[Value]) -> Vec<Value> {
        let mut values = values.to_vec();
        values.sort_by(|a, b| self.value_key(a).cmp(&self.value_key(b)));
        values.dedup_by(|a, b| self.value_key(a) == self.value_key(b));
        values
    }

    fn insert_unique(values: &mut Vec<Value>, value: Value) -> bool {
        if values.contains(&value) {
            return false;
        }
        values.push(value);
        true
    }

    fn should_accept_value<D: SCPDriver>(
        &self,
        value: &Value,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        _slot_index: u64,
    ) -> bool {
        let voters = self.get_nodes_that_voted(value);
        let acceptors = self.get_nodes_that_accepted(value);
        let supporters: HashSet<_> = voters.union(&acceptors).cloned().collect();
        let get_qs = |node_id: &NodeId| -> Option<ScpQuorumSet> { driver.get_quorum_set(node_id) };

        is_blocking_set(local_quorum_set, &acceptors)
            || is_quorum(local_quorum_set, &supporters, get_qs)
    }

    fn should_ratify_value<D: SCPDriver>(
        &self,
        value: &Value,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
    ) -> bool {
        let acceptors = self.get_nodes_that_accepted(value);
        let get_qs = |node_id: &NodeId| -> Option<ScpQuorumSet> { driver.get_quorum_set(node_id) };
        is_quorum(local_quorum_set, &acceptors, get_qs)
    }

    fn get_new_value_from_nomination<D: SCPDriver>(
        &self,
        nomination: &ScpNomination,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> Option<Value> {
        let mut best: Option<(u64, Value)> = None;
        let mut found_valid = false;

        let consider_value = |value: &Value,
                              found_valid: &mut bool,
                              best: &mut Option<(u64, Value)>| {
            let candidate = match driver.validate_value(slot_index, value, true) {
                ValidationLevel::FullyValidated => {
                    *found_valid = true;
                    Some(value.clone())
                }
                ValidationLevel::MaybeValid => driver.extract_valid_value(slot_index, value),
                ValidationLevel::Invalid => None,
            };

            if let Some(candidate) = candidate {
                if self.votes.contains(&candidate) {
                    return;
                }
                let hash = self.hash_value(driver, slot_index, &candidate);
                match best {
                    None => *best = Some((hash, candidate)),
                    Some((best_hash, _)) if hash >= *best_hash => {
                        *best = Some((hash, candidate))
                    }
                    _ => {}
                }
            }
        };

        for value in nomination.accepted.iter() {
            consider_value(value, &mut found_valid, &mut best);
        }

        if !found_valid {
            for value in nomination.votes.iter() {
                consider_value(value, &mut found_valid, &mut best);
            }
        }

        best.map(|(_, value)| value)
    }

    fn hash_value<D: SCPDriver>(&self, driver: &Arc<D>, slot_index: u64, value: &Value) -> u64 {
        let prev = self.previous_value.as_ref().unwrap_or(value);
        driver.compute_value_hash(slot_index, prev, self.round, value)
    }

    fn update_round_leaders<D: SCPDriver>(
        &mut self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
        prev_value: &Value,
    ) {
        let max_leader_count = 1 + self.count_quorum_nodes(local_quorum_set, local_node_id);

        while self.round_leaders.len() < max_leader_count {
            let mut new_leaders = HashSet::new();
            let mut top_priority = self.get_node_priority(
                local_quorum_set,
                driver,
                slot_index,
                prev_value,
                local_node_id,
                local_node_id,
            );
            new_leaders.insert(local_node_id.clone());

            self.for_each_quorum_node(local_quorum_set, local_node_id, &mut |node| {
                let priority = self.get_node_priority(
                    local_quorum_set,
                    driver,
                    slot_index,
                    prev_value,
                    local_node_id,
                    node,
                );
                if priority > top_priority {
                    top_priority = priority;
                    new_leaders.clear();
                }
                if priority == top_priority && priority > 0 {
                    new_leaders.insert(node.clone());
                }
            });

            if top_priority == 0 {
                new_leaders.clear();
            }

            let old_size = self.round_leaders.len();
            self.round_leaders.extend(new_leaders);
            if self.round_leaders.len() != old_size {
                return;
            }

            self.round = self.round.saturating_add(1);
        }
    }

    fn get_node_priority<D: SCPDriver>(
        &self,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
        prev_value: &Value,
        local_node_id: &NodeId,
        node_id: &NodeId,
    ) -> u64 {
        let weight = self.get_node_weight(local_quorum_set, local_node_id, node_id);
        if weight == 0 {
            return 0;
        }

        let hash = driver.compute_hash_node(slot_index, prev_value, false, self.round, node_id);
        if hash <= weight {
            driver.compute_hash_node(slot_index, prev_value, true, self.round, node_id)
        } else {
            0
        }
    }

    fn get_node_weight(
        &self,
        quorum_set: &ScpQuorumSet,
        local_node_id: &NodeId,
        node_id: &NodeId,
    ) -> u64 {
        if node_id == local_node_id {
            return u64::MAX;
        }

        let total = quorum_set.validators.len() + quorum_set.inner_sets.len();
        let threshold = quorum_set.threshold as u64;
        if threshold == 0 || total == 0 {
            return 0;
        }

        if quorum_set.validators.contains(node_id) {
            return self.compute_weight(u64::MAX, total as u64, threshold);
        }

        for inner in quorum_set.inner_sets.iter() {
            let weight = self.get_node_weight(inner, local_node_id, node_id);
            if weight > 0 {
                return self.compute_weight(weight, total as u64, threshold);
            }
        }

        0
    }

    fn compute_weight(&self, m: u64, total: u64, threshold: u64) -> u64 {
        if threshold == 0 || total == 0 {
            return 0;
        }
        let numerator = (m as u128) * (threshold as u128);
        let denominator = total as u128;
        let mut res = numerator / denominator;
        if numerator % denominator != 0 {
            res += 1;
        }
        res as u64
    }

    fn for_each_quorum_node<F>(
        &self,
        quorum_set: &ScpQuorumSet,
        local_node_id: &NodeId,
        f: &mut F,
    )
    where
        F: FnMut(&NodeId),
    {
        for node in quorum_set.validators.iter() {
            if node != local_node_id {
                f(node);
            }
        }
        for inner in quorum_set.inner_sets.iter() {
            self.for_each_quorum_node(inner, local_node_id, f);
        }
    }

    fn count_quorum_nodes(
        &self,
        quorum_set: &ScpQuorumSet,
        local_node_id: &NodeId,
    ) -> usize {
        let mut count = quorum_set
            .validators
            .iter()
            .filter(|node| *node != local_node_id)
            .count();
        for inner in quorum_set.inner_sets.iter() {
            count += self.count_quorum_nodes(inner, local_node_id);
        }
        count
    }

}

impl Default for NominationProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::ValidationLevel;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;
    use stellar_xdr::curr::{PublicKey, ScpBallot, Uint256};

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
        let env = make_nomination_envelope(
            make_node_id(2),
            7,
            &quorum_set,
            vec![v2, v1],
            vec![],
        );
        let state = nom.process_envelope(&env, &node, &quorum_set, &driver, 7);
        assert_eq!(state, EnvelopeState::Invalid);
    }

    #[test]
    fn test_nomination_rejects_non_monotonic_statement() {
        let node = make_node_id(1);
        let quorum_set = make_quorum_set(vec![node.clone()], 1);
        let driver = Arc::new(MockDriver::new(quorum_set.clone()));
        let mut nom = NominationProtocol::new();

        let v1 = make_value(&[1]);
        let env = make_nomination_envelope(
            make_node_id(2),
            8,
            &quorum_set,
            vec![v1.clone()],
            vec![],
        );
        let first = nom.process_envelope(&env, &node, &quorum_set, &driver, 8);
        let second = nom.process_envelope(&env, &node, &quorum_set, &driver, 8);

        assert!(matches!(first, EnvelopeState::Valid | EnvelopeState::ValidNew));
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
        nom.nominate(&node, &quorum_set, &driver, 9, value.clone(), &prev, false);

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

        nom.process_envelope(&env2, &node, &quorum_set, &driver, 9);
        nom.process_envelope(&env3, &node, &quorum_set, &driver, 9);

        assert!(nom.accepted().contains(&value));
        assert_eq!(nom.latest_composite(), Some(&value));
    }

    #[test]
    fn test_nomination_timeout_requires_start() {
        let node = make_node_id(1);
        let quorum_set = make_quorum_set(vec![node.clone()], 1);
        let driver = Arc::new(MockDriver::new(quorum_set.clone()));
        let mut nom = NominationProtocol::new();
        let value = make_value(&[4]);
        let prev = make_value(&[0]);

        let timed_out = nom.nominate(&node, &quorum_set, &driver, 10, value.clone(), &prev, true);
        assert!(!timed_out);
        assert!(!nom.is_started());

        nom.nominate(&node, &quorum_set, &driver, 10, value.clone(), &prev, false);
        let round_before = nom.round();

        nom.nominate(&node, &quorum_set, &driver, 10, value, &prev, true);
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
        let env_local = make_nomination_envelope(
            local.clone(),
            11,
            &quorum_set,
            vec![value_local],
            vec![],
        );
        let env_remote = make_nomination_envelope(
            remote.clone(),
            11,
            &quorum_set,
            vec![value_remote],
            vec![],
        );

        nom.process_envelope(&env_local, &local, &quorum_set, &driver, 11);
        nom.process_envelope(&env_remote, &local, &quorum_set, &driver, 11);

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
        let env_local = make_nomination_envelope(
            local.clone(),
            12,
            &quorum_set,
            vec![value_local],
            vec![],
        );

        nom.process_envelope(&env_local, &local, &quorum_set, &driver, 12);

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

        nom.process_envelope(&env_b, &local, &quorum_set, &driver, 13);
        nom.process_envelope(&env_c, &local, &quorum_set, &driver, 13);
        nom.process_envelope(&env_local, &local, &quorum_set, &driver, 13);

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
        let env_old = make_nomination_envelope(
            remote.clone(),
            14,
            &quorum_set,
            vec![value.clone()],
            vec![],
        );
        let env_new = make_nomination_envelope(
            remote.clone(),
            14,
            &quorum_set,
            vec![value.clone()],
            vec![value],
        );

        nom.process_envelope(&env_old, &local, &quorum_set, &driver, 14);
        nom.process_envelope(&env_new, &local, &quorum_set, &driver, 14);

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
        let env_new = make_nomination_envelope(
            remote.clone(),
            15,
            &quorum_set,
            vec![value_a],
            vec![],
        );

        let first = nom.process_envelope(&env_old, &local, &quorum_set, &driver, 15);
        let second = nom.process_envelope(&env_new, &local, &quorum_set, &driver, 15);

        assert!(matches!(first, EnvelopeState::Valid | EnvelopeState::ValidNew));
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

        nom.process_envelope(&env_remote, &local, &quorum_set, &driver, 16);
        nom.process_envelope(&env_local, &local, &quorum_set, &driver, 16);

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
}
