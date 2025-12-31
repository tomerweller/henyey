//! Nomination protocol implementation for SCP.
//!
//! The nomination protocol is the first phase of SCP consensus.
//! Nodes propose candidate values and vote to accept them. Once
//! a quorum accepts a set of values, they are combined into a
//! composite value that enters the ballot protocol.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use stellar_xdr::curr::{
    NodeId, ScpEnvelope, ScpNomination, ScpQuorumSet, ScpStatement,
    ScpStatementPledges, Value,
};

use crate::driver::{SCPDriver, ValidationLevel};
use crate::quorum::{hash_quorum_set, is_blocking_set, is_quorum_slice};
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
    /// Nomination started flag.
    started: bool,
    /// Nomination stopped flag (moving to ballot).
    stopped: bool,
    /// Latest composite value (combination of accepted values).
    latest_composite: Option<Value>,
    /// Latest nomination envelopes from each node.
    latest_nominations: HashMap<NodeId, ScpEnvelope>,
    /// Round leaders (nodes we're nominating values from).
    round_leaders: HashSet<NodeId>,
    /// Previously confirmed values.
    previously_accepted: HashSet<Value>,
}

impl NominationProtocol {
    /// Create a new nomination protocol state.
    pub fn new() -> Self {
        Self {
            round: 0,
            votes: Vec::new(),
            accepted: Vec::new(),
            started: false,
            stopped: false,
            latest_composite: None,
            latest_nominations: HashMap::new(),
            round_leaders: HashSet::new(),
            previously_accepted: HashSet::new(),
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

        // Bump round on timeout
        if timedout && self.started {
            self.round += 1;
        }

        self.started = true;

        // Update round leaders
        self.update_round_leaders(local_quorum_set, driver, slot_index, prev_value);

        // Add value to votes if not already present and valid
        let validation = driver.validate_value(slot_index, &value, true);
        if validation != ValidationLevel::Invalid && !self.votes.contains(&value) {
            self.votes.push(value.clone());
            driver.nominating_value(slot_index, &value);
        }

        // Emit nomination envelope
        self.emit_nomination(local_node_id, local_quorum_set, driver, slot_index);

        true
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

        // Check if this is newer than what we have
        if let Some(existing) = self.latest_nominations.get(node_id) {
            if let ScpStatementPledges::Nominate(existing_nom) =
                &existing.statement.pledges
            {
                // Newer means more votes or accepted values
                let is_newer = nomination.votes.len() > existing_nom.votes.len()
                    || nomination.accepted.len() > existing_nom.accepted.len();
                if !is_newer {
                    return EnvelopeState::Valid;
                }
            }
        }

        // Store the envelope
        self.latest_nominations
            .insert(node_id.clone(), envelope.clone());

        // Process voted and accepted values
        self.process_nomination_values(
            nomination,
            local_quorum_set,
            driver,
            slot_index,
        );

        // Update accepted values based on quorum
        let state_changed = self.update_accepted(local_quorum_set, driver, slot_index);

        // Update composite value
        if !self.accepted.is_empty() {
            self.update_composite(driver, slot_index);
        }

        // Re-emit if our state changed
        if state_changed {
            self.emit_nomination(local_node_id, local_quorum_set, driver, slot_index);
        }

        EnvelopeState::ValidNew
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

    /// Update round leaders based on hash-based priority.
    fn update_round_leaders<D: SCPDriver>(
        &mut self,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
        prev_value: &Value,
    ) {
        self.round_leaders.clear();

        // Collect all known nodes
        let mut all_nodes = HashSet::new();
        for validator in local_quorum_set.validators.iter() {
            all_nodes.insert(validator.clone());
        }

        // Add nodes from latest nominations
        for node_id in self.latest_nominations.keys() {
            all_nodes.insert(node_id.clone());
        }

        // Select leaders based on priority hash
        for node_id in all_nodes {
            let priority = driver.compute_hash_node(
                slot_index,
                prev_value,
                true,
                self.round,
                &node_id,
            );

            // Use a simple priority threshold (real implementation is more complex)
            // For now, include all nodes as potential leaders
            self.round_leaders.insert(node_id);
        }
    }

    /// Process votes and accepted values from a nomination.
    fn process_nomination_values<D: SCPDriver>(
        &mut self,
        nomination: &ScpNomination,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) {
        // Process voted values - we may want to add them to our votes
        for value in nomination.votes.iter() {
            if !self.votes.contains(value) && !self.accepted.contains(value) {
                // Validate before considering
                let validation = driver.validate_value(slot_index, value, true);
                if validation != ValidationLevel::Invalid {
                    // Could add to votes if from a leader
                    // (simplified - real implementation checks priority)
                }
            }
        }

        // Process accepted values - if a blocking set accepted, we should too
        for value in nomination.accepted.iter() {
            if !self.accepted.contains(value) {
                // Check if a blocking set has accepted this value
                let acceptors = self.get_nodes_that_accepted(value);
                if is_blocking_set(local_quorum_set, &acceptors) {
                    // Validate before accepting
                    let validation = driver.validate_value(slot_index, value, true);
                    if validation != ValidationLevel::Invalid {
                        self.accepted.push(value.clone());
                    }
                }
            }
        }
    }

    /// Update accepted values based on quorum analysis.
    ///
    /// A value is accepted if:
    /// 1. We voted for it AND a quorum has voted or accepted it, OR
    /// 2. A blocking set has accepted it
    fn update_accepted<D: SCPDriver>(
        &mut self,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> bool {
        let mut changed = false;

        // Check each voted value
        for value in self.votes.clone() {
            if self.accepted.contains(&value) {
                continue;
            }

            // Get nodes that have voted or accepted this value
            let voters = self.get_nodes_that_voted(&value);
            let acceptors = self.get_nodes_that_accepted(&value);

            let mut supporters: HashSet<_> = voters.union(&acceptors).cloned().collect();

            // Create a lookup function for quorum checking
            let get_qs = |node_id: &NodeId| -> Option<ScpQuorumSet> {
                if let Some(env) = self.latest_nominations.get(node_id) {
                    if let ScpStatementPledges::Nominate(nom) = &env.statement.pledges {
                        // Get quorum set from driver using the hash
                        return driver.get_quorum_set(node_id);
                    }
                }
                None
            };

            // Check if quorum slice satisfied
            if is_quorum_slice(local_quorum_set, &supporters, &get_qs) {
                // Validate before accepting
                let validation = driver.validate_value(slot_index, &value, true);
                if validation != ValidationLevel::Invalid {
                    self.accepted.push(value.clone());
                    changed = true;
                }
            }
        }

        changed
    }

    /// Update the composite value from accepted values.
    fn update_composite<D: SCPDriver>(&mut self, driver: &Arc<D>, slot_index: u64) {
        if self.accepted.is_empty() {
            return;
        }

        // Combine all accepted values
        if let Some(composite) = driver.combine_candidates(slot_index, &self.accepted) {
            if self.latest_composite.as_ref() != Some(&composite) {
                self.latest_composite = Some(composite);
            }
        }
    }

    /// Emit a nomination envelope.
    fn emit_nomination<D: SCPDriver>(
        &self,
        local_node_id: &NodeId,
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) {
        let nomination = ScpNomination {
            quorum_set_hash: hash_quorum_set(local_quorum_set).into(),
            votes: self.votes.clone().try_into().unwrap_or_default(),
            accepted: self.accepted.clone().try_into().unwrap_or_default(),
        };

        let statement = ScpStatement {
            node_id: local_node_id.clone(),
            slot_index,
            pledges: ScpStatementPledges::Nominate(nomination),
        };

        let mut envelope = ScpEnvelope {
            statement,
            signature: stellar_xdr::curr::Signature(
                Vec::new().try_into().unwrap_or_default(),
            ),
        };

        driver.sign_envelope(&mut envelope);
        driver.emit_envelope(&envelope);
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
}
