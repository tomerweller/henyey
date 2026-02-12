//! Per-slot consensus state for SCP.
//!
//! Each slot in SCP represents an independent consensus instance, typically
//! corresponding to a ledger sequence number in Stellar. This module provides
//! the [`Slot`] struct which manages the complete consensus state for a single
//! slot, including both the nomination and ballot protocol phases.
//!
//! # Slot Lifecycle
//!
//! 1. **Creation**: Slot is created when first needed (either via nomination
//!    or when receiving an envelope for that slot)
//! 2. **Nomination**: Nodes propose and vote on candidate values
//! 3. **Ballot Protocol**: Once candidates are confirmed, nodes vote on ballots
//!    to agree on a single value
//! 4. **Externalization**: When consensus is reached, the slot is externalized
//!    and its value becomes final
//!
//! # State Transitions
//!
//! ```text
//! [New] --> [Nominating] --> [Ballot: Prepare] --> [Ballot: Confirm] --> [Externalized]
//!                                    |                    |
//!                                    +--(timeout)---------+
//! ```
//!
//! # Force Externalization
//!
//! During catchup from historical data, slots can be force-externalized with
//! known values, bypassing the consensus process entirely.

use std::collections::HashMap;
use std::sync::Arc;

use stellar_xdr::curr::{NodeId, ScpEnvelope, ScpQuorumSet, ScpStatementPledges, Value};

use crate::ballot::{BallotPhase, BallotProtocol};
use crate::driver::SCPDriver;
use crate::nomination::NominationProtocol;
use crate::EnvelopeState;
use crate::SlotContext;

/// Per-slot consensus state managing nomination and ballot protocols.
///
/// A `Slot` encapsulates all the state needed to reach consensus on a single
/// value for a given slot index. Each slot progresses independently through
/// the nomination phase (where candidates are proposed) and the ballot phase
/// (where a single value is agreed upon).
///
/// # Fields
///
/// The slot maintains:
/// - Nomination protocol state for collecting and voting on candidate values
/// - Ballot protocol state for the prepare/confirm/externalize phases
/// - Envelope history for all received SCP messages
/// - Validation state tracking
#[derive(Debug)]
pub struct Slot {
    /// The slot index (typically corresponds to ledger sequence number).
    slot_index: u64,

    /// The local node's identifier (public key).
    local_node_id: NodeId,

    /// The local node's quorum set configuration.
    local_quorum_set: ScpQuorumSet,

    /// Whether this node is a validator (actively participates in consensus).
    is_validator: bool,

    /// State machine for the nomination protocol phase.
    nomination: NominationProtocol,

    /// State machine for the ballot protocol phase.
    ballot: BallotProtocol,

    /// History of all envelopes received for this slot, grouped by sender.
    envelopes: HashMap<NodeId, Vec<ScpEnvelope>>,

    /// The externalized value if consensus has been reached, None otherwise.
    externalized_value: Option<Value>,

    /// Whether nomination has been explicitly started for this slot.
    nomination_started: bool,

    /// Whether all values in this slot have been fully validated.
    ///
    /// This affects whether local envelopes are emitted to the network.
    /// When false, the node defers broadcasting its own statements.
    fully_validated: bool,

    /// Whether we've heard from a v-blocking set for this slot.
    ///
    /// Set once when a v-blocking threshold of nodes have sent messages.
    /// Matches stellar-core `mGotVBlocking`.
    got_v_blocking: bool,
}

impl Slot {
    /// Create a new slot.
    pub fn new(
        slot_index: u64,
        local_node_id: NodeId,
        local_quorum_set: ScpQuorumSet,
        is_validator: bool,
    ) -> Self {
        let mut nomination = NominationProtocol::new();
        nomination.set_fully_validated(is_validator);
        let mut ballot = BallotProtocol::new();
        ballot.set_fully_validated(is_validator);

        Self {
            slot_index,
            local_node_id,
            local_quorum_set,
            is_validator,
            nomination,
            ballot,
            envelopes: HashMap::new(),
            externalized_value: None,
            nomination_started: false,
            fully_validated: is_validator,
            got_v_blocking: false,
        }
    }

    /// Get the slot index.
    pub fn slot_index(&self) -> u64 {
        self.slot_index
    }

    /// Get the nomination protocol state.
    pub fn nomination(&self) -> &NominationProtocol {
        &self.nomination
    }

    /// Get the ballot protocol state.
    pub fn ballot(&self) -> &BallotProtocol {
        &self.ballot
    }

    /// Get the externalized value if consensus was reached.
    pub fn get_externalized_value(&self) -> Option<&Value> {
        self.externalized_value.as_ref()
    }

    /// Check if this slot is externalized.
    pub fn is_externalized(&self) -> bool {
        self.externalized_value.is_some()
    }

    /// Check if this slot is fully validated.
    pub fn is_fully_validated(&self) -> bool {
        self.fully_validated
    }

    /// Check if we've heard from quorum for the current ballot.
    pub fn heard_from_quorum(&self) -> bool {
        self.ballot.heard_from_quorum()
    }

    /// Check if we've heard from a v-blocking set.
    ///
    /// Matches stellar-core `Slot::gotVBlocking()`.
    pub fn got_v_blocking(&self) -> bool {
        self.got_v_blocking
    }

    /// Check and set `got_v_blocking` if v-blocking threshold is met.
    ///
    /// Called after processing an envelope from a new node. If we've already
    /// got v-blocking, this is a no-op. Otherwise, checks all nodes in our
    /// quorum set that have sent messages and determines if they form a
    /// v-blocking set.
    ///
    /// Matches stellar-core `Slot::maybeSetGotVBlocking()`.
    fn maybe_set_got_v_blocking(&mut self) {
        if self.got_v_blocking {
            return;
        }

        // Collect nodes we've heard from (have latest message in ballot or nomination)
        let mut heard_nodes = std::collections::HashSet::new();
        let all_nodes = crate::quorum::get_all_nodes(&self.local_quorum_set);
        for node_id in &all_nodes {
            // Check ballot protocol first, then nomination (matching stellar-core getLatestMessage)
            if self.ballot.latest_envelopes().contains_key(node_id)
                || self.nomination.get_latest_nomination(node_id).is_some()
            {
                heard_nodes.insert(node_id.clone());
            }
        }

        self.got_v_blocking = crate::quorum::is_v_blocking(&self.local_quorum_set, &heard_nodes);
    }

    /// Process an incoming SCP envelope.
    ///
    /// # Returns
    /// The state of the envelope after processing.
    pub fn process_envelope<D: SCPDriver>(
        &mut self,
        envelope: ScpEnvelope,
        driver: &Arc<D>,
    ) -> EnvelopeState {
        let node_id = envelope.statement.node_id.clone();

        // Check if this is the first message from this node
        // stellar-core checks getLatestMessage(nodeID) which checks ballot then nomination
        let prev = self.ballot.latest_envelopes().contains_key(&node_id)
            || self.nomination.get_latest_nomination(&node_id).is_some();

        // Process based on statement type
        let result = match &envelope.statement.pledges {
            ScpStatementPledges::Nominate(_) => self.process_nomination_envelope(&envelope, driver),
            ScpStatementPledges::Prepare(_)
            | ScpStatementPledges::Confirm(_)
            | ScpStatementPledges::Externalize(_) => {
                self.process_ballot_envelope(&envelope, driver)
            }
        };

        if result.is_valid() {
            self.envelopes
                .entry(node_id.clone())
                .or_default()
                .push(envelope.clone());

            // If this is the first valid message from this node,
            // check if we now have a v-blocking set (matching stellar-core)
            if !prev {
                self.maybe_set_got_v_blocking();
            }
        }

        // Check if we need to transition from nomination to ballot
        self.check_nomination_to_ballot(driver);

        // Check if we've externalized
        if self.ballot.is_externalized() && self.externalized_value.is_none() {
            if let Some(value) = self.ballot.get_externalized_value() {
                self.externalized_value = Some(value.clone());
                self.fully_validated = true;
                self.nomination.set_fully_validated(true);
                self.ballot.set_fully_validated(true);

                // Stop all timers when externalized
                driver.stop_timer(self.slot_index, crate::driver::SCPTimerType::Nomination);
                driver.stop_timer(self.slot_index, crate::driver::SCPTimerType::Ballot);
            }
        }

        result
    }

    /// Nominate a value for this slot.
    ///
    /// # Returns
    /// True if nomination was successful.
    pub fn nominate<D: SCPDriver>(
        &mut self,
        value: Value,
        prev_value: &Value,
        timedout: bool,
        driver: &Arc<D>,
    ) -> bool {
        if !self.is_validator {
            return false;
        }

        if self.is_externalized() {
            return false;
        }

        self.nomination_started = true;

        let ctx = SlotContext {
            local_node_id: &self.local_node_id,
            local_quorum_set: &self.local_quorum_set,
            driver,
            slot_index: self.slot_index,
        };
        let result = self.nomination.nominate(
            &ctx,
            value,
            prev_value,
            timedout,
        );

        // stellar-core always sets up the nomination timer after nominate() succeeds
        // in reaching the main logic (i.e., didn't return early due to
        // candidates already existing, stopped, or timed-out-before-started).
        // The timer is NOT conditional on `updated`.
        // We check the conditions that match stellar-core reaching line 654.
        if self.nomination.is_started()
            && !self.nomination.is_stopped()
            && self.nomination.candidates().is_empty()
        {
            let round = self.nomination.round();
            let timeout = driver.compute_timeout(round, true);
            driver.setup_timer(
                self.slot_index,
                crate::driver::SCPTimerType::Nomination,
                timeout,
            );
        }

        result
    }

    /// Stop nomination for this slot.
    pub fn stop_nomination<D: SCPDriver>(&mut self, driver: &Arc<D>) {
        self.nomination.stop();
        // Cancel the nomination timer
        driver.stop_timer(self.slot_index, crate::driver::SCPTimerType::Nomination);
    }

    /// Sync the composite candidate from nomination into ballot protocol.
    ///
    /// The stellar-core BallotProtocol accesses `mSlot.getLatestCompositeCandidate()` directly,
    /// but in Rust the ballot protocol doesn't hold a reference to the slot/nomination.
    /// We sync it before any ballot operation that might call `abandon_ballot`.
    fn sync_composite_candidate(&mut self) {
        self.ballot
            .set_composite_candidate(self.nomination.latest_composite().cloned());
    }

    /// Bump the ballot on timeout.
    pub fn bump_ballot_on_timeout<D: SCPDriver>(&mut self, driver: &Arc<D>) -> bool {
        if !self.is_validator {
            return false;
        }

        // Notify driver of timer expiration
        driver.timer_expired(self.slot_index, crate::driver::SCPTimerType::Ballot);

        let composite = self.nomination.latest_composite().cloned();
        let ctx = SlotContext {
            local_node_id: &self.local_node_id,
            local_quorum_set: &self.local_quorum_set,
            driver,
            slot_index: self.slot_index,
        };
        self.ballot.bump_timeout(
            &ctx,
            composite.as_ref(),
        )
    }

    /// Get all envelopes received for this slot.
    pub fn get_envelopes(&self) -> &HashMap<NodeId, Vec<ScpEnvelope>> {
        &self.envelopes
    }

    /// Get the latest envelope from a specific node.
    pub fn get_latest_nomination(&self, node_id: &NodeId) -> Option<&ScpEnvelope> {
        self.envelopes.get(node_id).and_then(|v| v.last())
    }

    /// Get the current ballot counter for this slot, if any.
    pub fn ballot_counter(&self) -> Option<u32> {
        self.ballot.current_ballot_counter()
    }

    /// Process the latest envelopes for this slot.
    pub fn process_current_state<F>(&self, mut f: F, force_self: bool) -> bool
    where
        F: FnMut(&ScpEnvelope) -> bool,
    {
        self.nomination.process_current_state(
            |env| f(env),
            &self.local_node_id,
            self.fully_validated,
            force_self,
        ) && self.ballot.process_current_state(
            |env| f(env),
            &self.local_node_id,
            self.fully_validated,
            force_self,
        )
    }

    /// Process a nomination envelope.
    fn process_nomination_envelope<D: SCPDriver>(
        &mut self,
        envelope: &ScpEnvelope,
        driver: &Arc<D>,
    ) -> EnvelopeState {
        let ctx = SlotContext {
            local_node_id: &self.local_node_id,
            local_quorum_set: &self.local_quorum_set,
            driver,
            slot_index: self.slot_index,
        };
        self.nomination.process_envelope(
            envelope,
            &ctx,
        )
    }

    /// Process a ballot protocol envelope.
    fn process_ballot_envelope<D: SCPDriver>(
        &mut self,
        envelope: &ScpEnvelope,
        driver: &Arc<D>,
    ) -> EnvelopeState {
        if !self.ballot.is_statement_sane(
            &envelope.statement,
            &self.local_node_id,
            &self.local_quorum_set,
            driver,
        ) {
            return EnvelopeState::Invalid;
        }

        let validation =
            self.ballot
                .validate_statement_values(&envelope.statement, driver, self.slot_index);

        if validation == crate::ValidationLevel::Invalid {
            return EnvelopeState::Invalid;
        }

        if validation == crate::ValidationLevel::MaybeValid {
            self.fully_validated = false;
            self.nomination.set_fully_validated(false);
            self.ballot.set_fully_validated(false);
        }

        // Sync composite candidate so abandon_ballot can use it
        self.sync_composite_candidate();

        let ctx = SlotContext {
            local_node_id: &self.local_node_id,
            local_quorum_set: &self.local_quorum_set,
            driver,
            slot_index: self.slot_index,
        };
        let result = self.ballot.process_envelope(
            envelope,
            &ctx,
        );

        // Check if set_confirm_commit signaled that nomination should stop
        // (matches stellar-core mSlot.stopNomination() call inside setConfirmCommit)
        if self.ballot.take_needs_stop_nomination() {
            self.nomination.stop();
            driver.stop_timer(self.slot_index, crate::driver::SCPTimerType::Nomination);
        }

        result
    }

    /// Check if we should transition from nomination to ballot protocol.
    fn check_nomination_to_ballot<D: SCPDriver>(&mut self, driver: &Arc<D>) {
        // If we already have a ballot, don't need to transition
        if self.ballot.current_ballot().is_some() {
            return;
        }

        // Check if nomination has produced a composite value
        let composite = self.nomination.latest_composite().cloned();
        if let Some(composite) = composite {
            // stellar-core does NOT stop nomination here — nomination continues to run
            // alongside the ballot protocol. stopNomination() is only called
            // when the slot is externalized (from setConfirmCommit).
            // Stop the nomination timer though (candidates already confirmed).
            driver.stop_timer(self.slot_index, crate::driver::SCPTimerType::Nomination);

            // Notify driver that ballot protocol is starting
            driver.started_ballot_protocol(self.slot_index, &composite);

            // Start ballot protocol with the composite value
            let ctx = SlotContext {
                local_node_id: &self.local_node_id,
                local_quorum_set: &self.local_quorum_set,
                driver,
                slot_index: self.slot_index,
            };
            self.ballot.bump(
                &ctx,
                composite.clone(),
                false,
            );
        }
    }

    /// Force externalize with a specific value.
    ///
    /// This is used during catchup when we receive historical ledgers
    /// that have already been externalized by the network, or when
    /// fast-forwarding via EXTERNALIZE messages from the network.
    pub fn force_externalize(&mut self, value: Value) {
        self.externalized_value = Some(value.clone());
        self.fully_validated = true;
        self.nomination.stop();
        self.nomination.set_fully_validated(true);
        self.ballot.force_externalize(value);
        self.ballot.set_fully_validated(true);
    }

    /// Get the current ballot phase.
    pub fn ballot_phase(&self) -> BallotPhase {
        self.ballot.phase()
    }

    /// Check if we're in nomination phase.
    pub fn is_nominating(&self) -> bool {
        self.nomination_started && !self.nomination.is_stopped()
    }

    /// Get the set of nodes we've heard from for this slot.
    ///
    /// Returns all node IDs that have sent valid envelopes for this slot.
    pub fn get_nodes_heard_from(&self) -> std::collections::HashSet<NodeId> {
        self.envelopes.keys().cloned().collect()
    }

    /// Get the total count of statements recorded for this slot.
    ///
    /// This counts all envelopes received from all nodes.
    pub fn get_statement_count(&self) -> usize {
        self.envelopes.values().map(|v| v.len()).sum()
    }

    /// Get the latest envelope from a specific node.
    ///
    /// Checks ballot protocol first, then nomination protocol.
    /// Matches stellar-core `Slot::getLatestMessage(NodeID const& id)`.
    pub fn get_latest_envelope(&self, node_id: &NodeId) -> Option<&ScpEnvelope> {
        self.ballot
            .latest_envelopes()
            .get(node_id)
            .or_else(|| self.nomination.get_latest_nomination(node_id))
    }

    /// Get the latest messages that would be sent for this slot.
    ///
    /// Returns the latest envelopes for both nomination and ballot protocols.
    /// Only returns messages if the slot is fully validated (matching stellar-core
    /// `Slot::getLatestMessagesSend` which gates on `mFullyValidated`).
    pub fn get_latest_messages_send(&self) -> Vec<ScpEnvelope> {
        let mut messages = Vec::new();

        if !self.fully_validated {
            return messages;
        }

        // Add latest nomination message if available
        if let Some(env) = self.nomination.get_last_envelope() {
            messages.push(env.clone());
        }

        // Add latest ballot message if available
        if let Some(env) = self.ballot.get_last_envelope() {
            messages.push(env.clone());
        }

        messages
    }

    /// Get nomination round leaders.
    ///
    /// Returns the set of nodes that are leaders for the current nomination round.
    pub fn get_nomination_leaders(&self) -> std::collections::HashSet<NodeId> {
        self.nomination.get_round_leaders().clone()
    }

    /// Get the latest composite candidate value for this slot.
    ///
    /// Returns the most recently computed composite value from the nomination protocol.
    /// Matches stellar-core `Slot::getLatestCompositeCandidate()`.
    pub fn get_latest_composite_candidate(&self) -> Option<Value> {
        self.nomination.latest_composite().cloned()
    }

    /// Get the externalizing state for this slot.
    ///
    /// Delegates to BallotProtocol::get_externalizing_state, matching stellar-core
    /// where `Slot::getExternalizingState()` calls
    /// `mBallotProtocol.getExternalizingState()`.
    pub fn get_externalizing_state(&self) -> Vec<ScpEnvelope> {
        self.ballot
            .get_externalizing_state(&self.local_node_id, self.fully_validated)
    }

    /// Record a historical statement for this slot.
    ///
    /// Historical statements are used for debugging and analysis.
    pub fn record_statement(&mut self, envelope: &ScpEnvelope) {
        let node_id = envelope.statement.node_id.clone();
        self.envelopes
            .entry(node_id)
            .or_default()
            .push(envelope.clone());
    }

    /// Get the quorum set hash from a statement.
    ///
    /// Extracts the quorum set hash from the statement's pledges.
    pub fn get_companion_quorum_set_hash_from_statement(
        statement: &stellar_xdr::curr::ScpStatement,
    ) -> Option<stellar_xdr::curr::Hash> {
        use ScpStatementPledges::*;
        match &statement.pledges {
            Nominate(nom) => Some(nom.quorum_set_hash.clone()),
            Prepare(prep) => Some(prep.quorum_set_hash.clone()),
            Confirm(conf) => Some(conf.quorum_set_hash.clone()),
            Externalize(ext) => Some(ext.commit_quorum_set_hash.clone()),
        }
    }

    /// Get values from a statement.
    ///
    /// Extracts all values referenced by a statement.
    pub fn get_statement_values(statement: &stellar_xdr::curr::ScpStatement) -> Vec<Value> {
        use ScpStatementPledges::*;
        let mut values = Vec::new();

        match &statement.pledges {
            Nominate(nom) => {
                values.extend(nom.votes.iter().cloned());
                values.extend(nom.accepted.iter().cloned());
            }
            Prepare(prep) => {
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
            Confirm(conf) => {
                values.push(conf.ballot.value.clone());
            }
            Externalize(ext) => {
                values.push(ext.commit.value.clone());
            }
        }

        values
    }

    /// Create an envelope from a statement.
    ///
    /// This is a helper for constructing envelopes with proper signing.
    pub fn create_envelope<D: SCPDriver>(
        &self,
        statement: stellar_xdr::curr::ScpStatement,
        driver: &Arc<D>,
    ) -> ScpEnvelope {
        let mut envelope = ScpEnvelope {
            statement,
            signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
        };
        driver.sign_envelope(&mut envelope);
        envelope
    }

    /// Restore state from a saved envelope (for crash recovery).
    ///
    /// This method is used to restore slot state from a previously saved envelope
    /// when restarting after a crash. It routes the envelope to the appropriate
    /// protocol (nomination or ballot) for state restoration.
    ///
    /// Matching stellar-core `Slot::setStateFromEnvelope`: validates that the envelope is
    /// from the local node and for this slot, checks if it's a new node, and
    /// calls `maybeSetGotVBlocking`.
    ///
    /// # Arguments
    /// * `envelope` - The envelope to restore state from
    ///
    /// # Returns
    /// True if state was successfully restored, false if the envelope is invalid.
    pub fn set_state_from_envelope(&mut self, envelope: &ScpEnvelope) -> bool {
        // stellar-core validates nodeID and slotIndex
        if envelope.statement.node_id != self.local_node_id
            || envelope.statement.slot_index != self.slot_index
        {
            tracing::trace!(
                slot = self.slot_index,
                "Slot::set_state_from_envelope invalid envelope"
            );
            return false;
        }

        // Check if this is first message from this node
        let prev = self
            .ballot
            .latest_envelopes()
            .contains_key(&envelope.statement.node_id)
            || self
                .nomination
                .get_latest_nomination(&envelope.statement.node_id)
                .is_some();

        let result = match &envelope.statement.pledges {
            ScpStatementPledges::Nominate(_) => self.nomination.set_state_from_envelope(envelope),
            ScpStatementPledges::Prepare(_)
            | ScpStatementPledges::Confirm(_)
            | ScpStatementPledges::Externalize(_) => {
                let result = self.ballot.set_state_from_envelope(envelope);
                if result && self.ballot.is_externalized() {
                    if let Some(value) = self.ballot.get_externalized_value() {
                        self.externalized_value = Some(value.clone());
                        self.fully_validated = true;
                    }
                }
                result
            }
        };

        if result && !prev {
            self.maybe_set_got_v_blocking();
        }

        result
    }

    /// Abandon the current ballot and move to a new one.
    ///
    /// This is used when we need to give up on the current ballot,
    /// for example when we detect that consensus cannot be reached.
    ///
    /// # Arguments
    /// * `driver` - The SCP driver
    /// * `counter` - The counter for the new ballot (0 to auto-increment)
    ///
    /// # Returns
    /// True if the ballot was abandoned successfully.
    pub fn abandon_ballot<D: SCPDriver>(&mut self, driver: &Arc<D>, counter: u32) -> bool {
        self.sync_composite_candidate();
        let ctx = SlotContext {
            local_node_id: &self.local_node_id,
            local_quorum_set: &self.local_quorum_set,
            driver,
            slot_index: self.slot_index,
        };
        self.ballot.abandon_ballot_public(
            counter,
            &ctx,
        )
    }

    /// Bump the ballot to a specific counter value.
    ///
    /// This is used when we need to bump to a specific ballot counter,
    /// for example when catching up to a higher ballot counter seen on the network.
    ///
    /// # Arguments
    /// * `driver` - The SCP driver
    /// * `value` - The value for the ballot
    /// * `counter` - The specific counter to bump to
    ///
    /// # Returns
    /// True if the ballot was bumped, false if the operation failed.
    pub fn bump_state<D: SCPDriver>(
        &mut self,
        driver: &Arc<D>,
        value: Value,
        counter: u32,
    ) -> bool {
        let ctx = SlotContext {
            local_node_id: &self.local_node_id,
            local_quorum_set: &self.local_quorum_set,
            driver,
            slot_index: self.slot_index,
        };
        self.ballot.bump_state(
            &ctx,
            value,
            counter,
        )
    }

    /// Force-bump the ballot state, auto-computing the counter.
    ///
    /// This mirrors stellar-core `BallotProtocol::bumpState(value, force=true)`.
    /// Counter is `current_counter + 1`, or 1 if no current ballot.
    pub fn force_bump_state<D: SCPDriver>(&mut self, driver: &Arc<D>, value: Value) -> bool {
        let ctx = SlotContext {
            local_node_id: &self.local_node_id,
            local_quorum_set: &self.local_quorum_set,
            driver,
            slot_index: self.slot_index,
        };
        self.ballot.bump(
            &ctx,
            value,
            true,
        )
    }

    /// Get mutable access to the nomination protocol.
    pub fn nomination_mut(&mut self) -> &mut NominationProtocol {
        &mut self.nomination
    }

    /// Get mutable access to the ballot protocol.
    pub fn ballot_mut(&mut self) -> &mut BallotProtocol {
        &mut self.ballot
    }

    /// Get the state of a node for this slot.
    ///
    /// Returns the QuorumInfoNodeState combining both nomination and ballot states.
    /// The ballot state takes precedence if the node has progressed to ballot protocol.
    pub fn get_node_state(&self, node_id: &NodeId) -> crate::QuorumInfoNodeState {
        // Check ballot state first (more advanced)
        let ballot_state = self.ballot.get_node_state(node_id);
        if ballot_state != crate::QuorumInfoNodeState::Missing {
            return ballot_state;
        }

        // Fall back to nomination state
        self.nomination.get_node_state(node_id)
    }

    /// Get a summary string of the slot state for debugging.
    pub fn get_state_string(&self) -> String {
        format!(
            "slot={} externalized={} nom=[{}] ballot=[{}]",
            self.slot_index,
            self.externalized_value.is_some(),
            self.nomination.get_state_string(),
            self.ballot.get_state_string()
        )
    }

    /// Get states of all nodes in quorum set for this slot.
    ///
    /// Returns a map from node ID to their state in this slot's consensus.
    pub fn get_all_node_states(
        &self,
    ) -> std::collections::HashMap<NodeId, crate::QuorumInfoNodeState> {
        let mut states = std::collections::HashMap::new();

        // Get all nodes from quorum set
        let nodes = crate::quorum::get_all_nodes(&self.local_quorum_set);
        for node_id in nodes {
            states.insert(node_id.clone(), self.get_node_state(&node_id));
        }

        states
    }

    /// Get JSON-serializable slot information.
    ///
    /// Returns a SlotInfo struct that can be serialized to JSON
    /// for debugging and monitoring purposes, matching stellar-core `getJsonInfo()`.
    pub fn get_info(&self) -> crate::SlotInfo {
        let phase = if self.externalized_value.is_some() {
            "EXTERNALIZED"
        } else if self.ballot.phase() != BallotPhase::Prepare
            || self.ballot.current_ballot().is_some()
        {
            "BALLOT"
        } else if self.nomination.is_started() {
            "NOMINATION"
        } else {
            "IDLE"
        };

        crate::SlotInfo {
            slot_index: self.slot_index,
            phase: phase.to_string(),
            fully_validated: self.fully_validated,
            nomination: if self.nomination.is_started() {
                Some(self.nomination.get_info())
            } else {
                None
            },
            ballot: if self.ballot.current_ballot().is_some() || self.externalized_value.is_some() {
                Some(self.ballot.get_info())
            } else {
                None
            },
        }
    }

    /// Get JSON-serializable quorum information.
    ///
    /// Returns a QuorumInfo struct that can be serialized to JSON
    /// for debugging and monitoring purposes, matching stellar-core `getJsonQuorumInfo()`.
    pub fn get_quorum_info(&self) -> crate::QuorumInfo {
        let node_states = self.get_all_node_states();
        let mut nodes = std::collections::HashMap::new();

        for (node_id, state) in &node_states {
            let state_str = match state {
                crate::QuorumInfoNodeState::Missing => "MISSING",
                crate::QuorumInfoNodeState::Nominating => "NOMINATING",
                crate::QuorumInfoNodeState::Preparing => "PREPARING",
                crate::QuorumInfoNodeState::Confirming => "CONFIRMING",
                crate::QuorumInfoNodeState::Externalized => "EXTERNALIZED",
            };

            // Get ballot counter if in ballot phase
            let ballot_counter = if let Some(env) = self.ballot.latest_envelopes().get(node_id) {
                match &env.statement.pledges {
                    ScpStatementPledges::Prepare(p) => Some(p.ballot.counter),
                    ScpStatementPledges::Confirm(c) => Some(c.ballot.counter),
                    ScpStatementPledges::Externalize(e) => Some(e.commit.counter),
                    _ => None,
                }
            } else {
                None
            };

            nodes.insert(
                crate::node_id_to_short_string(node_id),
                crate::NodeInfo {
                    state: state_str.to_string(),
                    ballot_counter,
                },
            );
        }

        // Check quorum and v-blocking status
        let responding_nodes: std::collections::HashSet<_> = node_states
            .iter()
            .filter(|(_, s)| **s != crate::QuorumInfoNodeState::Missing)
            .map(|(n, _)| n.clone())
            .collect();

        let quorum_reached =
            crate::quorum::is_quorum_slice(&self.local_quorum_set, &responding_nodes, &|_| None);

        let v_blocking = crate::quorum::is_v_blocking(&self.local_quorum_set, &responding_nodes);

        crate::QuorumInfo {
            slot_index: self.slot_index,
            local_node: crate::node_id_to_short_string(&self.local_node_id),
            quorum_set_hash: hex::encode(
                &crate::quorum::hash_quorum_set(&self.local_quorum_set).0[..8],
            ),
            nodes,
            quorum_reached,
            v_blocking,
        }
    }
}

#[cfg(test)]
mod tests;
