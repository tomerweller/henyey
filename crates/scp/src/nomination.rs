//! Nomination protocol implementation for SCP.
//!
//! The nomination protocol is the first phase of SCP consensus, where nodes
//! propose and vote on candidate values. The goal is to produce a set of
//! confirmed candidate values that can then be used in the ballot protocol.
//!
//! # Protocol Overview
//!
//! 1. **Vote**: Nodes vote for values they propose or receive from leaders
//! 2. **Accept**: A value is accepted when a v-blocking set accepts it,
//!    or when a quorum has voted or accepted it
//! 3. **Confirm**: A value is confirmed (becomes a candidate) when a quorum
//!    has accepted it
//!
//! # Value Progression
//!
//! ```text
//! [Proposed] --vote--> [Voted] --accept--> [Accepted] --ratify--> [Candidate]
//! ```
//!
//! # Round Leaders
//!
//! Each nomination round has a set of leaders determined by a deterministic
//! priority function. Leaders' values are prioritized during nomination.
//! The leader set grows over rounds to ensure progress.
//!
//! # Composite Value
//!
//! Once candidates are confirmed, they are combined into a single composite
//! value (via the driver's `combine_candidates` method) which is then used
//! to start the ballot protocol.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use stellar_xdr::curr::{
    Limits, NodeId, ScpEnvelope, ScpNomination, ScpQuorumSet, ScpStatement, ScpStatementPledges,
    Value, WriteXdr,
};

use crate::driver::{SCPDriver, ValidationLevel};
use crate::quorum::{hash_quorum_set, is_blocking_set, is_quorum};
use crate::EnvelopeState;
use crate::SlotContext;

/// State machine for the nomination protocol phase.
///
/// The `NominationProtocol` tracks all state needed for the nomination phase
/// of SCP consensus, including voted values, accepted values, confirmed
/// candidates, and the latest messages from each node.
///
/// # State Categories
///
/// - **Votes**: Values this node has voted for
/// - **Accepted**: Values accepted (confirmed by v-blocking or quorum)
/// - **Candidates**: Values confirmed by quorum (ready for ballot protocol)
///
/// # Monotonicity
///
/// Nomination statements are monotonic: a newer statement must contain
/// all values from previous statements plus at least one new value.
#[derive(Debug)]
pub struct NominationProtocol {
    /// Current nomination round number (increases on timeout).
    round: u32,

    /// Values this node has voted for.
    ///
    /// Values are added when we nominate them ourselves or adopt them
    /// from round leaders.
    votes: Vec<Value>,

    /// Values this node has accepted.
    ///
    /// A value is accepted when either:
    /// - A v-blocking set of nodes has accepted it
    /// - A quorum has voted for or accepted it
    accepted: Vec<Value>,

    /// Values confirmed by quorum (candidates for ballot protocol).
    ///
    /// These are values where a quorum has accepted them. Once we have
    /// candidates, they are combined into a composite value.
    candidates: Vec<Value>,

    /// Whether nomination has been started.
    started: bool,

    /// Whether nomination has been stopped (transitioning to ballot).
    stopped: bool,

    /// The latest composite value combining all candidates.
    ///
    /// This value is passed to the ballot protocol when candidates
    /// are confirmed.
    latest_composite: Option<Value>,

    /// The previous slot's value, used for priority hash computation.
    previous_value: Option<Value>,

    /// Count of nomination timeouts (used for round progression).
    timer_exp_count: u32,

    /// Latest nomination envelope from each node in the network.
    latest_nominations: HashMap<NodeId, ScpEnvelope>,

    /// Set of nodes that are leaders for the current round.
    ///
    /// Leaders are determined by a priority function based on the
    /// previous value and round number.
    round_leaders: HashSet<NodeId>,

    /// The last envelope we constructed locally.
    last_envelope: Option<ScpEnvelope>,

    /// The last envelope we actually emitted to the network.
    last_envelope_emit: Option<ScpEnvelope>,

    /// Whether the slot is fully validated (affects envelope emission).
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

    /// Get the last envelope constructed by this node.
    pub fn get_last_envelope(&self) -> Option<&ScpEnvelope> {
        self.last_envelope.as_ref()
    }

    /// Get the last envelope actually sent (emitted) to the network.
    ///
    /// This returns the most recent nomination envelope that was actually
    /// broadcast to the network, which may differ from `get_last_envelope()`
    /// when the slot is not fully validated.
    pub fn get_last_message_send(&self) -> Option<&ScpEnvelope> {
        self.last_envelope_emit.as_ref()
    }

    /// Get the current round leaders.
    pub fn get_round_leaders(&self) -> &HashSet<NodeId> {
        &self.round_leaders
    }

    /// Get the latest nomination envelope from a specific node.
    pub fn get_latest_nomination(&self, node_id: &NodeId) -> Option<&ScpEnvelope> {
        self.latest_nominations.get(node_id)
    }

    /// Get the timer expiration count.
    pub fn timer_exp_count(&self) -> u32 {
        self.timer_exp_count
    }

    /// Get the state of a node in the nomination protocol.
    ///
    /// Returns the QuorumInfoNodeState for a given node based on their
    /// latest nomination envelope, or Missing if we haven't heard from them.
    pub fn get_node_state(&self, node_id: &NodeId) -> crate::QuorumInfoNodeState {
        if self.latest_nominations.contains_key(node_id) {
            crate::QuorumInfoNodeState::Nominating
        } else {
            crate::QuorumInfoNodeState::Missing
        }
    }

    /// Get a summary string of the nomination state for debugging.
    pub fn get_state_string(&self) -> String {
        format!(
            "round={} started={} stopped={} votes={} accepted={} candidates={} leaders={}",
            self.round,
            self.started,
            self.stopped,
            self.votes.len(),
            self.accepted.len(),
            self.candidates.len(),
            self.round_leaders.len()
        )
    }

    /// Get JSON-serializable nomination information.
    ///
    /// Returns a NominationInfo struct that can be serialized to JSON
    /// for debugging and monitoring purposes.
    pub fn get_info(&self) -> crate::NominationInfo {
        crate::NominationInfo {
            running: self.started && !self.stopped,
            round: self.round,
            votes: self.votes.iter().map(crate::value_to_str).collect(),
            accepted: self.accepted.iter().map(crate::value_to_str).collect(),
            candidates: self.candidates.iter().map(crate::value_to_str).collect(),
            node_count: self.latest_nominations.len(),
        }
    }

    /// Process the latest nomination envelopes with a callback.
    pub fn process_current_state<F>(
        &self,
        f: F,
        local_node_id: &NodeId,
        fully_validated: bool,
        force_self: bool,
    ) -> bool
    where
        F: FnMut(&ScpEnvelope) -> bool,
    {
        crate::process_envelopes_current_state(
            &self.latest_nominations,
            f,
            local_node_id,
            fully_validated,
            force_self,
        )
    }

    /// Nominate a value for this slot.
    ///
    /// # Arguments
    /// * `ctx` - Shared slot context (node ID, quorum set, driver, slot index)
    /// * `value` - The value to nominate
    /// * `prev_value` - The previous slot's value (for priority calculation)
    /// * `timedout` - Whether this is a timeout-triggered nomination
    ///
    /// # Returns
    /// True if nomination was updated.
    pub(crate) fn nominate<'a, D: SCPDriver>(
        &mut self,
        ctx: &SlotContext<'a, D>,
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
        self.update_round_leaders(ctx, prev_value);

        let mut updated = self.adopt_leader_values(ctx);
        updated = self.vote_as_leader(ctx, &value) || updated;

        // Emit nomination envelope
        if updated {
            self.emit_nomination(ctx);
        }

        updated
    }

    /// Adopt values from round leaders' nominations.
    fn adopt_leader_values<'a, D: SCPDriver>(
        &mut self,
        ctx: &SlotContext<'a, D>,
    ) -> bool {
        let mut updated = false;
        for leader in self.round_leaders.clone() {
            let Some(env) = self.latest_nominations.get(&leader) else {
                continue;
            };
            let ScpStatementPledges::Nominate(nom) = &env.statement.pledges else {
                continue;
            };
            let Some(new_vote) =
                self.get_new_value_from_nomination(nom, ctx.driver, ctx.slot_index)
            else {
                continue;
            };
            if Self::insert_unique(&mut self.votes, new_vote.clone()) {
                updated = true;
                ctx.driver.nominating_value(ctx.slot_index, &new_vote);
            }
        }
        updated
    }

    /// Vote for our own value if we are a leader for this round.
    ///
    /// Handles upgrade timeout logic: if too many timeouts have occurred
    /// and all current votes contain upgrades, strips upgrades from our
    /// value before voting (stellar-core lines 597-651).
    fn vote_as_leader<'a, D: SCPDriver>(
        &mut self,
        ctx: &SlotContext<'a, D>,
        value: &Value,
    ) -> bool {
        if !self.round_leaders.contains(ctx.local_node_id) {
            return false;
        }

        let over_upgrade_timeout_limit =
            self.timer_exp_count >= ctx.driver.get_upgrade_nomination_timeout_limit();

        let mut should_vote_for_value = false;
        let mut vote_value = value.clone();

        if self.votes.is_empty() {
            should_vote_for_value = true;
        }

        if over_upgrade_timeout_limit {
            let all_votes_have_upgrades = self.votes.iter().all(|v| ctx.driver.has_upgrades(v));
            if all_votes_have_upgrades {
                if let Some(stripped) = ctx.driver.strip_all_upgrades(&vote_value) {
                    if stripped != vote_value {
                        vote_value = stripped;
                    }
                }
                should_vote_for_value = true;
            }
        }

        if should_vote_for_value {
            let validation = ctx.driver.validate_value(ctx.slot_index, &vote_value, true);
            if validation != ValidationLevel::Invalid
                && Self::insert_unique(&mut self.votes, vote_value.clone())
            {
                ctx.driver.nominating_value(ctx.slot_index, &vote_value);
                return true;
            }
        }

        false
    }

    /// Process a nomination envelope from the network.
    ///
    /// # Returns
    /// The state of the envelope after processing.
    pub(crate) fn process_envelope<'a, D: SCPDriver>(
        &mut self,
        envelope: &ScpEnvelope,
        ctx: &SlotContext<'a, D>,
    ) -> EnvelopeState {
        let node_id = &envelope.statement.node_id;

        let nomination = match &envelope.statement.pledges {
            ScpStatementPledges::Nominate(nom) => nom,
            _ => return EnvelopeState::Invalid,
        };

        if !self.is_newer_nomination_internal(node_id, nomination) {
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
            // Collect the votes from the envelope for acceptance checks.
            let votes_to_check: Vec<Value> = nomination.votes.iter().cloned().collect();

            let (mut modified, new_candidates) =
                self.attempt_promote(&votes_to_check, ctx.local_quorum_set, ctx.driver, ctx.slot_index);

            // N13: Only take round leader votes if we're still looking for
            // candidates (stellar-core processEnvelope lines 476-489).
            if self.candidates.is_empty() && self.round_leaders.contains(node_id) {
                if let Some(new_vote) =
                    self.get_new_value_from_nomination(nomination, ctx.driver, ctx.slot_index)
                {
                    if Self::insert_unique(&mut self.votes, new_vote.clone()) {
                        modified = true;
                        ctx.driver.nominating_value(ctx.slot_index, &new_vote);
                    }
                }
            }

            // stellar-core order: emit first, then composite update
            if modified {
                self.emit_nomination(ctx);
                state_changed = true;
            }

            if new_candidates {
                self.update_composite(ctx.driver, ctx.slot_index);
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
    ///
    /// Matches stellar-core `stopNomination()` which sets `mNominationStarted = false`.
    /// This ensures `process_envelope` no longer does accept/ratify processing
    /// after nomination has been stopped.
    pub fn stop(&mut self) {
        self.stopped = true;
        self.started = false;
    }

    /// Get the nodes whose nominations contain `value` in the given field.
    fn get_nodes_with_value(
        &self,
        value: &Value,
        field: fn(&ScpNomination) -> &[Value],
    ) -> HashSet<NodeId> {
        let mut nodes = HashSet::new();

        for (node_id, envelope) in &self.latest_nominations {
            if let ScpStatementPledges::Nominate(nom) = &envelope.statement.pledges {
                if field(nom).iter().any(|v| v == value) {
                    nodes.insert(node_id.clone());
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
                // Notify driver of the updated candidate value
                driver.updated_candidate_value(slot_index, &composite);
                self.latest_composite = Some(composite);
            }
        }
    }

    /// Attempt to promote votes to accepted and accepted to candidates.
    ///
    /// This is the core acceptance/ratification logic extracted from
    /// `process_envelope` so it can also be called from `emit_nomination`
    /// (matching stellar-core where `emitNomination()` calls `processEnvelope(self)`).
    ///
    /// The `votes_to_check` parameter specifies which voted values to check
    /// for acceptance. In stellar-core, `processEnvelope` iterates `nom.votes` from
    /// the envelope being processed — when called from `emitNomination`, those
    /// are our own votes.
    ///
    /// # Returns
    /// `(modified, new_candidates)` — whether votes/accepted changed, and
    /// whether new candidates were confirmed.
    fn attempt_promote<D: SCPDriver>(
        &mut self,
        votes_to_check: &[Value],
        local_quorum_set: &ScpQuorumSet,
        driver: &Arc<D>,
        slot_index: u64,
    ) -> (bool, bool) {
        let mut modified = false;
        let mut new_candidates = false;

        // Attempt to promote votes to accepted.
        for value in votes_to_check {
            if self.accepted.contains(value) {
                continue;
            }

            if !self.should_accept_value(value, local_quorum_set, driver, slot_index) {
                continue;
            }
            match driver.validate_value(slot_index, value, true) {
                ValidationLevel::FullyValidated => {
                    if Self::insert_unique(&mut self.accepted, value.clone()) {
                        Self::insert_unique(&mut self.votes, value.clone());
                        modified = true;
                    }
                }
                ValidationLevel::MaybeValid => {
                    if let Some(extracted) = driver.extract_valid_value(slot_index, value) {
                        if Self::insert_unique(&mut self.votes, extracted) {
                            modified = true;
                        }
                    }
                }
                ValidationLevel::Invalid => {}
            }
        }

        // Attempt to promote accepted values to candidates.
        for value in self.accepted.clone() {
            if self.candidates.contains(&value) {
                continue;
            }

            if self.should_ratify_value(&value, local_quorum_set, driver)
                && Self::insert_unique(&mut self.candidates, value.clone())
            {
                new_candidates = true;
                // N12: Stop the nomination timer when candidates are confirmed.
                driver.stop_timer(slot_index, crate::driver::SCPTimerType::Nomination);
            }
        }

        (modified, new_candidates)
    }

    /// Emit a nomination envelope.
    ///
    /// Matches stellar-core `emitNomination()` which creates the self-envelope then
    /// calls `processEnvelope(self)` to re-run acceptance/ratification checks.
    /// This can cascade: if acceptance modifies state, we emit again, and the
    /// `isNewerStatement` check prevents duplicate emissions.
    ///
    /// stellar-core flow:
    /// 1. Create envelope from current votes/accepted
    /// 2. `processEnvelope(self)` — records envelope, runs acceptance/ratification,
    ///    may recursively call `emitNomination()` (updating `mLastEnvelope`)
    /// 3. AFTER processEnvelope returns, check `isNewerStatement` against
    ///    `mLastEnvelope` (which the recursive call may have already updated)
    /// 4. Only set `mLastEnvelope` and emit if still newer
    fn emit_nomination<'a, D: SCPDriver>(
        &mut self,
        ctx: &SlotContext<'a, D>,
    ) {
        let votes = self.sorted_values(&self.votes);
        let accepted = self.sorted_values(&self.accepted);
        let nomination = ScpNomination {
            quorum_set_hash: hash_quorum_set(ctx.local_quorum_set).into(),
            votes: votes.clone().try_into().unwrap_or_default(),
            accepted: accepted.try_into().unwrap_or_default(),
        };

        let statement = ScpStatement {
            node_id: ctx.local_node_id.clone(),
            slot_index: ctx.slot_index,
            pledges: ScpStatementPledges::Nominate(nomination.clone()),
        };

        let mut envelope = ScpEnvelope {
            statement: statement.clone(),
            signature: stellar_xdr::curr::Signature(Vec::new().try_into().unwrap_or_default()),
        };

        ctx.driver.sign_envelope(&mut envelope);

        // Step 1: Record the envelope ( stellar-core recordEnvelope inside processEnvelope).
        // This stores in latest_nominations so quorum checks see our own state.
        if !self.record_local_nomination(ctx.local_node_id, &statement, envelope.clone()) {
            return;
        }

        // Step 2: Run self-processing (stellar-core processEnvelope body).
        // This may recursively call emit_nomination, updating last_envelope.
        if self.started {
            let (modified, new_candidates) =
                self.attempt_promote(&votes, ctx.local_quorum_set, ctx.driver, ctx.slot_index);

            if modified {
                // Cascade: stellar-core emitNomination -> processEnvelope -> emitNomination
                self.emit_nomination(ctx);
            }

            if new_candidates {
                self.update_composite(ctx.driver, ctx.slot_index);
            }
        }

        // Step 3: After self-processing (and any recursive emitNomination calls),
        // check if our envelope is still newer than last_envelope.
        // stellar-core: if (!mLastEnvelope || isNewerStatement(mLastEnvelope->nom, st.nom))
        let is_newer = match &self.last_envelope {
            None => true,
            Some(last) => {
                if let ScpStatementPledges::Nominate(last_nom) = &last.statement.pledges {
                    self.is_newer_nomination(last_nom, &nomination)
                } else {
                    true
                }
            }
        };

        if is_newer {
            self.last_envelope = Some(envelope.clone());
            if self.fully_validated {
                if self.last_envelope_emit.as_ref() != Some(&envelope) {
                    self.last_envelope_emit = Some(envelope.clone());
                    ctx.driver.emit_envelope(&envelope);
                }
            }
        }
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
        if !self.is_newer_nomination_internal(local_node_id, nomination) {
            return false;
        }
        // Safe to insert: we only store nominations here.
        // This keeps local state in the same envelope stream as remote peers.
        self.latest_nominations
            .insert(local_node_id.clone(), envelope);
        true
    }

    pub fn is_newer_statement(&self, node_id: &NodeId, statement: &ScpStatement) -> bool {
        let ScpStatementPledges::Nominate(nomination) = &statement.pledges else {
            return false;
        };
        self.is_newer_nomination_internal(node_id, nomination)
    }

    fn is_newer_nomination_internal(&self, node_id: &NodeId, nomination: &ScpNomination) -> bool {
        match self.latest_nominations.get(node_id) {
            None => true,
            Some(existing) => {
                if let ScpStatementPledges::Nominate(existing_nom) = &existing.statement.pledges {
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
        values.sort_by_key(|a| self.value_key(a));
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
        let voters = self.get_nodes_with_value(value, |nom| &nom.votes);
        let acceptors = self.get_nodes_with_value(value, |nom| &nom.accepted);
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
        let acceptors = self.get_nodes_with_value(value, |nom| &nom.accepted);
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
                ValidationLevel::FullyValidated => Some(value.clone()),
                ValidationLevel::MaybeValid => driver.extract_valid_value(slot_index, value),
                ValidationLevel::Invalid => None,
            };

            if let Some(candidate) = candidate {
                // stellar-core sets foundValidValue = true for ANY valid value
                // (FullyValidated or successfully extracted MaybeValid).
                // This determines whether we also look at votes after accepted.
                *found_valid = true;
                if self.votes.contains(&candidate) {
                    return;
                }
                let hash = self.hash_value(driver, slot_index, &candidate);
                match best {
                    None => *best = Some((hash, candidate)),
                    Some((best_hash, _)) if hash >= *best_hash => *best = Some((hash, candidate)),
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

    fn update_round_leaders<'a, D: SCPDriver>(
        &mut self,
        ctx: &SlotContext<'a, D>,
        prev_value: &Value,
    ) {
        // stellar-core normalizes the quorum set, removing self and adjusting thresholds.
        // This ensures weight calculations and leader selection match stellar-core.
        let mut normalized_qs = ctx.local_quorum_set.clone();
        crate::quorum::normalize_quorum_set_with_remove(&mut normalized_qs, Some(ctx.local_node_id));

        // maxLeaderCount = 1 (self) + all nodes in the normalized set
        let max_leader_count = 1 + Self::count_all_nodes(&normalized_qs);

        while self.round_leaders.len() < max_leader_count {
            let mut new_leaders = HashSet::new();
            let mut top_priority = self.get_node_priority(
                &normalized_qs,
                ctx.driver,
                ctx.slot_index,
                prev_value,
                ctx.local_node_id,
                ctx.local_node_id,
            );
            new_leaders.insert(ctx.local_node_id.clone());

            Self::for_all_nodes(&normalized_qs, &mut |node| {
                let priority = self.get_node_priority(
                    &normalized_qs,
                    ctx.driver,
                    ctx.slot_index,
                    prev_value,
                    ctx.local_node_id,
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

    /// Iterate over all nodes in a quorum set (stellar-core `LocalNode::forAllNodes`).
    ///
    /// Since the quorum set is already normalized with self removed,
    /// this iterates all validators without exclusions.
    fn for_all_nodes<F>(quorum_set: &ScpQuorumSet, f: &mut F)
    where
        F: FnMut(&NodeId),
    {
        for node in quorum_set.validators.iter() {
            f(node);
        }
        for inner in quorum_set.inner_sets.iter() {
            Self::for_all_nodes(inner, f);
        }
    }

    /// Count all nodes in a quorum set (stellar-core `forAllNodes` with counter).
    ///
    /// Since the quorum set is already normalized with self removed,
    /// this counts all validators without exclusions.
    fn count_all_nodes(quorum_set: &ScpQuorumSet) -> usize {
        let mut count = quorum_set.validators.len();
        for inner in quorum_set.inner_sets.iter() {
            count += Self::count_all_nodes(inner);
        }
        count
    }

    /// Restore state from a saved envelope (for crash recovery).
    ///
    /// This method is used to restore the nomination protocol state from a previously
    /// saved envelope when restarting after a crash. It sets up the internal state
    /// to match what it would have been after processing that envelope.
    ///
    /// stellar-core `setStateFromEnvelope` throws if `mNominationStarted` is true and
    /// does NOT set it to true. This should only be called before nomination starts.
    ///
    /// # Arguments
    /// * `envelope` - The envelope to restore state from
    ///
    /// # Returns
    /// True if state was successfully restored, false if the envelope is invalid
    /// for state restoration or if nomination has already started.
    pub fn set_state_from_envelope(&mut self, envelope: &ScpEnvelope) -> bool {
        if self.started {
            // stellar-core throws here: "Cannot set state after nomination is started"
            return false;
        }

        let nomination = match &envelope.statement.pledges {
            ScpStatementPledges::Nominate(nom) => nom,
            _ => return false,
        };

        // Restore votes and accepted values
        self.votes = nomination.votes.iter().cloned().collect();
        self.accepted = nomination.accepted.iter().cloned().collect();

        // Note: stellar-core does NOT set mNominationStarted = true here.
        // The state is restored but nomination is not considered "started"
        // until an explicit call to nominate().

        // Store the envelope
        self.latest_nominations
            .insert(envelope.statement.node_id.clone(), envelope.clone());
        self.last_envelope = Some(envelope.clone());

        true
    }

    /// Get the candidates (confirmed values ready for ballot protocol).
    pub fn candidates(&self) -> &[Value] {
        &self.candidates
    }
}

impl Default for NominationProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
