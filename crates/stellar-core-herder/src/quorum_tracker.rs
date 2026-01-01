//! Quorum tracker for monitoring whether we've heard from quorum.

use std::collections::{HashMap, HashSet};

use stellar_core_scp::{is_quorum, is_v_blocking};
use stellar_xdr::curr::{NodeId, ScpQuorumSet};
use stellar_core_scp::SlotIndex;

/// Tracks quorum participation over recent slots.
#[derive(Debug, Clone)]
pub struct QuorumTracker {
    local_quorum_set: Option<ScpQuorumSet>,
    max_slots: usize,
    slot_nodes: HashMap<SlotIndex, HashSet<NodeId>>,
}

impl QuorumTracker {
    /// Create a new tracker.
    pub fn new(local_quorum_set: Option<ScpQuorumSet>, max_slots: usize) -> Self {
        Self {
            local_quorum_set,
            max_slots,
            slot_nodes: HashMap::new(),
        }
    }

    /// Update the local quorum set.
    pub fn set_local_quorum_set(&mut self, quorum_set: Option<ScpQuorumSet>) {
        self.local_quorum_set = quorum_set;
    }

    /// Record that we've heard from a node for a slot.
    pub fn record_envelope(&mut self, slot: SlotIndex, node_id: NodeId) {
        self.slot_nodes
            .entry(slot)
            .or_default()
            .insert(node_id);
        self.prune();
    }

    /// Remove entries for a slot.
    pub fn clear_slot(&mut self, slot: SlotIndex) {
        self.slot_nodes.remove(&slot);
    }

    /// Check if we have a quorum for a slot.
    pub fn has_quorum<F>(&self, slot: SlotIndex, get_qs: F) -> bool
    where
        F: Fn(&NodeId) -> Option<ScpQuorumSet>,
    {
        let local = match &self.local_quorum_set {
            Some(qs) => qs,
            None => return false,
        };
        let nodes = match self.slot_nodes.get(&slot) {
            Some(nodes) => nodes,
            None => return false,
        };
        is_quorum(local, nodes, get_qs)
    }

    /// Check if we have a v-blocking set for a slot.
    pub fn is_v_blocking(&self, slot: SlotIndex) -> bool {
        let local = match &self.local_quorum_set {
            Some(qs) => qs,
            None => return false,
        };
        let nodes = match self.slot_nodes.get(&slot) {
            Some(nodes) => nodes,
            None => return false,
        };
        is_v_blocking(local, nodes)
    }

    fn prune(&mut self) {
        if self.max_slots == 0 || self.slot_nodes.len() <= self.max_slots {
            return;
        }

        let mut slots: Vec<_> = self.slot_nodes.keys().copied().collect();
        slots.sort_unstable();
        let remove_count = self.slot_nodes.len().saturating_sub(self.max_slots);
        for slot in slots.into_iter().take(remove_count) {
            self.slot_nodes.remove(&slot);
        }
    }
}
