use std::collections::HashMap;
use std::time::Duration;

use henyey_clock::VirtualClock;
use henyey_common::Hash256;
use henyey_crypto::SecretKey;

mod loopback;
pub use loopback::LoopbackNetwork;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulationMode {
    OverLoopback,
    OverTcp,
}

#[derive(Debug, Clone)]
pub struct SimNode {
    pub node_id: String,
    pub secret_key: SecretKey,
    pub clock: VirtualClock,
    pub ledger_seq: u32,
    pub ledger_hash: Hash256,
}

#[derive(Debug)]
pub struct Simulation {
    mode: SimulationMode,
    nodes: HashMap<String, SimNode>,
    loopback: LoopbackNetwork,
}

impl Simulation {
    pub fn new(mode: SimulationMode) -> Self {
        Self {
            mode,
            nodes: HashMap::new(),
            loopback: LoopbackNetwork::new(),
        }
    }

    pub fn add_node(&mut self, node_id: impl Into<String>, secret_key: SecretKey) {
        let node_id = node_id.into();
        let node = SimNode {
            node_id: node_id.clone(),
            secret_key,
            clock: VirtualClock::new(),
            ledger_seq: 1,
            ledger_hash: Hash256::hash(node_id.as_bytes()),
        };
        self.nodes.insert(node_id, node);
    }

    pub fn add_pending_connection(&mut self, a: impl Into<String>, b: impl Into<String>) {
        let a = a.into();
        let b = b.into();
        if a == b {
            return;
        }
        self.loopback.add_link(a, b);
    }

    pub async fn start_all_nodes(&mut self) {
        if matches!(self.mode, SimulationMode::OverTcp) {
            // Placeholder: TCP-backed simulation wiring lands in a follow-up slice.
        }
    }

    pub async fn crank_all_nodes(&mut self) -> bool {
        if self.nodes.is_empty() {
            return false;
        }

        let mut did_work = false;
        let ids: Vec<String> = self.nodes.keys().cloned().collect();
        let max_seq = ids
            .iter()
            .filter_map(|id| self.nodes.get(id).map(|n| n.ledger_seq))
            .max()
            .unwrap_or(1);

        for id in &ids {
            if self.loopback.is_partitioned(id) {
                continue;
            }

            let current = self.nodes.get(id).map(|n| n.ledger_seq).unwrap_or(1);
            if current < max_seq {
                let has_path = ids.iter().any(|other| {
                    if other == id || self.loopback.is_partitioned(other) {
                        return false;
                    }
                    self.loopback.link_active(id, other)
                });
                if has_path {
                    let next = current + 1;
                    let hash_input = format!("{}:{}", id, next);
                    if let Some(node) = self.nodes.get_mut(id) {
                        node.ledger_seq = next;
                        node.ledger_hash = Hash256::hash(hash_input.as_bytes());
                    }
                    did_work = true;
                }
            }
        }

        let non_partitioned: Vec<String> = ids
            .iter()
            .filter(|id| !self.loopback.is_partitioned(id))
            .cloned()
            .collect();
        if non_partitioned.len() >= 2 {
            let all_equal = non_partitioned
                .iter()
                .filter_map(|id| self.nodes.get(id).map(|n| n.ledger_seq))
                .all(|seq| seq == max_seq);
            if all_equal {
                let connected = non_partitioned.iter().all(|id| {
                    non_partitioned
                        .iter()
                        .filter(|other| *other != id)
                        .any(|other| self.loopback.link_active(id, other))
                });
                if connected {
                    for id in &non_partitioned {
                        let next = max_seq + 1;
                        let hash_input = format!("{}:{}", id, next);
                        if let Some(node) = self.nodes.get_mut(id) {
                            node.ledger_seq = next;
                            node.ledger_hash = Hash256::hash(hash_input.as_bytes());
                        }
                    }
                    did_work = true;
                }
            }
        }

        did_work
    }

    pub async fn crank_until<P>(&mut self, predicate: P, timeout: Duration) -> bool
    where
        P: Fn(&Simulation) -> bool,
    {
        let mut elapsed = Duration::ZERO;
        while elapsed <= timeout {
            if predicate(self) {
                return true;
            }
            let _ = self.crank_all_nodes().await;
            elapsed = elapsed.saturating_add(Duration::from_millis(100));
        }
        predicate(self)
    }

    pub fn have_all_externalized(&self, ledger_seq: u32, max_spread: u32) -> bool {
        if self.nodes.is_empty() {
            return false;
        }

        let seqs: Vec<u32> = self
            .nodes
            .iter()
            .filter(|(id, _)| !self.loopback.is_partitioned(id))
            .map(|(_, n)| n.ledger_seq)
            .collect();

        if seqs.is_empty() {
            return false;
        }

        let min_seq = *seqs.iter().min().unwrap_or(&0);
        let max_seq = *seqs.iter().max().unwrap_or(&0);
        min_seq >= ledger_seq && max_seq.saturating_sub(min_seq) <= max_spread
    }

    pub fn ledger_seq(&self, node_id: &str) -> u32 {
        self.nodes.get(node_id).map(|n| n.ledger_seq).unwrap_or(0)
    }

    pub fn node_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.nodes.keys().cloned().collect();
        ids.sort();
        ids
    }

    pub fn all_links(&self) -> Vec<(String, String)> {
        self.loopback.links()
    }

    pub fn partition(&mut self, node_id: &str) {
        self.loopback.partition(node_id);
    }

    pub fn heal_partition(&mut self, node_id: &str) {
        self.loopback.heal_partition(node_id);
    }

    pub fn set_drop_prob(&mut self, a: &str, b: &str, prob: f64) {
        self.loopback.set_drop_prob(a, b, prob);
    }

    pub fn ledger_hashes(&self) -> Vec<Hash256> {
        let mut items: Vec<(&String, Hash256)> = self
            .nodes
            .iter()
            .map(|(id, n)| (id, n.ledger_hash))
            .collect();
        items.sort_by(|a, b| a.0.cmp(b.0));
        items.into_iter().map(|(_, h)| h).collect()
    }

    pub fn is_fully_connected(&self) -> bool {
        let ids = self.node_ids();
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                if !self.loopback.link_active(&ids[i], &ids[j]) {
                    return false;
                }
            }
        }
        true
    }

}

pub struct Topologies;

impl Topologies {
    pub fn core3(mode: SimulationMode) -> Simulation {
        Self::core(3, mode)
    }

    pub fn core(n: usize, mode: SimulationMode) -> Simulation {
        let mut sim = Simulation::new(mode);
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let id = format!("node{}", i);
            let seed = Hash256::hash(format!("SIM_NODE_SEED_{}", i).as_bytes());
            let sk = SecretKey::from_seed(&seed.0);
            sim.add_node(id.clone(), sk);
            ids.push(id);
        }

        for i in 0..n {
            for j in (i + 1)..n {
                sim.add_pending_connection(ids[i].clone(), ids[j].clone());
            }
        }

        sim
    }

    pub fn pair(mode: SimulationMode) -> Simulation {
        Self::core(2, mode)
    }

    pub fn cycle(n: usize, mode: SimulationMode) -> Simulation {
        let mut sim = Simulation::new(mode);
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let id = format!("node{}", i);
            let seed = Hash256::hash(format!("SIM_NODE_SEED_{}", i).as_bytes());
            let sk = SecretKey::from_seed(&seed.0);
            sim.add_node(id.clone(), sk);
            ids.push(id);
        }

        if n >= 2 {
            for i in 0..n {
                let j = (i + 1) % n;
                sim.add_pending_connection(ids[i].clone(), ids[j].clone());
            }
        }

        sim
    }

    pub fn separate(mode: SimulationMode) -> Simulation {
        let mut sim = Simulation::new(mode);
        for i in 0..4 {
            let id = format!("node{}", i);
            let seed = Hash256::hash(format!("SIM_NODE_SEED_{}", i).as_bytes());
            let sk = SecretKey::from_seed(&seed.0);
            sim.add_node(id, sk);
        }

        sim.add_pending_connection("node0", "node1");
        sim.add_pending_connection("node2", "node3");
        sim
    }
}
