//! Deterministic link model with partition and drop-probability controls.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Default, Clone)]
pub struct LoopbackNetwork {
    links: HashSet<(String, String)>,
    partitions: HashSet<String>,
    drop_prob: HashMap<(String, String), f64>,
}

impl LoopbackNetwork {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_link(&mut self, a: impl Into<String>, b: impl Into<String>) {
        let a = a.into();
        let b = b.into();
        if a == b {
            return;
        }
        self.links.insert(ordered_pair(&a, &b));
    }

    pub fn links(&self) -> Vec<(String, String)> {
        self.links.iter().cloned().collect()
    }

    pub fn partition(&mut self, node_id: &str) {
        self.partitions.insert(node_id.to_string());
    }

    pub fn heal_partition(&mut self, node_id: &str) {
        self.partitions.remove(node_id);
    }

    pub fn set_drop_prob(&mut self, a: &str, b: &str, prob: f64) {
        self.drop_prob
            .insert(ordered_pair(a, b), prob.clamp(0.0, 1.0));
    }

    pub fn is_partitioned(&self, node_id: &str) -> bool {
        self.partitions.contains(node_id)
    }

    /// Returns all nodes directly linked to `node_id`, sorted for deterministic iteration.
    pub(crate) fn neighbors(&self, node_id: &str) -> Vec<String> {
        let mut result: Vec<String> = self
            .links
            .iter()
            .filter_map(|(a, b)| {
                if a == node_id {
                    Some(b.clone())
                } else if b == node_id {
                    Some(a.clone())
                } else {
                    None
                }
            })
            .collect();
        result.sort();
        result
    }

    pub fn link_active(&self, a: &str, b: &str) -> bool {
        let key = ordered_pair(a, b);
        if !self.links.contains(&key) {
            return false;
        }
        let drop_prob = self.drop_prob.get(&key).copied().unwrap_or(0.0);
        drop_prob < 1.0
    }
}

fn ordered_pair(a: &str, b: &str) -> (String, String) {
    if a < b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neighbors_cycle4_symmetric() {
        let mut net = LoopbackNetwork::new();
        // cycle4: node0→node1→node2→node3→node0
        net.add_link("node0", "node1");
        net.add_link("node1", "node2");
        net.add_link("node2", "node3");
        net.add_link("node3", "node0");

        assert_eq!(net.neighbors("node0"), vec!["node1", "node3"]);
        assert_eq!(net.neighbors("node1"), vec!["node0", "node2"]);
        assert_eq!(net.neighbors("node2"), vec!["node1", "node3"]);
        assert_eq!(net.neighbors("node3"), vec!["node0", "node2"]);
    }

    #[test]
    fn test_neighbors_core3() {
        let mut net = LoopbackNetwork::new();
        // core3: fully connected 3 nodes
        net.add_link("node0", "node1");
        net.add_link("node0", "node2");
        net.add_link("node1", "node2");

        assert_eq!(net.neighbors("node0"), vec!["node1", "node2"]);
        assert_eq!(net.neighbors("node1"), vec!["node0", "node2"]);
        assert_eq!(net.neighbors("node2"), vec!["node0", "node1"]);
    }

    #[test]
    fn test_neighbors_pair() {
        let mut net = LoopbackNetwork::new();
        net.add_link("node0", "node1");

        assert_eq!(net.neighbors("node0"), vec!["node1"]);
        assert_eq!(net.neighbors("node1"), vec!["node0"]);
    }

    #[test]
    fn test_neighbors_unlinked_node() {
        let mut net = LoopbackNetwork::new();
        net.add_link("node0", "node1");

        assert_eq!(net.neighbors("node2"), Vec::<String>::new());
    }

    #[test]
    fn test_neighbors_sorted_deterministic() {
        let mut net = LoopbackNetwork::new();
        // Add links in reverse order to verify sorting
        net.add_link("node3", "node0");
        net.add_link("node2", "node0");
        net.add_link("node1", "node0");

        // Should always be sorted regardless of insertion order
        assert_eq!(net.neighbors("node0"), vec!["node1", "node2", "node3"]);
    }
}
