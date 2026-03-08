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
