use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;
use stellar_core_scp::{is_quorum, is_quorum_slice};
use stellar_core_scp::quorum_config::parse_node_id;
use stellar_xdr::curr::{NodeId, ScpQuorumSet};

#[derive(Debug, Deserialize)]
struct QuorumIntersectionJson {
    nodes: Vec<NodeEntry>,
}

#[derive(Debug, Deserialize)]
struct NodeEntry {
    node: String,
    qset: QsetEntry,
}

#[derive(Debug, Deserialize)]
struct QsetEntry {
    t: u32,
    v: Vec<String>,
}

fn parse_qset(entry: &QsetEntry) -> anyhow::Result<ScpQuorumSet> {
    let mut validators = Vec::with_capacity(entry.v.len());
    for node in &entry.v {
        let parsed = parse_node_id(node).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        validators.push(parsed);
    }

    Ok(ScpQuorumSet {
        threshold: entry.t,
        validators: validators.try_into().unwrap_or_default(),
        inner_sets: Vec::new().try_into().unwrap_or_default(),
    })
}

fn load_quorum_map(path: &Path) -> anyhow::Result<HashMap<NodeId, ScpQuorumSet>> {
    let payload = fs::read_to_string(path)?;
    let json: QuorumIntersectionJson =
        serde_json::from_str(&payload).map_err(|e| anyhow::anyhow!("parse error: {}", e))?;

    let mut map = HashMap::new();
    for entry in json.nodes {
        let node_id = parse_node_id(&entry.node).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let qset = parse_qset(&entry.qset)?;
        map.insert(node_id, qset);
    }

    Ok(map)
}

fn is_quorum_for_set(nodes: &HashSet<NodeId>, qmap: &HashMap<NodeId, ScpQuorumSet>) -> bool {
    let Some(first) = nodes.iter().next() else {
        return false;
    };
    let Some(local_qset) = qmap.get(first) else {
        return false;
    };

    is_quorum(local_qset, nodes, |node_id| qmap.get(node_id).cloned())
}

fn network_enjoys_quorum_intersection(qmap: &HashMap<NodeId, ScpQuorumSet>) -> bool {
    let nodes: Vec<NodeId> = qmap.keys().cloned().collect();
    if nodes.is_empty() {
        return false;
    }

    let mut quorums: Vec<HashSet<NodeId>> = Vec::new();
    let total = nodes.len();
    for mask in 1..(1u64 << total) {
        let mut subset = HashSet::new();
        for (idx, node) in nodes.iter().enumerate() {
            if (mask >> idx) & 1 == 1 {
                subset.insert(node.clone());
            }
        }
        if is_quorum_for_set(&subset, qmap) {
            quorums.push(subset);
        }
    }

    for i in 0..quorums.len() {
        for j in (i + 1)..quorums.len() {
            if quorums[i].is_disjoint(&quorums[j]) {
                return false;
            }
        }
    }

    true
}

pub fn check_quorum_intersection_from_json(path: &Path) -> anyhow::Result<bool> {
    let qmap = load_quorum_map(path)?;
    for (node, qset) in &qmap {
        let nodes: HashSet<NodeId> = qmap.keys().cloned().collect();
        if !is_quorum_slice(qset, &nodes, &|id| qmap.get(id).cloned()) {
            anyhow::bail!(
                "quorum set for {} has no slice in network",
                node_id_to_hex(node)
            );
        }
    }

    Ok(network_enjoys_quorum_intersection(&qmap))
}

fn node_id_to_hex(node: &NodeId) -> String {
    use stellar_xdr::curr::PublicKey;
    match node.0 {
        PublicKey::PublicKeyTypeEd25519(ref key) => hex::encode(key.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn testdata_path(name: &str) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("..");
        path.push("..");
        path.push("testdata");
        path.push("check-quorum-intersection-json");
        path.push(name);
        path
    }

    #[test]
    fn test_enjoys_quorum_intersection() {
        let path = testdata_path("enjoys-intersection.json");
        let enjoys = check_quorum_intersection_from_json(&path).expect("check quorum intersection");
        assert!(enjoys);
    }

    #[test]
    fn test_no_quorum_intersection() {
        let path = testdata_path("no-intersection.json");
        let enjoys = check_quorum_intersection_from_json(&path).expect("check quorum intersection");
        assert!(!enjoys);
    }

    #[test]
    fn test_bad_key() {
        let path = testdata_path("bad-key.json");
        let err = check_quorum_intersection_from_json(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("invalid public key") || msg.contains("Invalid public key"),
            "{msg}"
        );
    }

    #[test]
    fn test_bad_threshold_type() {
        let path = testdata_path("bad-threshold-type.json");
        let err = check_quorum_intersection_from_json(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("parse"), "{msg}");
    }

    #[test]
    fn test_missing_file() {
        let path = testdata_path("no-file.json");
        let err = check_quorum_intersection_from_json(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("No such file") || msg.contains("read"), "{msg}");
    }
}
