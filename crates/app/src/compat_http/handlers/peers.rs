//! stellar-core compatible `/peers` handler.
//!
//! Returns peers in stellar-core's categorized format with camelCase fields.

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use henyey_overlay::ConnectionDirection;

use crate::compat_http::CompatServerState;

/// GET /peers
///
/// Returns peers in stellar-core's format: `{authenticated_peers: {inbound, outbound}, pending_peers: {inbound, outbound}}`.
pub(crate) async fn compat_peers_handler(
    State(state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    let app = &state.app;
    let snapshots = app.peer_snapshots().await;

    let mut authenticated_inbound = Vec::new();
    let mut authenticated_outbound = Vec::new();

    for peer in &snapshots {
        let entry = CompatPeerEntry {
            address: peer.info.address.to_string(),
            elapsed: peer.info.connected_at.elapsed().as_secs(),
            id: peer.info.peer_id.to_string(),
            olver: peer.info.overlay_version,
            ver: peer.info.version_string.clone(),
            message_read: peer.stats.messages_received,
            message_write: peer.stats.messages_sent,
        };

        match peer.info.direction {
            ConnectionDirection::Inbound => authenticated_inbound.push(entry),
            ConnectionDirection::Outbound => authenticated_outbound.push(entry),
        }
    }

    let response = CompatPeersResponse {
        authenticated_peers: CompatPeerCategory {
            inbound: authenticated_inbound,
            outbound: authenticated_outbound,
        },
        pending_peers: CompatPeerCategory {
            inbound: Vec::new(),
            outbound: Vec::new(),
        },
    };

    Json(response)
}

#[derive(Serialize)]
struct CompatPeersResponse {
    authenticated_peers: CompatPeerCategory,
    pending_peers: CompatPeerCategory,
}

#[derive(Serialize)]
struct CompatPeerCategory {
    inbound: Vec<CompatPeerEntry>,
    outbound: Vec<CompatPeerEntry>,
}

#[derive(Serialize)]
struct CompatPeerEntry {
    address: String,
    elapsed: u64,
    id: String,
    olver: u32,
    ver: String,
    message_read: u64,
    message_write: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify `/peers` response has stellar-core's exact JSON shape:
    /// `{authenticated_peers: {inbound: [...], outbound: [...]}, pending_peers: {inbound: [...], outbound: [...]}}`
    #[test]
    fn test_peers_response_shape() {
        let response = CompatPeersResponse {
            authenticated_peers: CompatPeerCategory {
                inbound: vec![CompatPeerEntry {
                    address: "127.0.0.1:11625".into(),
                    elapsed: 120,
                    id: "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEBD9AFZQ7TM4JRS9A".into(),
                    olver: 35,
                    ver: "stellar-core v25.0.1".into(),
                    message_read: 500,
                    message_write: 300,
                }],
                outbound: vec![],
            },
            pending_peers: CompatPeerCategory {
                inbound: vec![],
                outbound: vec![],
            },
        };

        let value = serde_json::to_value(&response).unwrap();
        let obj = value.as_object().unwrap();

        // Top-level keys
        assert!(obj.contains_key("authenticated_peers"));
        assert!(obj.contains_key("pending_peers"));
        assert_eq!(
            obj.len(),
            2,
            "should only have authenticated_peers and pending_peers"
        );

        // Each category has inbound/outbound
        for category_key in ["authenticated_peers", "pending_peers"] {
            let cat = value[category_key].as_object().unwrap();
            assert!(
                cat.contains_key("inbound"),
                "{category_key} missing inbound"
            );
            assert!(
                cat.contains_key("outbound"),
                "{category_key} missing outbound"
            );
            assert_eq!(
                cat.len(),
                2,
                "{category_key} should only have inbound/outbound"
            );
        }

        // Peer entry fields
        let peer = &value["authenticated_peers"]["inbound"][0];
        let expected_peer_keys = [
            "address",
            "elapsed",
            "id",
            "olver",
            "ver",
            "message_read",
            "message_write",
        ];
        for key in &expected_peer_keys {
            assert!(peer.get(key).is_some(), "missing peer entry key: {key}");
        }
        let peer_obj = peer.as_object().unwrap();
        assert_eq!(
            peer_obj.len(),
            expected_peer_keys.len(),
            "peer entry has unexpected extra keys"
        );
    }

    /// Verify empty peers response serializes correctly.
    #[test]
    fn test_peers_response_empty() {
        let response = CompatPeersResponse {
            authenticated_peers: CompatPeerCategory {
                inbound: vec![],
                outbound: vec![],
            },
            pending_peers: CompatPeerCategory {
                inbound: vec![],
                outbound: vec![],
            },
        };

        let value = serde_json::to_value(&response).unwrap();
        assert!(value["authenticated_peers"]["inbound"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(value["authenticated_peers"]["outbound"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(value["pending_peers"]["inbound"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(value["pending_peers"]["outbound"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}
