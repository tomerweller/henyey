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
