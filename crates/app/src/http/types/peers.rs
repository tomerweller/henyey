//! Types for peer-related endpoints.

use serde::{Deserialize, Serialize};

/// Response for the /peers endpoint.
#[derive(Serialize)]
pub struct PeersResponse {
    /// Authenticated peers categorized by direction.
    pub authenticated: PeersByDirection,
    /// Total number of authenticated peers.
    pub authenticated_count: usize,
    /// Number of pending (unauthenticated) peers.
    pub pending_count: usize,
}

/// Peers grouped by connection direction.
#[derive(Serialize)]
pub struct PeersByDirection {
    pub inbound: Vec<PeerInfo>,
    pub outbound: Vec<PeerInfo>,
}

/// Information about a connected peer.
#[derive(Serialize)]
pub struct PeerInfo {
    /// Peer public key (hex-encoded).
    pub id: String,
    /// Remote address (ip:port).
    pub address: String,
    /// Connection direction ("inbound" or "outbound").
    pub direction: String,
    /// Peer's software version string (e.g. "stellar-core v25.0.0").
    pub version: String,
    /// Peer's overlay protocol version.
    pub overlay_version: u32,
    /// Peer's ledger protocol version.
    pub ledger_version: u32,
    /// Messages sent to this peer.
    pub messages_sent: u64,
    /// Messages received from this peer.
    pub messages_received: u64,
    /// Bytes sent to this peer.
    pub bytes_sent: u64,
    /// Bytes received from this peer.
    pub bytes_received: u64,
    /// Seconds since connection was established.
    pub elapsed_secs: u64,
}

/// Query parameters for connecting to a peer.
#[derive(Deserialize)]
pub struct ConnectParams {
    pub addr: Option<String>,
    pub peer: Option<String>,
    pub port: Option<u16>,
}

/// Query parameters for dropping a peer.
#[derive(Deserialize)]
pub struct DropPeerParams {
    pub peer_id: Option<String>,
    pub node: Option<String>,
    pub ban: Option<u8>,
}

/// Query parameters for unbanning a peer.
#[derive(Deserialize)]
pub struct UnbanParams {
    pub peer_id: Option<String>,
    pub node: Option<String>,
}

/// Response for the /bans endpoint.
#[derive(Serialize)]
pub struct BansResponse {
    pub bans: Vec<String>,
}
