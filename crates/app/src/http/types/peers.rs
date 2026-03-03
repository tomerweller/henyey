//! Types for peer-related endpoints.

use serde::{Deserialize, Serialize};

/// Response for the /peers endpoint.
#[derive(Serialize)]
pub struct PeersResponse {
    pub count: usize,
    pub peers: Vec<PeerInfo>,
}

/// Information about a connected peer.
#[derive(Serialize)]
pub struct PeerInfo {
    pub id: String,
    pub address: String,
    pub direction: String,
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
