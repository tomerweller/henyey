//! P2P networking for rs-stellar-core.
//!
//! This crate implements the Stellar overlay network protocol, providing:
//!
//! - Peer discovery and connection management
//! - Authenticated peer connections (using Curve25519 key exchange)
//! - Message routing and flooding
//! - Bandwidth management and flow control
//!
//! ## Protocol
//!
//! The overlay uses TCP connections with XDR-encoded messages. Each connection
//! begins with an authentication handshake that establishes a shared secret
//! for message authentication.
//!
//! ## Message Types
//!
//! - **Hello**: Initial handshake with peer capabilities
//! - **Auth**: Authentication challenge/response
//! - **Peers**: Peer address exchange
//! - **Transaction**: Transaction broadcasting
//! - **SCP**: Consensus messages
//! - **GetSCPState**: Request peer's SCP state

mod auth;
mod codec;
mod connection;
mod error;
mod flood;
mod manager;
mod peer;

pub use auth::{AuthCert, AuthContext, AuthState};
pub use codec::{helpers as message_helpers, MessageCodec, MessageFrame};
pub use connection::{Connection, ConnectionDirection, ConnectionPool, Listener};
pub use error::OverlayError;
pub use flood::{compute_message_hash, FloodGate, FloodGateStats, FloodRecord};
pub use manager::{OverlayManager, OverlayMessage, OverlayStats};
pub use peer::{Peer, PeerInfo, PeerSender, PeerState, PeerStats, PeerStatsSnapshot};

/// Result type for overlay operations.
pub type Result<T> = std::result::Result<T, OverlayError>;

/// Configuration for the overlay network.
#[derive(Debug, Clone)]
pub struct OverlayConfig {
    /// Maximum number of inbound peer connections.
    pub max_inbound_peers: usize,
    /// Maximum number of outbound peer connections.
    pub max_outbound_peers: usize,
    /// Target number of outbound connections to maintain.
    pub target_outbound_peers: usize,
    /// Port to listen on for incoming connections.
    pub listen_port: u16,
    /// Known peers to connect to on startup.
    pub known_peers: Vec<PeerAddress>,
    /// Preferred peers that should always be connected.
    pub preferred_peers: Vec<PeerAddress>,
    /// Network passphrase for authentication.
    pub network_passphrase: String,
    /// Peer authentication timeout in seconds.
    pub auth_timeout_secs: u64,
    /// Connection timeout in seconds.
    pub connect_timeout_secs: u64,
    /// Message flood TTL in seconds.
    pub flood_ttl_secs: u64,
    /// Whether to listen for incoming connections.
    pub listen_enabled: bool,
    /// Version info string for Hello messages.
    pub version_string: String,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            max_inbound_peers: 64,
            max_outbound_peers: 8,
            target_outbound_peers: 8,
            listen_port: 11625,
            known_peers: Vec::new(),
            preferred_peers: Vec::new(),
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            auth_timeout_secs: 30,
            connect_timeout_secs: 10,
            flood_ttl_secs: 300,
            listen_enabled: true,
            version_string: "rs-stellar-core/0.1.0".to_string(),
        }
    }
}

impl OverlayConfig {
    /// Create testnet configuration with known testnet peers.
    pub fn testnet() -> Self {
        Self {
            known_peers: vec![
                PeerAddress::new("core-testnet1.stellar.org", 11625),
                PeerAddress::new("core-testnet2.stellar.org", 11625),
                PeerAddress::new("core-testnet3.stellar.org", 11625),
            ],
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            listen_enabled: false, // Don't listen by default for sync-only
            ..Default::default()
        }
    }

    /// Create mainnet configuration with known mainnet peers.
    pub fn mainnet() -> Self {
        Self {
            known_peers: vec![
                PeerAddress::new("core-live-a.stellar.org", 11625),
                PeerAddress::new("core-live-b.stellar.org", 11625),
                PeerAddress::new("core-live-c.stellar.org", 11625),
            ],
            network_passphrase: "Public Global Stellar Network ; September 2015".to_string(),
            listen_enabled: false,
            ..Default::default()
        }
    }
}

/// Address of a peer on the network.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerAddress {
    /// IP address or hostname.
    pub host: String,
    /// Port number.
    pub port: u16,
}

impl PeerAddress {
    /// Create a new peer address.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// Convert to a socket address string for connecting.
    pub fn to_socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl std::fmt::Display for PeerAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Unique identifier for a peer (their public key).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerId(pub stellar_xdr::curr::PublicKey);

impl PeerId {
    /// Create from XDR public key.
    pub fn from_xdr(key: stellar_xdr::curr::PublicKey) -> Self {
        Self(key)
    }

    /// Create from raw public key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::curr::Uint256(bytes),
        ))
    }

    /// Get the raw public key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        match &self.0 {
            stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                stellar_xdr::curr::Uint256(bytes),
            ) => bytes,
        }
    }

    /// Convert to hex string for display.
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display first 8 chars of hex
        let hex = self.to_hex();
        write!(f, "{}...", &hex[..8])
    }
}

/// Trait for handling incoming messages from the overlay.
#[async_trait::async_trait]
pub trait MessageHandler: Send + Sync {
    /// Handle an incoming message from a peer.
    async fn handle_message(
        &self,
        peer_id: &PeerId,
        message: stellar_xdr::curr::StellarMessage,
    ) -> Result<()>;
}

/// Local node information for overlay authentication.
#[derive(Clone)]
pub struct LocalNode {
    /// Ed25519 secret key for signing.
    pub secret_key: stellar_core_crypto::SecretKey,
    /// Network ID derived from passphrase.
    pub network_id: stellar_core_common::NetworkId,
    /// Overlay version info.
    pub version_string: String,
    /// Ledger version supported.
    pub ledger_version: u32,
    /// Overlay version supported.
    pub overlay_version: u32,
    /// Minimum overlay version we accept.
    pub overlay_min_version: u32,
    /// Port we listen on for peer connections.
    pub listening_port: u16,
}

impl LocalNode {
    /// Create a new local node with testnet defaults.
    pub fn new_testnet(secret_key: stellar_core_crypto::SecretKey) -> Self {
        Self {
            secret_key,
            network_id: stellar_core_common::NetworkId::testnet(),
            version_string: "stellar-core v25.0.1".to_string(),
            ledger_version: 24,
            overlay_version: 38,
            overlay_min_version: 35,
            listening_port: 11625,
        }
    }

    /// Create a new local node with mainnet defaults.
    pub fn new_mainnet(secret_key: stellar_core_crypto::SecretKey) -> Self {
        Self {
            secret_key,
            network_id: stellar_core_common::NetworkId::mainnet(),
            version_string: "stellar-core v25.0.1".to_string(),
            ledger_version: 24,
            overlay_version: 38,
            overlay_min_version: 35,
            listening_port: 11625,
        }
    }

    /// Create with custom network passphrase.
    pub fn new(secret_key: stellar_core_crypto::SecretKey, network_passphrase: &str) -> Self {
        Self {
            secret_key,
            network_id: stellar_core_common::NetworkId::from_passphrase(network_passphrase),
            version_string: "stellar-core v25.0.1".to_string(),
            ledger_version: 24,
            overlay_version: 38,
            overlay_min_version: 35,
            listening_port: 11625,
        }
    }

    /// Get our public key.
    pub fn public_key(&self) -> stellar_core_crypto::PublicKey {
        self.secret_key.public_key()
    }

    /// Get our XDR public key.
    pub fn xdr_public_key(&self) -> stellar_xdr::curr::PublicKey {
        (&self.public_key()).into()
    }

    /// Get our peer ID.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_xdr(self.xdr_public_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_address() {
        let addr = PeerAddress::new("127.0.0.1", 11625);
        assert_eq!(addr.to_socket_addr(), "127.0.0.1:11625");
        assert_eq!(addr.to_string(), "127.0.0.1:11625");
    }

    #[test]
    fn test_overlay_config_testnet() {
        let config = OverlayConfig::testnet();
        assert_eq!(config.known_peers.len(), 3);
        assert_eq!(
            config.network_passphrase,
            "Test SDF Network ; September 2015"
        );
    }

    #[test]
    fn test_peer_id() {
        let bytes = [1u8; 32];
        let peer_id = PeerId::from_bytes(bytes);
        assert_eq!(peer_id.as_bytes(), &bytes);
    }

    #[test]
    fn test_local_node() {
        let secret = stellar_core_crypto::SecretKey::generate();
        let node = LocalNode::new_testnet(secret);
        let peer_id = node.peer_id();
        assert!(!peer_id.to_hex().is_empty());
    }
}
