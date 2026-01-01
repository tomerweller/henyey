//! Error types for overlay operations.

use thiserror::Error;

/// Errors that can occur during overlay operations.
#[derive(Debug, Error)]
pub enum OverlayError {
    /// Connection failed.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Connection timed out.
    #[error("connection timeout: {0}")]
    ConnectionTimeout(String),

    /// Authentication failed.
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Authentication timed out.
    #[error("authentication timeout")]
    AuthenticationTimeout,

    /// Peer disconnected.
    #[error("peer disconnected: {0}")]
    PeerDisconnected(String),

    /// Message encoding/decoding error.
    #[error("message error: {0}")]
    Message(String),

    /// Invalid message received.
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// MAC verification failed.
    #[error("MAC verification failed")]
    MacVerificationFailed,

    /// Peer limit reached.
    #[error("peer limit reached")]
    PeerLimitReached,

    /// Peer not found.
    #[error("peer not found: {0}")]
    PeerNotFound(String),

    /// Peer is banned.
    #[error("peer is banned: {0}")]
    PeerBanned(String),

    /// Already connected to peer.
    #[error("already connected to peer")]
    AlreadyConnected,

    /// Protocol version mismatch.
    #[error("protocol version mismatch: {0}")]
    VersionMismatch(String),

    /// Network ID mismatch.
    #[error("network ID mismatch")]
    NetworkMismatch,

    /// Overlay not started.
    #[error("overlay not started")]
    NotStarted,

    /// Overlay already started.
    #[error("overlay already started")]
    AlreadyStarted,

    /// Overlay is shutting down.
    #[error("overlay is shutting down")]
    ShuttingDown,

    /// XDR encoding/decoding error.
    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::curr::Error),

    /// Crypto error.
    #[error("crypto error: {0}")]
    Crypto(#[from] stellar_core_crypto::CryptoError),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Channel send error.
    #[error("channel send error")]
    ChannelSend,

    /// Channel receive error.
    #[error("channel receive error")]
    ChannelRecv,

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl OverlayError {
    /// Check if this is a connection error that warrants retry.
    pub fn is_retriable(&self) -> bool {
        matches!(
            self,
            OverlayError::ConnectionFailed(_)
                | OverlayError::ConnectionTimeout(_)
                | OverlayError::Io(_)
        )
    }

    /// Check if this is a fatal error.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            OverlayError::NetworkMismatch | OverlayError::VersionMismatch(_)
        )
    }
}
