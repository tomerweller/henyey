//! Error types for overlay operations.
//!
//! Defines the [`OverlayError`] enum which covers all error conditions that
//! can occur during overlay network operations, including:
//!
//! - Connection failures and timeouts
//! - Authentication and MAC verification errors
//! - Protocol version mismatches
//! - Peer management errors
//! - Internal errors

use thiserror::Error;

/// Errors that can occur during overlay network operations.
///
/// This enum covers all error conditions from connection establishment
/// through message exchange and peer management.
#[derive(Debug, Error)]
pub enum OverlayError {
    // ===== Connection Errors =====
    /// TCP connection could not be established.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Connection attempt or receive operation timed out.
    #[error("connection timeout: {0}")]
    ConnectionTimeout(String),

    /// The peer closed the connection.
    #[error("peer disconnected: {0}")]
    PeerDisconnected(String),

    // ===== Authentication Errors =====
    /// Authentication handshake failed (invalid cert, bad signature, etc.).
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Authentication handshake did not complete in time.
    #[error("authentication timeout")]
    AuthenticationTimeout,

    /// HMAC verification failed on a received message.
    ///
    /// This indicates either a bug, network corruption, or an attack.
    #[error("MAC verification failed")]
    MacVerificationFailed,

    // ===== Protocol Errors =====
    /// Message encoding or decoding failed.
    #[error("message error: {0}")]
    Message(String),

    /// Received an unexpected or malformed message.
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// Peer's overlay protocol version is incompatible.
    #[error("protocol version mismatch: {0}")]
    VersionMismatch(String),

    /// Peer is on a different network (network ID doesn't match).
    #[error("network ID mismatch")]
    NetworkMismatch,

    // ===== Peer Management Errors =====
    /// Cannot accept more connections (limit reached).
    #[error("peer limit reached")]
    PeerLimitReached,

    /// The specified peer was not found.
    #[error("peer not found: {0}")]
    PeerNotFound(String),

    /// The peer has been banned and connections are rejected.
    #[error("peer is banned: {0}")]
    PeerBanned(String),

    /// Already have an active connection to this peer.
    #[error("already connected to peer")]
    AlreadyConnected,

    // ===== State Errors =====
    /// Operation requires the overlay to be running.
    #[error("overlay not started")]
    NotStarted,

    /// Cannot start because overlay is already running.
    #[error("overlay already started")]
    AlreadyStarted,

    /// Operation rejected because overlay is shutting down.
    #[error("overlay is shutting down")]
    ShuttingDown,

    // ===== Address Errors =====
    /// Invalid peer address format.
    #[error("invalid peer address: {0}")]
    InvalidPeerAddress(String),

    // ===== Database Errors =====
    /// Database operation failed.
    #[error("database error: {0}")]
    DatabaseError(String),

    // ===== Wrapped Errors =====
    /// XDR serialization/deserialization error.
    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::curr::Error),

    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] henyey_crypto::CryptoError),

    /// Low-level I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // ===== Internal Errors =====
    /// Internal channel send failed (receiver dropped).
    #[error("channel send error")]
    ChannelSend,

    /// Internal channel receive failed (sender dropped).
    #[error("channel receive error")]
    ChannelRecv,

    /// Unexpected internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl OverlayError {
    /// Returns true if this error is transient and the operation could succeed on retry.
    ///
    /// Connection failures, timeouts, and I/O errors are typically retriable.
    pub fn is_retriable(&self) -> bool {
        matches!(
            self,
            OverlayError::ConnectionFailed(_)
                | OverlayError::ConnectionTimeout(_)
                | OverlayError::Io(_)
        )
    }

    /// Returns true if this error indicates a fundamental incompatibility.
    ///
    /// Network mismatches and version incompatibilities are fatal - retrying
    /// will not help and the peer should not be contacted again.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            OverlayError::NetworkMismatch | OverlayError::VersionMismatch(_)
        )
    }
}
