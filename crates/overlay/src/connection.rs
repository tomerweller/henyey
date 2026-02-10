//! Low-level TCP connection handling for the Stellar overlay.
//!
//! This module provides the transport layer for overlay connections:
//!
//! - [`Connection`] - A single TCP connection with framed message I/O
//! - [`Listener`] - Accepts incoming TCP connections on a port
//! - [`ConnectionPool`] - Tracks connection counts against limits
//!
//! # Architecture
//!
//! Connections wrap a TCP stream with the [`MessageCodec`] for automatic
//! length-prefixed framing. The higher-level [`Peer`] type handles
//! authentication and message processing on top of a `Connection`.
//!
//! [`MessageCodec`]: crate::MessageCodec
//! [`Peer`]: crate::Peer

use crate::{
    codec::{MessageCodec, MessageFrame},
    OverlayError, PeerAddress, Result,
};
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;
use stellar_xdr::curr::AuthenticatedMessage;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing::{debug, trace};

/// Direction of a peer connection.
///
/// Used to determine the initiator/acceptor roles during key derivation
/// in the authentication handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    /// We initiated the connection (we are the "initiator" in key derivation).
    Outbound,
    /// The peer connected to us (we are the "acceptor" in key derivation).
    Inbound,
}

impl ConnectionDirection {
    /// Returns true if we initiated this connection.
    ///
    /// This determines our role in the authentication key derivation.
    pub fn we_called_remote(&self) -> bool {
        matches!(self, ConnectionDirection::Outbound)
    }
}

/// A TCP connection to a peer with framed message I/O.
///
/// Wraps a TCP stream with the [`MessageCodec`] for automatic message framing.
/// Provides async methods for sending and receiving [`AuthenticatedMessage`]s.
///
/// # Lifecycle
///
/// 1. Create via [`Connection::connect`] (outbound) or from [`Listener::accept`] (inbound)
/// 2. Use [`send`](Connection::send) and [`recv`](Connection::recv) for message I/O
/// 3. Call [`close`](Connection::close) when done (or drop the connection)
///
/// [`MessageCodec`]: crate::MessageCodec
/// [`AuthenticatedMessage`]: stellar_xdr::curr::AuthenticatedMessage
pub struct Connection {
    /// Framed stream for message encoding/decoding.
    framed: Framed<TcpStream, MessageCodec>,
    /// Remote peer's socket address.
    remote_addr: SocketAddr,
    /// Whether we initiated or accepted this connection.
    direction: ConnectionDirection,
    /// True if the connection has been closed.
    closed: bool,
}

impl Connection {
    /// Creates a connection from an existing TCP stream.
    ///
    /// Configures TCP_NODELAY to reduce latency and wraps the stream
    /// with the message codec.
    pub fn new(stream: TcpStream, direction: ConnectionDirection) -> Result<Self> {
        let remote_addr = stream.peer_addr()?;

        // Disable Nagle's algorithm for lower latency
        stream.set_nodelay(true)?;

        let framed = Framed::new(stream, MessageCodec::new());

        Ok(Self {
            framed,
            remote_addr,
            direction,
            closed: false,
        })
    }

    /// Connects to a peer address with a timeout.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionTimeout` if the connection is not established
    /// within `timeout_secs`, or `ConnectionFailed` for other errors.
    pub async fn connect(addr: &PeerAddress, timeout_secs: u64) -> Result<Self> {
        debug!("Connecting to peer: {}", addr);

        let socket_addr = addr.to_socket_addr();
        let connect_timeout = Duration::from_secs(timeout_secs);

        let stream = timeout(connect_timeout, TcpStream::connect(&socket_addr))
            .await
            .map_err(|_| OverlayError::ConnectionTimeout(addr.to_string()))?
            .map_err(|e| OverlayError::ConnectionFailed(format!("{}: {}", addr, e)))?;

        debug!("Connected to peer: {}", addr);
        Self::new(stream, ConnectionDirection::Outbound)
    }

    /// Returns the remote peer's socket address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Returns whether this is an inbound or outbound connection.
    pub fn direction(&self) -> ConnectionDirection {
        self.direction
    }

    /// Returns true if we initiated this connection.
    pub fn we_called_remote(&self) -> bool {
        self.direction.we_called_remote()
    }

    /// Returns true if the connection has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Sends an authenticated message to the peer.
    ///
    /// # Errors
    ///
    /// Returns `PeerDisconnected` if the connection is already closed,
    /// or a codec error if encoding fails.
    pub async fn send(&mut self, message: AuthenticatedMessage) -> Result<()> {
        if self.closed {
            return Err(OverlayError::PeerDisconnected(
                "connection closed".to_string(),
            ));
        }

        trace!("Sending message to {}", self.remote_addr);

        // Add timeout to prevent blocking indefinitely on TCP backpressure
        const SEND_TIMEOUT_SECS: u64 = 10;
        match timeout(
            Duration::from_secs(SEND_TIMEOUT_SECS),
            self.framed.send(message),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                self.closed = true;
                Err(e)
            }
            Err(_) => {
                self.closed = true;
                Err(OverlayError::ConnectionTimeout(format!(
                    "send timeout after {}s to {}",
                    SEND_TIMEOUT_SECS, self.remote_addr
                )))
            }
        }
    }

    /// Receives the next message from the peer.
    ///
    /// Returns `Ok(None)` if the connection was closed cleanly by the peer.
    pub async fn recv(&mut self) -> Result<Option<MessageFrame>> {
        if self.closed {
            debug!("recv called but connection already closed");
            return Ok(None);
        }

        match self.framed.next().await {
            Some(Ok(frame)) => {
                debug!(
                    "Received message from {} ({} bytes)",
                    self.remote_addr, frame.raw_len
                );
                Ok(Some(frame))
            }
            Some(Err(e)) => {
                debug!("Error receiving from {}: {}", self.remote_addr, e);
                self.closed = true;
                Err(e)
            }
            None => {
                debug!("Connection closed by peer: {}", self.remote_addr);
                self.closed = true;
                Ok(None)
            }
        }
    }

    /// Receives a message with a timeout.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionTimeout` if no message is received within `timeout_secs`.
    pub async fn recv_timeout(&mut self, timeout_secs: u64) -> Result<Option<MessageFrame>> {
        let recv_timeout = Duration::from_secs(timeout_secs);

        match timeout(recv_timeout, self.recv()).await {
            Ok(result) => result,
            Err(_) => {
                self.closed = true;
                Err(OverlayError::ConnectionTimeout(
                    "receive timeout".to_string(),
                ))
            }
        }
    }

    /// Closes the connection.
    ///
    /// This marks the connection as closed. The underlying TCP stream
    /// will be closed when the connection is dropped.
    pub async fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            debug!("Closed connection to {}", self.remote_addr);
        }
    }

    /// Splits the connection into separate send and receive halves.
    ///
    /// This allows concurrent sending and receiving on the same connection.
    pub fn split(self) -> (ConnectionSender, ConnectionReceiver) {
        let (sink, stream) = self.framed.split();
        (
            ConnectionSender {
                sink,
                remote_addr: self.remote_addr,
            },
            ConnectionReceiver {
                stream,
                remote_addr: self.remote_addr,
            },
        )
    }
}

/// Send half of a split connection.
///
/// Created by [`Connection::split`]. Allows sending messages without
/// holding a lock on the full connection.
pub struct ConnectionSender {
    sink: futures::stream::SplitSink<Framed<TcpStream, MessageCodec>, AuthenticatedMessage>,
    remote_addr: SocketAddr,
}

impl ConnectionSender {
    /// Sends a message to the peer.
    pub async fn send(&mut self, message: AuthenticatedMessage) -> Result<()> {
        trace!("Sending message to {}", self.remote_addr);
        self.sink.send(message).await
    }

    /// Returns the remote peer's socket address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

/// Receive half of a split connection.
///
/// Created by [`Connection::split`]. Allows receiving messages without
/// holding a lock on the full connection.
pub struct ConnectionReceiver {
    stream: futures::stream::SplitStream<Framed<TcpStream, MessageCodec>>,
    remote_addr: SocketAddr,
}

impl ConnectionReceiver {
    /// Receives the next message from the peer.
    ///
    /// Returns `Ok(None)` if the connection was closed.
    pub async fn recv(&mut self) -> Result<Option<MessageFrame>> {
        match self.stream.next().await {
            Some(Ok(frame)) => {
                trace!(
                    "Received message from {} ({} bytes)",
                    self.remote_addr,
                    frame.raw_len
                );
                Ok(Some(frame))
            }
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Returns the remote peer's socket address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

/// TCP listener for accepting incoming peer connections.
///
/// Binds to a port and accepts new connections, wrapping them as
/// inbound [`Connection`]s.
pub struct Listener {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl Listener {
    /// Binds to the specified port on all interfaces (0.0.0.0).
    ///
    /// # Errors
    ///
    /// Returns an IO error if the port is already in use or binding fails.
    pub async fn bind(port: u16) -> Result<Self> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).await?;
        let local_addr = listener.local_addr()?;

        debug!("Listening on {}", local_addr);

        Ok(Self {
            listener,
            local_addr,
        })
    }

    /// Returns the local address the listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accepts the next incoming connection.
    ///
    /// Blocks until a new connection arrives, then returns it as an
    /// inbound [`Connection`].
    pub async fn accept(&self) -> Result<Connection> {
        let (stream, remote_addr) = self.listener.accept().await?;
        debug!("Accepted connection from {}", remote_addr);

        Connection::new(stream, ConnectionDirection::Inbound)
    }
}

/// Thread-safe connection counter for enforcing connection limits.
///
/// Used to track inbound and outbound connection counts separately,
/// ensuring we don't exceed configured limits.
pub struct ConnectionPool {
    /// Maximum number of connections allowed.
    max_connections: usize,
    /// Current number of active connections.
    current_count: std::sync::atomic::AtomicUsize,
}

impl ConnectionPool {
    /// Creates a new connection pool with the given limit.
    pub fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            current_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Returns true if there's room for another connection.
    pub fn can_accept(&self) -> bool {
        self.current_count
            .load(std::sync::atomic::Ordering::Relaxed)
            < self.max_connections
    }

    /// Attempts to reserve a connection slot.
    ///
    /// Returns true if a slot was reserved, false if the limit is reached.
    /// Uses atomic compare-and-swap for thread safety.
    pub fn try_reserve(&self) -> bool {
        let mut current = self
            .current_count
            .load(std::sync::atomic::Ordering::Relaxed);
        loop {
            if current >= self.max_connections {
                return false;
            }
            match self.current_count.compare_exchange_weak(
                current,
                current + 1,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(new_current) => current = new_current,
            }
        }
    }

    /// Releases a previously reserved connection slot.
    ///
    /// Call this when a connection is closed.
    pub fn release(&self) {
        self.current_count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Returns the current number of connections.
    pub fn count(&self) -> usize {
        self.current_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_direction() {
        assert!(ConnectionDirection::Outbound.we_called_remote());
        assert!(!ConnectionDirection::Inbound.we_called_remote());
    }

    #[test]
    fn test_connection_pool() {
        let pool = ConnectionPool::new(2);
        assert!(pool.can_accept());
        assert_eq!(pool.count(), 0);

        assert!(pool.try_reserve());
        assert_eq!(pool.count(), 1);

        assert!(pool.try_reserve());
        assert_eq!(pool.count(), 2);

        assert!(!pool.try_reserve());
        assert!(!pool.can_accept());

        pool.release();
        assert!(pool.can_accept());
        assert_eq!(pool.count(), 1);
    }

    #[tokio::test]
    async fn test_peer_address_connect_format() {
        let addr = PeerAddress::new("127.0.0.1", 11625);
        assert_eq!(addr.to_socket_addr(), "127.0.0.1:11625");
    }
}
