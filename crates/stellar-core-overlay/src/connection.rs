//! TCP connection handling for Stellar overlay.
//!
//! Manages the low-level TCP connections, including:
//! - Accepting incoming connections
//! - Connecting to outbound peers
//! - Framed message reading/writing

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

/// Direction of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    /// We initiated the connection.
    Outbound,
    /// They connected to us.
    Inbound,
}

impl ConnectionDirection {
    /// Whether we called the remote peer.
    pub fn we_called_remote(&self) -> bool {
        matches!(self, ConnectionDirection::Outbound)
    }
}

/// A TCP connection to a peer.
pub struct Connection {
    /// The framed codec for reading/writing messages.
    framed: Framed<TcpStream, MessageCodec>,
    /// Remote peer address.
    remote_addr: SocketAddr,
    /// Connection direction.
    direction: ConnectionDirection,
    /// Whether the connection is closed.
    closed: bool,
}

impl Connection {
    /// Create a new connection from a TCP stream.
    pub fn new(stream: TcpStream, direction: ConnectionDirection) -> Result<Self> {
        let remote_addr = stream.peer_addr()?;

        // Configure TCP options
        stream.set_nodelay(true)?;

        let framed = Framed::new(stream, MessageCodec::new());

        Ok(Self {
            framed,
            remote_addr,
            direction,
            closed: false,
        })
    }

    /// Connect to a peer with timeout.
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

    /// Get the remote address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the connection direction.
    pub fn direction(&self) -> ConnectionDirection {
        self.direction
    }

    /// Whether we initiated this connection.
    pub fn we_called_remote(&self) -> bool {
        self.direction.we_called_remote()
    }

    /// Check if the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Send a message.
    pub async fn send(&mut self, message: AuthenticatedMessage) -> Result<()> {
        if self.closed {
            return Err(OverlayError::PeerDisconnected("connection closed".to_string()));
        }

        trace!("Sending message to {}", self.remote_addr);

        self.framed
            .send(message)
            .await
            .map_err(|e| {
                self.closed = true;
                e
            })
    }

    /// Receive a message.
    pub async fn recv(&mut self) -> Result<Option<MessageFrame>> {
        if self.closed {
            debug!("recv called but connection already closed");
            return Ok(None);
        }

        match self.framed.next().await {
            Some(Ok(frame)) => {
                debug!("Received message from {} ({} bytes)", self.remote_addr, frame.raw_len);
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

    /// Receive a message with timeout.
    pub async fn recv_timeout(&mut self, timeout_secs: u64) -> Result<Option<MessageFrame>> {
        let recv_timeout = Duration::from_secs(timeout_secs);

        match timeout(recv_timeout, self.recv()).await {
            Ok(result) => result,
            Err(_) => {
                self.closed = true;
                Err(OverlayError::ConnectionTimeout("receive timeout".to_string()))
            }
        }
    }

    /// Close the connection.
    pub async fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            // The TcpStream will be closed when framed is dropped
            debug!("Closed connection to {}", self.remote_addr);
        }
    }

    /// Split into send and receive halves.
    pub fn split(
        self,
    ) -> (
        ConnectionSender,
        ConnectionReceiver,
    ) {
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

/// Send half of a connection.
pub struct ConnectionSender {
    sink: futures::stream::SplitSink<Framed<TcpStream, MessageCodec>, AuthenticatedMessage>,
    remote_addr: SocketAddr,
}

impl ConnectionSender {
    /// Send a message.
    pub async fn send(&mut self, message: AuthenticatedMessage) -> Result<()> {
        trace!("Sending message to {}", self.remote_addr);
        self.sink.send(message).await
    }

    /// Get the remote address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

/// Receive half of a connection.
pub struct ConnectionReceiver {
    stream: futures::stream::SplitStream<Framed<TcpStream, MessageCodec>>,
    remote_addr: SocketAddr,
}

impl ConnectionReceiver {
    /// Receive a message.
    pub async fn recv(&mut self) -> Result<Option<MessageFrame>> {
        match self.stream.next().await {
            Some(Ok(frame)) => {
                trace!("Received message from {} ({} bytes)", self.remote_addr, frame.raw_len);
                Ok(Some(frame))
            }
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Get the remote address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

/// TCP listener for incoming connections.
pub struct Listener {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl Listener {
    /// Bind to a port.
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

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accept an incoming connection.
    pub async fn accept(&self) -> Result<Connection> {
        let (stream, remote_addr) = self.listener.accept().await?;
        debug!("Accepted connection from {}", remote_addr);

        Connection::new(stream, ConnectionDirection::Inbound)
    }
}

/// Connection pool for managing multiple connections.
pub struct ConnectionPool {
    max_connections: usize,
    current_count: std::sync::atomic::AtomicUsize,
}

impl ConnectionPool {
    /// Create a new connection pool.
    pub fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            current_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Check if we can accept more connections.
    pub fn can_accept(&self) -> bool {
        self.current_count.load(std::sync::atomic::Ordering::Relaxed) < self.max_connections
    }

    /// Try to reserve a connection slot.
    pub fn try_reserve(&self) -> bool {
        let mut current = self.current_count.load(std::sync::atomic::Ordering::Relaxed);
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

    /// Release a connection slot.
    pub fn release(&self) {
        self.current_count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get current connection count.
    pub fn count(&self) -> usize {
        self.current_count.load(std::sync::atomic::Ordering::Relaxed)
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
