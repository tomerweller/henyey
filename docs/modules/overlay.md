# Overlay Module Specification

**Crate**: `stellar-core-overlay`
**stellar-core mapping**: `src/overlay/`

## 1. Overview

The overlay module implements peer-to-peer networking:
- Peer discovery and connection management
- Message serialization and framing
- Authentication (MAC-based)
- Flood control and message routing
- Transaction and SCP message propagation

## 2. stellar-core Reference

In stellar-core, the overlay module (`src/overlay/`) contains:
- `OverlayManager.h/cpp` - Main coordinator
- `Peer.h/cpp` - Individual peer connection
- `PeerManager.h/cpp` - Peer lifecycle management
- `TCPPeer.h/cpp` - TCP implementation
- `FloodGate.h/cpp` - Message flooding control
- `ItemFetcher.h/cpp` - On-demand data fetching
- `Tracker.h/cpp` - Message tracking
- `SurveyManager.h/cpp` - Network surveys

### 2.1 Authentication Protocol

stellar-core uses a custom authentication protocol:
1. Exchange public keys
2. Derive shared secret using X25519
3. Use HMAC-SHA256 for message authentication

### 2.2 Message Types

Key overlay messages (from XDR):
- `HELLO` - Initial handshake
- `AUTH` - Authentication
- `ERROR_MSG` - Error reporting
- `DONT_HAVE` - Missing data response
- `GET_PEERS` / `PEERS` - Peer discovery
- `TX_SET` / `GET_TX_SET` - Transaction sets
- `TRANSACTION` - Single transaction
- `SCP_MESSAGE` - SCP envelope
- `FLOOD_ADVERT` / `FLOOD_DEMAND` - Flood control
- `SURVEY_*` - Network surveys

## 3. Rust Implementation

### 3.1 Dependencies

```toml
[dependencies]
stellar-xdr = { version = "25.0.0", features = ["std", "curr"] }
stellar-core-crypto = { path = "../stellar-core-crypto" }

# Async runtime
tokio = { version = "1", features = ["net", "io-util", "time", "sync", "rt-multi-thread"] }

# Networking
tokio-util = { version = "0.7", features = ["codec"] }
bytes = "1"

# Crypto (pure Rust)
x25519-dalek = { version = "2", default-features = false, features = ["std", "zeroize"] }
hmac = "0.12"
sha2 = { version = "0.10", default-features = false, features = ["std"] }

# Utilities
thiserror = "1"
tracing = "0.1"
parking_lot = "0.12"
futures = "0.3"
dashmap = "5"
rand = { version = "0.8", default-features = false, features = ["std", "std_rng"] }
```

### 3.2 Module Structure

```
stellar-core-overlay/
├── src/
│   ├── lib.rs
│   ├── overlay_manager.rs   # Main coordinator
│   ├── peer.rs              # Peer abstraction
│   ├── peer_manager.rs      # Connection lifecycle
│   ├── connection.rs        # TCP connection handling
│   ├── codec.rs             # Message framing
│   ├── auth.rs              # Authentication protocol
│   ├── flood_gate.rs        # Flood control
│   ├── item_fetcher.rs      # On-demand fetching
│   ├── messages.rs          # Message handling
│   └── error.rs
└── tests/
```

### 3.3 Core Types

#### OverlayManager

```rust
use std::net::SocketAddr;
use tokio::net::TcpListener;
use dashmap::DashMap;

/// Configuration for overlay network
pub struct OverlayConfig {
    pub listen_addr: SocketAddr,
    pub target_peer_connections: usize,
    pub max_peer_connections: usize,
    pub preferred_peers: Vec<String>,
    pub known_peers: Vec<String>,
    pub network_passphrase: String,
}

/// Main overlay network coordinator
pub struct OverlayManager {
    config: OverlayConfig,
    local_node: Arc<LocalOverlayNode>,
    peer_manager: Arc<PeerManager>,
    flood_gate: Arc<FloodGate>,
    /// Active peer connections
    peers: DashMap<PeerId, Arc<Peer>>,
    /// Shutdown signal
    shutdown: tokio::sync::broadcast::Sender<()>,
}

impl OverlayManager {
    pub async fn new(
        config: OverlayConfig,
        secret_key: SecretKey,
    ) -> Result<Self, OverlayError> {
        let local_node = Arc::new(LocalOverlayNode::new(secret_key, &config));
        let peer_manager = Arc::new(PeerManager::new(config.clone()));
        let flood_gate = Arc::new(FloodGate::new());
        let (shutdown, _) = tokio::sync::broadcast::channel(1);

        Ok(Self {
            config,
            local_node,
            peer_manager,
            flood_gate,
            peers: DashMap::new(),
            shutdown,
        })
    }

    /// Start the overlay network
    pub async fn start(&self) -> Result<(), OverlayError> {
        // Start listening for incoming connections
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        tracing::info!(addr = %self.config.listen_addr, "Overlay listening");

        // Spawn connection acceptor
        let self_clone = self.clone();
        tokio::spawn(async move {
            self_clone.accept_connections(listener).await;
        });

        // Connect to preferred/known peers
        self.connect_to_known_peers().await;

        Ok(())
    }

    async fn accept_connections(&self, listener: TcpListener) {
        let mut shutdown = self.shutdown.subscribe();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            tracing::debug!(addr = %addr, "Incoming connection");
                            self.handle_incoming(stream, addr).await;
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Accept error");
                        }
                    }
                }
                _ = shutdown.recv() => {
                    tracing::info!("Overlay shutting down");
                    break;
                }
            }
        }
    }

    async fn handle_incoming(&self, stream: tokio::net::TcpStream, addr: SocketAddr) {
        if self.peers.len() >= self.config.max_peer_connections {
            tracing::warn!(addr = %addr, "Max peers reached, rejecting");
            return;
        }

        // Create peer and start authentication
        match Peer::new_incoming(stream, addr, Arc::clone(&self.local_node)).await {
            Ok(peer) => {
                let peer = Arc::new(peer);
                self.peers.insert(peer.id(), Arc::clone(&peer));
                self.run_peer(peer).await;
            }
            Err(e) => {
                tracing::warn!(addr = %addr, error = %e, "Failed to create peer");
            }
        }
    }

    /// Connect to a peer
    pub async fn connect(&self, addr: &str) -> Result<PeerId, OverlayError> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        let socket_addr = stream.peer_addr()?;

        let peer = Peer::new_outgoing(stream, socket_addr, Arc::clone(&self.local_node)).await?;
        let peer = Arc::new(peer);
        let peer_id = peer.id();

        self.peers.insert(peer_id, Arc::clone(&peer));
        self.run_peer(peer).await;

        Ok(peer_id)
    }

    async fn run_peer(&self, peer: Arc<Peer>) {
        let flood_gate = Arc::clone(&self.flood_gate);
        let peers = self.peers.clone();

        tokio::spawn(async move {
            if let Err(e) = peer.run(&flood_gate).await {
                tracing::warn!(peer = %peer.id(), error = %e, "Peer disconnected");
            }
            peers.remove(&peer.id());
        });
    }

    /// Broadcast a message to all peers
    pub fn broadcast(&self, message: &StellarMessage) {
        for peer in self.peers.iter() {
            if let Err(e) = peer.send(message) {
                tracing::warn!(peer = %peer.id(), error = %e, "Failed to send");
            }
        }
    }

    /// Broadcast with flood control
    pub fn flood_message(&self, message: &StellarMessage) {
        let hash = self.flood_gate.message_hash(message);

        // Only flood if we haven't seen this message recently
        if self.flood_gate.add_message(&hash) {
            self.broadcast(message);
        }
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Shutdown the overlay
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(());
    }
}
```

#### Peer

```rust
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite, BufReader, BufWriter};

pub type PeerId = Hash256;

/// Remote peer connection state
pub enum PeerState {
    Connecting,
    Connected,
    Authenticated,
    Closing,
}

/// A connected peer
pub struct Peer {
    id: PeerId,
    address: SocketAddr,
    state: parking_lot::RwLock<PeerState>,
    /// Authenticated connection
    connection: AuthenticatedConnection,
    /// Peer info from HELLO
    peer_info: parking_lot::RwLock<Option<Hello>>,
    /// Message send channel
    tx: tokio::sync::mpsc::Sender<StellarMessage>,
}

impl Peer {
    pub async fn new_incoming(
        stream: TcpStream,
        address: SocketAddr,
        local_node: Arc<LocalOverlayNode>,
    ) -> Result<Self, OverlayError> {
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        // Perform authentication handshake
        let connection = AuthenticatedConnection::accept(stream, local_node).await?;

        let id = connection.peer_id();

        Ok(Self {
            id,
            address,
            state: parking_lot::RwLock::new(PeerState::Authenticated),
            connection,
            peer_info: parking_lot::RwLock::new(None),
            tx,
        })
    }

    pub async fn new_outgoing(
        stream: TcpStream,
        address: SocketAddr,
        local_node: Arc<LocalOverlayNode>,
    ) -> Result<Self, OverlayError> {
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        // Initiate authentication handshake
        let connection = AuthenticatedConnection::connect(stream, local_node).await?;

        let id = connection.peer_id();

        Ok(Self {
            id,
            address,
            state: parking_lot::RwLock::new(PeerState::Authenticated),
            connection,
            peer_info: parking_lot::RwLock::new(None),
            tx,
        })
    }

    pub fn id(&self) -> PeerId {
        self.id
    }

    pub fn send(&self, message: &StellarMessage) -> Result<(), OverlayError> {
        self.tx.try_send(message.clone())
            .map_err(|_| OverlayError::SendFailed)
    }

    pub async fn run(&self, flood_gate: &FloodGate) -> Result<(), OverlayError> {
        // Main peer loop - read messages and handle them
        loop {
            match self.connection.receive().await? {
                Some(msg) => {
                    self.handle_message(msg, flood_gate).await?;
                }
                None => {
                    // Connection closed
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_message(
        &self,
        message: StellarMessage,
        flood_gate: &FloodGate,
    ) -> Result<(), OverlayError> {
        match message {
            StellarMessage::Hello(hello) => {
                *self.peer_info.write() = Some(hello);
            }
            StellarMessage::ErrorMsg(err) => {
                tracing::warn!(peer = %self.id, code = ?err.code, msg = %err.msg, "Peer error");
            }
            StellarMessage::GetPeers => {
                // Respond with known peers
            }
            StellarMessage::Peers(peers) => {
                // Add to known peers list
            }
            StellarMessage::Transaction(tx) => {
                // Forward to transaction processor
            }
            StellarMessage::ScpMessage(envelope) => {
                // Forward to SCP
            }
            StellarMessage::FloodAdvert(advert) => {
                // Handle flood advertisement
            }
            StellarMessage::FloodDemand(demand) => {
                // Respond to flood demand
            }
            _ => {
                tracing::debug!(peer = %self.id, msg = ?message, "Unhandled message");
            }
        }
        Ok(())
    }
}
```

### 3.4 Authentication Protocol

```rust
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, SharedSecret};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Handles the authentication handshake and message MAC
pub struct AuthenticatedConnection {
    stream: BufReader<BufWriter<TcpStream>>,
    /// MAC key derived from shared secret
    mac_key: [u8; 32],
    /// Remote peer's node ID
    peer_node_id: NodeId,
    /// Sequence numbers for replay protection
    send_seq: u64,
    recv_seq: u64,
}

impl AuthenticatedConnection {
    /// Accept an incoming connection (server side)
    pub async fn accept(
        stream: TcpStream,
        local_node: Arc<LocalOverlayNode>,
    ) -> Result<Self, OverlayError> {
        let stream = BufReader::new(BufWriter::new(stream));

        // Generate ephemeral X25519 key pair
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rand::rngs::OsRng);
        let ephemeral_public = X25519Public::from(&ephemeral_secret);

        // Receive HELLO
        let hello = Self::receive_hello(&mut stream).await?;

        // Send our HELLO
        let our_hello = local_node.create_hello(&ephemeral_public);
        Self::send_hello(&mut stream, &our_hello).await?;

        // Receive AUTH
        let auth = Self::receive_auth(&mut stream).await?;

        // Derive shared secret
        let peer_ephemeral = X25519Public::from(hello.cert.pubkey);
        let shared_secret = ephemeral_secret.diffie_hellman(&peer_ephemeral);

        // Derive MAC key
        let mac_key = Self::derive_mac_key(&shared_secret, false);

        // Verify AUTH MAC
        Self::verify_auth(&auth, &mac_key)?;

        // Send our AUTH
        let our_auth = Self::create_auth(&mac_key);
        Self::send_auth(&mut stream, &our_auth).await?;

        Ok(Self {
            stream,
            mac_key,
            peer_node_id: hello.peer_id,
            send_seq: 0,
            recv_seq: 0,
        })
    }

    /// Connect to a peer (client side)
    pub async fn connect(
        stream: TcpStream,
        local_node: Arc<LocalOverlayNode>,
    ) -> Result<Self, OverlayError> {
        let mut stream = BufReader::new(BufWriter::new(stream));

        // Generate ephemeral X25519 key pair
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rand::rngs::OsRng);
        let ephemeral_public = X25519Public::from(&ephemeral_secret);

        // Send our HELLO
        let our_hello = local_node.create_hello(&ephemeral_public);
        Self::send_hello(&mut stream, &our_hello).await?;

        // Receive HELLO
        let hello = Self::receive_hello(&mut stream).await?;

        // Derive shared secret
        let peer_ephemeral = X25519Public::from(hello.cert.pubkey);
        let shared_secret = ephemeral_secret.diffie_hellman(&peer_ephemeral);

        // Derive MAC key
        let mac_key = Self::derive_mac_key(&shared_secret, true);

        // Send our AUTH
        let our_auth = Self::create_auth(&mac_key);
        Self::send_auth(&mut stream, &our_auth).await?;

        // Receive AUTH
        let auth = Self::receive_auth(&mut stream).await?;
        Self::verify_auth(&auth, &mac_key)?;

        Ok(Self {
            stream,
            mac_key,
            peer_node_id: hello.peer_id,
            send_seq: 0,
            recv_seq: 0,
        })
    }

    fn derive_mac_key(shared_secret: &SharedSecret, is_client: bool) -> [u8; 32] {
        // Derive MAC key using HKDF or similar
        let mut mac = HmacSha256::new_from_slice(shared_secret.as_bytes()).unwrap();
        mac.update(if is_client { b"client" } else { b"server" });
        let result = mac.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result.into_bytes());
        key
    }

    pub fn peer_id(&self) -> PeerId {
        Hash256::hash(&self.peer_node_id.to_xdr(stellar_xdr::Limits::none()).unwrap())
    }

    /// Send a message with MAC
    pub async fn send(&mut self, message: &StellarMessage) -> Result<(), OverlayError> {
        let xdr = message.to_xdr(stellar_xdr::Limits::none())?;

        // Compute MAC
        let mut mac = HmacSha256::new_from_slice(&self.mac_key).unwrap();
        mac.update(&self.send_seq.to_be_bytes());
        mac.update(&xdr);
        let mac_bytes = mac.finalize().into_bytes();

        self.send_seq += 1;

        // Send: length (4 bytes) + MAC (32 bytes) + XDR
        let len = (xdr.len() + 32) as u32;
        // Write to stream...

        Ok(())
    }

    /// Receive a message and verify MAC
    pub async fn receive(&mut self) -> Result<Option<StellarMessage>, OverlayError> {
        // Read length, MAC, XDR
        // Verify MAC
        // Parse XDR
        // Return message

        self.recv_seq += 1;
        todo!()
    }
}
```

### 3.5 Flood Gate

```rust
use std::time::{Duration, Instant};

/// Controls message flooding to prevent spam
pub struct FloodGate {
    /// Recently seen message hashes
    seen: DashMap<Hash256, Instant>,
    /// TTL for seen messages
    ttl: Duration,
}

impl FloodGate {
    pub fn new() -> Self {
        Self {
            seen: DashMap::new(),
            ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Compute hash of a message for deduplication
    pub fn message_hash(&self, message: &StellarMessage) -> Hash256 {
        let xdr = message.to_xdr(stellar_xdr::Limits::none()).unwrap();
        Hash256::hash(&xdr)
    }

    /// Add a message hash, returns true if new
    pub fn add_message(&self, hash: &Hash256) -> bool {
        let now = Instant::now();

        // Clean up expired entries periodically
        if rand::random::<u32>() % 100 == 0 {
            self.cleanup();
        }

        match self.seen.entry(*hash) {
            dashmap::mapref::entry::Entry::Occupied(_) => false,
            dashmap::mapref::entry::Entry::Vacant(e) => {
                e.insert(now);
                true
            }
        }
    }

    /// Check if we've seen a message
    pub fn has_seen(&self, hash: &Hash256) -> bool {
        self.seen.contains_key(hash)
    }

    fn cleanup(&self) {
        let now = Instant::now();
        self.seen.retain(|_, time| now.duration_since(*time) < self.ttl);
    }
}
```

### 3.6 Message Codec

```rust
use tokio_util::codec::{Decoder, Encoder};
use bytes::{Buf, BufMut, BytesMut};

/// Codec for framing Stellar messages over TCP
pub struct StellarMessageCodec {
    max_frame_size: usize,
}

impl StellarMessageCodec {
    pub fn new() -> Self {
        Self {
            max_frame_size: 256 * 1024, // 256KB max
        }
    }
}

impl Decoder for StellarMessageCodec {
    type Item = AuthenticatedMessage;
    type Error = OverlayError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }

        let len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;

        if len > self.max_frame_size {
            return Err(OverlayError::FrameTooLarge(len));
        }

        if src.len() < 4 + len {
            return Ok(None);
        }

        src.advance(4);
        let data = src.split_to(len);

        let msg = AuthenticatedMessage::from_xdr(&data, stellar_xdr::Limits::none())?;
        Ok(Some(msg))
    }
}

impl Encoder<AuthenticatedMessage> for StellarMessageCodec {
    type Error = OverlayError;

    fn encode(&mut self, item: AuthenticatedMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let xdr = item.to_xdr(stellar_xdr::Limits::none())?;

        if xdr.len() > self.max_frame_size {
            return Err(OverlayError::FrameTooLarge(xdr.len()));
        }

        dst.put_u32(xdr.len() as u32);
        dst.put_slice(&xdr);
        Ok(())
    }
}
```

## 4. Error Types

```rust
#[derive(Error, Debug)]
pub enum OverlayError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::Error),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Invalid MAC")]
    InvalidMac,

    #[error("Frame too large: {0}")]
    FrameTooLarge(usize),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Send failed")]
    SendFailed,

    #[error("Peer not found")]
    PeerNotFound,
}
```

## 5. Tests to Port from stellar-core

From `src/overlay/test/`:
- Authentication handshake
- Message serialization round-trips
- Flood gate deduplication
- Peer lifecycle (connect, disconnect, reconnect)
- Load testing with many messages

## 6. Testnet Bootstrap Peers

```rust
pub mod testnet {
    pub const BOOTSTRAP_PEERS: &[&str] = &[
        "core-testnet1.stellar.org:11625",
        "core-testnet2.stellar.org:11625",
        "core-testnet3.stellar.org:11625",
    ];
}
```
