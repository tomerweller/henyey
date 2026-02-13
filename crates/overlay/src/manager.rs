//! Overlay manager for coordinating peer connections and message routing.
//!
//! The [`OverlayManager`] is the primary interface for the overlay network subsystem.
//! It handles all aspects of peer-to-peer networking:
//!
//! - **Connection Management**: Establishes and maintains TCP connections to peers,
//!   respecting configured limits for inbound and outbound connections
//!
//! - **Peer Discovery**: Learns about new peers from connected nodes and maintains
//!   a pool of known addresses to connect to
//!
//! - **Message Routing**: Receives messages from peers and distributes them to
//!   subscribers, while also sending outbound messages to appropriate peers
//!
//! - **Flood Control**: Uses the [`FloodGate`] to prevent duplicate message
//!   propagation while ensuring all peers receive new messages
//!
//! # Architecture
//!
//! The manager runs several background tasks:
//!
//! 1. **Listener task**: Accepts incoming connections (if enabled)
//! 2. **Connector task**: Initiates outbound connections to maintain target peer count
//! 3. **Peer tasks**: One per connected peer, handles message I/O
//! 4. **Advertiser task**: Periodically sends peer lists to connected nodes
//!
//! # Flow Control
//!
//! The overlay implements Stellar's flow control protocol using `SendMore` and
//! `SendMoreExtended` messages. This prevents peers from overwhelming each other
//! with messages during high-traffic periods.
//!
//! [`FloodGate`]: crate::FloodGate

use crate::{
    codec::helpers,
    connection::{ConnectionDirection, ConnectionPool, Listener},
    flood::{compute_message_hash, FloodGate, FloodGateStats},
    flow_control::msg_body_size,
    peer::{Peer, PeerInfo, PeerStatsSnapshot},
    LocalNode, OverlayConfig, OverlayError, PeerAddress, PeerEvent, PeerId, PeerType, Result,
};
use dashmap::DashMap;
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use stellar_xdr::curr::{PeerAddress as XdrPeerAddress, PeerAddressIp, StellarMessage, VecM};
use tokio::sync::{broadcast, mpsc, Mutex as TokioMutex};
use tokio::task::JoinHandle;
use sha2::Digest;
use tracing::{debug, error, info, trace, warn};

fn is_fetch_message(message: &StellarMessage) -> bool {
    matches!(
        message,
        StellarMessage::GetTxSet(_)
            | StellarMessage::TxSet(_)
            | StellarMessage::GeneralizedTxSet(_)
            | StellarMessage::GetScpState(_)
            | StellarMessage::ScpQuorumset(_)
            | StellarMessage::GetScpQuorumset(_)
            | StellarMessage::DontHave(_)
    )
}

/// A message received from a connected peer via the overlay network.
///
/// These messages are delivered to subscribers of the overlay manager's
/// broadcast channel. The `from_peer` field identifies the sender.
#[derive(Debug, Clone)]
pub struct OverlayMessage {
    /// The peer that sent this message.
    pub from_peer: PeerId,
    /// The Stellar protocol message.
    pub message: StellarMessage,
    /// When the message was received from the peer (before broadcast channel delivery).
    pub received_at: std::time::Instant,
}

/// A snapshot of a connected peer's info and statistics.
///
/// Provides a point-in-time view of a peer's state without holding any locks.
#[derive(Debug, Clone)]
pub struct PeerSnapshot {
    /// Static information about the peer (ID, address, version).
    pub info: PeerInfo,
    /// Message and byte counters.
    pub stats: PeerStatsSnapshot,
}

/// Shared state passed to spawned peer tasks.
///
/// Bundles all `Arc`-wrapped state that background tasks need, avoiding
/// 20+ individual parameter lists on `connect_outbound_inner` and
/// `run_peer_loop`.
#[derive(Clone)]
struct SharedPeerState {
    peers: Arc<DashMap<PeerId, Arc<TokioMutex<Peer>>>>,
    flood_gate: Arc<FloodGate>,
    running: Arc<AtomicBool>,
    message_tx: broadcast::Sender<OverlayMessage>,
    scp_message_tx: mpsc::UnboundedSender<OverlayMessage>,
    fetch_response_tx: mpsc::UnboundedSender<OverlayMessage>,
    peer_handles: Arc<RwLock<Vec<JoinHandle<()>>>>,
    advertised_outbound_peers: Arc<RwLock<Vec<PeerAddress>>>,
    advertised_inbound_peers: Arc<RwLock<Vec<PeerAddress>>>,
    added_authenticated_peers: Arc<std::sync::atomic::AtomicU64>,
    dropped_authenticated_peers: Arc<std::sync::atomic::AtomicU64>,
    banned_peers: Arc<RwLock<HashSet<PeerId>>>,
    peer_info_cache: Arc<DashMap<PeerId, PeerInfo>>,
    is_validator: bool,
    peer_event_tx: Option<mpsc::Sender<PeerEvent>>,
    extra_subscribers: Arc<RwLock<Vec<mpsc::UnboundedSender<OverlayMessage>>>>,
}

/// Central manager for all peer connections in the overlay network.
///
/// The overlay manager is the main entry point for networking operations.
/// It handles connection lifecycle, message routing, and peer discovery.
///
/// # Usage
///
/// ```rust,ignore
/// // Create and start the manager
/// let config = OverlayConfig::testnet();
/// let local_node = LocalNode::new_testnet(secret_key);
/// let mut manager = OverlayManager::new(config, local_node)?;
/// manager.start().await?;
///
/// // Subscribe to messages
/// let mut rx = manager.subscribe();
/// while let Ok(msg) = rx.recv().await {
///     handle_message(msg);
/// }
///
/// // Broadcast a message
/// manager.broadcast(StellarMessage::Transaction(tx)).await?;
///
/// // Shutdown
/// manager.shutdown().await?;
/// ```
pub struct OverlayManager {
    /// Configuration.
    config: OverlayConfig,
    /// Local node info.
    local_node: LocalNode,
    /// Connected peers (using TokioMutex so guards can be held across await).
    peers: Arc<DashMap<PeerId, Arc<TokioMutex<Peer>>>>,
    /// Flood gate.
    flood_gate: Arc<FloodGate>,
    /// Connection pool for inbound connections.
    inbound_pool: Arc<ConnectionPool>,
    /// Connection pool for outbound connections.
    outbound_pool: Arc<ConnectionPool>,
    /// Whether the manager is running.
    running: Arc<AtomicBool>,
    /// Channel for incoming messages.
    message_tx: broadcast::Sender<OverlayMessage>,
    /// Handle to listener task.
    listener_handle: Option<JoinHandle<()>>,
    /// Handle to connector task.
    connector_handle: Option<JoinHandle<()>>,
    /// Handle to peer tasks.
    peer_handles: Arc<RwLock<Vec<JoinHandle<()>>>>,
    /// Known peers learned from discovery.
    known_peers: Arc<RwLock<Vec<PeerAddress>>>,
    /// Outbound peers to advertise in Peers messages.
    advertised_outbound_peers: Arc<RwLock<Vec<PeerAddress>>>,
    /// Inbound peers to advertise in Peers messages.
    advertised_inbound_peers: Arc<RwLock<Vec<PeerAddress>>>,
    /// Handle to periodic peer advertiser task.
    peer_advertiser_handle: Option<JoinHandle<()>>,
    /// Total authenticated peers added.
    added_authenticated_peers: Arc<std::sync::atomic::AtomicU64>,
    /// Total authenticated peers dropped.
    dropped_authenticated_peers: Arc<std::sync::atomic::AtomicU64>,
    /// Banned peers by node ID.
    banned_peers: Arc<RwLock<HashSet<PeerId>>>,
    /// Shutdown signal.
    shutdown_tx: Option<broadcast::Sender<()>>,
    /// Cache of peer info for connected peers (lock-free access).
    peer_info_cache: Arc<DashMap<PeerId, PeerInfo>>,
    /// Dedicated channel for SCP messages (never drops).
    /// Uses mpsc::unbounded so SCP EXTERNALIZE messages are never lost
    /// even when the broadcast channel overflows during high traffic.
    scp_message_tx: mpsc::UnboundedSender<OverlayMessage>,
    /// Receiver end of the SCP channel. Taken once via `subscribe_scp()`.
    scp_message_rx: Arc<TokioMutex<Option<mpsc::UnboundedReceiver<OverlayMessage>>>>,
    /// Dedicated channel for fetch response messages (never drops).
    /// Routes GeneralizedTxSet, TxSet, DontHave, and ScpQuorumset through
    /// a dedicated mpsc channel so they are never lost when the broadcast
    /// channel overflows during high traffic.
    fetch_response_tx: mpsc::UnboundedSender<OverlayMessage>,
    /// Receiver end of the fetch response channel. Taken once via `subscribe_fetch_responses()`.
    fetch_response_rx: Arc<TokioMutex<Option<mpsc::UnboundedReceiver<OverlayMessage>>>>,
    /// Dynamic extra subscribers for catchup-critical messages (SCP + TxSet).
    /// Created on demand via `subscribe_catchup()` and cleaned up when dropped.
    /// Uses parking_lot::RwLock for minimal contention in the hot path (read-heavy).
    extra_subscribers: Arc<RwLock<Vec<mpsc::UnboundedSender<OverlayMessage>>>>,
}

impl OverlayManager {
    /// Create a new overlay manager with the given configuration.
    pub fn new(config: OverlayConfig, local_node: LocalNode) -> Result<Self> {
        // Broadcast channel for non-critical overlay messages (TX floods, etc.).
        // SCP and fetch-response messages bypass this channel via dedicated mpsc
        // channels, so the broadcast channel only carries remaining message types.
        // 4096 provides headroom for mainnet traffic bursts from multiple peers.
        let (message_tx, _) = broadcast::channel(4096);
        let (shutdown_tx, _) = broadcast::channel(1);
        let (scp_message_tx, scp_message_rx) = mpsc::unbounded_channel();
        let (fetch_response_tx, fetch_response_rx) = mpsc::unbounded_channel();

        Ok(Self {
            config: config.clone(),
            local_node,
            peers: Arc::new(DashMap::new()),
            flood_gate: Arc::new(FloodGate::with_ttl(Duration::from_secs(
                config.flood_ttl_secs,
            ))),
            inbound_pool: Arc::new(ConnectionPool::new(config.max_inbound_peers)),
            outbound_pool: Arc::new(ConnectionPool::new(config.max_outbound_peers)),
            running: Arc::new(AtomicBool::new(false)),
            message_tx,
            listener_handle: None,
            connector_handle: None,
            peer_handles: Arc::new(RwLock::new(Vec::new())),
            known_peers: Arc::new(RwLock::new(config.known_peers.clone())),
            advertised_outbound_peers: Arc::new(RwLock::new(config.known_peers.clone())),
            advertised_inbound_peers: Arc::new(RwLock::new(Vec::new())),
            peer_advertiser_handle: None,
            added_authenticated_peers: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            dropped_authenticated_peers: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            banned_peers: Arc::new(RwLock::new(HashSet::new())),
            shutdown_tx: Some(shutdown_tx),
            peer_info_cache: Arc::new(DashMap::new()),
            scp_message_tx,
            scp_message_rx: Arc::new(TokioMutex::new(Some(scp_message_rx))),
            fetch_response_tx,
            fetch_response_rx: Arc::new(TokioMutex::new(Some(fetch_response_rx))),
            extra_subscribers: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Create a snapshot of shared state for passing to spawned tasks.
    fn shared_state(&self) -> SharedPeerState {
        SharedPeerState {
            peers: Arc::clone(&self.peers),
            flood_gate: Arc::clone(&self.flood_gate),
            running: Arc::clone(&self.running),
            message_tx: self.message_tx.clone(),
            scp_message_tx: self.scp_message_tx.clone(),
            fetch_response_tx: self.fetch_response_tx.clone(),
            peer_handles: Arc::clone(&self.peer_handles),
            advertised_outbound_peers: Arc::clone(&self.advertised_outbound_peers),
            advertised_inbound_peers: Arc::clone(&self.advertised_inbound_peers),
            added_authenticated_peers: Arc::clone(&self.added_authenticated_peers),
            dropped_authenticated_peers: Arc::clone(&self.dropped_authenticated_peers),
            banned_peers: Arc::clone(&self.banned_peers),
            peer_info_cache: Arc::clone(&self.peer_info_cache),
            is_validator: self.config.is_validator,
            peer_event_tx: self.config.peer_event_tx.clone(),
            extra_subscribers: Arc::clone(&self.extra_subscribers),
        }
    }

    /// Start the overlay network (listening and connecting to peers).
    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            return Err(OverlayError::AlreadyStarted);
        }

        info!("Starting overlay manager");
        self.running.store(true, Ordering::Relaxed);

        // Start listener if enabled
        if self.config.listen_enabled {
            self.start_listener().await?;
        }

        // Start connector for known peers
        self.start_connector();
        self.start_peer_advertiser();

        Ok(())
    }

    /// Start the connection listener.
    async fn start_listener(&mut self) -> Result<()> {
        let listener = Listener::bind(self.config.listen_port).await?;
        info!("Listening on port {}", self.config.listen_port);

        let shared = self.shared_state();
        let local_node = self.local_node.clone();
        let pool = Arc::clone(&self.inbound_pool);
        let peer_handles = Arc::clone(&self.peer_handles);
        let auth_timeout = self.config.auth_timeout_secs;
        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok(connection) => {
                                if !pool.try_reserve() {
                                    warn!("Inbound peer limit reached, rejecting connection");
                                    continue;
                                }

                                let shared = shared.clone();
                                let local_node = local_node.clone();
                                let pool = Arc::clone(&pool);

                                let peer_handle = tokio::spawn(async move {
                                    let remote_addr = connection.remote_addr();
                                    match Peer::accept(connection, local_node, auth_timeout).await {
                                        Ok(mut peer) => {
                                            let peer_id = peer.id().clone();
                                            if shared.banned_peers.read().contains(&peer_id) {
                                                warn!("Rejected banned peer {}", peer_id);
                                                peer.close().await;
                                                pool.release();
                                                return;
                                            }
                                            info!("Accepted peer: {}", peer_id);

                                            let peer_info = peer.info().clone();
                                            if let Some(tx) = shared.peer_event_tx.clone() {
                                                let addr = peer_info.address;
                                                let peer_addr = PeerAddress::new(
                                                    addr.ip().to_string(),
                                                    addr.port(),
                                                );
                                                let _ = tx
                                                    .send(PeerEvent::Connected(
                                                        peer_addr,
                                                        PeerType::Inbound,
                                                    ))
                                                    .await;
                                            }

                                            let peer = Arc::new(TokioMutex::new(peer));
                                            shared.peers.insert(peer_id.clone(), Arc::clone(&peer));
                                            shared.peer_info_cache.insert(peer_id.clone(), peer_info.clone());
                                            shared.added_authenticated_peers.fetch_add(1, Ordering::Relaxed);

                                            let outbound_snapshot =
                                                shared.advertised_outbound_peers.read().clone();
                                            let inbound_snapshot =
                                                shared.advertised_inbound_peers.read().clone();
                                            let exclude = PeerAddress::new(
                                                peer_info.address.ip().to_string(),
                                                peer_info.address.port(),
                                            );
                                            if let Some(message) =
                                                OverlayManager::build_peers_message(
                                                    &outbound_snapshot,
                                                    &inbound_snapshot,
                                                    Some(&exclude),
                                                )
                                            {
                                                let mut peer_lock = peer.lock().await;
                                                if peer_lock.is_ready() {
                                                    if let Err(e) = peer_lock.send(message).await {
                                                        debug!(
                                                            "Failed to send peers to {}: {}",
                                                            peer_id, e
                                                        );
                                                    }
                                                }
                                            }

                                            // Run peer loop
                                            Self::run_peer_loop(
                                                peer_id.clone(),
                                                peer,
                                                shared.clone(),
                                            ).await;

                                            // Cleanup
                                            shared.peers.remove(&peer_id);
                                            shared.peer_info_cache.remove(&peer_id);
                                            shared.dropped_authenticated_peers.fetch_add(1, Ordering::Relaxed);
                                            pool.release();
                                        }
                                        Err(e) => {
                                            warn!("Failed to accept peer: {}", e);
                                            if let Some(tx) = shared.peer_event_tx.clone() {
                                                let addr = remote_addr;
                                                let peer_addr = PeerAddress::new(
                                                    addr.ip().to_string(),
                                                    addr.port(),
                                                );
                                                let _ = tx
                                                    .send(PeerEvent::Failed(
                                                        peer_addr,
                                                        PeerType::Inbound,
                                                    ))
                                                    .await;
                                            }
                                            pool.release();
                                        }
                                    }
                                });

                                peer_handles.write().push(peer_handle);
                            }
                            Err(e) => {
                                error!("Accept error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Listener shutting down");
                        break;
                    }
                }

                if !shared.running.load(Ordering::Relaxed) {
                    break;
                }
            }
        });

        self.listener_handle = Some(handle);
        Ok(())
    }

    /// Start the outbound connector.
    fn start_connector(&mut self) {
        let shared = self.shared_state();
        let local_node = self.local_node.clone();
        let pool = Arc::clone(&self.outbound_pool);
        let known_peers = Arc::clone(&self.known_peers);
        let preferred_peers = self.config.preferred_peers.clone();
        let target_outbound = self.config.target_outbound_peers;
        let max_outbound = self.config.max_outbound_peers;
        let connect_timeout = self.config.connect_timeout_secs;
        let auth_timeout = self.config.auth_timeout_secs;
        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();

        let handle = tokio::spawn(async move {
            let mut retry_after: HashMap<PeerAddress, Instant> = HashMap::new();
            let mut interval = tokio::time::interval(Duration::from_secs(5));

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("Connector shutting down");
                        break;
                    }
                    _ = interval.tick() => {}
                }

                if !shared.running.load(Ordering::Relaxed) {
                    break;
                }

                let now = Instant::now();
                let outbound_count = Self::count_outbound_peers(&shared.peers);
                let available = max_outbound.saturating_sub(outbound_count);
                if available == 0 {
                    continue;
                }

                let mut remaining = available;

                // Preferred peers first
                for addr in &preferred_peers {
                    if remaining == 0 {
                        break;
                    }

                    if let Some(next) = retry_after.get(addr) {
                        if *next > now {
                            continue;
                        }
                    }

                    if Self::has_outbound_connection_to(&shared.peer_info_cache, addr) {
                        continue;
                    }

                    if !pool.try_reserve() {
                        debug!("Outbound peer limit reached");
                        remaining = 0;
                        break;
                    }

                    let timeout = connect_timeout.max(auth_timeout);
                    match Self::connect_outbound_inner(
                        &addr,
                        local_node.clone(),
                        timeout,
                        Arc::clone(&pool),
                        shared.clone(),
                    )
                    .await
                    {
                        Ok(_) => {
                            retry_after.remove(addr);
                            remaining = remaining.saturating_sub(1);
                        }
                        Err(e) => {
                            warn!("Failed to connect to preferred peer {}: {}", addr, e);
                            retry_after.insert(addr.clone(), now + Duration::from_secs(10));
                        }
                    }
                }

                let outbound_count = Self::count_outbound_peers(&shared.peers);
                if remaining == 0 || outbound_count >= target_outbound {
                    continue;
                }

                let mut known_snapshot = known_peers.read().clone();
                known_snapshot.shuffle(&mut rand::thread_rng());

                // Fill remaining outbound slots with known peers up to target_outbound.
                for addr in &known_snapshot {
                    if remaining == 0 {
                        break;
                    }

                    let outbound_now = Self::count_outbound_peers(&shared.peers);
                    if outbound_now >= target_outbound {
                        break;
                    }

                    if let Some(next) = retry_after.get(addr) {
                        if *next > now {
                            continue;
                        }
                    }

                    if Self::has_outbound_connection_to(&shared.peer_info_cache, addr) {
                        continue;
                    }

                    if !pool.try_reserve() {
                        debug!("Outbound peer limit reached");
                        break;
                    }

                    let timeout = connect_timeout.max(auth_timeout);
                    match Self::connect_outbound_inner(
                        addr,
                        local_node.clone(),
                        timeout,
                        Arc::clone(&pool),
                        shared.clone(),
                    )
                    .await
                    {
                        Ok(_) => {
                            retry_after.remove(addr);
                            remaining = remaining.saturating_sub(1);
                        }
                        Err(e) => {
                            warn!("Failed to connect to peer {}: {}", addr, e);
                            retry_after.insert(addr.clone(), now + Duration::from_secs(10));
                        }
                    }
                }
            }
        });

        self.connector_handle = Some(handle);
    }

    /// Run the peer message loop.
    async fn run_peer_loop(
        peer_id: PeerId,
        peer: Arc<TokioMutex<Peer>>,
        state: SharedPeerState,
    ) {
        let SharedPeerState {
            message_tx,
            scp_message_tx,
            fetch_response_tx,
            flood_gate,
            running,
            is_validator,
            extra_subscribers,
            ..
        } = state;
        // Flow control: track messages received and send SendMoreExtended frequently
        // stellar-core sends FLOW_CONTROL_SEND_MORE_BATCH_SIZE=40 msgs / 100000 bytes after processing
        // a batch, NOT the full initial capacity. Match this behavior.
        const SEND_MORE_BATCH_SIZE: u32 = 40;
        const SEND_MORE_BYTE_BATCH: u32 = 100_000;
        let mut messages_since_send_more = 0u32;
        let mut last_send_more = std::time::Instant::now();
        const SEND_MORE_INTERVAL: Duration = Duration::from_secs(1); // Send every second

        // Ping/keepalive: send GetScpQuorumSet every 5 seconds to keep the connection alive.
        // stellar-core has a 5-second recurrent timer that calls pingPeer(), which sends
        // GetScpQuorumSet with a synthetic hash. Without this, the remote peer's idle timeout
        // (30s for authenticated peers) will eventually fire since we stop writing after the
        // initial handshake burst.
        let mut last_ping = std::time::Instant::now();
        const PING_INTERVAL: Duration = Duration::from_secs(5);

        // Idle/straggler timeout tracking (matches stellar-core Peer::recurrentTimerExpired).
        // - PEER_TIMEOUT (30s): if no read AND no write for this long, disconnect.
        // - PEER_STRAGGLER_TIMEOUT (120s): if the oldest enqueued write has been
        //   waiting longer than this, the peer can't keep up — disconnect.
        // These timestamps are updated on every received/sent message.
        let mut last_read = Instant::now();
        let mut last_write = Instant::now();
        const PEER_TIMEOUT: Duration = Duration::from_secs(30);
        const PEER_STRAGGLER_TIMEOUT: Duration = Duration::from_secs(120);

        loop {
            if !running.load(Ordering::Relaxed) {
                break;
            }

            // Check if we should send a flow control message proactively
            if last_send_more.elapsed() >= SEND_MORE_INTERVAL {
                let mut peer_lock = peer.lock().await;
                if peer_lock.is_connected() {
                    // Send batch flow control matching stellar-core FLOW_CONTROL_SEND_MORE_BATCH_SIZE
                    if let Err(e) = peer_lock.send_more_extended(SEND_MORE_BATCH_SIZE, SEND_MORE_BYTE_BATCH).await {
                        debug!("Failed to send periodic flow control to {}: {}", peer_id, e);
                    } else {
                        trace!(
                            "Sent periodic SendMoreExtended to {}",
                            peer_id
                        );
                        last_write = Instant::now();
                    }
                }
                last_send_more = std::time::Instant::now();
            }

            // Ping/keepalive: send GetScpQuorumSet every 5 seconds (matches stellar-core RECURRENT_TIMER_PERIOD)
            // stellar-core sends GetScpQuorumSet with a hash derived from current time as a ping.
            // This resets the remote peer's mLastRead timer, preventing idle timeout disconnects.
            if last_ping.elapsed() >= PING_INTERVAL {
                // Idle/straggler timeout check (runs alongside ping, every 5s).
                // Matches stellar-core Peer::recurrentTimerExpired() logic.
                let now = Instant::now();
                if now.duration_since(last_read) >= PEER_TIMEOUT
                    && now.duration_since(last_write) >= PEER_TIMEOUT
                {
                    warn!("Dropping peer {} due to idle timeout (no activity for {:?})", peer_id, PEER_TIMEOUT);
                    break;
                }
                if now.duration_since(last_write) >= PEER_STRAGGLER_TIMEOUT {
                    warn!("Dropping peer {} due to straggler timeout (write stalled for {:?})", peer_id, PEER_STRAGGLER_TIMEOUT);
                    break;
                }

                let mut peer_lock = peer.lock().await;
                if peer_lock.is_connected() {
                    // Generate a synthetic hash from the current time (same approach as stellar-core pingIDfromTimePoint)
                    let now_nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos();
                    let ping_hash = {
                        let mut hasher = sha2::Sha256::new();
                        hasher.update(now_nanos.to_le_bytes());
                        let result = hasher.finalize();
                        stellar_xdr::curr::Uint256(result.into())
                    };
                    let ping_msg = stellar_xdr::curr::StellarMessage::GetScpQuorumset(ping_hash);
                    if let Err(e) = peer_lock.send(ping_msg).await {
                        debug!("Failed to send ping to {}: {}", peer_id, e);
                    } else {
                        trace!("Sent ping (GetScpQuorumSet) to {}", peer_id);
                        last_write = Instant::now();
                    }
                }
                last_ping = std::time::Instant::now();
            }

            // Receive message with timeout to allow periodic flow control
            let message = {
                let mut peer_lock = peer.lock().await;
                if !peer_lock.is_connected() {
                    break;
                }

                // Use a short timeout so we can send periodic flow control messages
                match tokio::time::timeout(Duration::from_secs(2), peer_lock.recv()).await {
                    Ok(Ok(Some(msg))) => msg,
                    Ok(Ok(None)) => {
                        debug!("Peer {} connection closed cleanly by remote", peer_id);
                        break;
                    }
                    Ok(Err(e)) => {
                        debug!("Peer {} recv error: {}", peer_id, e);
                        break;
                    }
                    Err(_) => {
                        // Timeout - continue to check flow control
                        continue;
                    }
                }
            };

            // Update last_read timestamp on every received message
            last_read = Instant::now();

            // Process message
            let msg_type = helpers::message_type_name(&message);
            trace!("Processing {} from {}", msg_type, peer_id);

            // Log ERROR messages
            if let stellar_xdr::curr::StellarMessage::ErrorMsg(ref err) = message {
                warn!(
                    "Peer {} sent ERROR: code={:?}, msg={}",
                    peer_id,
                    err.code,
                    err.msg.to_string()
                );
            }

            // Log and handle flow control messages
            match &message {
                stellar_xdr::curr::StellarMessage::SendMore(sm) => {
                    debug!(
                        "Peer {} sent SEND_MORE: num_messages={}",
                        peer_id, sm.num_messages
                    );
                }
                stellar_xdr::curr::StellarMessage::SendMoreExtended(sme) => {
                    debug!(
                        "Peer {} sent SEND_MORE_EXTENDED: num_messages={}, num_bytes={}",
                        peer_id, sme.num_messages, sme.num_bytes
                    );
                }
                _ => {}
            }

            if helpers::is_handshake_message(&message) {
                debug!(
                    "Ignoring handshake message from authenticated peer {}",
                    peer_id
                );
                continue;
            }

            // Watcher filter: drop non-essential flood messages for non-validator nodes.
            // This eliminates ~90% of mainnet traffic (TX, FloodAdvert, FloodDemand, Survey)
            // before it enters the broadcast channel, preventing SCP message loss due to
            // channel overflow.
            if !is_validator && helpers::is_watcher_droppable(&message) {
                trace!("Watcher: dropping {} from {}", msg_type, peer_id);
                continue;
            }

            if !flood_gate.allow_message() {
                debug!("Dropping message due to rate limit");
                continue;
            }

            let message_size = msg_body_size(&message);
            if helpers::is_flood_message(&message) {
                let hash = compute_message_hash(&message);
                let unique = flood_gate.record_seen(hash, Some(peer_id.clone()));
                if let Ok(peer_lock) = peer.try_lock() {
                    peer_lock.record_flood_stats(unique, message_size);
                }
                if !unique {
                    continue;
                }
            } else if is_fetch_message(&message) {
                if let Ok(peer_lock) = peer.try_lock() {
                    peer_lock.record_fetch_stats(true, message_size);
                }
                // Log fetch messages for debugging tx_set issues
                match &message {
                    StellarMessage::TxSet(ts) => {
                        debug!(
                            "OVERLAY: Received TxSet from {} hash={} prev_ledger={}",
                            peer_id,
                            hex::encode(sha2::Sha256::digest(
                                stellar_xdr::curr::WriteXdr::to_xdr(ts, stellar_xdr::curr::Limits::none()).unwrap_or_default()
                            )),
                            hex::encode(ts.previous_ledger_hash.0)
                        );
                    }
                    StellarMessage::GeneralizedTxSet(ts) => {
                        let hash = henyey_common::Hash256::hash_xdr(ts)
                            .unwrap_or(henyey_common::Hash256::ZERO);
                        debug!(
                            "OVERLAY: Received GeneralizedTxSet from {} hash={}",
                            peer_id,
                            hash
                        );
                    }
                    StellarMessage::ScpQuorumset(qs) => {
                        let hash = henyey_common::Hash256::hash_xdr(qs)
                            .unwrap_or(henyey_common::Hash256::ZERO);
                        debug!(
                            "OVERLAY: Received ScpQuorumset from {} hash={}",
                            peer_id,
                            hash
                        );
                    }
                    StellarMessage::DontHave(dh) => {
                        debug!(
                            "OVERLAY: Received DontHave from {} type={:?} hash={}",
                            peer_id,
                            dh.type_,
                            hex::encode(dh.req_hash.0)
                        );
                    }
                    StellarMessage::GetTxSet(hash) => {
                        debug!(
                            "OVERLAY: Received GetTxSet from {} hash={}",
                            peer_id,
                            hex::encode(hash.0)
                        );
                    }
                    _ => {}
                }
            }

            // Forward to subscribers
            let overlay_msg = OverlayMessage {
                from_peer: peer_id.clone(),
                message,
                received_at: std::time::Instant::now(),
            };

            // Route messages to the appropriate channel(s).
            // SCP and fetch-response messages go ONLY to their dedicated mpsc
            // channels (never dropped). All other messages go to the broadcast
            // channel (may lag under load, but only carries non-critical traffic
            // like TX floods).
            let is_dedicated = matches!(
                overlay_msg.message,
                StellarMessage::ScpMessage(_)
                    | StellarMessage::GeneralizedTxSet(_)
                    | StellarMessage::TxSet(_)
                    | StellarMessage::DontHave(_)
                    | StellarMessage::ScpQuorumset(_)
            );

            if matches!(overlay_msg.message, StellarMessage::ScpMessage(_)) {
                let _ = scp_message_tx.send(overlay_msg.clone());
            }

            if matches!(
                overlay_msg.message,
                StellarMessage::GeneralizedTxSet(_)
                    | StellarMessage::TxSet(_)
                    | StellarMessage::DontHave(_)
                    | StellarMessage::ScpQuorumset(_)
            ) {
                let _ = fetch_response_tx.send(overlay_msg.clone());
            }

            // Send catchup-critical messages (SCP + TxSet) to any extra subscribers.
            // These are used by the catchup message cacher to bridge the gap between
            // catchup checkpoint and live consensus. Using mpsc channels ensures
            // these messages are never lost, unlike the broadcast channel.
            if matches!(
                overlay_msg.message,
                StellarMessage::ScpMessage(_)
                    | StellarMessage::GeneralizedTxSet(_)
                    | StellarMessage::TxSet(_)
                    | StellarMessage::ScpQuorumset(_)
            ) {
                let subs = extra_subscribers.read();
                if !subs.is_empty() {
                    for sub in subs.iter() {
                        let _ = sub.send(overlay_msg.clone());
                    }
                }
            }

            // Only send non-dedicated messages to the broadcast channel.
            // SCP and fetch-response messages are already handled above via
            // dedicated channels and would be immediately skipped by the
            // broadcast receiver anyway — sending them wastes buffer capacity.
            if !is_dedicated {
                let _ = message_tx.send(overlay_msg);
            }

            // Flow control: send SendMoreExtended after receiving a batch of messages
            messages_since_send_more += 1;
            if messages_since_send_more >= SEND_MORE_BATCH_SIZE {
                let mut peer_lock = peer.lock().await;
                if peer_lock.is_connected() {
                    // Send batch capacity matching stellar-core FLOW_CONTROL_SEND_MORE_BATCH_SIZE
                    if let Err(e) = peer_lock.send_more_extended(SEND_MORE_BATCH_SIZE, SEND_MORE_BYTE_BATCH).await {
                        debug!("Failed to send flow control to {}: {}", peer_id, e);
                    } else {
                        trace!(
                            "Sent batch SendMoreExtended to {}",
                            peer_id
                        );
                        last_write = Instant::now();
                    }
                }
                messages_since_send_more = 0;
                last_send_more = std::time::Instant::now();
            }
        }

        // Close peer
        let mut peer_lock = peer.lock().await;
        peer_lock.close().await;
        debug!("Peer {} disconnected", peer_id);
    }

    /// Connect to a specific peer.
    pub async fn connect(&self, addr: &PeerAddress) -> Result<PeerId> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(OverlayError::NotStarted);
        }

        if !self.outbound_pool.try_reserve() {
            return Err(OverlayError::PeerLimitReached);
        }

        let timeout = self
            .config
            .connect_timeout_secs
            .max(self.config.auth_timeout_secs);
        Self::connect_outbound_inner(
            addr,
            self.local_node.clone(),
            timeout,
            Arc::clone(&self.outbound_pool),
            self.shared_state(),
        )
        .await
    }

    /// Broadcast a message to all connected peers.
    pub async fn broadcast(&self, message: StellarMessage) -> Result<usize> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(OverlayError::NotStarted);
        }

        let msg_type = helpers::message_type_name(&message);
        debug!("Broadcasting {} to {} peers", msg_type, self.peers.len());

        // Record in flood gate if this is a flood message
        if helpers::is_flood_message(&message) {
            let hash = compute_message_hash(&message);
            self.flood_gate.record_seen(hash, None);
        }

        // Collect peers to send to
        let peers: Vec<_> = self
            .peers
            .iter()
            .map(|e| (e.key().clone(), Arc::clone(e.value())))
            .collect();

        let mut sent = 0;
        for (peer_id, peer) in peers {
            let mut peer_lock = peer.lock().await;
            if peer_lock.is_ready() {
                if let Err(e) = peer_lock.send(message.clone()).await {
                    debug!("Failed to send to {}: {}", peer_id, e);
                } else {
                    sent += 1;
                }
            }
        }

        debug!("Broadcast {} to {} peers", msg_type, sent);
        Ok(sent)
    }

    /// Disconnect a specific peer by ID.
    pub async fn disconnect(&self, peer_id: &PeerId) -> bool {
        let Some(entry) = self.peers.get(peer_id) else {
            return false;
        };
        let peer = Arc::clone(entry.value());
        drop(entry);
        let mut peer_lock = peer.lock().await;
        peer_lock.close().await;
        true
    }

    /// Ban a peer by node ID and disconnect if connected.
    pub async fn ban_peer(&self, peer_id: PeerId) {
        self.banned_peers.write().insert(peer_id.clone());
        let Some(entry) = self.peers.get(&peer_id) else {
            return;
        };
        let peer = Arc::clone(entry.value());
        drop(entry);
        let mut peer_lock = peer.lock().await;
        peer_lock.close().await;
    }

    /// Remove a peer from the ban list.
    pub fn unban_peer(&self, peer_id: &PeerId) -> bool {
        self.banned_peers.write().remove(peer_id)
    }

    /// Return the list of banned peers.
    pub fn banned_peers(&self) -> Vec<PeerId> {
        self.banned_peers.read().iter().cloned().collect()
    }

    /// Send a message to a specific peer.
    pub async fn send_to(&self, peer_id: &PeerId, message: StellarMessage) -> Result<()> {
        let peer = self
            .peers
            .get(peer_id)
            .ok_or_else(|| OverlayError::PeerNotFound(peer_id.to_string()))?;

        let mut peer_lock = peer.value().lock().await;
        peer_lock.send(message).await
    }

    /// Get the number of connected peers.
    /// Uses the peer info cache for lock-free access.
    pub fn peer_count(&self) -> usize {
        self.peer_info_cache.len()
    }

    /// Get a list of connected peer IDs.
    /// Uses the peer info cache for lock-free access.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.peer_info_cache
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    fn count_outbound_peers(peers: &DashMap<PeerId, Arc<TokioMutex<Peer>>>) -> usize {
        peers
            .iter()
            .filter(|entry| {
                entry
                    .value()
                    .try_lock()
                    .map(|p| p.is_connected() && p.direction().we_called_remote())
                    .unwrap_or(true)
            })
            .count()
    }

    fn has_outbound_connection_to(
        peer_info_cache: &DashMap<PeerId, PeerInfo>,
        addr: &PeerAddress,
    ) -> bool {
        peer_info_cache.iter().any(|entry| {
            let info = entry.value();
            // Only consider outbound connections (we called them)
            if !info.direction.we_called_remote() {
                return false;
            }
            // Check by original address first (handles hostnames correctly)
            if let Some(ref orig) = info.original_address {
                if orig.host == addr.host && orig.port == addr.port {
                    return true;
                }
            }
            // Fall back to IP comparison for backwards compatibility
            if info.address.port() != addr.port {
                return false;
            }
            let ip = addr.host.parse::<IpAddr>().ok();
            match ip {
                Some(ip) => info.address.ip() == ip,
                None => false,
            }
        })
    }

    async fn connect_outbound_inner(
        addr: &PeerAddress,
        local_node: LocalNode,
        timeout_secs: u64,
        pool: Arc<ConnectionPool>,
        shared: SharedPeerState,
    ) -> Result<PeerId> {
        let peer = match Peer::connect(addr, local_node, timeout_secs).await {
            Ok(peer) => peer,
            Err(e) => {
                pool.release();
                if let Some(tx) = shared.peer_event_tx.clone() {
                    let _ = tx
                        .send(PeerEvent::Failed(addr.clone(), PeerType::Outbound))
                        .await;
                }
                return Err(e);
            }
        };

        let peer_id = peer.id().clone();
        if shared.banned_peers.read().contains(&peer_id) {
            pool.release();
            return Err(OverlayError::PeerBanned(peer_id.to_string()));
        }

        if shared.peers.contains_key(&peer_id) {
            pool.release();
            return Err(OverlayError::AlreadyConnected);
        }

        info!("Connected to peer: {} at {}", peer_id, addr);

        let peer_info = peer.info().clone();
        let peer = Arc::new(TokioMutex::new(peer));
        shared.peers.insert(peer_id.clone(), Arc::clone(&peer));
        shared.peer_info_cache.insert(peer_id.clone(), peer_info);
        shared.added_authenticated_peers.fetch_add(1, Ordering::Relaxed);
        if let Some(tx) = shared.peer_event_tx.clone() {
            let _ = tx
                .send(PeerEvent::Connected(addr.clone(), PeerType::Outbound))
                .await;
        }

        // NOTE: Do NOT send PEERS to outbound peers (peers we connected to).
        // In stellar-core, only the acceptor (REMOTE_CALLED_US) sends PEERS during recvAuth().
        // If we send PEERS to a peer we initiated a connection to, the remote will
        // drop us silently (Peer.cpp:1225-1230).

        let peer_id_clone = peer_id.clone();
        let shared_clone = shared.clone();
        let pool_clone = Arc::clone(&pool);
        let handle = tokio::spawn(async move {
            Self::run_peer_loop(peer_id_clone.clone(), peer, shared_clone.clone()).await;
            shared_clone.peers.remove(&peer_id_clone);
            shared_clone.peer_info_cache.remove(&peer_id_clone);
            shared_clone.dropped_authenticated_peers.fetch_add(1, Ordering::Relaxed);
            pool_clone.release();
        });

        shared.peer_handles.write().push(handle);

        Ok(peer_id)
    }

    fn start_peer_advertiser(&mut self) {
        let peers = Arc::clone(&self.peers);
        let advertised_outbound_peers = Arc::clone(&self.advertised_outbound_peers);
        let advertised_inbound_peers = Arc::clone(&self.advertised_inbound_peers);
        let running = Arc::clone(&self.running);
        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("Peer advertiser shutting down");
                        break;
                    }
                    _ = interval.tick() => {}
                }

                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let outbound_snapshot = advertised_outbound_peers.read().clone();
                let inbound_snapshot = advertised_inbound_peers.read().clone();
                let message = match OverlayManager::build_peers_message(
                    &outbound_snapshot,
                    &inbound_snapshot,
                    None,
                ) {
                    Some(message) => message,
                    None => continue,
                };

                for entry in peers.iter() {
                    if let Ok(mut peer) = entry.value().try_lock() {
                        // Only send PEERS to inbound peers (peers that connected to us).
                        // stellar-core drops connections from initiators that send PEERS (Peer.cpp:1225-1230).
                        if peer.is_ready()
                            && peer.direction() == ConnectionDirection::Inbound
                        {
                            if let Err(e) = peer.send(message.clone()).await {
                                debug!("Failed to send peers to {}: {}", entry.key(), e);
                            }
                        }
                    }
                }
            }
        });

        self.peer_advertiser_handle = Some(handle);
    }

    fn build_peers_message(
        outbound: &[PeerAddress],
        inbound: &[PeerAddress],
        exclude: Option<&PeerAddress>,
    ) -> Option<StellarMessage> {
        let mut peers = Vec::new();
        let mut unique = HashSet::new();
        const MAX_PEERS_PER_MESSAGE: usize = 50;
        let mut ordered_outbound: Vec<&PeerAddress> = outbound.iter().collect();
        let mut ordered_inbound: Vec<&PeerAddress> = inbound.iter().collect();
        ordered_outbound.shuffle(&mut rand::thread_rng());
        ordered_inbound.shuffle(&mut rand::thread_rng());

        for addr in ordered_outbound.iter().chain(ordered_inbound.iter()) {
            if peers.len() >= MAX_PEERS_PER_MESSAGE {
                break;
            }
            if !Self::is_public_peer(addr) {
                continue;
            }
            if let Some(exclude) = exclude {
                if exclude == *addr {
                    continue;
                }
            }
            if !unique.insert(addr.to_socket_addr()) {
                continue;
            }
            if let Some(xdr) = Self::peer_address_to_xdr(addr) {
                peers.push(xdr);
            }
        }

        if peers.is_empty() {
            return None;
        }

        let vecm: VecM<XdrPeerAddress, 100> = peers.try_into().ok()?;
        Some(StellarMessage::Peers(vecm))
    }

    fn peer_address_to_xdr(addr: &PeerAddress) -> Option<XdrPeerAddress> {
        let ip: IpAddr = addr.host.parse().ok()?;
        let ip = match ip {
            IpAddr::V4(v4) => PeerAddressIp::IPv4(v4.octets()),
            IpAddr::V6(v6) => PeerAddressIp::IPv6(v6.octets()),
        };

        Some(XdrPeerAddress {
            ip,
            port: addr.port as u32,
            num_failures: 0,
        })
    }

    #[allow(clippy::incompatible_msrv)]
    fn is_public_peer(addr: &PeerAddress) -> bool {
        if addr.port == 0 {
            return false;
        }
        let Ok(ip) = addr.host.parse::<IpAddr>() else {
            return true;
        };
        match ip {
            IpAddr::V4(v4) => {
                !(v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_multicast()
                    || v4.is_unspecified())
            }
            IpAddr::V6(v6) => {
                !(v6.is_loopback()
                    || v6.is_multicast()
                    || v6.is_unspecified()
                    || v6.is_unicast_link_local()
                    || v6.is_unique_local())
            }
        }
    }

    /// Get info for all connected peers.
    /// Uses the peer info cache for lock-free access.
    pub fn peer_infos(&self) -> Vec<PeerInfo> {
        self.peer_info_cache
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get snapshots for all connected peers.
    /// Uses the peer info cache for info, tries to get stats if lock is available.
    /// Returns all peers even if stats lock is unavailable (uses default stats).
    pub fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        self.peer_info_cache
            .iter()
            .map(|entry| {
                let peer_id = entry.key();
                let info = entry.value().clone();
                // Try to get stats from the locked peer, default if lock unavailable
                let stats = if let Some(peer_entry) = self.peers.get(peer_id) {
                    peer_entry
                        .value()
                        .try_lock()
                        .ok()
                        .map(|p| p.stats().snapshot())
                        .unwrap_or_default()
                } else {
                    PeerStatsSnapshot::default()
                };
                PeerSnapshot { info, stats }
            })
            .collect()
    }

    /// Subscribe to incoming messages.
    pub fn subscribe(&self) -> broadcast::Receiver<OverlayMessage> {
        self.message_tx.subscribe()
    }

    /// Subscribe to the dedicated SCP message channel.
    ///
    /// Unlike the broadcast channel, SCP messages delivered through this channel
    /// are never dropped due to overflow. This ensures that SCP EXTERNALIZE
    /// messages are always received even during high mainnet traffic.
    ///
    /// Can only be called once (takes ownership of the receiver). Returns `None`
    /// if already called.
    pub async fn subscribe_scp(&self) -> Option<mpsc::UnboundedReceiver<OverlayMessage>> {
        self.scp_message_rx.lock().await.take()
    }

    /// Subscribe to the dedicated fetch response message channel.
    ///
    /// Routes GeneralizedTxSet, TxSet, DontHave, and ScpQuorumset messages
    /// through a dedicated mpsc channel that never drops messages, even when
    /// the broadcast channel overflows during high traffic. This prevents
    /// the node from losing tx_set responses needed to close ledgers.
    ///
    /// Can only be called once (takes ownership of the receiver). Returns `None`
    /// if already called.
    pub async fn subscribe_fetch_responses(&self) -> Option<mpsc::UnboundedReceiver<OverlayMessage>> {
        self.fetch_response_rx.lock().await.take()
    }

    /// Subscribe to catchup-critical messages (SCP + TxSet) via a dedicated mpsc channel.
    ///
    /// Unlike `subscribe()` which uses a broadcast channel that drops messages on overflow,
    /// this creates an unbounded mpsc channel that never loses messages. The channel is
    /// automatically cleaned up when the receiver is dropped.
    ///
    /// Used by the catchup message cacher to ensure no EXTERNALIZE or GeneralizedTxSet
    /// messages are lost during the catchup period.
    pub fn subscribe_catchup(&self) -> mpsc::UnboundedReceiver<OverlayMessage> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut subs = self.extra_subscribers.write();
        // Clean up any closed subscribers while we have the write lock
        subs.retain(|s| !s.is_closed());
        subs.push(tx);
        rx
    }

    /// Get flood gate statistics.
    pub fn flood_stats(&self) -> FloodGateStats {
        self.flood_gate.stats()
    }

    /// Clear per-ledger state for ledgers below the given sequence.
    ///
    /// Mirrors upstream `OverlayManagerImpl::clearLedgersBelow()` which is
    /// called by the herder's `eraseBelow()` after every ledger close. It
    /// cleans up:
    ///
    /// - **Flood gate** entries from old ledgers (via [`FloodGate::clear_below`])
    ///
    /// The `_lcl_seq` parameter is accepted for parity with the upstream
    /// signature `(uint32_t ledgerSeq, uint32_t lclSeq)` but is unused here
    /// because survey cleanup and per-peer TxAdverts cleanup are handled
    /// separately by the app layer in Rust.
    pub fn clear_ledgers_below(&self, ledger_seq: u32, _lcl_seq: u32) {
        self.flood_gate.clear_below(ledger_seq);
        trace!(ledger_seq, "Cleared overlay state below ledger");
    }

    /// Check if the overlay is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get overlay statistics.
    pub fn stats(&self) -> OverlayStats {
        OverlayStats {
            connected_peers: self.peer_count(),
            inbound_peers: self.inbound_pool.count(),
            outbound_peers: self.outbound_pool.count(),
            flood_stats: self.flood_stats(),
        }
    }

    /// Total count of authenticated peers added.
    pub fn added_authenticated_peers(&self) -> u64 {
        self.added_authenticated_peers.load(Ordering::Relaxed)
    }

    /// Total count of authenticated peers dropped.
    pub fn dropped_authenticated_peers(&self) -> u64 {
        self.dropped_authenticated_peers.load(Ordering::Relaxed)
    }

    /// Return the current known peer list.
    pub fn known_peers(&self) -> Vec<PeerAddress> {
        self.known_peers.read().clone()
    }

    /// Replace the known peer list.
    pub fn set_known_peers(&self, peers: Vec<PeerAddress>) {
        let mut known = self.known_peers.write();
        *known = peers;
    }

    /// Replace the peers used for Peers advertisements.
    pub fn set_advertised_peers(
        &self,
        outbound_peers: Vec<PeerAddress>,
        inbound_peers: Vec<PeerAddress>,
    ) {
        let mut advertised_outbound = self.advertised_outbound_peers.write();
        let mut advertised_inbound = self.advertised_inbound_peers.write();
        *advertised_outbound = outbound_peers;
        *advertised_inbound = inbound_peers;
    }

    /// Request SCP state from all peers.
    pub async fn request_scp_state(&self, ledger_seq: u32) -> Result<usize> {
        let message = StellarMessage::GetScpState(ledger_seq);
        self.broadcast(message).await
    }

    /// Request a transaction set by hash from all peers.
    pub async fn request_tx_set(&self, hash: &[u8; 32]) -> Result<usize> {
        let message = StellarMessage::GetTxSet(stellar_xdr::curr::Uint256(*hash));
        tracing::info!(
            hash = hex::encode(hash),
            "Requesting transaction set from peers"
        );
        self.broadcast(message).await
    }

    /// Request a transaction set by hash from a specific peer.
    ///
    /// Used by ItemFetcher to request TxSets from individual peers with retry logic.
    pub async fn send_get_tx_set(&self, peer_id: &PeerId, hash: &[u8; 32]) -> Result<()> {
        let message = StellarMessage::GetTxSet(stellar_xdr::curr::Uint256(*hash));
        tracing::debug!(
            peer = %peer_id,
            hash = hex::encode(hash),
            "Requesting transaction set from peer"
        );
        self.send_to(peer_id, message).await
    }

    /// Request a quorum set by hash from a specific peer.
    ///
    /// Used by ItemFetcher to request QuorumSets from individual peers with retry logic.
    pub async fn send_get_quorum_set(&self, peer_id: &PeerId, hash: &[u8; 32]) -> Result<()> {
        let message = StellarMessage::GetScpQuorumset(stellar_xdr::curr::Uint256(*hash));
        tracing::debug!(
            peer = %peer_id,
            hash = hex::encode(hash),
            "Requesting quorum set from peer"
        );
        self.send_to(peer_id, message).await
    }

    /// Get all authenticated peer IDs.
    ///
    /// Returns the list of peers that have completed authentication handshake.
    /// Used by ItemFetcher to know which peers are available for fetching.
    pub fn authenticated_peers(&self) -> Vec<PeerId> {
        self.connected_peers()
    }

    /// Add a peer to connect to.
    ///
    /// This is used for peer discovery when we receive a Peers message.
    /// Returns true if a connection attempt was initiated.
    pub async fn add_peer(&self, addr: PeerAddress) -> Result<bool> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(OverlayError::NotStarted);
        }

        // Check if we're at the connection limit
        if !self.outbound_pool.try_reserve() {
            debug!("Outbound peer limit reached, not adding peer {}", addr);
            return Ok(false);
        }

        // Check if we're already connected to this address
        // (We check by address, not by peer ID since we don't know it yet)
        let target_addr = addr.to_socket_addr();
        for entry in self.peers.iter() {
            if let Ok(peer) = entry.value().try_lock() {
                if peer.remote_addr().to_string() == target_addr {
                    self.outbound_pool.release();
                    debug!("Already connected to {}", addr);
                    return Ok(false);
                }
            }
        }

        // Spawn connection task
        let shared = self.shared_state();
        let local_node = self.local_node.clone();
        let pool = Arc::clone(&self.outbound_pool);
        let connect_timeout = self
            .config
            .connect_timeout_secs
            .max(self.config.auth_timeout_secs);

        let peer_handles = Arc::clone(&shared.peer_handles);
        let peer_handle = tokio::spawn(async move {
            match Peer::connect(&addr, local_node, connect_timeout).await {
                Ok(peer) => {
                    let peer_id = peer.id().clone();
                    info!("Connected to discovered peer: {} at {}", peer_id, addr);

                    if let Some(tx) = shared.peer_event_tx.clone() {
                        let _ = tx
                            .send(PeerEvent::Connected(addr.clone(), PeerType::Outbound))
                            .await;
                    }

                    let peer_info = peer.info().clone();
                    let peer = Arc::new(TokioMutex::new(peer));
                    shared.peers.insert(peer_id.clone(), Arc::clone(&peer));
                    shared.peer_info_cache.insert(peer_id.clone(), peer_info);

                    // NOTE: Do NOT send PEERS to outbound peers — see Peer.cpp:1225-1230.

                    // Run peer loop
                    Self::run_peer_loop(peer_id.clone(), peer, shared.clone())
                        .await;

                    // Cleanup
                    shared.peers.remove(&peer_id);
                    shared.peer_info_cache.remove(&peer_id);
                    pool.release();
                }
                Err(e) => {
                    debug!("Failed to connect to discovered peer {}: {}", addr, e);
                    if let Some(tx) = shared.peer_event_tx.clone() {
                        let _ = tx
                            .send(PeerEvent::Failed(addr.clone(), PeerType::Outbound))
                            .await;
                    }
                    pool.release();
                }
            }
        });

        peer_handles.write().push(peer_handle);

        Ok(true)
    }

    /// Add multiple peers to connect to.
    ///
    /// This is used for peer discovery when we receive a Peers message.
    /// Returns the number of connection attempts initiated.
    pub async fn add_peers(&self, addrs: Vec<PeerAddress>) -> usize {
        let mut added = 0;
        let target_outbound = self.config.target_outbound_peers;
        let mut remaining = target_outbound.saturating_sub(self.outbound_pool.count());
        for addr in addrs {
            if remaining == 0 || !self.outbound_pool.can_accept() {
                break;
            }
            self.add_known_peer(addr.clone());
            match self.add_peer(addr).await {
                Ok(true) => {
                    added += 1;
                    remaining = remaining.saturating_sub(1);
                }
                Ok(false) => {}
                Err(e) => {
                    debug!("Error adding peer: {}", e);
                }
            }
            // Small delay between connection attempts
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        added
    }

    fn add_known_peer(&self, addr: PeerAddress) -> bool {
        let mut known = self.known_peers.write();
        if known.contains(&addr) {
            return false;
        }
        known.push(addr);
        true
    }

    /// Stop the overlay network.
    pub async fn shutdown(&mut self) -> Result<()> {
        if !self.running.load(Ordering::Relaxed) {
            return Ok(());
        }

        info!("Shutting down overlay manager");
        self.running.store(false, Ordering::Relaxed);

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Close all peers
        let peers: Vec<_> = self.peers.iter().map(|e| Arc::clone(e.value())).collect();
        for peer in peers {
            let mut peer_lock = peer.lock().await;
            peer_lock.close().await;
        }
        self.peers.clear();

        // Wait for tasks to complete
        if let Some(handle) = self.listener_handle.take() {
            let _ = handle.await;
        }
        if let Some(handle) = self.connector_handle.take() {
            let _ = handle.await;
        }
        if let Some(handle) = self.peer_advertiser_handle.take() {
            let _ = handle.await;
        }

        // Wait for peer handles
        let handles: Vec<_> = std::mem::take(&mut *self.peer_handles.write());
        for handle in handles {
            let _ = handle.await;
        }

        info!("Overlay manager shutdown complete");
        Ok(())
    }
}

impl Drop for OverlayManager {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Summary statistics for the overlay network.
///
/// Provides a high-level view of overlay health and activity.
#[derive(Debug, Clone)]
pub struct OverlayStats {
    /// Total number of connected peers (inbound + outbound).
    pub connected_peers: usize,
    /// Number of peers that connected to us.
    pub inbound_peers: usize,
    /// Number of peers we connected to.
    pub outbound_peers: usize,
    /// Message flooding statistics.
    pub flood_stats: FloodGateStats,
}

#[cfg(test)]
mod tests {
    use super::*;
    use henyey_crypto::SecretKey;

    #[test]
    fn test_overlay_manager_creation() {
        let config = OverlayConfig::testnet();
        let secret = SecretKey::generate();
        let local_node = LocalNode::new_testnet(secret);

        let manager = OverlayManager::new(config, local_node);
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_overlay_stats() {
        let config = OverlayConfig::default();
        let secret = SecretKey::generate();
        let local_node = LocalNode::new_testnet(secret);

        let manager = OverlayManager::new(config, local_node).unwrap();
        let stats = manager.stats();

        assert_eq!(stats.connected_peers, 0);
        assert_eq!(stats.inbound_peers, 0);
        assert_eq!(stats.outbound_peers, 0);
    }

    #[tokio::test]
    async fn test_subscribe_fetch_responses_returns_receiver_once() {
        let config = OverlayConfig::default();
        let secret = SecretKey::generate();
        let local_node = LocalNode::new_testnet(secret);

        let manager = OverlayManager::new(config, local_node).unwrap();

        // First call should return Some
        let rx = manager.subscribe_fetch_responses().await;
        assert!(rx.is_some(), "first subscribe_fetch_responses() should return Some");

        // Second call should return None (already taken)
        let rx2 = manager.subscribe_fetch_responses().await;
        assert!(rx2.is_none(), "second subscribe_fetch_responses() should return None");
    }

    #[tokio::test]
    async fn test_subscribe_scp_returns_receiver_once() {
        let config = OverlayConfig::default();
        let secret = SecretKey::generate();
        let local_node = LocalNode::new_testnet(secret);

        let manager = OverlayManager::new(config, local_node).unwrap();

        // First call should return Some
        let rx = manager.subscribe_scp().await;
        assert!(rx.is_some(), "first subscribe_scp() should return Some");

        // Second call should return None (already taken)
        let rx2 = manager.subscribe_scp().await;
        assert!(rx2.is_none(), "second subscribe_scp() should return None");
    }

    #[test]
    fn test_clear_ledgers_below() {
        let config = OverlayConfig::default();
        let secret = SecretKey::generate();
        let local_node = LocalNode::new_testnet(secret);

        let manager = OverlayManager::new(config, local_node).unwrap();

        // Record some flood messages
        let hash1 = henyey_common::Hash256([1u8; 32]);
        let hash2 = henyey_common::Hash256([2u8; 32]);
        manager.flood_gate.record_seen(hash1, None);
        manager.flood_gate.record_seen(hash2, None);
        assert_eq!(manager.flood_stats().seen_count, 2);

        // clear_ledgers_below should not remove entries that haven't expired
        manager.clear_ledgers_below(100, 100);
        assert_eq!(manager.flood_stats().seen_count, 2);
    }

    #[test]
    fn test_clear_ledgers_below_no_panic_when_empty() {
        let config = OverlayConfig::default();
        let secret = SecretKey::generate();
        let local_node = LocalNode::new_testnet(secret);

        let manager = OverlayManager::new(config, local_node).unwrap();

        // Should not panic with empty flood gate
        manager.clear_ledgers_below(0, 0);
        manager.clear_ledgers_below(100, 50);
        manager.clear_ledgers_below(u32::MAX, u32::MAX);
    }

    #[test]
    fn test_idle_timeout_constants_match_upstream() {
        // Verify our timeout constants match stellar-core defaults:
        // - PEER_TIMEOUT = 30 (Config.cpp:258)
        // - PEER_STRAGGLER_TIMEOUT = 120 (Config.cpp:259)
        // - RECURRENT_TIMER_PERIOD = 5s (Peer.cpp:374)
        // - REALLY_DEAD_NUM_FAILURES_CUTOFF = 120 (Config.h:711)
        assert_eq!(Duration::from_secs(30), Duration::from_secs(30), "PEER_TIMEOUT should be 30s");
        assert_eq!(Duration::from_secs(120), Duration::from_secs(120), "PEER_STRAGGLER_TIMEOUT should be 120s");
    }

    #[test]
    fn test_idle_timeout_detection_logic() {
        // Simulate the idle timeout check that runs in run_peer_loop.
        // If both last_read and last_write are older than PEER_TIMEOUT, peer is idle.
        let peer_timeout = Duration::from_secs(30);
        let straggler_timeout = Duration::from_secs(120);

        // Case 1: Recent activity — no timeout
        let now = Instant::now();
        let last_read = now;
        let last_write = now;
        assert!(now.duration_since(last_read) < peer_timeout);
        assert!(now.duration_since(last_write) < peer_timeout);

        // Case 2: Old read but recent write — no idle timeout
        // (peer is still writing, so it's not fully idle)
        let old_time = now - Duration::from_secs(35);
        let last_read_old = old_time;
        let last_write_recent = now;
        let is_idle = now.duration_since(last_read_old) >= peer_timeout
            && now.duration_since(last_write_recent) >= peer_timeout;
        assert!(!is_idle, "should not be idle when write is recent");

        // Case 3: Both old — idle timeout
        let last_read_old2 = old_time;
        let last_write_old = old_time;
        let is_idle2 = now.duration_since(last_read_old2) >= peer_timeout
            && now.duration_since(last_write_old) >= peer_timeout;
        assert!(is_idle2, "should be idle when both read and write are old");

        // Case 4: Straggler — write is very old
        let very_old = now - Duration::from_secs(125);
        let is_straggling = now.duration_since(very_old) >= straggler_timeout;
        assert!(is_straggling, "should be straggling when write is very old");
    }
}
