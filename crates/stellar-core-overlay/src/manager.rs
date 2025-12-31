//! OverlayManager for managing all peer connections.
//!
//! Handles:
//! - Accepting incoming connections
//! - Connecting to outbound peers
//! - Broadcasting messages
//! - Message routing

use crate::{
    codec::helpers,
    connection::{ConnectionPool, Listener},
    flood::{compute_message_hash, FloodGate, FloodGateStats},
    peer::{Peer, PeerInfo, PeerState},
    LocalNode, MessageHandler, OverlayConfig, OverlayError, PeerAddress, PeerId, Result,
};
use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use stellar_xdr::curr::StellarMessage;
use tokio::sync::{broadcast, mpsc, Mutex as TokioMutex};
use tokio::task::JoinHandle;
use parking_lot::RwLock;
use tracing::{debug, error, info, trace, warn};

/// Message received from the overlay.
#[derive(Debug, Clone)]
pub struct OverlayMessage {
    /// The peer that sent the message.
    pub from_peer: PeerId,
    /// The message.
    pub message: StellarMessage,
}

/// Manager for all peer connections.
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
    /// Shutdown signal.
    shutdown_tx: Option<broadcast::Sender<()>>,
}

impl OverlayManager {
    /// Create a new overlay manager with the given configuration.
    pub fn new(config: OverlayConfig, local_node: LocalNode) -> Result<Self> {
        let (message_tx, _) = broadcast::channel(65536);
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            config: config.clone(),
            local_node,
            peers: Arc::new(DashMap::new()),
            flood_gate: Arc::new(FloodGate::with_ttl(Duration::from_secs(config.flood_ttl_secs))),
            inbound_pool: Arc::new(ConnectionPool::new(config.max_inbound_peers)),
            outbound_pool: Arc::new(ConnectionPool::new(config.max_outbound_peers)),
            running: Arc::new(AtomicBool::new(false)),
            message_tx,
            listener_handle: None,
            connector_handle: None,
            peer_handles: Arc::new(RwLock::new(Vec::new())),
            shutdown_tx: Some(shutdown_tx),
        })
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

        Ok(())
    }

    /// Start the connection listener.
    async fn start_listener(&mut self) -> Result<()> {
        let listener = Listener::bind(self.config.listen_port).await?;
        info!("Listening on port {}", self.config.listen_port);

        let peers = Arc::clone(&self.peers);
        let local_node = self.local_node.clone();
        let pool = Arc::clone(&self.inbound_pool);
        let running = Arc::clone(&self.running);
        let message_tx = self.message_tx.clone();
        let flood_gate = Arc::clone(&self.flood_gate);
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

                                let peers = Arc::clone(&peers);
                                let local_node = local_node.clone();
                                let pool = Arc::clone(&pool);
                                let message_tx = message_tx.clone();
                                let flood_gate = Arc::clone(&flood_gate);
                                let running = Arc::clone(&running);

                                let peer_handle = tokio::spawn(async move {
                                    match Peer::accept(connection, local_node, auth_timeout).await {
                                        Ok(peer) => {
                                            let peer_id = peer.id().clone();
                                            info!("Accepted peer: {}", peer_id);

                                            let peer = Arc::new(TokioMutex::new(peer));
                                            peers.insert(peer_id.clone(), Arc::clone(&peer));

                                            // Run peer loop
                                            Self::run_peer_loop(
                                                peer_id.clone(),
                                                peer,
                                                message_tx,
                                                flood_gate,
                                                running,
                                            ).await;

                                            // Cleanup
                                            peers.remove(&peer_id);
                                            pool.release();
                                        }
                                        Err(e) => {
                                            warn!("Failed to accept peer: {}", e);
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

                if !running.load(Ordering::Relaxed) {
                    break;
                }
            }
        });

        self.listener_handle = Some(handle);
        Ok(())
    }

    /// Start the outbound connector.
    fn start_connector(&mut self) {
        let peers = Arc::clone(&self.peers);
        let local_node = self.local_node.clone();
        let pool = Arc::clone(&self.outbound_pool);
        let running = Arc::clone(&self.running);
        let message_tx = self.message_tx.clone();
        let flood_gate = Arc::clone(&self.flood_gate);
        let peer_handles = Arc::clone(&self.peer_handles);
        let known_peers = self.config.known_peers.clone();
        let connect_timeout = self.config.connect_timeout_secs;
        let auth_timeout = self.config.auth_timeout_secs;
        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();

        let handle = tokio::spawn(async move {
            // Connect to known peers
            for addr in &known_peers {
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                if !pool.try_reserve() {
                    debug!("Outbound peer limit reached");
                    break;
                }

                let peers = Arc::clone(&peers);
                let local_node = local_node.clone();
                let pool = Arc::clone(&pool);
                let message_tx = message_tx.clone();
                let flood_gate = Arc::clone(&flood_gate);
                let running = Arc::clone(&running);
                let addr = addr.clone();

                let peer_handle = tokio::spawn(async move {
                    match Peer::connect(&addr, local_node, connect_timeout.max(auth_timeout)).await {
                        Ok(peer) => {
                            let peer_id = peer.id().clone();
                            info!("Connected to peer: {} at {}", peer_id, addr);

                            let peer = Arc::new(TokioMutex::new(peer));
                            peers.insert(peer_id.clone(), Arc::clone(&peer));

                            // Run peer loop
                            Self::run_peer_loop(
                                peer_id.clone(),
                                peer,
                                message_tx,
                                flood_gate,
                                running,
                            ).await;

                            // Cleanup
                            peers.remove(&peer_id);
                            pool.release();
                        }
                        Err(e) => {
                            warn!("Failed to connect to {}: {}", addr, e);
                            pool.release();
                        }
                    }
                });

                peer_handles.write().push(peer_handle);

                // Small delay between connection attempts
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            // Wait for shutdown
            let _ = shutdown_rx.recv().await;
            debug!("Connector shutting down");
        });

        self.connector_handle = Some(handle);
    }

    /// Run the peer message loop.
    async fn run_peer_loop(
        peer_id: PeerId,
        peer: Arc<TokioMutex<Peer>>,
        message_tx: broadcast::Sender<OverlayMessage>,
        flood_gate: Arc<FloodGate>,
        running: Arc<AtomicBool>,
    ) {
        // Flow control: track messages received and send SendMoreExtended frequently
        // Peers disconnect if we don't send enough flow control messages
        // CRITICAL: Must use SendMoreExtended since we initialized with it in handshake
        const SEND_MORE_THRESHOLD: u32 = 5; // Send flow control after just 5 messages
        let mut messages_since_send_more = 0u32;
        let mut last_send_more = std::time::Instant::now();
        const SEND_MORE_INTERVAL: Duration = Duration::from_secs(1); // Send every second

        loop {
            if !running.load(Ordering::Relaxed) {
                break;
            }

            // Check if we should send a flow control message proactively
            if last_send_more.elapsed() >= SEND_MORE_INTERVAL {
                let mut peer_lock = peer.lock().await;
                if peer_lock.is_connected() {
                    // Send generous flow control matching our handshake values
                    // Use SendMoreExtended to match the handshake (not SendMore)
                    if let Err(e) = peer_lock.send_more_extended(500, 50_000_000).await {
                        debug!("Failed to send periodic flow control to {}: {}", peer_id, e);
                    } else {
                        trace!("Sent periodic flow control (SendMoreExtended 500/50MB) to {}", peer_id);
                    }
                }
                last_send_more = std::time::Instant::now();
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
                    Ok(Ok(None)) => break,
                    Ok(Err(e)) => {
                        debug!("Peer {} error: {}", peer_id, e);
                        break;
                    }
                    Err(_) => {
                        // Timeout - continue to check flow control
                        continue;
                    }
                }
            };

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

            // Check for duplicate flood messages
            if helpers::is_flood_message(&message) {
                let hash = compute_message_hash(&message);
                if !flood_gate.record_seen(hash, Some(peer_id.clone())) {
                    // Duplicate, skip
                    continue;
                }
            }

            // Forward to subscribers
            let overlay_msg = OverlayMessage {
                from_peer: peer_id.clone(),
                message,
            };

            let _ = message_tx.send(overlay_msg);

            // Flow control: send SendMoreExtended after receiving a batch of messages
            messages_since_send_more += 1;
            if messages_since_send_more >= SEND_MORE_THRESHOLD {
                let mut peer_lock = peer.lock().await;
                if peer_lock.is_connected() {
                    // Send generous capacity matching handshake values
                    if let Err(e) = peer_lock.send_more_extended(500, 50_000_000).await {
                        debug!("Failed to send flow control to {}: {}", peer_id, e);
                    } else {
                        trace!("Sent batch flow control (SendMoreExtended 500/50MB) to {}", peer_id);
                    }
                }
                messages_since_send_more = 0;
                last_send_more = std::time::Instant::now();
            }
        }

        // Close peer
        let mut peer_lock = peer.lock().await;
        peer_lock.close().await;
        info!("Peer {} disconnected", peer_id);
    }

    /// Connect to a specific peer.
    pub async fn connect(&self, addr: &PeerAddress) -> Result<PeerId> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(OverlayError::NotStarted);
        }

        if !self.outbound_pool.try_reserve() {
            return Err(OverlayError::PeerLimitReached);
        }

        let timeout = self.config.connect_timeout_secs.max(self.config.auth_timeout_secs);
        let peer = Peer::connect(addr, self.local_node.clone(), timeout).await?;
        let peer_id = peer.id().clone();

        // Check if already connected
        if self.peers.contains_key(&peer_id) {
            self.outbound_pool.release();
            return Err(OverlayError::AlreadyConnected);
        }

        info!("Connected to peer: {} at {}", peer_id, addr);

        let peers = Arc::clone(&self.peers);
        let pool = Arc::clone(&self.outbound_pool);
        let message_tx = self.message_tx.clone();
        let flood_gate = Arc::clone(&self.flood_gate);
        let running = Arc::clone(&self.running);
        let peer_id_clone = peer_id.clone();

        let peer = Arc::new(TokioMutex::new(peer));
        peers.insert(peer_id.clone(), Arc::clone(&peer));

        let handle = tokio::spawn(async move {
            Self::run_peer_loop(peer_id_clone.clone(), peer, message_tx, flood_gate, running).await;
            peers.remove(&peer_id_clone);
            pool.release();
        });

        self.peer_handles.write().push(handle);

        Ok(peer_id)
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
        let peers: Vec<_> = self.peers.iter().map(|e| (e.key().clone(), Arc::clone(e.value()))).collect();

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
    /// Uses try_lock to avoid blocking; may undercount if peers are locked.
    pub fn peer_count(&self) -> usize {
        self.peers
            .iter()
            .filter(|entry| {
                entry.value().try_lock()
                    .map(|p| p.is_connected())
                    .unwrap_or(true) // Assume connected if locked
            })
            .count()
    }

    /// Get a list of connected peer IDs.
    /// Uses try_lock to avoid blocking.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|entry| {
                entry.value().try_lock()
                    .map(|p| p.is_connected())
                    .unwrap_or(true)
            })
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get info for all connected peers.
    /// Uses try_lock to avoid blocking; skips peers that are locked.
    pub fn peer_infos(&self) -> Vec<PeerInfo> {
        self.peers
            .iter()
            .filter_map(|entry| {
                entry.value().try_lock()
                    .ok()
                    .filter(|p| p.is_connected())
                    .map(|p| p.info().clone())
            })
            .collect()
    }

    /// Subscribe to incoming messages.
    pub fn subscribe(&self) -> broadcast::Receiver<OverlayMessage> {
        self.message_tx.subscribe()
    }

    /// Get flood gate statistics.
    pub fn flood_stats(&self) -> FloodGateStats {
        self.flood_gate.stats()
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

    /// Request SCP state from all peers.
    pub async fn request_scp_state(&self, ledger_seq: u32) -> Result<usize> {
        let message = StellarMessage::GetScpState(ledger_seq);
        self.broadcast(message).await
    }

    /// Request a transaction set by hash from all peers.
    pub async fn request_tx_set(&self, hash: &[u8; 32]) -> Result<usize> {
        let message = StellarMessage::GetTxSet(stellar_xdr::curr::Uint256(*hash));
        tracing::info!(hash = hex::encode(hash), "Requesting transaction set from peers");
        self.broadcast(message).await
    }

    /// Request peers from all connected peers.
    /// Note: GetPeers was removed in Protocol 24. Peers are now pushed via the Peers message.
    pub async fn request_peers(&self) -> Result<usize> {
        // In the current protocol, peers are advertised via Peers messages
        // There is no explicit request mechanism
        warn!("request_peers called but GetPeers is no longer supported");
        Ok(0)
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
        let peers = Arc::clone(&self.peers);
        let local_node = self.local_node.clone();
        let pool = Arc::clone(&self.outbound_pool);
        let message_tx = self.message_tx.clone();
        let flood_gate = Arc::clone(&self.flood_gate);
        let running = Arc::clone(&self.running);
        let connect_timeout = self.config.connect_timeout_secs.max(self.config.auth_timeout_secs);
        let peer_handles = Arc::clone(&self.peer_handles);

        let peer_handle = tokio::spawn(async move {
            match Peer::connect(&addr, local_node, connect_timeout).await {
                Ok(peer) => {
                    let peer_id = peer.id().clone();
                    info!("Connected to discovered peer: {} at {}", peer_id, addr);

                    let peer = Arc::new(TokioMutex::new(peer));
                    peers.insert(peer_id.clone(), Arc::clone(&peer));

                    // Run peer loop
                    Self::run_peer_loop(
                        peer_id.clone(),
                        peer,
                        message_tx,
                        flood_gate,
                        running,
                    ).await;

                    // Cleanup
                    peers.remove(&peer_id);
                    pool.release();
                }
                Err(e) => {
                    debug!("Failed to connect to discovered peer {}: {}", addr, e);
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
        for addr in addrs {
            match self.add_peer(addr).await {
                Ok(true) => added += 1,
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

/// Overlay statistics.
#[derive(Debug, Clone)]
pub struct OverlayStats {
    /// Number of connected peers.
    pub connected_peers: usize,
    /// Number of inbound connections.
    pub inbound_peers: usize,
    /// Number of outbound connections.
    pub outbound_peers: usize,
    /// Flood gate statistics.
    pub flood_stats: FloodGateStats,
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_core_crypto::SecretKey;

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
}
