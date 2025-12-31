//! Application struct and component initialization for rs-stellar-core.
//!
//! The App struct is the main entry point that coordinates all subsystems:
//! - Database for persistent storage
//! - BucketManager for ledger state
//! - LedgerManager for ledger operations
//! - HistoryManager for archive access
//! - OverlayManager for P2P networking
//! - Herder for consensus coordination

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio::sync::Mutex as TokioMutex;

use stellar_core_bucket::BucketManager;
use stellar_core_herder::{Herder, HerderCallback, HerderConfig, EnvelopeState};
use stellar_core_history::{CatchupManager, HistoryArchive, CatchupOutput};
use stellar_core_ledger::{
    LedgerCloseData, LedgerManager, LedgerManagerConfig, TransactionSetVariant,
};
use stellar_core_overlay::{OverlayManager, OverlayConfig as OverlayManagerConfig, LocalNode, OverlayMessage, PeerAddress};
use stellar_xdr::curr::{Hash, ScpEnvelope, StellarMessage, TransactionSet};

use crate::config::AppConfig;
use crate::logging::CatchupProgress;

/// Application state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// Application is initializing.
    Initializing,
    /// Application is catching up from history.
    CatchingUp,
    /// Application is synced and tracking consensus.
    Synced,
    /// Application is running as a validator.
    Validating,
    /// Application is shutting down.
    ShuttingDown,
}

impl std::fmt::Display for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppState::Initializing => write!(f, "Initializing"),
            AppState::CatchingUp => write!(f, "Catching Up"),
            AppState::Synced => write!(f, "Synced"),
            AppState::Validating => write!(f, "Validating"),
            AppState::ShuttingDown => write!(f, "Shutting Down"),
        }
    }
}

/// The main application struct.
pub struct App {
    /// Application configuration.
    config: AppConfig,

    /// Current application state.
    state: RwLock<AppState>,

    /// Database connection.
    db: stellar_core_db::Database,

    /// Node keypair.
    keypair: stellar_core_crypto::SecretKey,

    /// Bucket manager for ledger state persistence.
    bucket_manager: Arc<BucketManager>,

    /// Ledger manager for ledger operations.
    ledger_manager: Arc<LedgerManager>,

    /// Overlay network manager.
    overlay: TokioMutex<Option<OverlayManager>>,

    /// Herder for consensus coordination.
    herder: Arc<Herder>,

    /// Current ledger sequence.
    current_ledger: RwLock<u32>,

    /// Whether running as validator.
    is_validator: bool,

    /// Shutdown signal sender.
    shutdown_tx: tokio::sync::broadcast::Sender<()>,

    /// Shutdown signal receiver.
    _shutdown_rx: tokio::sync::broadcast::Receiver<()>,

    /// Channel for outbound SCP envelopes.
    scp_envelope_tx: tokio::sync::mpsc::Sender<ScpEnvelope>,

    /// Receiver for outbound SCP envelopes.
    scp_envelope_rx: TokioMutex<tokio::sync::mpsc::Receiver<ScpEnvelope>>,

    /// Last processed externalized slot (for ledger close triggering).
    last_processed_slot: RwLock<u64>,
}

impl App {
    /// Create a new application instance.
    pub async fn new(config: AppConfig) -> anyhow::Result<Self> {
        tracing::info!(
            node_name = %config.node.name,
            network = %config.network.passphrase,
            "Initializing rs-stellar-core"
        );

        // Validate configuration
        config.validate()?;

        // Initialize database
        let db = Self::init_database(&config)?;

        // Initialize or generate keypair
        let keypair = Self::init_keypair(&config)?;

        tracing::info!(
            public_key = %keypair.public_key().to_strkey(),
            "Node identity"
        );

        // Convert quorum set config to XDR
        let local_quorum_set = config.node.quorum_set.to_xdr();
        if let Some(ref qs) = local_quorum_set {
            tracing::info!(
                threshold = qs.threshold,
                validators = qs.validators.len(),
                inner_sets = qs.inner_sets.len(),
                "Loaded quorum set configuration"
            );
        }

        // Initialize bucket manager for ledger state persistence
        let bucket_dir = config.database.path.parent()
            .unwrap_or(&config.database.path)
            .join("buckets");
        std::fs::create_dir_all(&bucket_dir)?;

        let bucket_manager = Arc::new(BucketManager::new(bucket_dir)?);
        tracing::info!("Bucket manager initialized");

        // Initialize ledger manager
        let ledger_manager = Arc::new(LedgerManager::with_config(
            db.clone(),
            bucket_manager.clone(),
            config.network.passphrase.clone(),
            LedgerManagerConfig {
                max_snapshots: 10,
                validate_bucket_hash: true,
                persist_to_db: true,
            },
        ));
        tracing::info!("Ledger manager initialized");

        // Create herder configuration
        let herder_config = HerderConfig {
            max_pending_transactions: 1000,
            is_validator: config.node.is_validator,
            ledger_close_time: 5,
            node_public_key: keypair.public_key(),
            network_id: config.network_id(),
            max_externalized_slots: 12,
            max_tx_set_size: 1000,
            pending_config: Default::default(),
            tx_queue_config: Default::default(),
            local_quorum_set,
        };

        // Create herder (with or without secret key for signing)
        let herder = if config.node.is_validator {
            Arc::new(Herder::with_secret_key(herder_config, keypair.clone()))
        } else {
            Arc::new(Herder::new(herder_config))
        };

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        // Create channel for outbound SCP envelopes
        let (scp_envelope_tx, scp_envelope_rx) = tokio::sync::mpsc::channel(100);

        // Wire up envelope sender for validators
        if config.node.is_validator {
            let tx = scp_envelope_tx.clone();
            herder.set_envelope_sender(move |envelope| {
                // Non-blocking send - if channel is full, we drop the envelope
                // (This is fine, SCP will retry)
                let _ = tx.try_send(envelope);
            });
            tracing::info!("Envelope sender configured for validator mode");
        }

        Ok(Self {
            is_validator: config.node.is_validator,
            config,
            state: RwLock::new(AppState::Initializing),
            db,
            keypair,
            bucket_manager,
            ledger_manager,
            overlay: TokioMutex::new(None),
            herder,
            current_ledger: RwLock::new(0),
            shutdown_tx,
            _shutdown_rx: shutdown_rx,
            scp_envelope_tx,
            scp_envelope_rx: TokioMutex::new(scp_envelope_rx),
            last_processed_slot: RwLock::new(0),
        })
    }

    /// Initialize the database.
    fn init_database(config: &AppConfig) -> anyhow::Result<stellar_core_db::Database> {
        tracing::info!(path = ?config.database.path, "Opening database");

        // Ensure parent directory exists
        if let Some(parent) = config.database.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let db = stellar_core_db::Database::open(&config.database.path)?;
        tracing::debug!("Database opened successfully");
        Ok(db)
    }

    /// Initialize the node keypair.
    fn init_keypair(config: &AppConfig) -> anyhow::Result<stellar_core_crypto::SecretKey> {
        if let Some(ref seed) = config.node.node_seed {
            tracing::debug!("Using configured node seed");
            let keypair = stellar_core_crypto::SecretKey::from_strkey(seed)?;
            Ok(keypair)
        } else {
            tracing::info!("Generating ephemeral node keypair");
            Ok(stellar_core_crypto::SecretKey::generate())
        }
    }

    /// Get the application configuration.
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    /// Get the current application state.
    pub async fn state(&self) -> AppState {
        *self.state.read().await
    }

    /// Set the application state.
    async fn set_state(&self, state: AppState) {
        let mut current = self.state.write().await;
        if *current != state {
            tracing::info!(from = %*current, to = %state, "State transition");
            *current = state;
        }
    }

    /// Get the database.
    pub fn database(&self) -> &stellar_core_db::Database {
        &self.db
    }

    /// Get the node's public key.
    pub fn public_key(&self) -> stellar_core_crypto::PublicKey {
        self.keypair.public_key()
    }

    /// Get the network ID.
    pub fn network_id(&self) -> stellar_core_common::Hash256 {
        self.config.network_id()
    }

    /// Run catchup to a target ledger.
    ///
    /// This downloads history from archives and applies it to bring the
    /// node up to date with the network.
    pub async fn catchup(&self, target: CatchupTarget) -> anyhow::Result<CatchupResult> {
        self.set_state(AppState::CatchingUp).await;

        let progress = Arc::new(CatchupProgress::new());

        tracing::info!(?target, "Starting catchup");

        // Determine target ledger
        let target_ledger = match target {
            CatchupTarget::Current => {
                // Query archive for latest checkpoint
                self.get_latest_checkpoint().await?
            }
            CatchupTarget::Ledger(seq) => seq,
            CatchupTarget::Checkpoint(checkpoint) => checkpoint * 64,
        };

        progress.set_target(target_ledger);

        tracing::info!(target_ledger = target_ledger, "Target ledger determined");

        // Run catchup work
        let output = self.run_catchup_work(target_ledger, progress.clone()).await?;

        // Initialize ledger manager with catchup results
        // This validates that the bucket list hash matches the ledger header
        self.ledger_manager.initialize_from_buckets(
            output.bucket_list,
            output.hot_archive_bucket_list,
            output.header,
        )
            .map_err(|e| anyhow::anyhow!("Failed to initialize ledger manager: {}", e))?;

        tracing::info!(
            ledger_seq = output.result.ledger_seq,
            "Ledger manager initialized from catchup"
        );

        progress.set_phase(crate::logging::CatchupPhase::Complete);
        progress.summary();

        Ok(CatchupResult {
            ledger_seq: output.result.ledger_seq,
            ledger_hash: output.result.ledger_hash,
            buckets_applied: output.result.buckets_downloaded,
            ledgers_replayed: output.result.ledgers_applied,
        })
    }

    /// Get the latest checkpoint from history archives.
    async fn get_latest_checkpoint(&self) -> anyhow::Result<u32> {
        tracing::info!("Querying history archives for latest checkpoint");

        // Try each configured archive to get the current ledger
        for archive_config in &self.config.history.archives {
            match HistoryArchive::new(&archive_config.url) {
                Ok(archive) => {
                    match archive.get_current_ledger().await {
                        Ok(ledger) => {
                            tracing::info!(
                                ledger,
                                archive = %archive_config.url,
                                "Got current ledger from archive"
                            );
                            // Round down to the latest completed checkpoint
                            let checkpoint = stellar_core_history::checkpoint::latest_checkpoint_before_or_at(ledger)
                                .ok_or_else(|| anyhow::anyhow!("No checkpoint available for ledger {}", ledger))?;
                            return Ok(checkpoint);
                        }
                        Err(e) => {
                            tracing::warn!(
                                archive = %archive_config.url,
                                error = %e,
                                "Failed to get current ledger from archive"
                            );
                            continue;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        archive = %archive_config.url,
                        error = %e,
                        "Failed to create archive client"
                    );
                    continue;
                }
            }
        }

        Err(anyhow::anyhow!("Failed to get current ledger from any archive"))
    }

    /// Run the catchup work using the real CatchupManager.
    async fn run_catchup_work(
        &self,
        target_ledger: u32,
        progress: Arc<CatchupProgress>,
    ) -> anyhow::Result<CatchupOutput> {
        use crate::logging::CatchupPhase;

        // Phase 1: Create history archives from config
        progress.set_phase(CatchupPhase::DownloadingState);
        tracing::info!(target_ledger, "Downloading history archive state");

        let archives: Vec<HistoryArchive> = self.config.history.archives
            .iter()
            .filter(|a| a.get_enabled)
            .filter_map(|a| {
                match HistoryArchive::new(&a.url) {
                    Ok(archive) => Some(archive),
                    Err(e) => {
                        tracing::warn!(url = %a.url, error = %e, "Failed to create archive");
                        None
                    }
                }
            })
            .collect();

        if archives.is_empty() {
            return Err(anyhow::anyhow!("No history archives available"));
        }

        tracing::info!(archive_count = archives.len(), "Created history archive clients");

        // Create CatchupManager using Arc references
        let archives_arc: Vec<Arc<HistoryArchive>> = archives.into_iter().map(Arc::new).collect();
        let mut catchup_manager = CatchupManager::new_with_arcs(
            archives_arc,
            self.bucket_manager.clone(),
            Arc::new(self.db.clone()),
        );

        // Run catchup
        progress.set_phase(CatchupPhase::DownloadingBuckets);
        let output = catchup_manager.catchup_to_ledger(target_ledger).await
            .map_err(|e| anyhow::anyhow!("Catchup failed: {}", e))?;

        // Update progress with bucket count
        progress.set_total_buckets(output.result.buckets_downloaded);
        for _ in 0..output.result.buckets_downloaded {
            progress.bucket_downloaded();
        }

        // Update ledger progress
        progress.set_phase(CatchupPhase::ReplayingLedgers);
        for _ in 0..output.result.ledgers_applied {
            progress.ledger_applied();
        }

        // Verify
        progress.set_phase(CatchupPhase::Verifying);
        tracing::info!("Verifying catchup state");

        Ok(output)
    }

    /// Run the main event loop.
    ///
    /// This starts all subsystems and runs until shutdown is signaled.
    pub async fn run(&self) -> anyhow::Result<()> {
        tracing::info!("Starting main event loop");

        // First, check if we need to catch up
        let current_ledger = self.get_current_ledger().await?;

        if current_ledger == 0 {
            tracing::info!("No ledger state, running catchup first");
            let result = self.catchup(CatchupTarget::Current).await?;
            *self.current_ledger.write().await = result.ledger_seq;
        } else {
            // Ledger manager was already initialized (e.g., catchup ran before run())
            *self.current_ledger.write().await = current_ledger;
        }

        // Bootstrap herder with current ledger
        let ledger_seq = *self.current_ledger.read().await;
        self.herder.start_syncing();
        self.herder.bootstrap(ledger_seq);
        tracing::info!(ledger_seq, "Herder bootstrapped");

        // Start overlay network
        self.start_overlay().await?;

        // Wait a short time for initial peer connections, then request SCP state
        tokio::time::sleep(Duration::from_millis(500)).await;
        self.request_scp_state_from_peers().await;

        // Set state based on validator mode
        if self.is_validator {
            self.set_state(AppState::Validating).await;
        } else {
            self.set_state(AppState::Synced).await;
        }

        // Get message receiver from overlay
        let message_rx = {
            let overlay = self.overlay.lock().await;
            overlay.as_ref().map(|o| o.subscribe())
        };

        let mut message_rx = match message_rx {
            Some(rx) => rx,
            None => {
                tracing::warn!("Overlay not started, running without network");
                // Create a dummy receiver that never receives
                let (tx, rx) = tokio::sync::broadcast::channel::<OverlayMessage>(1);
                drop(tx);
                rx
            }
        };

        // Main run loop
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let mut consensus_interval = tokio::time::interval(Duration::from_secs(5));
        let mut stats_interval = tokio::time::interval(Duration::from_secs(30));
        let mut peer_maintenance_interval = tokio::time::interval(Duration::from_secs(10));

        // Get mutable access to SCP envelope receiver
        let mut scp_rx = self.scp_envelope_rx.lock().await;

        tracing::info!("Entering main event loop");

        // Add a short heartbeat interval for debugging
        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            tokio::select! {
                // NOTE: Removed biased; to ensure timers get fair polling

                // Process overlay messages
                msg = message_rx.recv() => {
                    match msg {
                        Ok(overlay_msg) => {
                            let msg_type = match &overlay_msg.message {
                                StellarMessage::ScpMessage(_) => "SCP",
                                StellarMessage::Transaction(_) => "TX",
                                StellarMessage::TxSet(_) => "TxSet",
                                StellarMessage::GeneralizedTxSet(_) => "GeneralizedTxSet",
                                StellarMessage::GetTxSet(_) => "GetTxSet",
                                StellarMessage::Hello(_) => "Hello",
                                StellarMessage::Peers(_) => "Peers",
                                _ => "Other",
                            };
                            tracing::debug!(msg_type, "Received overlay message");
                            self.handle_overlay_message(overlay_msg).await;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(skipped = n, "Message receiver lagged");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            tracing::info!("Overlay message channel closed");
                            break;
                        }
                    }
                }

                // Broadcast outbound SCP envelopes
                envelope = scp_rx.recv() => {
                    if let Some(envelope) = envelope {
                        let slot = envelope.statement.slot_index;
                        let msg = StellarMessage::ScpMessage(envelope);
                        let overlay = self.overlay.lock().await;
                        if let Some(ref overlay) = *overlay {
                            match overlay.broadcast(msg).await {
                                Ok(count) => {
                                    tracing::debug!(slot, peers = count, "Broadcast SCP envelope");
                                }
                                Err(e) => {
                                    tracing::warn!(slot, error = %e, "Failed to broadcast SCP envelope");
                                }
                            }
                        }
                    }
                }

                // Consensus timer - trigger ledger close for validators and process externalized
                _ = consensus_interval.tick() => {
                    // Check for externalized slots to process
                    self.process_externalized_slots().await;

                    // Request any pending tx sets we need
                    self.request_pending_tx_sets().await;

                    // For validators, try to trigger next round
                    if self.is_validator {
                        self.try_trigger_consensus().await;
                    }
                }

                // Stats logging
                _ = stats_interval.tick() => {
                    self.log_stats().await;
                }

                // Peer maintenance - reconnect if peer count drops too low
                _ = peer_maintenance_interval.tick() => {
                    self.maintain_peers().await;
                }

                // Shutdown signal (lowest priority)
                _ = shutdown_rx.recv() => {
                    tracing::info!("Shutdown signal received");
                    break;
                }

                // Heartbeat for debugging
                _ = heartbeat_interval.tick() => {
                    let tracking_slot = self.herder.tracking_slot();
                    let ledger = *self.current_ledger.read().await;
                    let latest_ext = self.herder.latest_externalized_slot().unwrap_or(0);
                    let overlay = self.overlay.lock().await;
                    let peers = overlay.as_ref().map(|o| o.peer_count()).unwrap_or(0);
                    drop(overlay);
                    tracing::info!(
                        tracking_slot,
                        ledger,
                        latest_ext,
                        peers,
                        "Heartbeat"
                    );
                }
            }
        }

        self.set_state(AppState::ShuttingDown).await;
        self.shutdown_internal().await?;

        Ok(())
    }

    /// Start the overlay network.
    async fn start_overlay(&self) -> anyhow::Result<()> {
        tracing::info!("Starting overlay network");

        // Create local node info
        let local_node = if self.config.network.passphrase.contains("Test") {
            LocalNode::new_testnet(self.keypair.clone())
        } else {
            LocalNode::new_mainnet(self.keypair.clone())
        };

        // Start with testnet or mainnet defaults
        let mut overlay_config = if self.config.network.passphrase.contains("Test") {
            OverlayManagerConfig::testnet()
        } else {
            OverlayManagerConfig::mainnet()
        };

        // Override with app config settings
        overlay_config.max_inbound_peers = self.config.overlay.max_inbound_peers;
        overlay_config.max_outbound_peers = self.config.overlay.max_outbound_peers;
        overlay_config.target_outbound_peers = self.config.overlay.target_outbound_peers;
        overlay_config.listen_port = self.config.overlay.peer_port;
        overlay_config.listen_enabled = self.is_validator; // Validators listen for connections
        overlay_config.network_passphrase = self.config.network.passphrase.clone();

        // Convert known peers from strings to PeerAddress
        if !self.config.overlay.known_peers.is_empty() {
            overlay_config.known_peers = self.config.overlay.known_peers
                .iter()
                .filter_map(|s| {
                    // Parse "host:port" or just "host" (default port 11625)
                    let parts: Vec<&str> = s.split(':').collect();
                    match parts.len() {
                        1 => Some(PeerAddress::new(parts[0], 11625)),
                        2 => parts[1].parse().ok().map(|port| PeerAddress::new(parts[0], port)),
                        _ => None,
                    }
                })
                .collect();
        }

        // Convert preferred peers
        if !self.config.overlay.preferred_peers.is_empty() {
            overlay_config.preferred_peers = self.config.overlay.preferred_peers
                .iter()
                .filter_map(|s| {
                    let parts: Vec<&str> = s.split(':').collect();
                    match parts.len() {
                        1 => Some(PeerAddress::new(parts[0], 11625)),
                        2 => parts[1].parse().ok().map(|port| PeerAddress::new(parts[0], port)),
                        _ => None,
                    }
                })
                .collect();
        }

        tracing::info!(
            listen_port = overlay_config.listen_port,
            known_peers = overlay_config.known_peers.len(),
            listen_enabled = overlay_config.listen_enabled,
            "Creating overlay with config"
        );

        let mut overlay = OverlayManager::new(overlay_config, local_node)?;
        overlay.start().await?;

        let peer_count = overlay.peer_count();
        tracing::info!(peer_count, "Overlay network started");

        *self.overlay.lock().await = Some(overlay);
        Ok(())
    }

    /// Handle a message from the overlay network.
    async fn handle_overlay_message(&self, msg: OverlayMessage) {
        match msg.message {
            StellarMessage::ScpMessage(envelope) => {
                let slot = envelope.statement.slot_index;
                let tracking = self.herder.tracking_slot();

                // Check if this is an EXTERNALIZE message so we can request the tx set
                let is_externalize = matches!(
                    &envelope.statement.pledges,
                    stellar_xdr::curr::ScpStatementPledges::Externalize(_)
                );

                match self.herder.receive_scp_envelope(envelope) {
                    EnvelopeState::Valid => {
                        tracing::info!(slot, tracking, "Processed SCP envelope (valid)");

                        // For EXTERNALIZE messages, immediately try to close ledger and request tx set
                        if is_externalize {
                            // First, process externalized slots to register pending tx set requests
                            self.process_externalized_slots().await;
                            // Then, immediately request any pending tx sets
                            self.request_pending_tx_sets().await;
                        }
                    }
                    EnvelopeState::Pending => {
                        tracing::info!(slot, tracking, "SCP envelope buffered for future slot");
                    }
                    EnvelopeState::Duplicate => {
                        // Expected, ignore silently
                    }
                    EnvelopeState::TooOld => {
                        tracing::info!(slot, tracking, "SCP envelope too old");
                    }
                    EnvelopeState::Invalid => {
                        tracing::warn!(slot, peer = ?msg.from_peer, "Invalid SCP envelope");
                    }
                    EnvelopeState::InvalidSignature => {
                        tracing::warn!(slot, peer = ?msg.from_peer, "SCP envelope with invalid signature");
                    }
                }
            }

            StellarMessage::Transaction(tx_env) => {
                match self.herder.receive_transaction(tx_env.clone()) {
                    stellar_core_herder::TxQueueResult::Added => {
                        tracing::debug!(peer = ?msg.from_peer, "Transaction added to queue");
                        // Forward the transaction to other peers (flood)
                        let overlay = self.overlay.lock().await;
                        if let Some(ref overlay) = *overlay {
                            let forward_msg = StellarMessage::Transaction(tx_env);
                            if let Ok(count) = overlay.broadcast(forward_msg).await {
                                tracing::debug!(peers = count, "Forwarded transaction to peers");
                            }
                        }
                    }
                    stellar_core_herder::TxQueueResult::Duplicate => {
                        // Expected, ignore
                    }
                    stellar_core_herder::TxQueueResult::QueueFull => {
                        tracing::warn!("Transaction queue full, dropping transaction");
                    }
                    stellar_core_herder::TxQueueResult::FeeTooLow => {
                        tracing::debug!("Transaction fee too low, rejected");
                    }
                    stellar_core_herder::TxQueueResult::Invalid => {
                        tracing::debug!("Invalid transaction rejected");
                    }
                }
            }

            StellarMessage::GetScpState(ledger_seq) => {
                tracing::debug!(ledger_seq, peer = ?msg.from_peer, "Peer requested SCP state");
                self.send_scp_state(&msg.from_peer, ledger_seq).await;
            }

            StellarMessage::Peers(peer_list) => {
                tracing::debug!(count = peer_list.len(), peer = ?msg.from_peer, "Received peer list");
                self.process_peer_list(peer_list).await;
            }

            StellarMessage::TxSet(tx_set) => {
                tracing::info!(peer = ?msg.from_peer, "Received TxSet");
                self.handle_tx_set(tx_set).await;
            }

            StellarMessage::GeneralizedTxSet(gen_tx_set) => {
                tracing::info!(peer = ?msg.from_peer, "Received GeneralizedTxSet");
                self.handle_generalized_tx_set(gen_tx_set).await;
            }

            StellarMessage::GetTxSet(hash) => {
                tracing::debug!(hash = hex::encode(hash.0), peer = ?msg.from_peer, "Peer requested TxSet");
                self.send_tx_set(&msg.from_peer, &hash.0).await;
            }

            _ => {
                // Other message types (Hello, Auth, etc.) are handled by overlay
                tracing::trace!(msg_type = ?std::mem::discriminant(&msg.message), "Ignoring message type");
            }
        }
    }

    /// Try to close a specific slot directly when we receive its tx set.
    /// This bypasses gap detection since we're processing a specific slot we have data for.
    /// Note: This can close slots that were previously "skipped" if we now have the tx set.
    async fn try_close_slot_directly(&self, slot: u64) {
        tracing::info!(slot, "Attempting to close specific slot directly");

        // Note: We intentionally don't check last_processed_slot here because
        // process_externalized_slots marks slots as "processed" even when skipped.
        // This function is called when we receive the tx set, so we should
        // attempt to close regardless.

        // Get ledger close info from herder for this specific slot
        let close_info = match self.herder.check_ledger_close(slot) {
            Some(info) => info,
            None => {
                tracing::debug!(slot, "No ledger close info for slot");
                return;
            }
        };

        let ledger_seq = slot as u32;

        // Get transactions from the tx set
        let transactions = match close_info.tx_set {
            Some(tx_set) => tx_set.transactions,
            None => {
                tracing::debug!(slot, "Tx set still not available for slot");
                return;
            }
        };

        tracing::info!(
            ledger_seq,
            tx_count = transactions.len(),
            close_time = close_info.close_time,
            "Closing specific slot with received tx set"
        );

        // Update ledger manager to the previous sequence so the close works
        let current_ledger = self.ledger_manager.current_ledger_seq();
        if current_ledger != ledger_seq - 1 {
            tracing::info!(
                current_ledger,
                expected = ledger_seq - 1,
                "Adjusting ledger sequence before close"
            );
            self.ledger_manager.set_ledger_sequence(ledger_seq - 1);
            *self.current_ledger.write().await = ledger_seq - 1;
        }

        // Close the ledger using the HerderCallback implementation
        match HerderCallback::close_ledger(
            self,
            ledger_seq,
            transactions,
            close_info.close_time,
        ).await {
            Ok(hash) => {
                tracing::info!(
                    ledger_seq,
                    hash = %hash.to_hex(),
                    "Successfully closed specific slot"
                );

                // Update last processed
                *self.last_processed_slot.write().await = slot;
                *self.current_ledger.write().await = ledger_seq;

                // Clean up applied transactions from the queue
                self.herder.cleanup();
            }
            Err(e) => {
                tracing::error!(
                    ledger_seq,
                    error = %e,
                    "Failed to close specific slot"
                );
            }
        }
    }

    /// Process any externalized slots that need ledger close.
    async fn process_externalized_slots(&self) {
        // Get the latest externalized slot
        let latest_externalized = match self.herder.latest_externalized_slot() {
            Some(slot) => slot,
            None => {
                tracing::debug!("No externalized slots yet");
                return;
            }
        };

        tracing::debug!(latest_externalized, "Processing externalized slots");

        // Check if we've already processed this slot
        let last_processed = *self.last_processed_slot.read().await;
        if latest_externalized <= last_processed {
            tracing::debug!(latest_externalized, last_processed, "Already processed");
            return; // Already processed
        }

        tracing::debug!(latest_externalized, last_processed, "Need to process");

        // Get the current ledger from ledger manager
        let current_ledger = match self.get_current_ledger().await {
            Ok(seq) => seq,
            Err(_) => return, // Can't determine current ledger
        };

        // Check if we need to fast-forward the ledger state
        // This happens when we've been fast-forwarded by EXTERNALIZE messages
        // Any gap > 1 means we missed ledgers and need to skip to the current state
        if latest_externalized as u32 > current_ledger + 1 {
            let gap = latest_externalized as u32 - current_ledger;
            tracing::info!(
                current_ledger,
                latest_externalized,
                gap,
                "Gap detected - fast-forwarding ledger state"
            );

            // Update the ledger manager to the slot before latest_externalized
            // so the next close will work for that slot
            let new_seq = (latest_externalized - 1) as u32;
            self.ledger_manager.set_ledger_sequence(new_seq);

            // Update our internal tracking
            *self.current_ledger.write().await = new_seq;

            // Skip trying to close all the missed ledgers - update last_processed to skip them
            *self.last_processed_slot.write().await = latest_externalized - 1;
            tracing::info!(
                skipped_to = latest_externalized - 1,
                "Skipped missed ledgers during fast-forward, will try to close latest"
            );
            // Don't return - continue to try closing the latest externalized slot
            // This ensures we register pending tx set requests
        }

        // Re-read last_processed after potential update
        let last_processed = *self.last_processed_slot.read().await;
        if latest_externalized <= last_processed {
            return;
        }

        // Get ledger close info from herder
        let close_info = match self.herder.check_ledger_close(latest_externalized) {
            Some(info) => info,
            None => {
                tracing::debug!(slot = latest_externalized, "No ledger close info yet");
                return;
            }
        };

        let ledger_seq = latest_externalized as u32;

        // Get transactions from the tx set
        // If we don't have the tx set, we can't close the ledger properly
        // This happens when we joined the network mid-consensus
        let transactions = match close_info.tx_set {
            Some(tx_set) => tx_set.transactions,
            None => {
                // We don't have the transaction set, so we can't properly close this ledger
                // Mark it as processed and move on - the tx set might arrive via try_close_slot_directly
                // but if the network has moved on, we need to keep up
                tracing::info!(
                    ledger_seq,
                    "Skipping ledger close - waiting for tx set (will retry if received)"
                );
                *self.last_processed_slot.write().await = latest_externalized;
                *self.current_ledger.write().await = ledger_seq;
                self.ledger_manager.set_ledger_sequence(ledger_seq);
                return;
            }
        };

        tracing::info!(
            ledger_seq,
            tx_count = transactions.len(),
            close_time = close_info.close_time,
            "Processing externalized slot"
        );

        // Close the ledger using the HerderCallback implementation
        match HerderCallback::close_ledger(
            self,
            ledger_seq,
            transactions,
            close_info.close_time,
        ).await {
            Ok(hash) => {
                tracing::info!(
                    ledger_seq,
                    hash = %hash.to_hex(),
                    "Successfully closed ledger"
                );

                // Update last processed
                *self.last_processed_slot.write().await = latest_externalized;

                // Clean up applied transactions from the queue
                self.herder.cleanup();
            }
            Err(e) => {
                tracing::error!(
                    ledger_seq,
                    error = %e,
                    "Failed to close ledger"
                );
            }
        }
    }

    /// Try to trigger consensus for the next ledger (validators only).
    async fn try_trigger_consensus(&self) {
        let current_slot = self.herder.tracking_slot();

        // Check if we should start a new round
        if self.herder.is_tracking() {
            let next_slot = (current_slot + 1) as u32;
            tracing::debug!(next_slot, "Checking if we should trigger consensus");

            // In a full implementation, we would:
            // 1. Check if enough time has passed since last close
            // 2. Build a transaction set from queued transactions
            // 3. Create a StellarValue with the tx set hash and close time
            // 4. Start SCP nomination with that value

            // For now, trigger the herder
            if let Err(e) = self.herder.trigger_next_ledger(next_slot).await {
                tracing::error!(error = %e, slot = next_slot, "Failed to trigger ledger");
            }
        }
    }

    /// Maintain peer connections - reconnect if peer count drops too low.
    async fn maintain_peers(&self) {
        let overlay_guard = self.overlay.lock().await;
        let overlay = match overlay_guard.as_ref() {
            Some(o) => o,
            None => return,
        };

        let peer_count = overlay.peer_count();
        let min_peers = 3; // Minimum peers we want

        if peer_count < min_peers {
            tracing::info!(
                peer_count,
                min_peers,
                "Peer count below threshold, reconnecting to known peers"
            );

            // Try to reconnect to known peers
            let mut reconnected = false;
            for addr_str in &self.config.overlay.known_peers {
                if overlay.peer_count() >= self.config.overlay.target_outbound_peers {
                    break;
                }

                // Parse "host:port" or just "host" (default port 11625)
                let parts: Vec<&str> = addr_str.split(':').collect();
                let peer_addr = match parts.len() {
                    1 => Some(PeerAddress::new(parts[0], 11625)),
                    2 => parts[1].parse().ok().map(|port| PeerAddress::new(parts[0], port)),
                    _ => None,
                };

                if let Some(addr) = peer_addr {
                    if let Err(e) = overlay.connect(&addr).await {
                        tracing::debug!(addr = %addr_str, error = %e, "Failed to reconnect to peer");
                    } else {
                        reconnected = true;
                    }
                }
            }

            // Drop the lock explicitly before requesting SCP state
            // (which needs to acquire the lock again)
            let _ = overlay;
            drop(overlay_guard);

            if reconnected {
                // Give peers time to complete handshake
                tokio::time::sleep(Duration::from_millis(200)).await;
                self.request_scp_state_from_peers().await;
            }
        }
    }

    /// Request SCP state from all connected peers.
    async fn request_scp_state_from_peers(&self) {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => return,
        };

        let peer_count = overlay.peer_count();
        if peer_count == 0 {
            tracing::debug!("No peers connected, cannot request SCP state");
            return;
        }

        // Request SCP state from our current ledger
        let ledger_seq = self.ledger_manager.current_ledger_seq();
        match overlay.request_scp_state(ledger_seq).await {
            Ok(count) => {
                tracing::info!(
                    ledger_seq,
                    peers_sent = count,
                    "Requested SCP state from peers"
                );
            }
            Err(e) => {
                tracing::warn!(
                    ledger_seq,
                    error = %e,
                    "Failed to request SCP state from peers"
                );
            }
        }
    }

    /// Send SCP state to a peer in response to GetScpState.
    async fn send_scp_state(&self, peer_id: &stellar_core_overlay::PeerId, from_ledger: u32) {
        let from_slot = from_ledger as u64;
        let (envelopes, quorum_set) = self.herder.get_scp_state(from_slot);

        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => return,
        };

        // Send our quorum set first if we have one configured
        if let Some(qs) = quorum_set {
            let msg = StellarMessage::ScpQuorumset(qs);
            if let Err(e) = overlay.send_to(peer_id, msg).await {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to send quorum set");
            }
        }

        // Send SCP envelopes for recent slots
        for envelope in envelopes {
            let msg = StellarMessage::ScpMessage(envelope);
            if let Err(e) = overlay.send_to(peer_id, msg).await {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to send SCP envelope");
                break; // Stop if we can't send
            }
        }

        tracing::debug!(peer = ?peer_id, from_ledger, "Sent SCP state response");
    }

    /// Process a peer list received from the network.
    async fn process_peer_list(&self, peer_list: stellar_xdr::curr::VecM<stellar_xdr::curr::PeerAddress, 100>) {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => return,
        };

        // Convert XDR peer addresses to our PeerAddress format
        let addrs: Vec<PeerAddress> = peer_list
            .iter()
            .filter_map(|xdr_addr| {
                // Extract IP address from the XDR type
                let ip = match &xdr_addr.ip {
                    stellar_xdr::curr::PeerAddressIp::IPv4(bytes) => {
                        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
                    }
                    stellar_xdr::curr::PeerAddressIp::IPv6(bytes) => {
                        // Format IPv6 address
                        let parts: Vec<u16> = bytes.chunks(2)
                            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                            .collect();
                        format!(
                            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                            parts[0], parts[1], parts[2], parts[3],
                            parts[4], parts[5], parts[6], parts[7]
                        )
                    }
                };

                let port = xdr_addr.port;

                // Skip obviously invalid addresses
                if port == 0 {
                    return None;
                }

                Some(PeerAddress::new(ip, port as u16))
            })
            .collect();

        if !addrs.is_empty() {
            let count = overlay.add_peers(addrs).await;
            if count > 0 {
                tracing::info!(added = count, "Added peers from discovery");
            }
        }
    }

    /// Handle a TxSet message from the network.
    async fn handle_tx_set(&self, tx_set: stellar_xdr::curr::TransactionSet) {
        use stellar_core_herder::TransactionSet;
        use stellar_xdr::curr::WriteXdr;

        // For legacy TransactionSet, hash is SHA-256 of XDR-encoded set
        let xdr_bytes = match tx_set.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(error = %e, "Failed to encode TxSet to XDR");
                return;
            }
        };
        let hash = stellar_core_common::Hash256::hash(&xdr_bytes);

        // Convert transactions
        let transactions: Vec<_> = tx_set.txs.to_vec();

        // Create our internal TransactionSet with correct hash
        let internal_tx_set = TransactionSet::with_hash(hash, transactions);

        tracing::info!(
            hash = %internal_tx_set.hash,
            tx_count = internal_tx_set.transactions.len(),
            "Processing TxSet"
        );

        // Give it to the herder
        if let Some(slot) = self.herder.receive_tx_set(internal_tx_set) {
            tracing::info!(slot, "Received pending TxSet, attempting ledger close");
            // Retry ledger close now that we have the tx set
            self.process_externalized_slots().await;
        }
    }

    /// Handle a GeneralizedTxSet message from the network.
    async fn handle_generalized_tx_set(&self, gen_tx_set: stellar_xdr::curr::GeneralizedTransactionSet) {
        use stellar_xdr::curr::{GeneralizedTransactionSet, TransactionPhase, TxSetComponent, WriteXdr};
        use stellar_core_herder::TransactionSet;

        // Compute hash as SHA-256 of XDR-encoded GeneralizedTransactionSet
        // This matches how stellar-core computes it: xdrSha256(xdrTxSet)
        let xdr_bytes = match gen_tx_set.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(error = %e, "Failed to encode GeneralizedTxSet to XDR");
                return;
            }
        };
        let hash = stellar_core_common::Hash256::hash(&xdr_bytes);

        // Extract transactions from GeneralizedTransactionSet
        let transactions: Vec<stellar_xdr::curr::TransactionEnvelope> = match &gen_tx_set {
            GeneralizedTransactionSet::V1(v1) => {
                v1.phases
                    .iter()
                    .flat_map(|phase| {
                        match phase {
                            TransactionPhase::V0(components) => {
                                components.iter().flat_map(|component| {
                                    match component {
                                        TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) => {
                                            comp.txs.to_vec()
                                        }
                                    }
                                }).collect::<Vec<_>>()
                            }
                            TransactionPhase::V1(parallel) => {
                                // V1 phases have parallel execution stages
                                parallel.execution_stages
                                    .iter()
                                    .flat_map(|stage| {
                                        stage.0.iter().flat_map(|cluster| cluster.0.to_vec())
                                    })
                                    .collect()
                            }
                        }
                    })
                    .collect()
            }
        };

        tracing::info!(
            hash = %hash,
            tx_count = transactions.len(),
            "Processing GeneralizedTxSet"
        );

        // Create internal tx set with the correct hash
        let internal_tx_set = TransactionSet::with_hash(hash, transactions);

        // Give it to the herder
        if let Some(slot) = self.herder.receive_tx_set(internal_tx_set) {
            tracing::info!(slot, "Received pending GeneralizedTxSet, attempting ledger close");
            // Close this specific slot directly - don't use process_externalized_slots
            // which might fast-forward past this slot
            self.try_close_slot_directly(slot).await;
        }
    }

    /// Send a TxSet to a peer in response to GetTxSet.
    async fn send_tx_set(&self, peer_id: &stellar_core_overlay::PeerId, hash: &[u8; 32]) {
        let hash256 = stellar_core_common::Hash256::from_bytes(*hash);

        // Get the tx set from cache
        let tx_set = match self.herder.get_tx_set(&hash256) {
            Some(ts) => ts,
            None => {
                tracing::debug!(hash = hex::encode(hash), peer = ?peer_id, "TxSet not found in cache");
                return;
            }
        };

        // Convert to XDR TransactionSet
        // For now we use the legacy TransactionSet format
        // In the future, we should use GeneralizedTransactionSet for Protocol 20+
        let prev_hash = self.ledger_manager.current_header_hash();
        let xdr_tx_set = stellar_xdr::curr::TransactionSet {
            previous_ledger_hash: Hash::from(prev_hash),
            txs: tx_set.transactions.try_into().unwrap_or_default(),
        };

        let message = StellarMessage::TxSet(xdr_tx_set);

        let overlay = self.overlay.lock().await;
        if let Some(ref overlay) = *overlay {
            if let Err(e) = overlay.send_to(peer_id, message).await {
                tracing::warn!(hash = hex::encode(hash), peer = ?peer_id, error = %e, "Failed to send TxSet");
            } else {
                tracing::debug!(hash = hex::encode(hash), peer = ?peer_id, "Sent TxSet");
            }
        }
    }

    /// Request pending transaction sets from peers.
    async fn request_pending_tx_sets(&self) {
        let pending_hashes = self.herder.get_pending_tx_set_hashes();
        if pending_hashes.is_empty() {
            return;
        }

        tracing::info!(
            count = pending_hashes.len(),
            "Requesting pending tx sets"
        );

        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => {
                tracing::warn!("No overlay available to request tx sets");
                return;
            }
        };

        let peer_count = overlay.peer_count();
        if peer_count == 0 {
            tracing::warn!("No peers connected, cannot request tx sets");
            return;
        }

        for hash in &pending_hashes {
            tracing::info!(hash = %hash, "Requesting tx set from peers");
            if let Err(e) = overlay.request_tx_set(&hash.0).await {
                tracing::warn!(hash = %hash, error = %e, "Failed to request TxSet");
            }
        }
    }

    /// Log current stats.
    async fn log_stats(&self) {
        let stats = self.herder.stats();
        let ledger = *self.current_ledger.read().await;

        // Get overlay stats if available
        let (peer_count, flood_stats) = {
            let overlay = self.overlay.lock().await;
            match overlay.as_ref() {
                Some(o) => (o.peer_count(), Some(o.flood_stats())),
                None => (0, None),
            }
        };

        tracing::info!(
            state = ?stats.state,
            tracking_slot = stats.tracking_slot,
            pending_txs = stats.pending_transactions,
            ledger,
            peers = peer_count,
            is_validator = self.is_validator,
            "Node status"
        );

        if let Some(fs) = flood_stats {
            tracing::debug!(
                seen_messages = fs.seen_count,
                dropped_messages = fs.dropped_messages,
                "Flood gate stats"
            );
        }
    }

    /// Get the current ledger sequence from the database.
    async fn get_current_ledger(&self) -> anyhow::Result<u32> {
        // Check if ledger manager is initialized
        if self.ledger_manager.is_initialized() {
            return Ok(self.ledger_manager.current_ledger_seq());
        }
        // No state yet
        Ok(0)
    }

    /// Signal the application to shut down.
    pub fn shutdown(&self) {
        tracing::info!("Shutdown requested");
        let _ = self.shutdown_tx.send(());
    }

    /// Internal shutdown cleanup.
    async fn shutdown_internal(&self) -> anyhow::Result<()> {
        tracing::info!("Performing shutdown cleanup");

        // In a full implementation:
        // 1. Stop accepting new connections
        // 2. Drain pending work
        // 3. Close peer connections gracefully
        // 4. Flush database

        Ok(())
    }

    /// Get application info.
    pub fn info(&self) -> AppInfo {
        AppInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            node_name: self.config.node.name.clone(),
            public_key: self.keypair.public_key().to_strkey(),
            network_passphrase: self.config.network.passphrase.clone(),
            is_validator: self.config.node.is_validator,
            database_path: self.config.database.path.clone(),
        }
    }
}

/// Target for catchup operation.
#[derive(Debug, Clone, Copy)]
pub enum CatchupTarget {
    /// Catch up to the current/latest ledger.
    Current,
    /// Catch up to a specific ledger sequence.
    Ledger(u32),
    /// Catch up to a specific checkpoint number.
    Checkpoint(u32),
}

/// Result of a catchup operation.
#[derive(Debug, Clone)]
pub struct CatchupResult {
    /// Final ledger sequence.
    pub ledger_seq: u32,
    /// Hash of the final ledger.
    pub ledger_hash: stellar_core_common::Hash256,
    /// Number of buckets applied.
    pub buckets_applied: u32,
    /// Number of ledgers replayed.
    pub ledgers_replayed: u32,
}

impl std::fmt::Display for CatchupResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Caught up to ledger {} (hash: {}, {} buckets, {} ledgers replayed)",
            self.ledger_seq,
            &self.ledger_hash.to_hex()[..16],
            self.buckets_applied,
            self.ledgers_replayed
        )
    }
}

/// Application info for the info command.
#[derive(Debug, Clone)]
pub struct AppInfo {
    /// Application version.
    pub version: String,
    /// Node name.
    pub node_name: String,
    /// Node public key.
    pub public_key: String,
    /// Network passphrase.
    pub network_passphrase: String,
    /// Whether this node is a validator.
    pub is_validator: bool,
    /// Database path.
    pub database_path: std::path::PathBuf,
}

impl std::fmt::Display for AppInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "rs-stellar-core {}", self.version)?;
        writeln!(f)?;
        writeln!(f, "Node Information:")?;
        writeln!(f, "  Name:       {}", self.node_name)?;
        writeln!(f, "  Public Key: {}", self.public_key)?;
        writeln!(f, "  Validator:  {}", self.is_validator)?;
        writeln!(f)?;
        writeln!(f, "Network:")?;
        writeln!(f, "  Passphrase: {}", self.network_passphrase)?;
        writeln!(f)?;
        writeln!(f, "Storage:")?;
        writeln!(f, "  Database:   {}", self.database_path.display())?;
        Ok(())
    }
}

/// Application builder for more flexible initialization.
pub struct AppBuilder {
    config: Option<AppConfig>,
    config_path: Option<std::path::PathBuf>,
}

impl AppBuilder {
    /// Create a new application builder.
    pub fn new() -> Self {
        Self {
            config: None,
            config_path: None,
        }
    }

    /// Use the given configuration.
    pub fn with_config(mut self, config: AppConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Load configuration from a file.
    pub fn with_config_file(mut self, path: impl AsRef<Path>) -> Self {
        self.config_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Build the application.
    pub async fn build(self) -> anyhow::Result<App> {
        let config = if let Some(config) = self.config {
            config
        } else if let Some(path) = self.config_path {
            AppConfig::from_file_with_env(&path)?
        } else {
            AppConfig::default()
        };

        App::new(config).await
    }
}

impl Default for AppBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of HerderCallback for App.
///
/// This enables the herder to trigger ledger closes through the app.
#[async_trait::async_trait]
impl HerderCallback for App {
    async fn close_ledger(
        &self,
        ledger_seq: u32,
        tx_set: Vec<stellar_xdr::curr::TransactionEnvelope>,
        close_time: u64,
    ) -> stellar_core_herder::Result<stellar_core_common::Hash256> {
        tracing::info!(
            ledger_seq,
            tx_count = tx_set.len(),
            close_time,
            "Closing ledger"
        );

        // Get the previous ledger hash
        let prev_hash = self.ledger_manager.current_header_hash();

        // Create the transaction set
        let tx_set_variant = TransactionSetVariant::Classic(TransactionSet {
            previous_ledger_hash: Hash::from(prev_hash),
            txs: tx_set.try_into().map_err(|_| {
                stellar_core_herder::HerderError::Internal("Failed to create tx set".into())
            })?,
        });

        // Create close data
        let close_data = LedgerCloseData::new(
            ledger_seq,
            tx_set_variant,
            close_time,
            prev_hash,
        );

        // Begin the ledger close
        let mut close_ctx = self.ledger_manager.begin_close(close_data).map_err(|e| {
            stellar_core_herder::HerderError::Internal(format!("Failed to begin close: {}", e))
        })?;

        // Apply transactions
        let results = close_ctx.apply_transactions().map_err(|e| {
            stellar_core_herder::HerderError::Internal(format!("Failed to apply transactions: {}", e))
        })?;

        let success_count = results.iter().filter(|r| r.success).count();
        let fail_count = results.len() - success_count;
        tracing::info!(
            ledger_seq,
            tx_success = success_count,
            tx_failed = fail_count,
            "Transactions applied"
        );

        // Commit the ledger
        let result = close_ctx.commit().map_err(|e| {
            stellar_core_herder::HerderError::Internal(format!("Failed to commit ledger: {}", e))
        })?;

        // Update current ledger tracking
        *self.current_ledger.write().await = ledger_seq;

        tracing::info!(
            ledger_seq = result.ledger_seq(),
            hash = %result.header_hash.to_hex(),
            "Ledger closed successfully"
        );

        Ok(result.header_hash)
    }

    async fn validate_tx_set(&self, _tx_set_hash: &stellar_core_common::Hash256) -> bool {
        // For now, accept all transaction sets
        // In a full implementation, this would:
        // 1. Check we have the tx set locally
        // 2. Validate all transactions are valid
        // 3. Check the tx set hash matches
        true
    }

    async fn broadcast_scp_message(&self, envelope: ScpEnvelope) {
        let slot = envelope.statement.slot_index;
        // Send through the channel to be picked up by the main loop
        if let Err(e) = self.scp_envelope_tx.try_send(envelope) {
            tracing::warn!(slot, error = %e, "Failed to queue SCP envelope for broadcast");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_app_creation() {
        let config = crate::config::ConfigBuilder::new()
            .database_path("/tmp/rs-stellar-test.db")
            .build();

        let app = App::new(config).await.unwrap();
        assert_eq!(app.state().await, AppState::Initializing);
    }

    #[tokio::test]
    async fn test_app_info() {
        let config = crate::config::ConfigBuilder::new()
            .node_name("test-node")
            .database_path("/tmp/rs-stellar-test.db")
            .build();

        let app = App::new(config).await.unwrap();
        let info = app.info();

        assert_eq!(info.node_name, "test-node");
        assert!(!info.public_key.is_empty());
        assert!(info.public_key.starts_with('G'));
    }

    #[test]
    fn test_catchup_result_display() {
        let result = CatchupResult {
            ledger_seq: 1000,
            ledger_hash: stellar_core_common::Hash256::ZERO,
            buckets_applied: 22,
            ledgers_replayed: 64,
        };

        let display = format!("{}", result);
        assert!(display.contains("1000"));
        assert!(display.contains("22 buckets"));
    }
}
