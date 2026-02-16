//! Run command implementation for rs-stellar-core.
//!
//! The run command starts the node and keeps it synchronized with the network.
//! This is the primary operational mode for a Stellar Core node.
//!
//! # Responsibilities
//!
//! The run command handles:
//! - **Catchup**: Automatically catching up from history if the node is behind
//! - **Peer Management**: Connecting to peers and handling disconnections
//! - **Consensus**: Tracking SCP consensus (or participating for validators)
//! - **Ledger Close**: Applying externalized ledgers to update state
//! - **HTTP API**: Serving status and control endpoints
//!
//! # Command Line Usage
//!
//! ```text
//! rs-stellar-core run                    # Run as a full node
//! rs-stellar-core run --validator        # Run as a validator
//! rs-stellar-core run --watcher          # Run as a watcher (no catchup)
//! ```
//!
//! # Running Modes
//!
//! | Mode | Description | Consensus Role |
//! |------|-------------|----------------|
//! | `Full` | Standard node with catchup | Tracks consensus |
//! | `Validator` | Active consensus participant | Votes in SCP |
//! | `Watcher` | Observe-only, no catchup | Passive observer |
//!
//! # HTTP Status Server
//!
//! When enabled, the [`StatusServer`] provides REST endpoints for monitoring
//! and control. Key endpoints include:
//!
//! - `GET /info` - Node information and version
//! - `GET /metrics` - Prometheus-format metrics
//! - `GET /peers` - Connected peer list
//! - `GET /ledger` - Current ledger state
//! - `POST /tx` - Submit transactions
//! - `POST /shutdown` - Graceful shutdown

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::Query;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use henyey_common::NetworkId;
use henyey_crypto::{self, PublicKey as CryptoPublicKey};
use henyey_overlay::{PeerAddress, PeerId};
use henyey_scp::hash_quorum_set;
use henyey_tx::TransactionFrame;
use stellar_xdr::curr::LedgerUpgrade;
use tokio::signal;
use tokio::sync::broadcast;

use crate::app::{App, AppState, CatchupTarget, SurveyReport};
use crate::config::AppConfig;

/// Node running mode determining behavior and consensus participation.
///
/// The mode affects whether the node catches up from history, participates
/// in consensus, and how aggressively it maintains synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunMode {
    /// Full node: catches up from history and tracks consensus.
    ///
    /// This is the default mode suitable for most use cases. The node
    /// maintains full ledger state and can serve queries.
    #[default]
    Full,
    /// Validator: actively participates in SCP consensus.
    ///
    /// Requires a valid `node_seed` and properly configured quorum set.
    /// The node will vote on ledger values and sign SCP messages.
    Validator,
    /// Watcher: observe-only mode without catchup.
    ///
    /// Useful for monitoring the network without maintaining full state.
    /// The node connects to peers but does not sync from history.
    Watcher,
}

impl std::fmt::Display for RunMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunMode::Full => write!(f, "full"),
            RunMode::Validator => write!(f, "validator"),
            RunMode::Watcher => write!(f, "watcher"),
        }
    }
}

/// Configuration options for the run command.
///
/// Controls the running mode, synchronization behavior, and catchup policy.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Running mode (full, validator, or watcher).
    pub mode: RunMode,
    /// Force catchup even if local state exists.
    pub force_catchup: bool,
    /// Block until the node is fully synced before returning from run.
    pub wait_for_sync: bool,
    /// Maximum ledger age (in ledgers) before triggering automatic catchup.
    ///
    /// If the local ledger is more than this many ledgers behind, catchup
    /// will be triggered. Default is 300 (~25 minutes at 5s close time).
    pub max_ledger_age: u32,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            mode: RunMode::Full,
            force_catchup: false,
            wait_for_sync: true,
            max_ledger_age: 300, // ~25 minutes of ledgers
        }
    }
}

impl RunOptions {
    /// Create options for running as a validator.
    pub fn validator() -> Self {
        Self {
            mode: RunMode::Validator,
            ..Default::default()
        }
    }

    /// Create options for running as a watcher.
    pub fn watcher() -> Self {
        Self {
            mode: RunMode::Watcher,
            force_catchup: false,
            wait_for_sync: false,
            ..Default::default()
        }
    }

    /// Set whether to force catchup.
    pub fn with_force_catchup(mut self, force: bool) -> Self {
        self.force_catchup = force;
        self
    }
}

/// Run the node with the given configuration and options.
pub async fn run_node(config: AppConfig, options: RunOptions) -> anyhow::Result<()> {
    tracing::info!(
        mode = %options.mode,
        node_name = %config.node.name,
        network = %config.network.passphrase,
        "Starting henyey node"
    );

    // Validate mode-specific requirements
    validate_run_options(&config, &options)?;

    // Store HTTP config before moving config
    let http_enabled = config.http.enabled;
    let http_port = config.http.port;

    // Create the application
    let app = Arc::new(App::new(config).await?);

    // Set the weak self reference for spawning tasks from &self methods
    app.set_self_arc().await;

    // Set up shutdown handling
    let shutdown_app = app.clone();
    let shutdown_handle = tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        tracing::info!("Shutdown signal received");
        shutdown_app.shutdown();
    });

    // Start the HTTP status server if enabled
    let http_handle = if http_enabled {
        let status_server = StatusServer::new(http_port, app.clone());
        Some(tokio::spawn(async move {
            if let Err(e) = status_server.start().await {
                tracing::error!(error = %e, "HTTP status server error");
            }
        }))
    } else {
        None
    };

    // Print startup info
    print_startup_info(&app, &options);

    // Run the main loop
    let result = run_main_loop(app.clone(), options).await;

    // Clean up
    shutdown_handle.abort();
    if let Some(handle) = http_handle {
        handle.abort();
    }

    match result {
        Ok(()) => {
            tracing::info!("Node stopped gracefully");
            Ok(())
        }
        Err(e) => {
            tracing::error!(error = %e, "Node stopped with error");
            Err(e)
        }
    }
}

/// Validate that the options are compatible with the configuration.
fn validate_run_options(config: &AppConfig, options: &RunOptions) -> anyhow::Result<()> {
    if options.mode == RunMode::Validator {
        if !config.node.is_validator {
            anyhow::bail!("Cannot run in validator mode: node is not configured as a validator");
        }
        if config.node.node_seed.is_none() {
            anyhow::bail!("Validators must have a node_seed configured");
        }
    }

    Ok(())
}

/// Print information about the node at startup.
fn print_startup_info(app: &App, options: &RunOptions) {
    let info = app.info();
    println!("henyey {}", info.version);
    println!();
    println!("Node: {}", info.node_name);
    println!("Mode: {}", options.mode);
    println!("Public Key: {}", info.public_key);
    println!("Network: {}", info.network_passphrase);
    println!();
}

/// Run the main application loop.
async fn run_main_loop(app: Arc<App>, options: RunOptions) -> anyhow::Result<()> {
    // Attempt to restore node state from persisted DB + on-disk bucket files.
    // This avoids a full catchup when the node restarts with intact state.
    if !options.force_catchup {
        match app.load_last_known_ledger().await {
            Ok(true) => {
                let (seq, _hash, _close_time, _protocol) = app.ledger_info();
                tracing::info!(lcl_seq = seq, "Restored state from disk, skipping full catchup");
                app.set_state(AppState::Synced).await;
                app.set_current_ledger(seq).await;
            }
            Ok(false) => {
                tracing::debug!("No persisted state available, will check catchup");
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to restore from disk, will check catchup");
            }
        }
    }

    // Check if we need to catch up
    let needs_catchup = check_needs_catchup(&app, &options).await?;

    if needs_catchup {
        if options.mode == RunMode::Watcher {
            tracing::info!("Watcher mode: skipping catchup");
        } else {
            tracing::info!("Node is behind, starting catchup");

            // Start overlay network BEFORE catchup to receive tx_sets during catchup.
            // This helps bridge the gap between catchup checkpoint and live consensus.
            app.start_overlay().await?;

            // Start a background task to cache messages during catchup.
            let catchup_message_handle = app.start_catchup_message_caching().await;

            // Start a background task to request SCP state after peers connect.
            // This triggers peers to send us EXTERNALIZE messages which contain tx_set_hashes.
            let scp_request_handle = {
                let app_clone = Arc::clone(&app);
                tokio::spawn(async move {
                    // Wait for peers to complete handshake
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    tracing::info!("Requesting SCP state during catchup");
                    app_clone.request_scp_state_from_peers().await;
                })
            };

            // Run catchup using mode from config
            let catchup_mode = app.config().catchup.to_mode();
            tracing::info!(?catchup_mode, "Starting catchup with configured mode");
            app.catchup_with_mode(CatchupTarget::Current, catchup_mode).await?;

            // Wait for SCP state request to complete
            let _ = scp_request_handle.await;

            // Stop the catchup message caching task
            if let Some(handle) = catchup_message_handle {
                handle.abort();
                tracing::info!("Stopped catchup message caching task");
            }
        }
    }

    // Start the sync recovery manager for consensus stuck detection
    app.start_sync_recovery();

    // Start the main run loop in the background so we can optionally wait for sync.
    tracing::info!("Starting main run loop");
    let run_app = Arc::clone(&app);
    let run_handle = tokio::spawn(async move { run_app.run().await });
    if options.wait_for_sync {
        wait_for_sync(&app).await;
    }
    match run_handle.await {
        Ok(result) => result?,
        Err(err) => anyhow::bail!("run loop task failed: {}", err),
    }

    Ok(())
}

/// Check if the node needs to catch up.
async fn check_needs_catchup(app: &App, options: &RunOptions) -> anyhow::Result<bool> {
    if options.force_catchup {
        return Ok(true);
    }

    let current_state = app.state().await;
    if current_state == AppState::Initializing {
        return Ok(true);
    }

    let (_seq, _hash, close_time, _protocol_version) = app.ledger_info();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let target_close_time = app.target_ledger_close_time() as u64;
    let max_age_seconds = target_close_time.saturating_mul(options.max_ledger_age as u64);
    Ok(is_ledger_too_old(close_time, now, max_age_seconds))
}

fn is_ledger_too_old(close_time: u64, now: u64, max_age_seconds: u64) -> bool {
    if close_time == 0 {
        return true;
    }
    if max_age_seconds == 0 {
        return false;
    }
    now.saturating_sub(close_time) > max_age_seconds
}

async fn wait_for_sync(app: &App) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        let state = app.state().await;
        if matches!(state, AppState::Synced | AppState::Validating) {
            tracing::info!(state = %state, "Node is synced");
            break;
        }
        if state == AppState::ShuttingDown {
            tracing::warn!("Shutdown requested before sync completed");
            break;
        }
    }
}

/// Wait for a shutdown signal (Ctrl+C or SIGTERM).
async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM");
        }
    }
}

/// Current node status and metrics.
///
/// Provides a snapshot of the node's operational state, useful for
/// monitoring and health checks. Available via the `/status` HTTP endpoint.
#[derive(Debug, Clone, Default, Serialize)]
pub struct NodeStatus {
    /// Current ledger sequence number.
    pub ledger_seq: u32,
    /// Hash of the current ledger header (hex-encoded).
    pub ledger_hash: Option<String>,
    /// Number of currently connected peers.
    pub peer_count: usize,
    /// Current SCP consensus state (e.g., "tracking", "synced").
    pub consensus_state: String,
    /// Number of transactions in the pending queue.
    pub pending_tx_count: usize,
    /// Node uptime in seconds since startup.
    pub uptime_secs: u64,
    /// Current application state (see [`AppState`]).
    pub state: String,
}

impl std::fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Node Status:")?;
        writeln!(f, "  State: {}", self.state)?;
        writeln!(f, "  Ledger: {}", self.ledger_seq)?;
        if let Some(hash) = &self.ledger_hash {
            writeln!(f, "  Ledger Hash: {}", hash)?;
        }
        writeln!(f, "  Peers: {}", self.peer_count)?;
        writeln!(f, "  Consensus: {}", self.consensus_state)?;
        writeln!(f, "  Pending TXs: {}", self.pending_tx_count)?;
        writeln!(f, "  Uptime: {}s", self.uptime_secs)?;
        Ok(())
    }
}

/// High-level node runner that manages the complete run lifecycle.
///
/// Wraps an [`App`] instance and provides a simpler interface for running
/// the node. Handles startup, shutdown coordination, and status queries.
///
/// # Example
///
/// ```no_run
/// use henyey_app::{AppConfig, RunOptions};
/// use henyey_app::run_cmd::NodeRunner;
///
/// # async fn example() -> anyhow::Result<()> {
/// let config = AppConfig::testnet();
/// let runner = NodeRunner::new(config, RunOptions::default()).await?;
/// runner.run().await?;
/// # Ok(())
/// # }
/// ```
pub struct NodeRunner {
    app: Arc<App>,
    options: RunOptions,
    start_time: std::time::Instant,
    shutdown_tx: broadcast::Sender<()>,
}

impl NodeRunner {
    /// Create a new node runner.
    pub async fn new(config: AppConfig, options: RunOptions) -> anyhow::Result<Self> {
        let app = Arc::new(App::new(config).await?);
        app.set_self_arc().await;
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            app,
            options,
            start_time: std::time::Instant::now(),
            shutdown_tx,
        })
    }

    /// Get the application instance.
    pub fn app(&self) -> &Arc<App> {
        &self.app
    }

    /// Get the current node status.
    pub async fn status(&self) -> NodeStatus {
        let (ledger_seq, ledger_hash, _close_time, _protocol_version) = self.app.ledger_info();
        let stats = self.app.herder_stats();
        let peer_count = self.app.peer_snapshots().await.len();
        NodeStatus {
            ledger_seq,
            ledger_hash: Some(ledger_hash.to_hex()),
            peer_count,
            consensus_state: stats.state.to_string(),
            pending_tx_count: stats.pending_transactions,
            uptime_secs: self.start_time.elapsed().as_secs(),
            state: format!("{}", self.app.state().await),
        }
    }

    /// Run the node.
    pub async fn run(&self) -> anyhow::Result<()> {
        run_main_loop(self.app.clone(), self.options.clone()).await
    }

    /// Request shutdown.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
        self.app.shutdown();
    }

    /// Subscribe to shutdown notifications.
    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }
}

/// Shared state for the HTTP server.
struct ServerState {
    app: Arc<App>,
    start_time: Instant,
    log_handle: Option<crate::logging::LogLevelHandle>,
}

/// HTTP server for node status and control.
///
/// Provides endpoints for monitoring and interacting with the node:
/// - GET /info - node information
/// - GET /metrics - prometheus-style metrics
/// - GET /peers - connected peers
/// - POST /connect - connect to peer (query param `addr`)
/// - POST /droppeer - disconnect peer (query param `peer_id`)
/// - GET /bans - list banned peers
/// - POST /unban - remove peer from ban list (query param `peer_id`)
/// - GET /ledger - current ledger info
/// - GET /upgrades - current/proposed upgrades
/// - POST /self-check - run self-check validation
/// - GET /survey - survey report (local + peer responses)
/// - GET /scp - SCP status summary (query param `limit`)
/// - POST /survey/start - start survey collecting (query param `nonce`)
/// - POST /survey/stop - stop survey collecting
/// - POST /survey/topology - queue a topology request (query param `node`)
/// - POST /survey/reporting/stop - stop survey reporting
/// - POST /tx - submit transactions
/// - POST /shutdown - request a graceful shutdown
/// - GET/POST /ll - get or set log levels dynamically
pub struct StatusServer {
    port: u16,
    app: Arc<App>,
    start_time: Instant,
    log_handle: Option<crate::logging::LogLevelHandle>,
}

impl StatusServer {
    /// Create a new status server.
    pub fn new(port: u16, app: Arc<App>) -> Self {
        Self {
            port,
            app,
            start_time: Instant::now(),
            log_handle: None,
        }
    }

    /// Create a new status server with a log level handle for dynamic log changes.
    pub fn with_log_handle(
        port: u16,
        app: Arc<App>,
        log_handle: crate::logging::LogLevelHandle,
    ) -> Self {
        Self {
            port,
            app,
            start_time: Instant::now(),
            log_handle: Some(log_handle),
        }
    }

    /// Start the server.
    pub async fn start(self) -> anyhow::Result<()> {
        let state = Arc::new(ServerState {
            app: self.app,
            start_time: self.start_time,
            log_handle: self.log_handle,
        });

        let mut shutdown_rx = state.app.subscribe_shutdown();

        let app = Router::new()
            .route("/", get(root_handler))
            .route("/info", get(info_handler))
            .route("/status", get(status_handler))
            .route("/metrics", get(metrics_handler))
            .route("/peers", get(peers_handler))
            .route("/connect", post(connect_handler))
            .route("/droppeer", post(droppeer_handler))
            .route("/bans", get(bans_handler))
            .route("/unban", post(unban_handler))
            .route("/ledger", get(ledger_handler))
            .route("/upgrades", get(upgrades_handler))
            .route("/self-check", post(self_check_handler))
            .route("/quorum", get(quorum_handler))
            .route("/survey", get(survey_handler))
            .route("/scp", get(scp_handler))
            .route("/survey/start", post(start_survey_collecting_handler))
            .route("/survey/stop", post(stop_survey_collecting_handler))
            .route("/survey/topology", post(survey_topology_handler))
            .route(
                "/survey/reporting/stop",
                post(stop_survey_reporting_handler),
            )
            .route("/tx", post(submit_tx_handler))
            .route("/shutdown", post(shutdown_handler))
            .route("/health", get(health_handler))
            .route("/ll", get(ll_handler).post(ll_handler))
            .route("/manualclose", post(manualclose_handler))
            .route("/sorobaninfo", get(sorobaninfo_handler))
            .route("/clearmetrics", post(clearmetrics_handler))
            .route("/logrotate", post(logrotate_handler))
            .route("/maintenance", post(maintenance_handler))
            .route("/dumpproposedsettings", get(dumpproposedsettings_handler))
            .with_state(state);

        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        tracing::info!(port = self.port, "Starting HTTP status server");

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.recv().await;
            })
            .await?;

        Ok(())
    }
}

// ============================================================================
// HTTP Handler Response Types
// ============================================================================

/// Response for the root endpoint.
#[derive(Serialize)]
struct RootResponse {
    name: String,
    version: String,
    endpoints: Vec<String>,
}

/// Response for the /info endpoint.
#[derive(Serialize)]
struct InfoResponse {
    version: String,
    node_name: String,
    public_key: String,
    network_passphrase: String,
    is_validator: bool,
    state: String,
    uptime_secs: u64,
}

/// Response for the /metrics endpoint (Prometheus format).
#[derive(Serialize)]
struct MetricsResponse {
    ledger_seq: u32,
    peer_count: usize,
    pending_transactions: u64,
    uptime_seconds: u64,
    state: String,
    is_validator: bool,
}

/// Response for the /peers endpoint.
#[derive(Serialize)]
struct PeersResponse {
    count: usize,
    peers: Vec<PeerInfo>,
}

/// Information about a connected peer.
#[derive(Serialize)]
struct PeerInfo {
    id: String,
    address: String,
    direction: String,
}

/// Response for the /ledger endpoint.
#[derive(Serialize)]
struct LedgerResponse {
    sequence: u32,
    hash: String,
    close_time: u64,
    protocol_version: u32,
}

/// Response for the /upgrades endpoint.
#[derive(Serialize)]
struct UpgradesResponse {
    current: UpgradeState,
    proposed: Vec<UpgradeItem>,
}

#[derive(Serialize)]
struct UpgradeState {
    protocol_version: u32,
    base_fee: u32,
    base_reserve: u32,
    max_tx_set_size: u32,
}

#[derive(Serialize)]
struct UpgradeItem {
    r#type: String,
    value: u32,
}

/// Response for the /quorum endpoint.
#[derive(Serialize)]
struct QuorumResponse {
    local: Option<QuorumSetResponse>,
}

/// Response for the /scp endpoint.
#[derive(Serialize)]
struct ScpInfoResponse {
    node: String,
    slots: Vec<ScpSlotInfo>,
}

/// Summary of SCP slot state.
#[derive(Serialize)]
struct ScpSlotInfo {
    slot_index: u64,
    is_externalized: bool,
    is_nominating: bool,
    ballot_phase: String,
    nomination_round: u32,
    ballot_round: Option<u32>,
    envelope_count: usize,
}

/// JSON representation of a quorum set.
#[derive(Serialize)]
struct QuorumSetResponse {
    hash: String,
    threshold: u32,
    validators: Vec<String>,
    inner_sets: Vec<QuorumSetResponse>,
}

/// Request for submitting a transaction.
#[derive(Deserialize)]
struct SubmitTxRequest {
    tx: String, // Base64-encoded XDR transaction envelope
}

/// Response for transaction submission.
#[derive(Serialize)]
struct SubmitTxResponse {
    success: bool,
    hash: Option<String>,
    error: Option<String>,
}

/// Response for the /health endpoint.
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    state: String,
    ledger_seq: u32,
    peer_count: usize,
}

/// Response for the /bans endpoint.
#[derive(Serialize)]
struct BansResponse {
    bans: Vec<String>,
}

/// Response for the /self-check endpoint.
#[derive(Serialize)]
struct SelfCheckResponse {
    ok: bool,
    checked_ledgers: u32,
    last_checked_ledger: Option<u32>,
    message: Option<String>,
}

/// Query parameters for /ll endpoint.
#[derive(Deserialize)]
struct LlParams {
    level: Option<String>,
    partition: Option<String>,
}

/// Response for the /ll endpoint.
#[derive(Serialize)]
struct LlResponse {
    levels: std::collections::HashMap<String, String>,
}

/// Query parameters for /manualclose endpoint.
#[derive(Deserialize)]
struct ManualCloseParams {
    #[serde(rename = "ledgerSeq")]
    ledger_seq: Option<u32>,
    #[serde(rename = "closeTime")]
    close_time: Option<u64>,
}

/// Response for the /manualclose endpoint.
#[derive(Serialize)]
struct ManualCloseResponse {
    success: bool,
    ledger_seq: Option<u32>,
    message: Option<String>,
}

/// Query parameters for /sorobaninfo endpoint.
#[derive(Deserialize)]
struct SorobanInfoParams {
    format: Option<String>,
}

/// Response for the /sorobaninfo endpoint (basic format).
#[derive(Serialize)]
struct SorobanInfoResponse {
    max_contract_size: u32,
    max_contract_data_key_size: u32,
    max_contract_data_entry_size: u32,
    tx: SorobanTxLimits,
    ledger: SorobanLedgerLimits,
    fee_rate_per_instructions_increment: i64,
    fee_read_ledger_entry: i64,
    fee_write_ledger_entry: i64,
    fee_read_1kb: i64,
    fee_write_1kb: i64,
    fee_historical_1kb: i64,
    fee_contract_events_size_1kb: i64,
    fee_transaction_size_1kb: i64,
    state_archival: SorobanStateArchival,
}

/// Soroban per-transaction resource limits.
#[derive(Serialize)]
struct SorobanTxLimits {
    max_instructions: i64,
    memory_limit: u32,
    max_read_ledger_entries: u32,
    max_read_bytes: u32,
    max_write_ledger_entries: u32,
    max_write_bytes: u32,
    max_contract_events_size_bytes: u32,
    max_size_bytes: u32,
}

/// Soroban per-ledger resource limits.
#[derive(Serialize)]
struct SorobanLedgerLimits {
    max_instructions: i64,
    max_read_ledger_entries: u32,
    max_read_bytes: u32,
    max_write_ledger_entries: u32,
    max_write_bytes: u32,
    max_tx_size_bytes: u32,
    max_tx_count: u32,
}

/// Soroban state archival settings.
#[derive(Serialize)]
struct SorobanStateArchival {
    max_entry_ttl: u32,
    min_temporary_ttl: u32,
    min_persistent_ttl: u32,
    persistent_rent_rate_denominator: i64,
    temp_rent_rate_denominator: i64,
    max_entries_to_archive: u32,
    bucketlist_size_window_sample_size: u32,
    eviction_scan_size: i64,
    starting_eviction_scan_level: u32,
}

/// Query parameters for starting survey collecting.
#[derive(Deserialize)]
struct StartSurveyParams {
    nonce: u32,
}

/// Query parameters for requesting topology from a peer.
#[derive(Deserialize)]
struct SurveyTopologyParams {
    node: String,
    inbound_index: Option<u32>,
    outbound_index: Option<u32>,
}

/// Query parameters for connecting to a peer.
#[derive(Deserialize)]
struct ConnectParams {
    addr: Option<String>,
    peer: Option<String>,
    port: Option<u16>,
}

/// Query parameters for dropping a peer.
#[derive(Deserialize)]
struct DropPeerParams {
    peer_id: Option<String>,
    node: Option<String>,
    ban: Option<u8>,
}

/// Query parameters for unbanning a peer.
#[derive(Deserialize)]
struct UnbanParams {
    peer_id: Option<String>,
    node: Option<String>,
}

/// Query parameters for the /scp endpoint.
#[derive(Deserialize)]
struct ScpParams {
    limit: Option<usize>,
}

/// Response for survey command endpoints.
#[derive(Serialize)]
struct SurveyCommandResponse {
    success: bool,
    message: String,
}

/// Query parameters for /clearmetrics endpoint.
#[derive(Deserialize)]
struct ClearMetricsParams {
    domain: Option<String>,
}

/// Response for the /clearmetrics endpoint.
#[derive(Serialize)]
struct ClearMetricsResponse {
    message: String,
}

/// Query parameters for /maintenance endpoint.
#[derive(Deserialize)]
struct MaintenanceParams {
    queue: Option<String>,
    count: Option<u32>,
}

/// Response for the /maintenance endpoint.
#[derive(Serialize)]
struct MaintenanceResponse {
    message: String,
}

/// Response for the /logrotate endpoint.
#[derive(Serialize)]
struct LogRotateResponse {
    message: String,
}

/// Query parameters for /dumpproposedsettings endpoint.
#[derive(Deserialize)]
struct DumpProposedSettingsParams {
    blob: Option<String>,
}

// ============================================================================
// HTTP Handlers
// ============================================================================

async fn root_handler() -> Json<RootResponse> {
    Json(RootResponse {
        name: "henyey".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        endpoints: vec![
            "/info".to_string(),
            "/status".to_string(),
            "/metrics".to_string(),
            "/peers".to_string(),
            "/connect".to_string(),
            "/droppeer".to_string(),
            "/bans".to_string(),
            "/unban".to_string(),
            "/ledger".to_string(),
            "/upgrades".to_string(),
            "/self-check".to_string(),
            "/quorum".to_string(),
            "/survey".to_string(),
            "/scp".to_string(),
            "/survey/start".to_string(),
            "/survey/stop".to_string(),
            "/survey/topology".to_string(),
            "/survey/reporting/stop".to_string(),
            "/tx".to_string(),
            "/shutdown".to_string(),
            "/health".to_string(),
            "/ll".to_string(),
            "/manualclose".to_string(),
            "/sorobaninfo".to_string(),
            "/clearmetrics".to_string(),
            "/logrotate".to_string(),
            "/maintenance".to_string(),
            "/dumpproposedsettings".to_string(),
        ],
    })
}

async fn info_handler(State(state): State<Arc<ServerState>>) -> Json<InfoResponse> {
    let info = state.app.info();
    let app_state = state.app.state().await;
    let uptime = state.start_time.elapsed().as_secs();

    Json(InfoResponse {
        version: info.version,
        node_name: info.node_name,
        public_key: info.public_key,
        network_passphrase: info.network_passphrase,
        is_validator: info.is_validator,
        state: format!("{}", app_state),
        uptime_secs: uptime,
    })
}

async fn status_handler(State(state): State<Arc<ServerState>>) -> Json<NodeStatus> {
    let (ledger_seq, ledger_hash, _close_time, _protocol_version) = state.app.ledger_info();
    let stats = state.app.herder_stats();
    let peer_count = state.app.peer_snapshots().await.len();
    Json(NodeStatus {
        ledger_seq,
        ledger_hash: Some(ledger_hash.to_hex()),
        peer_count,
        consensus_state: stats.state.to_string(),
        pending_tx_count: stats.pending_transactions,
        uptime_secs: state.start_time.elapsed().as_secs(),
        state: format!("{}", state.app.state().await),
    })
}

async fn metrics_handler(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    let app_state = state.app.state().await;
    let uptime = state.start_time.elapsed().as_secs();
    let (ledger_seq, _hash, _close_time, _protocol_version) = state.app.ledger_info();
    let peer_count = state.app.peer_snapshots().await.len();
    let pending_transactions = state.app.pending_transaction_count() as u64;
    let app_info = state.app.info();

    // Get metrics from herder (we don't have direct access, so use available info)
    let metrics = MetricsResponse {
        ledger_seq,
        peer_count,
        pending_transactions,
        uptime_seconds: uptime,
        state: format!("{}", app_state),
        is_validator: app_info.is_validator,
    };

    // Return Prometheus-style text format
    let mut prometheus_text = format!(
        "# HELP stellar_ledger_sequence Current ledger sequence number\n\
         # TYPE stellar_ledger_sequence gauge\n\
         stellar_ledger_sequence {}\n\
         # HELP stellar_peer_count Number of connected peers\n\
         # TYPE stellar_peer_count gauge\n\
         stellar_peer_count {}\n\
         # HELP stellar_pending_transactions Number of pending transactions\n\
         # TYPE stellar_pending_transactions gauge\n\
         stellar_pending_transactions {}\n\
         # HELP stellar_uptime_seconds Node uptime in seconds\n\
         # TYPE stellar_uptime_seconds counter\n\
         stellar_uptime_seconds {}\n\
         # HELP stellar_is_validator Whether this node is a validator\n\
         # TYPE stellar_is_validator gauge\n\
         stellar_is_validator {}\n",
        metrics.ledger_seq,
        metrics.peer_count,
        metrics.pending_transactions,
        metrics.uptime_seconds,
        if metrics.is_validator { 1 } else { 0 }
    );

    // Add meta stream metrics if active
    if app_info.meta_stream_bytes_total > 0 || app_info.meta_stream_writes_total > 0 {
        prometheus_text.push_str(&format!(
            "# HELP stellar_meta_stream_bytes_total Total bytes written to metadata output stream\n\
             # TYPE stellar_meta_stream_bytes_total counter\n\
             stellar_meta_stream_bytes_total {}\n\
             # HELP stellar_meta_stream_writes_total Total frames written to metadata output stream\n\
             # TYPE stellar_meta_stream_writes_total counter\n\
             stellar_meta_stream_writes_total {}\n",
            app_info.meta_stream_bytes_total, app_info.meta_stream_writes_total
        ));
    }

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        prometheus_text,
    )
}

async fn peers_handler(State(state): State<Arc<ServerState>>) -> Json<PeersResponse> {
    let mut peers = state
        .app
        .peer_snapshots()
        .await
        .into_iter()
        .map(|snapshot| PeerInfo {
            id: snapshot.info.peer_id.to_hex(),
            address: snapshot.info.address.to_string(),
            direction: match snapshot.info.direction {
                henyey_overlay::ConnectionDirection::Inbound => "inbound",
                henyey_overlay::ConnectionDirection::Outbound => "outbound",
            }
            .to_string(),
        })
        .collect::<Vec<_>>();
    peers.sort_by(|a, b| a.id.cmp(&b.id));
    Json(PeersResponse {
        count: peers.len(),
        peers,
    })
}

async fn connect_handler(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<ConnectParams>,
) -> impl IntoResponse {
    let addr = match parse_connect_params(&params) {
        Ok(addr) => addr,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SurveyCommandResponse {
                    success: false,
                    message,
                }),
            );
        }
    };

    match state.app.connect_peer(addr).await {
        Ok(peer_id) => (
            StatusCode::OK,
            Json(SurveyCommandResponse {
                success: true,
                message: format!("Connected to peer {}", peer_id),
            }),
        ),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(SurveyCommandResponse {
                success: false,
                message: format!("Failed to connect: {}", err),
            }),
        ),
    }
}

async fn droppeer_handler(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<DropPeerParams>,
) -> impl IntoResponse {
    let peer_id = match parse_peer_id_params(&params.peer_id, &params.node) {
        Ok(peer_id) => peer_id,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SurveyCommandResponse {
                    success: false,
                    message,
                }),
            );
        }
    };

    let ban_requested = params.ban.unwrap_or(0) == 1;
    if !state.app.disconnect_peer(&peer_id).await {
        (
            StatusCode::NOT_FOUND,
            Json(SurveyCommandResponse {
                success: false,
                message: "Peer not found".to_string(),
            }),
        )
    } else {
        if ban_requested {
            if let Err(err) = state.app.ban_peer(peer_id.clone()).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(SurveyCommandResponse {
                        success: false,
                        message: format!("Failed to ban peer: {}", err),
                    }),
                );
            }
        }
        let message = if ban_requested {
            format!("Disconnected and banned peer {}", peer_id)
        } else {
            format!("Disconnected peer {}", peer_id)
        };
        (
            StatusCode::OK,
            Json(SurveyCommandResponse {
                success: true,
                message,
            }),
        )
    }
}

async fn ledger_handler(State(state): State<Arc<ServerState>>) -> Json<LedgerResponse> {
    let (sequence, hash, close_time, protocol_version) = state.app.ledger_info();
    Json(LedgerResponse {
        sequence,
        hash: hash.to_hex(),
        close_time,
        protocol_version,
    })
}

async fn upgrades_handler(State(state): State<Arc<ServerState>>) -> Json<UpgradesResponse> {
    let (protocol_version, base_fee, base_reserve, max_tx_set_size) =
        state.app.current_upgrade_state();
    let proposed = state
        .app
        .proposed_upgrades()
        .into_iter()
        .filter_map(map_upgrade_item)
        .collect::<Vec<_>>();

    Json(UpgradesResponse {
        current: UpgradeState {
            protocol_version,
            base_fee,
            base_reserve,
            max_tx_set_size,
        },
        proposed,
    })
}

async fn self_check_handler(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    match state.app.self_check(32) {
        Ok(result) => (
            StatusCode::OK,
            Json(SelfCheckResponse {
                ok: result.ok,
                checked_ledgers: result.checked_ledgers,
                last_checked_ledger: result.last_checked_ledger,
                message: None,
            }),
        ),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SelfCheckResponse {
                ok: false,
                checked_ledgers: 0,
                last_checked_ledger: None,
                message: Some(err.to_string()),
            }),
        ),
    }
}

async fn bans_handler(State(state): State<Arc<ServerState>>) -> Response {
    match state.app.banned_peers().await {
        Ok(bans) => {
            let bans = bans
                .into_iter()
                .filter_map(peer_id_to_strkey)
                .collect::<Vec<_>>();
            (StatusCode::OK, Json(BansResponse { bans })).into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SurveyCommandResponse {
                success: false,
                message: format!("Failed to read bans: {}", err),
            }),
        )
            .into_response(),
    }
}

async fn unban_handler(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<UnbanParams>,
) -> impl IntoResponse {
    let peer_id = match parse_peer_id_params(&params.peer_id, &params.node) {
        Ok(peer_id) => peer_id,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SurveyCommandResponse {
                    success: false,
                    message,
                }),
            );
        }
    };

    match state.app.unban_peer(&peer_id).await {
        Ok(removed) => {
            let message = if removed {
                format!("Unbanned peer {}", peer_id)
            } else {
                "Peer not found in ban list".to_string()
            };
            (
                StatusCode::OK,
                Json(SurveyCommandResponse {
                    success: removed,
                    message,
                }),
            )
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SurveyCommandResponse {
                success: false,
                message: format!("Failed to unban peer: {}", err),
            }),
        ),
    }
}

async fn quorum_handler(State(state): State<Arc<ServerState>>) -> Json<QuorumResponse> {
    let local = state
        .app
        .local_quorum_set()
        .map(|qs| quorum_set_response(&qs));
    Json(QuorumResponse { local })
}

fn quorum_set_response(quorum_set: &stellar_xdr::curr::ScpQuorumSet) -> QuorumSetResponse {
    let hash = hash_quorum_set(quorum_set).to_hex();
    let validators = quorum_set
        .validators
        .iter()
        .filter_map(node_id_to_strkey)
        .collect::<Vec<_>>();
    let inner_sets = quorum_set
        .inner_sets
        .iter()
        .map(quorum_set_response)
        .collect::<Vec<_>>();
    QuorumSetResponse {
        hash,
        threshold: quorum_set.threshold,
        validators,
        inner_sets,
    }
}

fn node_id_to_strkey(node_id: &stellar_xdr::curr::NodeId) -> Option<String> {
    match &node_id.0 {
        stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key) => {
            CryptoPublicKey::from_bytes(&key.0)
                .ok()
                .map(|pk| pk.to_strkey())
        }
    }
}

fn peer_id_to_strkey(peer_id: PeerId) -> Option<String> {
    node_id_to_strkey(&stellar_xdr::curr::NodeId(peer_id.0))
}

fn map_upgrade_item(upgrade: LedgerUpgrade) -> Option<UpgradeItem> {
    match upgrade {
        LedgerUpgrade::Version(value) => Some(UpgradeItem {
            r#type: "protocol_version".to_string(),
            value,
        }),
        LedgerUpgrade::BaseFee(value) => Some(UpgradeItem {
            r#type: "base_fee".to_string(),
            value,
        }),
        LedgerUpgrade::BaseReserve(value) => Some(UpgradeItem {
            r#type: "base_reserve".to_string(),
            value,
        }),
        LedgerUpgrade::MaxTxSetSize(value) => Some(UpgradeItem {
            r#type: "max_tx_set_size".to_string(),
            value,
        }),
        _ => None,
    }
}

fn parse_connect_params(params: &ConnectParams) -> Result<PeerAddress, String> {
    if let Some(addr) = params.addr.as_ref() {
        let (host, port) = addr
            .split_once(':')
            .ok_or_else(|| "addr must be host:port".to_string())?;
        let port = port
            .parse::<u16>()
            .map_err(|_| "invalid port".to_string())?;
        return Ok(PeerAddress::new(host.to_string(), port));
    }

    let Some(peer) = params.peer.as_ref() else {
        return Err("addr or peer/port must be provided".to_string());
    };
    let port = params
        .port
        .ok_or_else(|| "port must be provided".to_string())?;
    Ok(PeerAddress::new(peer.to_string(), port))
}

fn parse_peer_id_params(peer_id: &Option<String>, node: &Option<String>) -> Result<PeerId, String> {
    let value = peer_id
        .as_ref()
        .or(node.as_ref())
        .ok_or_else(|| "peer_id or node must be provided".to_string())?;
    parse_peer_id(value)
}

fn parse_peer_id(value: &str) -> Result<PeerId, String> {
    if let Ok(bytes) = hex::decode(value) {
        if let Ok(raw) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return Ok(PeerId::from_bytes(raw));
        }
    }

    let key = CryptoPublicKey::from_strkey(value)
        .map_err(|_| "invalid peer_id (expected 32-byte hex or strkey)".to_string())?;
    Ok(PeerId::from_bytes(*key.as_bytes()))
}

async fn survey_handler(State(state): State<Arc<ServerState>>) -> Json<SurveyReport> {
    let report = state.app.survey_report().await;
    Json(report)
}

async fn scp_handler(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<ScpParams>,
) -> Json<ScpInfoResponse> {
    let limit = params.limit.unwrap_or(2).min(20);
    let slots = state
        .app
        .scp_slot_snapshots(limit)
        .into_iter()
        .map(ScpSlotInfo::from)
        .collect();
    Json(ScpInfoResponse {
        node: state.app.info().public_key,
        slots,
    })
}

impl From<crate::app::ScpSlotSnapshot> for ScpSlotInfo {
    fn from(snapshot: crate::app::ScpSlotSnapshot) -> Self {
        Self {
            slot_index: snapshot.slot_index,
            is_externalized: snapshot.is_externalized,
            is_nominating: snapshot.is_nominating,
            ballot_phase: snapshot.ballot_phase,
            nomination_round: snapshot.nomination_round,
            ballot_round: snapshot.ballot_round,
            envelope_count: snapshot.envelope_count,
        }
    }
}

async fn start_survey_collecting_handler(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<StartSurveyParams>,
) -> impl IntoResponse {
    if !survey_booted(&state).await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SurveyCommandResponse {
                success: false,
                message: "Application is not fully booted, try again later.".to_string(),
            }),
        );
    }
    let ok = state.app.start_survey_collecting(params.nonce).await;
    let message = if ok {
        "Requested network to start survey collecting."
    } else {
        "Failed to start survey collecting."
    };
    (
        StatusCode::OK,
        Json(SurveyCommandResponse {
            success: ok,
            message: message.to_string(),
        }),
    )
}

async fn stop_survey_collecting_handler(
    State(state): State<Arc<ServerState>>,
) -> impl IntoResponse {
    if !survey_booted(&state).await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SurveyCommandResponse {
                success: false,
                message: "Application is not fully booted, try again later.".to_string(),
            }),
        );
    }
    let ok = state.app.stop_survey_collecting().await;
    let message = if ok {
        "Requested network to stop survey collecting."
    } else {
        "Failed to stop survey collecting."
    };
    (
        StatusCode::OK,
        Json(SurveyCommandResponse {
            success: ok,
            message: message.to_string(),
        }),
    )
}

async fn survey_topology_handler(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<SurveyTopologyParams>,
) -> impl IntoResponse {
    if !survey_booted(&state).await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SurveyCommandResponse {
                success: false,
                message: "Application is not fully booted, try again later.".to_string(),
            }),
        );
    }
    let pubkey = match henyey_crypto::PublicKey::from_strkey(&params.node) {
        Ok(key) => key,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SurveyCommandResponse {
                    success: false,
                    message: "Invalid node public key".to_string(),
                }),
            );
        }
    };
    let peer_id = henyey_overlay::PeerId::from_bytes(*pubkey.as_bytes());
    let (Some(inbound), Some(outbound)) = (params.inbound_index, params.outbound_index) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(SurveyCommandResponse {
                success: false,
                message: "Missing inbound_index or outbound_index".to_string(),
            }),
        );
    };

    let ok = state
        .app
        .survey_topology_timesliced(peer_id, inbound, outbound)
        .await;
    let message = if ok {
        "Survey request queued."
    } else {
        "Survey request rejected."
    };
    (
        StatusCode::OK,
        Json(SurveyCommandResponse {
            success: ok,
            message: message.to_string(),
        }),
    )
}

async fn survey_booted(state: &ServerState) -> bool {
    matches!(
        state.app.state().await,
        crate::app::AppState::Synced | crate::app::AppState::Validating
    )
}

async fn stop_survey_reporting_handler(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    state.app.stop_survey_reporting().await;
    (
        StatusCode::OK,
        Json(SurveyCommandResponse {
            success: true,
            message: "Survey reporting stopped.".to_string(),
        }),
    )
}

async fn submit_tx_handler(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<SubmitTxRequest>,
) -> impl IntoResponse {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use stellar_xdr::curr::{Limits, ReadXdr, TransactionEnvelope};

    // Decode and validate the transaction
    let tx_bytes = match STANDARD.decode(&request.tx) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitTxResponse {
                    success: false,
                    hash: None,
                    error: Some(format!("Invalid base64: {}", e)),
                }),
            );
        }
    };

    // Parse the transaction envelope
    let tx_env = match TransactionEnvelope::from_xdr(&tx_bytes, Limits::none()) {
        Ok(env) => env,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitTxResponse {
                    success: false,
                    hash: None,
                    error: Some(format!("Invalid XDR: {}", e)),
                }),
            );
        }
    };

    let network_id = NetworkId::from_passphrase(&state.app.info().network_passphrase);
    let mut frame = TransactionFrame::with_network(tx_env.clone(), network_id);
    let hash = frame.compute_hash(&network_id).ok();
    let result = state.app.submit_transaction(tx_env);

    let (success, error) = match result {
        henyey_herder::TxQueueResult::Added => (true, None),
        henyey_herder::TxQueueResult::Duplicate => {
            (true, Some("Transaction already in queue".to_string()))
        }
        henyey_herder::TxQueueResult::QueueFull => {
            (false, Some("Transaction queue full".to_string()))
        }
        henyey_herder::TxQueueResult::FeeTooLow => {
            (false, Some("Transaction fee too low".to_string()))
        }
        henyey_herder::TxQueueResult::Invalid(code) => {
            let msg = match code {
                Some(c) => format!("Transaction invalid: {}", c),
                None => "Transaction invalid".to_string(),
            };
            (false, Some(msg))
        }
        henyey_herder::TxQueueResult::Banned => {
            (false, Some("Transaction from banned source".to_string()))
        }
        henyey_herder::TxQueueResult::Filtered => (
            false,
            Some("Transaction filtered by operation type".to_string()),
        ),
        henyey_herder::TxQueueResult::TryAgainLater => (
            false,
            Some("Account already has pending transaction".to_string()),
        ),
    };

    (
        StatusCode::OK,
        Json(SubmitTxResponse {
            success,
            hash: hash.map(|value| value.to_hex()),
            error,
        }),
    )
}

async fn shutdown_handler(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    state.app.shutdown();
    (
        StatusCode::OK,
        Json(SurveyCommandResponse {
            success: true,
            message: "Shutdown requested.".to_string(),
        }),
    )
}

async fn health_handler(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    let app_state = state.app.state().await;
    let is_healthy = matches!(app_state, AppState::Synced | AppState::Validating);
    let (ledger_seq, _hash, _close_time, _protocol_version) = state.app.ledger_info();
    let peer_count = state.app.peer_snapshots().await.len();

    let response = HealthResponse {
        status: if is_healthy { "healthy" } else { "unhealthy" }.to_string(),
        state: format!("{}", app_state),
        ledger_seq,
        peer_count,
    };

    let status = if is_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(response))
}

/// Handler for /ll endpoint - get or set log levels.
///
/// GET /ll - returns current log levels for all partitions
/// POST /ll?level=INFO - set global log level
/// POST /ll?level=DEBUG&partition=SCP - set log level for specific partition
async fn ll_handler(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<LlParams>,
) -> impl IntoResponse {
    use std::collections::HashMap;

    // If we don't have a log handle, return the stub response
    let Some(log_handle) = &state.log_handle else {
        // Fallback: return static levels when no handle is available
        let mut levels = HashMap::new();
        for (partition, _) in crate::logging::LOG_PARTITIONS {
            levels.insert(partition.to_string(), "INFO".to_string());
        }
        levels.insert("Global".to_string(), "INFO".to_string());

        if params.level.is_some() {
            levels.insert(
                "warning".to_string(),
                "Log level handle not available. Logging initialized without dynamic support."
                    .to_string(),
            );
        }

        return (StatusCode::OK, Json(LlResponse { levels }));
    };

    if let Some(level_str) = &params.level {
        // Setting a log level
        if let Some(partition) = &params.partition {
            // Set level for specific partition
            match log_handle.set_partition_level(partition, level_str) {
                Ok(()) => {
                    tracing::info!(
                        partition = %partition,
                        level = %level_str,
                        "Log level updated for partition"
                    );
                    let levels = log_handle.get_levels();
                    return (StatusCode::OK, Json(LlResponse { levels }));
                }
                Err(e) => {
                    let mut levels = HashMap::new();
                    levels.insert("error".to_string(), e.to_string());
                    return (StatusCode::BAD_REQUEST, Json(LlResponse { levels }));
                }
            }
        } else {
            // Set global level
            match log_handle.set_level(level_str) {
                Ok(()) => {
                    tracing::info!(level = %level_str, "Global log level updated");
                    let levels = log_handle.get_levels();
                    return (StatusCode::OK, Json(LlResponse { levels }));
                }
                Err(e) => {
                    let mut levels = HashMap::new();
                    levels.insert("error".to_string(), e.to_string());
                    return (StatusCode::BAD_REQUEST, Json(LlResponse { levels }));
                }
            }
        }
    }

    // GET request: return current levels
    let levels = log_handle.get_levels();
    (StatusCode::OK, Json(LlResponse { levels }))
}

/// Handler for /manualclose endpoint - manually close a ledger.
///
/// Triggers a manual ledger close. Requires:
/// - The node must be configured as a validator (`is_validator = true`)
/// - Manual close mode must be enabled (`manual_close = true`)
///
/// Parameters (ledgerSeq, closeTime) are only accepted in RUN_STANDALONE mode,
/// which is not currently implemented. Without parameters, triggers the next
/// ledger close via the herder.
async fn manualclose_handler(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<ManualCloseParams>,
) -> impl IntoResponse {
    // RUN_STANDALONE mode is not implemented, so parameters are not accepted
    if params.ledger_seq.is_some() || params.close_time.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ManualCloseResponse {
                success: false,
                ledger_seq: None,
                message: Some(
                    "The 'manualclose' command accepts parameters only if the configuration includes RUN_STANDALONE=true.".to_string()
                ),
            }),
        );
    }

    // Try to trigger manual close
    match state.app.manual_close_ledger().await {
        Ok(new_ledger) => (
            StatusCode::OK,
            Json(ManualCloseResponse {
                success: true,
                ledger_seq: Some(new_ledger),
                message: Some(format!("Triggered manual close for ledger {}", new_ledger)),
            }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ManualCloseResponse {
                success: false,
                ledger_seq: None,
                message: Some(e.to_string()),
            }),
        ),
    }
}

/// Handler for /sorobaninfo endpoint - get Soroban network configuration.
async fn sorobaninfo_handler(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<SorobanInfoParams>,
) -> impl IntoResponse {
    let format = params.format.as_deref().unwrap_or("basic");

    let (_, _, _, protocol_version) = state.app.ledger_info();

    match format {
        "basic" => {
            // Load Soroban configuration from ledger state
            let Some(info) = state.app.soroban_network_info() else {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "error": "Soroban config not available (ledger not initialized or pre-protocol 20)",
                        "protocol_version": protocol_version
                    })),
                );
            };

            let response = SorobanInfoResponse {
                max_contract_size: info.max_contract_size,
                max_contract_data_key_size: info.max_contract_data_key_size,
                max_contract_data_entry_size: info.max_contract_data_entry_size,
                tx: SorobanTxLimits {
                    max_instructions: info.tx_max_instructions,
                    memory_limit: info.tx_memory_limit,
                    max_read_ledger_entries: info.tx_max_read_ledger_entries,
                    max_read_bytes: info.tx_max_read_bytes,
                    max_write_ledger_entries: info.tx_max_write_ledger_entries,
                    max_write_bytes: info.tx_max_write_bytes,
                    max_contract_events_size_bytes: info.tx_max_contract_events_size_bytes,
                    max_size_bytes: info.tx_max_size_bytes,
                },
                ledger: SorobanLedgerLimits {
                    max_instructions: info.ledger_max_instructions,
                    max_read_ledger_entries: info.ledger_max_read_ledger_entries,
                    max_read_bytes: info.ledger_max_read_bytes,
                    max_write_ledger_entries: info.ledger_max_write_ledger_entries,
                    max_write_bytes: info.ledger_max_write_bytes,
                    max_tx_size_bytes: info.ledger_max_tx_size_bytes,
                    max_tx_count: info.ledger_max_tx_count,
                },
                fee_rate_per_instructions_increment: info.fee_rate_per_instructions_increment,
                fee_read_ledger_entry: info.fee_read_ledger_entry,
                fee_write_ledger_entry: info.fee_write_ledger_entry,
                fee_read_1kb: info.fee_read_1kb,
                fee_write_1kb: info.fee_write_1kb,
                fee_historical_1kb: info.fee_historical_1kb,
                fee_contract_events_size_1kb: info.fee_contract_events_size_1kb,
                fee_transaction_size_1kb: info.fee_transaction_size_1kb,
                state_archival: SorobanStateArchival {
                    max_entry_ttl: info.max_entry_ttl,
                    min_temporary_ttl: info.min_temporary_ttl,
                    min_persistent_ttl: info.min_persistent_ttl,
                    persistent_rent_rate_denominator: info.persistent_rent_rate_denominator,
                    temp_rent_rate_denominator: info.temp_rent_rate_denominator,
                    max_entries_to_archive: info.max_entries_to_archive,
                    bucketlist_size_window_sample_size: info.bucketlist_size_window_sample_size,
                    eviction_scan_size: info.eviction_scan_size,
                    starting_eviction_scan_level: info.starting_eviction_scan_level,
                },
            };
            (
                StatusCode::OK,
                Json(serde_json::to_value(response).unwrap()),
            )
        }
        "detailed" | "upgrade_xdr" => {
            // These formats require reading actual config entries from ledger
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "error": format!("Format '{}' not yet implemented", format),
                    "available_formats": ["basic"]
                })),
            )
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("Unknown format: {}", format),
                "available_formats": ["basic", "detailed", "upgrade_xdr"]
            })),
        ),
    }
}

/// Handler for /clearmetrics endpoint - clear metrics registry.
///
/// POST /clearmetrics - clears all metrics
/// POST /clearmetrics?domain=stellar-core - clears metrics for a specific domain
///
/// Note: Since we use Prometheus-style metrics that are typically scraped externally,
/// this endpoint clears internal counter states. The behavior matches stellar-core
/// which resets medida metrics counters.
async fn clearmetrics_handler(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<ClearMetricsParams>,
) -> Json<ClearMetricsResponse> {
    let domain = params.domain.unwrap_or_default();

    // Clear metrics via the app (this is a no-op for Prometheus-style metrics,
    // but we log the request for parity with stellar-core)
    state.app.clear_metrics(&domain);

    let message = if domain.is_empty() {
        "Cleared all metrics!".to_string()
    } else {
        format!("Cleared {} metrics!", domain)
    };

    Json(ClearMetricsResponse { message })
}

/// Handler for /logrotate endpoint - trigger log file rotation.
///
/// POST /logrotate - triggers log rotation
///
/// Note: The Rust implementation uses `tracing` with `tracing-subscriber`.
/// Log rotation depends on the logging backend configuration (e.g., tracing-appender).
/// This endpoint signals a rotation request, matching stellar-core behavior.
async fn logrotate_handler() -> Json<LogRotateResponse> {
    // Log rotation in Rust is typically handled by the logging backend
    // (e.g., tracing-appender with time-based or size-based rotation).
    // We log the request to match stellar-core behavior.
    tracing::info!("Log rotate requested");

    Json(LogRotateResponse {
        message: "Log rotate...".to_string(),
    })
}

/// Handler for /maintenance endpoint - trigger manual database maintenance.
///
/// POST /maintenance?queue=true - triggers maintenance
/// POST /maintenance?queue=true&count=50000 - triggers maintenance with custom count
///
/// Maintenance cleans up old SCP history and ledger headers to prevent
/// unbounded database growth.
async fn maintenance_handler(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<MaintenanceParams>,
) -> Json<MaintenanceResponse> {
    if params.queue.as_deref() != Some("true") {
        return Json(MaintenanceResponse {
            message: "No work performed".to_string(),
        });
    }

    let count = params.count.unwrap_or(50000);
    state.app.perform_maintenance(count);

    Json(MaintenanceResponse {
        message: "Done".to_string(),
    })
}

/// Handler for /dumpproposedsettings endpoint - dump proposed Soroban config settings.
///
/// GET /dumpproposedsettings?blob=<base64-xdr> - returns the ConfigUpgradeSet
///
/// The blob parameter should be a base64-encoded XDR ConfigUpgradeSetKey.
/// This endpoint looks up the corresponding ConfigUpgradeSet from the ledger
/// and returns it as JSON.
async fn dumpproposedsettings_handler(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<DumpProposedSettingsParams>,
) -> impl IntoResponse {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use stellar_xdr::curr::{ConfigUpgradeSetKey, Limits, ReadXdr};

    let Some(blob) = params.blob else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Must specify a ConfigUpgradeSetKey blob: dumpproposedsettings?blob=<ConfigUpgradeSetKey in xdr format>"
            })),
        );
    };

    // Decode base64 blob
    let bytes = match STANDARD.decode(&blob) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("Invalid base64: {}", e)
                })),
            );
        }
    };

    // Deserialize as ConfigUpgradeSetKey
    let key: ConfigUpgradeSetKey = match ConfigUpgradeSetKey::from_xdr(&bytes, Limits::none()) {
        Ok(k) => k,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("Invalid XDR: {}", e)
                })),
            );
        }
    };

    // Load ConfigUpgradeSet from ledger
    match state.app.get_config_upgrade_set(&key) {
        Some(settings) => (StatusCode::OK, Json(serde_json::json!(settings))),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "configUpgradeSet is missing or invalid"
            })),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_mode_display() {
        assert_eq!(format!("{}", RunMode::Full), "full");
        assert_eq!(format!("{}", RunMode::Validator), "validator");
        assert_eq!(format!("{}", RunMode::Watcher), "watcher");
    }

    #[test]
    fn test_run_options_default() {
        let options = RunOptions::default();
        assert_eq!(options.mode, RunMode::Full);
        assert!(!options.force_catchup);
        assert!(options.wait_for_sync);
    }

    #[test]
    fn test_run_options_validator() {
        let options = RunOptions::validator();
        assert_eq!(options.mode, RunMode::Validator);
    }

    #[test]
    fn test_run_options_watcher() {
        let options = RunOptions::watcher();
        assert_eq!(options.mode, RunMode::Watcher);
        assert!(!options.wait_for_sync);
    }

    #[test]
    fn test_node_status_display() {
        let status = NodeStatus {
            ledger_seq: 1000,
            ledger_hash: None,
            peer_count: 5,
            consensus_state: "tracking".to_string(),
            pending_tx_count: 10,
            uptime_secs: 3600,
            state: "Synced".to_string(),
        };

        let display = format!("{}", status);
        assert!(display.contains("Ledger: 1000"));
        assert!(display.contains("Peers: 5"));
        assert!(display.contains("Uptime: 3600s"));
    }

    #[test]
    fn test_is_ledger_too_old() {
        assert!(is_ledger_too_old(0, 100, 10));
        assert!(!is_ledger_too_old(100, 105, 10));
        assert!(is_ledger_too_old(100, 111, 10));
        assert!(!is_ledger_too_old(100, 1000, 0));
    }
}
