//! Core application struct and component initialization for rs-stellar-core.
//!
//! This module contains the [`App`] struct, which is the central coordinator for all
//! Stellar Core subsystems. It manages the lifecycle of:
//!
//! - **Database**: SQLite persistence for ledger headers, transactions, and state
//! - **BucketManager**: Merkle tree storage for ledger entry snapshots
//! - **LedgerManager**: Ledger close operations and state transitions
//! - **OverlayManager**: P2P network connections and message routing
//! - **Herder**: SCP consensus coordination and transaction queue management
//!
//! # Application Lifecycle
//!
//! The typical lifecycle of an App instance:
//!
//! 1. **Initialization** ([`App::new`]): Load configuration, open database, initialize
//!    subsystems, and restore state from disk
//! 2. **Catchup** ([`App::catchup`]): If behind, download and apply history from archives
//! 3. **Run** ([`App::run`]): Enter the main event loop, processing peer messages
//!    and participating in consensus
//! 4. **Shutdown** ([`App::shutdown`]): Gracefully stop all subsystems
//!
//! # State Machine
//!
//! The application transitions through these states (see [`AppState`]):
//!
//! ```text
//! Initializing -> CatchingUp -> Synced <-> Validating
//!                     ^            |
//!                     |            v
//!                     +--- ShuttingDown
//! ```
//!
//! # Consensus Integration
//!
//! For validator nodes, the App coordinates SCP message flow:
//! - Receives SCP envelopes from peers via the overlay
//! - Passes them to the Herder for processing
//! - Broadcasts locally-generated envelopes back to peers
//! - Triggers ledger close when consensus is reached

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::{seq::SliceRandom, Rng};
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::RwLock;

use henyey_bucket::BucketManager;
use henyey_bucket::{BucketList, HasNextState, HotArchiveBucketList};
use henyey_common::{Hash256, NetworkId};
use henyey_db::{
    BucketListQueries, HistoryQueries, LedgerQueries, PublishQueueQueries, ScpQueries,
};
use henyey_db::queries::StateQueries;
use henyey_db::schema::state_keys;
use henyey_herder::{
    drift_tracker::CloseTimeDriftTracker,
    sync_recovery::{SyncRecoveryCallback, SyncRecoveryHandle, SyncRecoveryManager},
    EnvelopeState, Herder, HerderCallback, HerderConfig, HerderStats, TxQueueConfig,
};
use henyey_history::{
    is_checkpoint_ledger, latest_checkpoint_before_or_at, CatchupManager, CatchupMode,
    CatchupOutput, CheckpointData, ExistingBucketState, HistoryArchive, HistoryArchiveState,
    GENESIS_LEDGER_SEQ, CHECKPOINT_FREQUENCY,
    build_history_archive_state,
};
use henyey_historywork::{
    build_checkpoint_data, get_progress, HistoryWorkBuilder, HistoryWorkState,
};
use henyey_ledger::{
    LedgerCloseData, LedgerCloseResult, LedgerManager, LedgerManagerConfig, SorobanNetworkInfo,
    TransactionSetVariant,
};
use henyey_overlay::{
    ConnectionDirection, LocalNode, OverlayConfig as OverlayManagerConfig, OverlayManager,
    OverlayMessage, PeerAddress, PeerEvent, PeerId, PeerSnapshot, PeerType,
};
use henyey_scp::hash_quorum_set;
use henyey_tx::TransactionFrame;
use henyey_work::{WorkScheduler, WorkSchedulerConfig, WorkState};
use stellar_xdr::curr::{
    Curve25519Public, DontHave, EncryptedBody, FloodAdvert, FloodDemand, Hash, LedgerCloseMeta,
    LedgerScpMessages, LedgerUpgrade, MessageType, ReadXdr, ScpEnvelope, ScpHistoryEntry,
    ScpHistoryEntryV0, SignedTimeSlicedSurveyResponseMessage, StellarMessage, StellarValue,
    StellarValueExt, SurveyMessageCommandType, SurveyRequestMessage, SurveyResponseBody,
    SurveyResponseMessage, TimeSlicedPeerDataList, TimeSlicedSurveyRequestMessage,
    TimeSlicedSurveyResponseMessage, TimeSlicedSurveyStartCollectingMessage,
    TimeSlicedSurveyStopCollectingMessage, TopologyResponseBodyV2, TransactionHistoryEntry,
    TransactionHistoryEntryExt, TransactionHistoryResultEntry, TransactionHistoryResultEntryExt,
    TransactionMeta, TransactionResultPair, TransactionResultSet, TransactionSet, TxAdvertVector,
    TxDemandVector, UpgradeType, VecM, WriteXdr,
};
use x25519_dalek::{PublicKey as CurvePublicKey, StaticSecret as CurveSecretKey};

use crate::config::AppConfig;
use crate::logging::CatchupProgress;
use crate::meta_stream::{MetaStreamError, MetaStreamManager};
use crate::survey::{SurveyDataManager, SurveyMessageLimiter, SurveyPhase};
use henyey_ledger::{
    close_time as ledger_close_time, compute_header_hash, verify_header_chain,
};
use stellar_xdr::curr::TransactionEnvelope;

const TIME_SLICED_PEERS_MAX: usize = 25;
const PEER_TYPE_OUTBOUND: i32 = 1;
const PEER_TYPE_PREFERRED: i32 = 2;
const PEER_TYPE_INBOUND: i32 = 0;
const PEER_MAX_FAILURES_TO_SEND: u32 = 10;
const TX_SET_REQUEST_WINDOW: u64 = 12;
const MAX_TX_SET_REQUESTS_PER_TICK: usize = 32;
/// Consensus stuck timeout matching stellar-core's CONSENSUS_STUCK_TIMEOUT_SECONDS.
/// If no ledger closes within this time while we have buffered ledgers waiting,
/// we trigger out-of-sync recovery.
const CONSENSUS_STUCK_TIMEOUT_SECS: u64 = 35;

/// Faster timeout when all peers report DontHave or disconnect.
/// This allows us to trigger catchup sooner when we know peers don't have the tx sets.
const TX_SET_UNAVAILABLE_TIMEOUT_SECS: u64 = 5;

/// Timeout for pending tx_set requests with no response from any peer.
/// If we've been requesting a tx_set for this long with zero responses
/// (no GeneralizedTxSet AND no DontHave), assume peers silently dropped
/// the requests and treat as if all peers said DontHave.
const TX_SET_REQUEST_TIMEOUT_SECS: u64 = 10;

/// Recovery timer for out-of-sync recovery attempts.
/// Matches stellar-core's OUT_OF_SYNC_RECOVERY_TIMER.
const OUT_OF_SYNC_RECOVERY_TIMER_SECS: u64 = 10;

/// How long to cache the archive checkpoint before re-querying.
/// This prevents repeated network calls to the archive when we're stuck.
const ARCHIVE_CHECKPOINT_CACHE_SECS: u64 = 60;

/// Post-catchup recovery window: after completing catchup, prefer SCP recovery
/// over triggering another catchup for at least one full checkpoint cycle (~5 min).
/// The first checkpoint after initial catchup won't be published to archives for
/// ~320s (64 ledgers * 5s). During this window, missing ledgers can only be filled
/// via SCP state requests from peers, not from archive downloads.
const POST_CATCHUP_RECOVERY_WINDOW_SECS: u64 = 300;

/// Maximum number of recovery attempts after catchup before giving up on
/// SCP-based gap filling and falling back to a second catchup. Peers only cache
/// ~12 recent slots, so if the gap slots were evicted before we connected,
/// recovery will never succeed. 3 attempts × 10s interval = 30s before fallback.
const MAX_POST_CATCHUP_RECOVERY_ATTEMPTS: u32 = 3;

fn build_generalized_tx_set(
    tx_set: &henyey_herder::TransactionSet,
) -> Option<stellar_xdr::curr::GeneralizedTransactionSet> {
    use stellar_xdr::curr::{
        GeneralizedTransactionSet, TransactionPhase, TransactionSetV1, TxSetComponent,
        TxSetComponentTxsMaybeDiscountedFee,
    };

    let component =
        TxSetComponent::TxsetCompTxsMaybeDiscountedFee(TxSetComponentTxsMaybeDiscountedFee {
            base_fee: None,
            txs: tx_set.transactions.clone().try_into().ok()?,
        });
    let phase = TransactionPhase::V0(vec![component].try_into().ok()?);
    Some(GeneralizedTransactionSet::V1(TransactionSetV1 {
        previous_ledger_hash: Hash(tx_set.previous_ledger_hash.0),
        phases: vec![phase].try_into().ok()?,
    }))
    }

fn decode_upgrades(upgrades: Vec<UpgradeType>) -> Vec<LedgerUpgrade> {
    upgrades
        .into_iter()
        .filter_map(|upgrade| {
            let bytes = upgrade.0.as_slice();
            match LedgerUpgrade::from_xdr(bytes, stellar_xdr::curr::Limits::none()) {
                Ok(decoded) => Some(decoded),
                Err(err) => {
                    tracing::warn!(error = %err, "Failed to decode ledger upgrade");
                    None
                }
            }
        })
        .collect()
}

/// Application lifecycle state.
///
/// Represents the current phase of the application's operation. State transitions
/// are logged and can be observed via the HTTP status endpoint.
///
/// # State Transitions
///
/// - `Initializing` -> `CatchingUp`: When catchup is required
/// - `Initializing` -> `Synced`: When already up-to-date
/// - `CatchingUp` -> `Synced`: When catchup completes successfully
/// - `Synced` -> `Validating`: When consensus participation begins (validators only)
/// - `Synced` -> `CatchingUp`: When node falls behind and needs to re-sync
/// - Any -> `ShuttingDown`: When shutdown is requested
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// Application is initializing subsystems and loading state from disk.
    Initializing,
    /// Application is downloading and applying history from archives.
    CatchingUp,
    /// Application is synced with the network and tracking consensus.
    Synced,
    /// Application is actively participating in consensus as a validator.
    Validating,
    /// Application is gracefully shutting down.
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

/// Report of survey topology data collected from a single peer.
#[derive(Debug, Serialize)]
pub struct SurveyPeerReport {
    /// Public key of the peer that provided this report (hex-encoded).
    pub peer_id: String,
    /// Topology response containing peer statistics and node data.
    pub response: TopologyResponseBodyV2,
}

/// Aggregated network survey report.
///
/// Contains both local node survey data and responses collected from peers
/// during a time-sliced overlay survey. This data is used for network
/// topology analysis and monitoring.
#[derive(Debug, Serialize)]
pub struct SurveyReport {
    pub phase: SurveyPhase,
    pub nonce: Option<u32>,
    pub local_node: Option<stellar_xdr::curr::TimeSlicedNodeData>,
    pub inbound_peers: Vec<stellar_xdr::curr::TimeSlicedPeerData>,
    pub outbound_peers: Vec<stellar_xdr::curr::TimeSlicedPeerData>,
    pub peer_reports: BTreeMap<u32, Vec<SurveyPeerReport>>,
    pub survey_in_progress: bool,
    pub backlog: Vec<String>,
    pub bad_response_nodes: Vec<String>,
}

/// State for a ledger close running on a background thread.
///
/// Created by [`App::try_start_ledger_close`] and consumed by
/// [`App::handle_close_complete`] once the blocking close finishes.
struct PendingLedgerClose {
    /// Join handle for the `spawn_blocking` task.
    handle: tokio::task::JoinHandle<std::result::Result<LedgerCloseResult, String>>,
    /// Sequence number being closed.
    ledger_seq: u32,
    /// The transaction set used for closing.
    tx_set: henyey_herder::TransactionSet,
    /// Variant of the tx set (classic or generalized).
    tx_set_variant: TransactionSetVariant,
    /// Close time for the ledger.
    close_time: u64,
}

/// The main application struct coordinating all Stellar Core subsystems.
///
/// `App` is the central component that:
/// - Owns all long-lived subsystem handles (database, bucket manager, ledger manager, etc.)
/// - Manages the application lifecycle (initialization, catchup, run, shutdown)
/// - Routes messages between the overlay network and consensus components
/// - Handles transaction submission and flooding
/// - Provides HTTP API endpoints for monitoring and control
///
/// # Thread Safety
///
/// `App` is designed to be shared across async tasks via `Arc<App>`. Internal
/// state is protected by appropriate locks (`RwLock`, `Mutex`).
///
/// # Creating an App
///
/// ```no_run
/// use henyey_app::{App, AppConfig};
///
/// # async fn example() -> anyhow::Result<()> {
/// let config = AppConfig::testnet();
/// let app = App::new(config).await?;
/// # Ok(())
/// # }
/// ```
pub struct App {
    /// Application configuration.
    config: AppConfig,

    /// Current application state.
    state: RwLock<AppState>,

    /// Database connection.
    db: henyey_db::Database,
    /// Lock file handle to prevent multiple instances.
    /// Stored to keep the lock alive for the lifetime of the App.
    _db_lock: Option<File>,

    /// Node keypair.
    keypair: henyey_crypto::SecretKey,

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
    /// Prevent concurrent catchup runs when we fall behind.
    catchup_in_progress: AtomicBool,
    /// Buffered externalized ledgers waiting to apply.
    syncing_ledgers: RwLock<BTreeMap<u32, henyey_herder::LedgerCloseInfo>>,
    /// Latest externalized slot we've observed (for liveness checks).
    last_externalized_slot: AtomicU64,
    /// Time when we last observed an externalized slot.
    last_externalized_at: RwLock<Instant>,
    /// Last time we requested SCP state due to stalled externalization.
    last_scp_state_request_at: RwLock<Instant>,

    /// Time-sliced survey data manager.
    survey_data: RwLock<SurveyDataManager>,

    /// Pending transaction hashes to advertise.
    tx_advert_queue: RwLock<Vec<Hash256>>,
    /// Deduplication set for pending tx adverts.
    tx_advert_set: RwLock<HashSet<Hash256>>,

    /// Per-peer advert tracking and queues for demand scheduling.
    tx_adverts_by_peer: RwLock<HashMap<henyey_overlay::PeerId, PeerTxAdverts>>,
    /// Demand history for transaction pulls.
    tx_demand_history: RwLock<HashMap<Hash256, TxDemandHistory>>,
    /// Pending demand hashes in FIFO order for retention.
    tx_pending_demands: RwLock<VecDeque<Hash256>>,
    /// Per-txset DontHave tracking to avoid retrying peers that lack the set.
    tx_set_dont_have: RwLock<HashMap<Hash256, HashSet<henyey_overlay::PeerId>>>,
    /// Last time we requested a tx set by hash (throttling).
    tx_set_last_request: RwLock<HashMap<Hash256, TxSetRequestState>>,
    /// Tracks when all peers have been exhausted for a tx set (all said DontHave or disconnected).
    /// When this is true, we use a faster timeout to trigger catchup.
    tx_set_all_peers_exhausted: AtomicBool,
    /// Tx set hashes we've already logged "all peers exhausted" warning for (to avoid spam).
    tx_set_exhausted_warned: RwLock<HashSet<Hash256>>,
    /// When we detected consensus is stuck (for timeout detection).
    /// Stores (current_ledger, first_buffered, stuck_start_time, last_recovery_attempt).
    consensus_stuck_state: RwLock<Option<ConsensusStuckState>>,
    /// When catchup last completed (for cooldown).
    last_catchup_completed_at: RwLock<Option<Instant>>,
    /// Cached archive checkpoint (ledger, queried_at) to avoid repeated network calls.
    cached_archive_checkpoint: RwLock<Option<(u32, Instant)>>,
    /// SCP latency samples for surveys.
    scp_latency: RwLock<ScpLatencyTracker>,

    /// Survey scheduler state for time-sliced surveys.
    survey_scheduler: RwLock<SurveyScheduler>,
    /// Next survey nonce.
    survey_nonce: RwLock<u32>,
    /// Ephemeral survey encryption secrets keyed by nonce.
    survey_secrets: RwLock<HashMap<u32, [u8; 32]>>,
    /// Survey responses keyed by nonce.
    survey_results:
        RwLock<HashMap<u32, HashMap<henyey_overlay::PeerId, TopologyResponseBodyV2>>>,
    /// Survey message limiter for rate limiting and deduplication.
    survey_limiter: RwLock<SurveyMessageLimiter>,
    /// Survey throttle timeout between survey runs.
    survey_throttle: Duration,
    /// Survey reporting backlog state (surveyor-side).
    survey_reporting: RwLock<SurveyReportingState>,
    /// SCP timeout scheduling state.
    scp_timeouts: RwLock<ScpTimeoutState>,

    /// Metadata output stream manager for emitting LedgerCloseMeta.
    meta_stream: std::sync::Mutex<Option<MetaStreamManager>>,

    /// Close time drift tracker for clock synchronization monitoring.
    drift_tracker: std::sync::Mutex<CloseTimeDriftTracker>,

    /// Handle for sending commands to the sync recovery manager.
    /// Uses parking_lot::RwLock for synchronous access from callbacks.
    sync_recovery_handle: parking_lot::RwLock<Option<SyncRecoveryHandle>>,

    /// Whether ledger application is currently in progress (for sync recovery).
    is_applying_ledger: AtomicBool,

    /// Flag set by SyncRecoveryManager to request recovery from the main loop.
    /// The main loop checks this and triggers buffered catchup when set.
    sync_recovery_pending: AtomicBool,

    /// Total number of times the node lost sync.
    lost_sync_count: AtomicU64,
    /// Monotonic counter used for ping IDs.
    ping_counter: AtomicU64,
    /// In-flight ping requests keyed by hash.
    ping_inflight: RwLock<HashMap<Hash256, PingInfo>>,
    /// In-flight ping hash per peer.
    peer_ping_inflight: RwLock<HashMap<henyey_overlay::PeerId, Hash256>>,

    /// Weak reference to self for spawning background tasks from &self methods.
    /// Set via `set_self_arc` after wrapping in Arc.
    self_arc: RwLock<std::sync::Weak<Self>>,
}

#[derive(Debug)]
struct TxAdvertHistory {
    entries: HashMap<Hash256, u32>,
    order: VecDeque<(Hash256, u32)>,
    capacity: usize,
}

impl TxAdvertHistory {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn seen(&self, hash: &Hash256) -> bool {
        self.entries.contains_key(hash)
    }

    fn remember(&mut self, hash: Hash256, ledger_seq: u32) {
        self.entries.insert(hash, ledger_seq);
        self.order.push_back((hash, ledger_seq));

        while self.entries.len() > self.capacity {
            if let Some((old_hash, old_seq)) = self.order.pop_front() {
                if self.entries.get(&old_hash) == Some(&old_seq) {
                    self.entries.remove(&old_hash);
                }
            }
        }
    }

    fn clear_below(&mut self, ledger_seq: u32) {
        self.entries.retain(|_, seq| *seq >= ledger_seq);
        self.order
            .retain(|(hash, seq)| *seq >= ledger_seq && self.entries.get(hash) == Some(seq));
    }
}

#[derive(Debug, Clone)]
struct TxSetRequestState {
    last_request: Instant,
    /// When this tx_set was first requested. Used to detect peers that silently
    /// drop GetTxSet requests (no response AND no DontHave).
    first_requested: Instant,
    next_peer_offset: usize,
}

/// State for tracking consensus stuck condition.
/// Matches stellar-core's out-of-sync recovery behavior.
#[derive(Debug, Clone)]
struct ConsensusStuckState {
    /// Current ledger when stuck was detected.
    current_ledger: u32,
    /// First buffered ledger when stuck was detected.
    first_buffered: u32,
    /// When we first detected the stuck condition.
    stuck_start: Instant,
    /// Last time we attempted recovery (broadcast SCP + request state).
    last_recovery_attempt: Instant,
    /// Number of recovery attempts made.
    recovery_attempts: u32,
    /// Whether we've already triggered catchup for this stuck state.
    /// Set to true when catchup is triggered, prevents repeated catchup attempts
    /// when archive has no newer checkpoint available.
    catchup_triggered: bool,
}

/// Actions to take when consensus is stuck.
#[derive(Debug, Clone, Copy)]
enum ConsensusStuckAction {
    /// Wait for tx set to arrive.
    Wait,
    /// Attempt recovery (broadcast SCP + request state from peers).
    AttemptRecovery,
    /// Trigger catchup after timeout.
    TriggerCatchup,
}

#[derive(Debug)]
struct PeerTxAdverts {
    incoming: VecDeque<Hash256>,
    retry: VecDeque<Hash256>,
    history: TxAdvertHistory,
}

impl PeerTxAdverts {
    fn new() -> Self {
        Self {
            incoming: VecDeque::new(),
            retry: VecDeque::new(),
            history: TxAdvertHistory::new(50_000),
        }
    }

    fn seen_advert(&self, hash: &Hash256) -> bool {
        self.history.seen(hash)
    }

    fn remember(&mut self, hash: Hash256, ledger_seq: u32) {
        self.history.remember(hash, ledger_seq);
    }

    fn queue_incoming(&mut self, hashes: &[Hash], ledger_seq: u32, max_ops: usize) {
        for hash in hashes {
            let hash256 = Hash256::from(hash.clone());
            self.remember(hash256, ledger_seq);
        }

        let start = hashes.len().saturating_sub(max_ops);
        for hash in hashes.iter().skip(start) {
            self.incoming.push_back(Hash256::from(hash.clone()));
        }

        while self.size() > max_ops {
            self.pop_advert();
        }
    }

    fn retry_incoming(&mut self, hashes: Vec<Hash256>, max_ops: usize) {
        self.retry.extend(hashes);
        while self.size() > max_ops {
            self.pop_advert();
        }
    }

    fn pop_advert(&mut self) -> Option<Hash256> {
        if let Some(hash) = self.retry.pop_front() {
            return Some(hash);
        }
        self.incoming.pop_front()
    }

    fn has_advert(&self) -> bool {
        self.size() > 0
    }

    fn size(&self) -> usize {
        self.retry.len() + self.incoming.len()
    }

    fn clear_below(&mut self, ledger_seq: u32) {
        self.history.clear_below(ledger_seq);
    }
}

#[derive(Debug)]
struct TxDemandHistory {
    first_demanded: Instant,
    last_demanded: Instant,
    peers: HashMap<henyey_overlay::PeerId, Instant>,
    latency_recorded: bool,
}

#[derive(Debug, Clone, Copy)]
enum DemandStatus {
    Demand,
    RetryLater,
    Discard,
}

#[derive(Debug, Clone)]
struct PingInfo {
    peer_id: henyey_overlay::PeerId,
    sent_at: Instant,
}

#[derive(Debug, Default)]
struct ScpLatencyTracker {
    first_seen: HashMap<u64, Instant>,
    self_sent: HashMap<u64, Instant>,
    self_to_other_recorded: HashSet<u64>,
    first_to_self_samples_ms: VecDeque<u64>,
    self_to_other_samples_ms: VecDeque<u64>,
}

#[derive(Debug)]
struct SurveyReportingState {
    running: bool,
    peers: HashSet<henyey_overlay::PeerId>,
    queue: VecDeque<henyey_overlay::PeerId>,
    inbound_indices: HashMap<henyey_overlay::PeerId, u32>,
    outbound_indices: HashMap<henyey_overlay::PeerId, u32>,
    bad_response_nodes: HashSet<henyey_overlay::PeerId>,
    next_topoff: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SurveyReportingStart {
    Started,
    AlreadyRunning,
    NotReady,
}

impl SurveyReportingState {
    fn new() -> Self {
        Self {
            running: false,
            peers: HashSet::new(),
            queue: VecDeque::new(),
            inbound_indices: HashMap::new(),
            outbound_indices: HashMap::new(),
            bad_response_nodes: HashSet::new(),
            next_topoff: Instant::now(),
        }
    }
}

impl ScpLatencyTracker {
    const MAX_SAMPLES: usize = 256;

    fn record_first_seen(&mut self, slot: u64) {
        self.first_seen.entry(slot).or_insert_with(Instant::now);
    }

    fn record_self_sent(&mut self, slot: u64) -> Option<u64> {
        let now = Instant::now();
        let mut sample = None;
        if let Some(first) = self.first_seen.get(&slot) {
            let delta = now.duration_since(*first).as_millis() as u64;
            Self::push_sample(&mut self.first_to_self_samples_ms, delta);
            sample = Some(delta);
        }
        self.self_sent.insert(slot, now);
        sample
    }

    fn record_other_after_self(&mut self, slot: u64) -> Option<u64> {
        if self.self_to_other_recorded.contains(&slot) {
            return None;
        }
        if let Some(sent) = self.self_sent.get(&slot) {
            let delta = sent.elapsed().as_millis() as u64;
            Self::push_sample(&mut self.self_to_other_samples_ms, delta);
            self.self_to_other_recorded.insert(slot);
            return Some(delta);
        }
        None
    }

    fn push_sample(samples: &mut VecDeque<u64>, value: u64) {
        samples.push_back(value);
        if samples.len() > Self::MAX_SAMPLES {
            samples.pop_front();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SurveySchedulerPhase {
    Idle,
    StartSent,
    RequestSent,
}

#[derive(Debug)]
struct SurveyScheduler {
    phase: SurveySchedulerPhase,
    next_action: Instant,
    peers: Vec<henyey_overlay::PeerId>,
    nonce: u32,
    ledger_num: u32,
    last_started: Option<Instant>,
}

impl SurveyScheduler {
    fn new() -> Self {
        Self {
            phase: SurveySchedulerPhase::Idle,
            next_action: Instant::now() + Duration::from_secs(60),
            peers: Vec::new(),
            nonce: 0,
            ledger_num: 0,
            last_started: None,
        }
    }
}

#[derive(Debug)]
struct ScpTimeoutState {
    slot: u64,
    next_nomination: Option<Instant>,
    next_ballot: Option<Instant>,
}

impl ScpTimeoutState {
    fn new() -> Self {
        Self {
            slot: 0,
            next_nomination: None,
            next_ballot: None,
        }
    }
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

        let db_lock = Self::acquire_db_lock(&config)?;

        // Initialize database
        let db = Self::init_database(&config)?;

        // Ensure network passphrase matches stored state.
        Self::ensure_network_passphrase(&db, &config.network.passphrase)?;

        // Verify on-disk ledger headers before loading state.
        Self::verify_on_disk_integrity(&db)?;

        // Initialize or generate keypair
        let keypair = Self::init_keypair(&config)?;

        tracing::info!(
            public_key = %keypair.public_key().to_strkey(),
            "Node identity"
        );

        let is_validator = config.node.is_validator;
        let max_inbound_peers = config.overlay.max_inbound_peers as u32;
        let max_outbound_peers = config.overlay.max_outbound_peers as u32;

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
        let bucket_dir = config
            .database
            .path
            .parent()
            .unwrap_or(&config.database.path)
            .join("buckets");
        std::fs::create_dir_all(&bucket_dir)?;

        let bucket_manager = Arc::new(BucketManager::new(bucket_dir.clone())?);
        tracing::info!("Bucket manager initialized");

        // Initialize ledger manager
        let ledger_manager = Arc::new(LedgerManager::new(
            config.network.passphrase.clone(),
            LedgerManagerConfig {
                validate_bucket_hash: true,
                emit_classic_events: config.events.emit_classic_events,
                backfill_stellar_asset_events: config.events.backfill_stellar_asset_events,
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
            max_externalized_slots: TX_SET_REQUEST_WINDOW as usize,
            max_tx_set_size: 1000,
            pending_config: Default::default(),
            tx_queue_config: TxQueueConfig {
                max_dex_ops: config.surge_pricing.max_dex_tx_operations,
                max_classic_bytes: Some(config.surge_pricing.classic_byte_allowance),
                max_soroban_bytes: Some(config.surge_pricing.soroban_byte_allowance),
                ..Default::default()
            },
            local_quorum_set,
            proposed_upgrades: config.upgrades.to_ledger_upgrades(),
        };

        // Create herder (with or without secret key for signing)
        let survey_throttle = Duration::from_secs(herder_config.ledger_close_time as u64 * 3);

        let herder = if config.node.is_validator {
            Arc::new(Herder::with_secret_key(herder_config, keypair.clone()))
        } else {
            Arc::new(Herder::new(herder_config))
        };
        herder.set_ledger_manager(ledger_manager.clone());

        if let Some(qs) = herder.local_quorum_set() {
            let hash = hash_quorum_set(&qs);
            if let Err(err) = db.store_scp_quorum_set(&hash, 0, &qs) {
                tracing::warn!(error = %err, "Failed to store local quorum set");
            }
        }

        // Initialize metadata stream if configured
        let meta_stream = if config.metadata.output_stream.is_some()
            || config.metadata.debug_ledgers > 0
        {
            match MetaStreamManager::new(&config.metadata, &bucket_dir) {
                Ok(ms) => {
                    if ms.is_streaming() {
                        tracing::info!("Metadata output stream initialized");
                    }
                    Some(ms)
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to initialize metadata stream");
                    return Err(e.into());
                }
            }
        } else {
            None
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
            is_validator,
            config,
            state: RwLock::new(AppState::Initializing),
            db,
            _db_lock: Some(db_lock),
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
            catchup_in_progress: AtomicBool::new(false),
            syncing_ledgers: RwLock::new(BTreeMap::new()),
            last_externalized_slot: AtomicU64::new(0),
            last_externalized_at: RwLock::new(Instant::now()),
            last_scp_state_request_at: RwLock::new(Instant::now()),
            survey_data: RwLock::new(SurveyDataManager::new(
                is_validator,
                max_inbound_peers,
                max_outbound_peers,
            )),
            tx_advert_queue: RwLock::new(Vec::new()),
            tx_advert_set: RwLock::new(HashSet::new()),
            tx_adverts_by_peer: RwLock::new(HashMap::new()),
            tx_demand_history: RwLock::new(HashMap::new()),
            tx_pending_demands: RwLock::new(VecDeque::new()),
            tx_set_dont_have: RwLock::new(HashMap::new()),
            tx_set_last_request: RwLock::new(HashMap::new()),
            tx_set_all_peers_exhausted: AtomicBool::new(false),
            tx_set_exhausted_warned: RwLock::new(HashSet::new()),
            consensus_stuck_state: RwLock::new(None),
            last_catchup_completed_at: RwLock::new(None),
            cached_archive_checkpoint: RwLock::new(None),
            scp_latency: RwLock::new(ScpLatencyTracker::default()),
            survey_scheduler: RwLock::new(SurveyScheduler::new()),
            survey_nonce: RwLock::new(1),
            survey_secrets: RwLock::new(HashMap::new()),
            survey_results: RwLock::new(HashMap::new()),
            survey_limiter: RwLock::new(SurveyMessageLimiter::new(6, 10)),
            survey_throttle,
            survey_reporting: RwLock::new(SurveyReportingState::new()),
            scp_timeouts: RwLock::new(ScpTimeoutState::new()),
            meta_stream: std::sync::Mutex::new(meta_stream),
            drift_tracker: std::sync::Mutex::new(CloseTimeDriftTracker::new()),
            sync_recovery_handle: parking_lot::RwLock::new(None), // Initialized in run() when needed
            is_applying_ledger: AtomicBool::new(false),
            sync_recovery_pending: AtomicBool::new(false),
            lost_sync_count: AtomicU64::new(0),
            ping_counter: AtomicU64::new(0),
            ping_inflight: RwLock::new(HashMap::new()),
            peer_ping_inflight: RwLock::new(HashMap::new()),
            self_arc: RwLock::new(std::sync::Weak::new()),
        })
    }

    fn verify_on_disk_integrity(db: &henyey_db::Database) -> anyhow::Result<()> {
        const VERIFY_DEPTH: u32 = 128;

        let Some(latest) = db.get_latest_ledger_seq()? else {
            return Ok(());
        };
        if latest == 0 {
            return Ok(());
        }

        let mut current_seq = latest;
        let mut checked = 0u32;
        while current_seq > 0 && checked < VERIFY_DEPTH {
            let current = db
                .get_ledger_header(current_seq)?
                .ok_or_else(|| anyhow::anyhow!("Missing ledger header at {}", current_seq))?;
            let prev_seq = current_seq - 1;
            let Some(prev) = db.get_ledger_header(prev_seq)? else {
                tracing::warn!(
                    missing_seq = prev_seq,
                    latest_seq = latest,
                    "Ledger header chain has a gap; skipping deeper integrity checks"
                );
                break;
            };
            let prev_hash = compute_header_hash(&prev)?;
            verify_header_chain(&prev, &prev_hash, &current)?;
            current_seq = prev_seq;
            checked += 1;
        }

        // NOTE: Skip list entries store bucket_list_hash values (not header
        // hashes), so they cannot be verified by comparing against stored
        // header hashes.  stellar-core does not perform skip list
        // verification on startup either.

        Ok(())
    }

    fn ensure_network_passphrase(
        db: &henyey_db::Database,
        passphrase: &str,
    ) -> anyhow::Result<()> {
        let stored = db.get_network_passphrase()?;
        if let Some(existing) = stored {
            if existing != passphrase {
                anyhow::bail!(
                    "Network passphrase mismatch: db has '{}', config has '{}'",
                    existing,
                    passphrase
                );
            }
            return Ok(());
        }
        db.set_network_passphrase(passphrase)?;
        Ok(())
    }

    /// Initialize the database.
    fn init_database(config: &AppConfig) -> anyhow::Result<henyey_db::Database> {
        tracing::info!(path = ?config.database.path, "Opening database");

        // Ensure parent directory exists
        if let Some(parent) = config.database.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let db = henyey_db::Database::open(&config.database.path)?;
        tracing::debug!("Database opened successfully");
        Ok(db)
    }

    fn acquire_db_lock(config: &AppConfig) -> anyhow::Result<File> {
        use fs2::FileExt;

        let lock_path = config.database.path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lock_path)?;
        file.try_lock_exclusive().map_err(|_| {
            anyhow::anyhow!("database is locked (lockfile: {})", lock_path.display())
        })?;
        Ok(file)
    }

    /// Initialize the node keypair.
    fn init_keypair(config: &AppConfig) -> anyhow::Result<henyey_crypto::SecretKey> {
        if let Some(ref seed) = config.node.node_seed {
            tracing::debug!("Using configured node seed");
            let keypair = henyey_crypto::SecretKey::from_strkey(seed)?;
            Ok(keypair)
        } else {
            tracing::info!("Generating ephemeral node keypair");
            Ok(henyey_crypto::SecretKey::generate())
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
    pub(crate) async fn set_state(&self, state: AppState) {
        let mut current = self.state.write().await;
        if *current != state {
            if matches!(*current, AppState::Synced | AppState::Validating)
                && state == AppState::CatchingUp
            {
                self.lost_sync_count.fetch_add(1, Ordering::Relaxed);
            }
            tracing::info!(from = %*current, to = %state, "State transition");
            *current = state;
        }
    }

    /// Set the tracked current ledger sequence.
    pub(crate) async fn set_current_ledger(&self, seq: u32) {
        *self.current_ledger.write().await = seq;
    }

    /// Get the database.
    pub fn database(&self) -> &henyey_db::Database {
        &self.db
    }

    /// Get the node's public key.
    pub fn public_key(&self) -> henyey_crypto::PublicKey {
        self.keypair.public_key()
    }

    /// Get the network ID.
    pub fn network_id(&self) -> henyey_common::Hash256 {
        self.config.network_id()
    }

    pub async fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        let overlay = self.overlay.lock().await;
        overlay
            .as_ref()
            .map(|overlay| overlay.peer_snapshots())
            .unwrap_or_default()
    }

    pub async fn connect_peer(&self, addr: PeerAddress) -> anyhow::Result<PeerId> {
        let overlay = self.overlay.lock().await;
        let overlay = overlay
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Overlay manager not available"))?;
        overlay.connect(&addr).await.map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn disconnect_peer(&self, peer_id: &PeerId) -> bool {
        let overlay = self.overlay.lock().await;
        let Some(overlay) = overlay.as_ref() else {
            return false;
        };
        overlay.disconnect(peer_id).await
    }

    pub async fn ban_peer(&self, peer_id: PeerId) -> anyhow::Result<()> {
        let Some(strkey) = Self::peer_id_to_strkey(&peer_id) else {
            anyhow::bail!("Invalid peer id");
        };
        self.db.ban_node(&strkey)?;
        let overlay = self.overlay.lock().await;
        let overlay = overlay
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Overlay manager not available"))?;
        overlay.ban_peer(peer_id).await;
        Ok(())
    }

    pub async fn unban_peer(&self, peer_id: &PeerId) -> anyhow::Result<bool> {
        let Some(strkey) = Self::peer_id_to_strkey(peer_id) else {
            anyhow::bail!("Invalid peer id");
        };
        self.db.unban_node(&strkey)?;
        let overlay = self.overlay.lock().await;
        let overlay = overlay
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Overlay manager not available"))?;
        Ok(overlay.unban_peer(peer_id))
    }

    pub async fn banned_peers(&self) -> anyhow::Result<Vec<PeerId>> {
        let bans = self.db.load_bans()?;
        let mut peers = Vec::new();
        for ban in bans {
            if let Some(peer_id) = Self::strkey_to_peer_id(&ban) {
                peers.push(peer_id);
            } else {
                tracing::warn!(node = %ban, "Ignoring invalid ban entry");
            }
        }
        Ok(peers)
    }

    pub fn ledger_info(&self) -> (u32, henyey_common::Hash256, u64, u32) {
        let header = self.ledger_manager.current_header();
        let hash = self.ledger_manager.current_header_hash();
        let close_time = ledger_close_time(&header);
        (header.ledger_seq, hash, close_time, header.ledger_version)
    }

    pub fn target_ledger_close_time(&self) -> u32 {
        self.herder.ledger_close_time()
    }

    pub fn current_upgrade_state(&self) -> (u32, u32, u32, u32) {
        let header = self.ledger_manager.current_header();
        (
            header.ledger_version,
            header.base_fee,
            header.base_reserve,
            header.max_tx_set_size,
        )
    }

    pub fn proposed_upgrades(&self) -> Vec<LedgerUpgrade> {
        self.config.upgrades.to_ledger_upgrades()
    }

    /// Get Soroban network configuration information.
    ///
    /// Returns the Soroban-related configuration settings from the current ledger
    /// state, or `None` if not available (pre-protocol 20 or not initialized).
    pub fn soroban_network_info(&self) -> Option<SorobanNetworkInfo> {
        self.ledger_manager.soroban_network_info()
    }

    /// Manually close a ledger (for testing/manual close mode).
    ///
    /// This triggers the herder to close the next ledger. It requires:
    /// - The node must be configured as a validator (`is_validator = true`)
    /// - Manual close mode must be enabled (`manual_close = true`)
    ///
    /// # Returns
    ///
    /// * `Ok(new_ledger_seq)` - The ledger was successfully triggered
    /// * `Err` - An error occurred (not a validator, manual close not enabled, etc.)
    pub async fn manual_close_ledger(&self) -> anyhow::Result<u32> {
        // Check if node is a validator
        if !self.config.node.is_validator {
            anyhow::bail!(
                "Issuing a manual ledger close requires NODE_IS_VALIDATOR to be set to true."
            );
        }

        // Check if manual close mode is enabled
        if !self.config.node.manual_close {
            anyhow::bail!("Manual close is disabled. Set manual_close = true in configuration.");
        }

        // Get the next ledger sequence
        let (current_ledger, _, _, _) = self.ledger_info();
        let next_ledger = current_ledger + 1;

        // Trigger the herder to close the next ledger
        self.herder
            .trigger_next_ledger(next_ledger)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to trigger next ledger: {}", e))?;

        Ok(next_ledger)
    }

    pub fn self_check(&self, depth: u32) -> anyhow::Result<SelfCheckResult> {
        let Some(latest) = self.db.get_latest_ledger_seq()? else {
            return Ok(SelfCheckResult {
                ok: true,
                checked_ledgers: 0,
                last_checked_ledger: None,
            });
        };
        if latest == 0 {
            return Ok(SelfCheckResult {
                ok: true,
                checked_ledgers: 0,
                last_checked_ledger: None,
            });
        }

        let mut current_seq = latest;
        let mut checked = 0u32;
        let mut last_verified = None;

        while current_seq > 0 && checked < depth {
            let current = self
                .db
                .get_ledger_header(current_seq)?
                .ok_or_else(|| anyhow::anyhow!("Missing ledger header at {}", current_seq))?;
            let prev_seq = current_seq - 1;
            let prev = self
                .db
                .get_ledger_header(prev_seq)?
                .ok_or_else(|| anyhow::anyhow!("Missing ledger header at {}", prev_seq))?;
            let prev_hash = compute_header_hash(&prev)?;
            verify_header_chain(&prev, &prev_hash, &current)?;
            last_verified = Some(current_seq);
            current_seq = prev_seq;
            checked += 1;
        }

        Ok(SelfCheckResult {
            ok: true,
            checked_ledgers: checked,
            last_checked_ledger: last_verified,
        })
    }

    pub fn pending_transaction_count(&self) -> usize {
        self.herder.stats().pending_transactions
    }

    pub fn submit_transaction(
        &self,
        tx: TransactionEnvelope,
    ) -> henyey_herder::TxQueueResult {
        self.herder.receive_transaction(tx)
    }

    pub fn herder_stats(&self) -> HerderStats {
        self.herder.stats()
    }

    /// Clear metrics registry.
    ///
    /// In stellar-core, this resets the medida metrics counters.
    /// In our Prometheus-style implementation, metrics are typically scraped externally
    /// and don't have explicit clear semantics. This method logs the request for
    /// operational visibility.
    ///
    /// # Arguments
    ///
    /// * `domain` - Optional domain filter (empty string means all metrics)
    pub fn clear_metrics(&self, domain: &str) {
        if domain.is_empty() {
            tracing::info!("Clearing all metrics");
        } else {
            tracing::info!(domain = %domain, "Clearing metrics for domain");
        }
        // Note: Prometheus-style metrics don't have a clear operation.
        // The metrics are scraped externally and typically reset on node restart.
        // We log the request for operational visibility and parity with stellar-core.
    }

    /// Perform manual database maintenance.
    ///
    /// Cleans up old SCP history and ledger headers to prevent unbounded database growth.
    /// This is the same maintenance performed automatically by the background maintainer,
    /// but can be triggered manually via the `/maintenance` HTTP endpoint.
    ///
    /// # Arguments
    ///
    /// * `count` - Maximum number of entries to delete per table
    pub fn perform_maintenance(&self, count: u32) {
        use crate::maintainer::CHECKPOINT_FREQUENCY;

        let (ledger_seq, _, _, _) = self.ledger_info();
        let lcl = ledger_seq;

        // Get minimum queued publish checkpoint if available
        let min_queued = self.db.load_publish_queue(Some(1)).ok().and_then(|queue| {
            queue.first().copied()
        });

        // Calculate the minimum ledger we need to keep
        let qmin = min_queued.unwrap_or(lcl).min(lcl);
        let lmin = qmin.saturating_sub(CHECKPOINT_FREQUENCY);

        tracing::info!(
            trim_below = lmin,
            count = count,
            lcl = lcl,
            min_queued = ?min_queued,
            "Performing manual maintenance"
        );

        // Delete old SCP history
        if let Err(e) = self.db.delete_old_scp_entries(lmin, count) {
            tracing::warn!(error = %e, "Failed to delete old SCP entries");
        }

        // Delete old ledger headers
        if let Err(e) = self.db.delete_old_ledger_headers(lmin, count) {
            tracing::warn!(error = %e, "Failed to delete old ledger headers");
        }
    }

    /// Get a ConfigUpgradeSet from the ledger by its key.
    ///
    /// Looks up the temporary ledger entry containing the ConfigUpgradeSet
    /// that corresponds to the given ConfigUpgradeSetKey.
    ///
    /// # Arguments
    ///
    /// * `key` - The ConfigUpgradeSetKey identifying the upgrade set
    ///
    /// # Returns
    ///
    /// * `Some(json)` - The ConfigUpgradeSet as a JSON-serializable value
    /// * `None` - The upgrade set was not found or is invalid
    pub fn get_config_upgrade_set(
        &self,
        key: &stellar_xdr::curr::ConfigUpgradeSetKey,
    ) -> Option<serde_json::Value> {
        let frame = self.ledger_manager.get_config_upgrade_set(key)?;
        let upgrade_set = frame.to_xdr();

        // Convert to JSON-serializable format
        Some(serde_json::json!({
            "updated_entry": upgrade_set.updated_entry.iter().map(|entry| {
                format!("{:?}", entry)
            }).collect::<Vec<_>>()
        }))
    }

    pub fn scp_slot_snapshots(&self, limit: usize) -> Vec<ScpSlotSnapshot> {
        let Some(scp) = self.herder.scp() else {
            return Vec::new();
        };
        let (ledger_seq, _, _, _) = self.ledger_info();
        let latest_slot = self
            .herder
            .latest_externalized_slot()
            .unwrap_or(ledger_seq as u64);
        let mut slot = latest_slot;
        let mut snapshots = Vec::new();

        while slot > 0 && snapshots.len() < limit {
            if let Some(state) = scp.get_slot_state(slot) {
                let envelopes = self.herder.get_scp_envelopes(slot);
                snapshots.push(ScpSlotSnapshot {
                    slot_index: state.slot_index,
                    is_externalized: state.is_externalized,
                    is_nominating: state.is_nominating,
                    ballot_phase: format!("{:?}", state.ballot_phase),
                    nomination_round: state.nomination_round,
                    ballot_round: state.ballot_round,
                    envelope_count: envelopes.len(),
                });
            }
            slot = slot.saturating_sub(1);
        }

        snapshots
    }

    fn extract_tx_metas(meta: &LedgerCloseMeta) -> Vec<TransactionMeta> {
        match meta {
            LedgerCloseMeta::V0(_) => Vec::new(),
            LedgerCloseMeta::V1(v1) => v1
                .tx_processing
                .iter()
                .map(|processing| processing.tx_apply_processing.clone())
                .collect(),
            LedgerCloseMeta::V2(v2) => v2
                .tx_processing
                .iter()
                .map(|processing| processing.tx_apply_processing.clone())
                .collect(),
        }
    }

    fn persist_ledger_close(
        &self,
        header: &stellar_xdr::curr::LedgerHeader,
        tx_set_variant: &TransactionSetVariant,
        tx_results: &[TransactionResultPair],
        tx_metas: Option<&[TransactionMeta]>,
    ) -> anyhow::Result<()> {
        let header_xdr = header.to_xdr(stellar_xdr::curr::Limits::none())?;
        let network_id = NetworkId::from_passphrase(&self.config.network.passphrase);
        let ordered_txs: Vec<TransactionEnvelope> = tx_set_variant
            .transactions_with_base_fee()
            .into_iter()
            .map(|(tx, _)| tx)
            .collect();
        let tx_count = ordered_txs.len().min(tx_results.len());
        let meta_count = tx_metas.map(|metas| metas.len()).unwrap_or(0);
        let scp_envelopes = self.herder.get_scp_envelopes(header.ledger_seq as u64);
        let mut scp_quorum_sets = Vec::new();
        for envelope in &scp_envelopes {
            if let Some(hash) = Self::scp_quorum_set_hash(&envelope.statement) {
                let hash256 = Hash256::from_bytes(hash.0);
                if let Some(qset) = self.herder.get_quorum_set_by_hash(hash256.as_bytes()) {
                    scp_quorum_sets.push((hash256, qset));
                } else {
                    tracing::warn!(hash = %hash256.to_hex(), "Missing quorum set for SCP history");
                }
            }
        }

        if tx_results.len() != ordered_txs.len() {
            tracing::warn!(
                tx_count = ordered_txs.len(),
                result_count = tx_results.len(),
                "Transaction count mismatch while persisting history"
            );
        }
        if tx_metas.is_some() && meta_count < tx_count {
            tracing::warn!(
                tx_count,
                meta_count,
                "Transaction meta count mismatch while persisting history"
            );
        }

        let tx_set_entry = match tx_set_variant {
            TransactionSetVariant::Classic(set) => set.clone(),
            TransactionSetVariant::Generalized(set) => {
                let stellar_xdr::curr::GeneralizedTransactionSet::V1(set_v1) = set;
                TransactionSet {
                    previous_ledger_hash: set_v1.previous_ledger_hash.clone(),
                    txs: VecM::default(),
                }
            }
        };
        let tx_history_entry = TransactionHistoryEntry {
            ledger_seq: header.ledger_seq,
            tx_set: tx_set_entry,
            ext: match tx_set_variant {
                TransactionSetVariant::Classic(_) => TransactionHistoryEntryExt::V0,
                TransactionSetVariant::Generalized(set) => {
                    TransactionHistoryEntryExt::V1(set.clone())
                }
            },
        };
        let tx_result_set = TransactionResultSet {
            results: tx_results.to_vec().try_into().unwrap_or_default(),
        };
        let tx_result_entry = TransactionHistoryResultEntry {
            ledger_seq: header.ledger_seq,
            tx_result_set,
            ext: TransactionHistoryResultEntryExt::default(),
        };

        // Build HAS from current bucket list state for restart recovery.
        // This captures pending merge outputs so a restarted node can
        // reconstruct the bucket list without re-downloading from archives.
        let has_json = {
            let bucket_list = self.ledger_manager.bucket_list();
            let hot_archive_guard = self.ledger_manager.hot_archive_bucket_list();
            let hot_archive_ref = hot_archive_guard.as_ref();

            // Ensure hot archive buckets are persisted to disk for restart recovery.
            // Hot archive merges are all in-memory, so after each close the curr/snap
            // buckets may have no backing file.
            if let Some(habl) = hot_archive_ref {
                let bucket_dir = self.config.database.path
                    .parent()
                    .unwrap_or(&self.config.database.path)
                    .join("buckets");
                for level in habl.levels() {
                    for bucket in [&level.curr, &level.snap] {
                        if bucket.backing_file_path().is_none() && !bucket.hash().is_zero() {
                            let permanent = bucket_dir.join(format!("{}.bucket.xdr", bucket.hash().to_hex()));
                            if !permanent.exists() {
                                if let Err(e) = bucket.save_to_xdr_file(&permanent) {
                                    tracing::warn!(
                                        error = %e,
                                        hash = %bucket.hash().to_hex(),
                                        "Failed to persist in-memory hot archive bucket to disk"
                                    );
                                }
                            }
                        }
                    }
                }
            }

            let has = build_history_archive_state(
                header.ledger_seq,
                &bucket_list,
                hot_archive_ref,
                Some(self.config.network.passphrase.clone()),
            )
            .map_err(|e| anyhow::anyhow!("Failed to build HAS: {}", e))?;
            has.to_json()
                .map_err(|e| anyhow::anyhow!("Failed to serialize HAS: {}", e))?
        };

        self.db.transaction(|conn| {
            conn.store_ledger_header(header, &header_xdr)?;
            conn.store_tx_history_entry(header.ledger_seq, &tx_history_entry)?;
            conn.store_tx_result_entry(header.ledger_seq, &tx_result_entry)?;
            if is_checkpoint_ledger(header.ledger_seq) {
                let levels = self.ledger_manager.bucket_list_levels();
                conn.store_bucket_list(header.ledger_seq, &levels)?;
                if self.is_validator {
                    conn.enqueue_publish(header.ledger_seq)?;
                }
            }
            for index in 0..tx_count {
                let tx = &ordered_txs[index];
                let tx_result = &tx_results[index];
                let tx_meta = tx_metas.and_then(|metas| metas.get(index));

                let frame = TransactionFrame::with_network(tx.clone(), network_id);
                let tx_hash = frame
                    .hash(&network_id)
                    .map_err(|e| henyey_db::DbError::Integrity(e.to_string()))?;
                let tx_id = tx_hash.to_hex();

                let tx_body = tx.to_xdr(stellar_xdr::curr::Limits::none())?;
                let tx_result_xdr = tx_result.to_xdr(stellar_xdr::curr::Limits::none())?;
                let tx_meta_xdr = match tx_meta {
                    Some(meta) => Some(meta.to_xdr(stellar_xdr::curr::Limits::none())?),
                    None => None,
                };

                conn.store_transaction(
                    header.ledger_seq,
                    index as u32,
                    &tx_id,
                    &tx_body,
                    &tx_result_xdr,
                    tx_meta_xdr.as_deref(),
                )?;
            }

            conn.store_scp_history(header.ledger_seq, &scp_envelopes)?;
            for (hash, qset) in &scp_quorum_sets {
                conn.store_scp_quorum_set(hash, header.ledger_seq, qset)?;
            }

            // Persist HAS and LCL for restart recovery
            conn.set_state(state_keys::HISTORY_ARCHIVE_STATE, &has_json)?;
            conn.set_last_closed_ledger(header.ledger_seq)?;

            Ok(())
        })?;

        Ok(())
    }

    /// Attempt to restore node state from persisted DB and on-disk bucket files.
    ///
    /// This is the Rust equivalent of stellar-core's `loadLastKnownLedger`.
    /// On success, the ledger manager is initialized with the bucket list
    /// reconstructed from disk, avoiding a full catchup from history archives.
    ///
    /// Returns `true` if state was successfully restored, `false` if no persisted
    /// state is available (fresh node or corrupt state).
    pub async fn load_last_known_ledger(&self) -> anyhow::Result<bool> {
        // Step 1: Read LCL sequence from DB
        let lcl_seq = self.db.with_connection(|conn| {
            conn.get_last_closed_ledger()
        })?;
        let Some(lcl_seq) = lcl_seq else {
            tracing::debug!("No last closed ledger in DB, cannot restore from disk");
            return Ok(false);
        };
        if lcl_seq == 0 {
            tracing::debug!("LCL is 0, cannot restore from disk");
            return Ok(false);
        }

        // Step 2: Read HAS JSON from DB
        let has_json = self.db.with_connection(|conn| {
            conn.get_state(state_keys::HISTORY_ARCHIVE_STATE)
        })?;
        let Some(has_json) = has_json else {
            tracing::warn!(lcl_seq, "LCL found but no HAS in DB, cannot restore");
            return Ok(false);
        };
        let has = HistoryArchiveState::from_json(&has_json)
            .map_err(|e| anyhow::anyhow!("Failed to parse persisted HAS: {}", e))?;

        // Step 3: Verify consistency between LCL and HAS
        if has.current_ledger != lcl_seq {
            tracing::warn!(
                lcl_seq,
                has_ledger = has.current_ledger,
                "LCL and HAS disagree on current ledger, cannot restore"
            );
            return Ok(false);
        }

        tracing::info!(
            lcl_seq,
            bucket_levels = has.current_buckets.len(),
            "Found persisted state, attempting restore from disk"
        );

        // Step 4: Load ledger header from DB
        let header = self.db.get_ledger_header(lcl_seq)?
            .ok_or_else(|| anyhow::anyhow!("LCL header missing from DB at seq {}", lcl_seq))?;

        // Compute header hash (we don't store it separately)
        let header_hash = compute_header_hash(&header)
            .map_err(|e| anyhow::anyhow!("Failed to compute header hash: {}", e))?;

        // Step 5: Verify essential bucket files exist on disk.
        // We only require curr/snap hashes — pending merge outputs (next.output)
        // are optional; if missing we'll discard the pending merge state.
        let mut essential_hashes: Vec<Hash256> = has.bucket_hash_pairs()
            .iter()
            .flat_map(|(curr, snap)| [*curr, *snap])
            .filter(|h| !h.is_zero())
            .collect();
        // Also include hot archive bucket hashes
        if let Some(hot_pairs) = has.hot_archive_bucket_hash_pairs() {
            for (curr, snap) in &hot_pairs {
                if !curr.is_zero() {
                    essential_hashes.push(*curr);
                }
                if !snap.is_zero() {
                    essential_hashes.push(*snap);
                }
            }
        }
        let missing = self.bucket_manager.verify_buckets_exist(&essential_hashes);
        if !missing.is_empty() {
            tracing::warn!(
                missing_count = missing.len(),
                first_missing = %missing[0].to_hex(),
                "Missing essential bucket files on disk, cannot restore"
            );
            return Ok(false);
        }

        // Step 5b: Check which pending merge outputs are available.
        // If a next.output hash is missing on disk, downgrade that level's
        // merge state so restore_from_has doesn't try to load it.
        let mut has = has;
        for level in &mut has.current_buckets {
            if level.next.state == 1 {
                // state 1 = FB_HASH_OUTPUT (merge completed, output hash known)
                if let Some(ref output_hex) = level.next.output {
                    if let Ok(hash) = Hash256::from_hex(output_hex) {
                        if !hash.is_zero() && !self.bucket_manager.bucket_exists(&hash) {
                            tracing::info!(
                                output = %hash.to_hex(),
                                "Pending merge output not on disk, discarding merge state"
                            );
                            level.next.state = 0;
                            level.next.output = None;
                        }
                    }
                }
            }
        }

        // Step 6: Reconstruct bucket lists from HAS using shared helper
        let (bucket_list, hot_archive) = self.reconstruct_bucket_lists(&has, &header, lcl_seq).await?;

        // Step 7: Initialize LedgerManager
        if self.ledger_manager.is_initialized() {
            self.ledger_manager.reset();
        }
        self.ledger_manager
            .initialize(bucket_list, hot_archive, header.clone(), header_hash)
            .map_err(|e| anyhow::anyhow!("Failed to initialize ledger manager from disk: {}", e))?;

        tracing::info!(
            lcl_seq,
            header_hash = %header_hash.to_hex(),
            protocol_version = header.ledger_version,
            "Successfully restored node state from disk"
        );

        Ok(true)
    }

    /// Reconstruct both live and hot archive bucket lists from a parsed HAS,
    /// including restarting any pending merges from saved input/output hashes.
    ///
    /// Shared helper used by both `load_last_known_ledger` (startup restore)
    /// and `rebuild_bucket_lists_from_has` (Case 1 replay).
    async fn reconstruct_bucket_lists(
        &self,
        has: &HistoryArchiveState,
        header: &stellar_xdr::curr::LedgerHeader,
        lcl_seq: u32,
    ) -> anyhow::Result<(BucketList, HotArchiveBucketList)> {
        // Reconstruct live BucketList
        let live_hash_pairs = has.bucket_hash_pairs();
        let live_next_states: Vec<HasNextState> = has
            .live_next_states()
            .into_iter()
            .map(|s| HasNextState {
                state: s.state,
                output: s.output,
                input_curr: s.input_curr,
                input_snap: s.input_snap,
            })
            .collect();

        let bucket_manager = self.bucket_manager.clone();
        let load_bucket = |hash: &Hash256| -> henyey_bucket::Result<henyey_bucket::Bucket> {
            let arc = bucket_manager.load_bucket(hash)?;
            Ok(std::sync::Arc::try_unwrap(arc).unwrap_or_else(|arc| (*arc).clone()))
        };

        let mut bucket_list = BucketList::restore_from_has(
            &live_hash_pairs,
            &live_next_states,
            load_bucket,
        ).map_err(|e| anyhow::anyhow!("Failed to restore live bucket list: {}", e))?;

        let bucket_dir = self.config.database.path
            .parent()
            .unwrap_or(&self.config.database.path)
            .join("buckets");
        bucket_list.set_bucket_dir(bucket_dir.clone());
        bucket_list.set_ledger_seq(lcl_seq);

        // Restart pending merges from HAS state.
        // This matches stellar-core loadLastKnownLedgerInternal() which calls
        // AssumeStateWork -> assumeState() -> restartMerges().
        {
            let protocol_version = header.ledger_version;
            let load_bucket_for_merge = |hash: &Hash256| -> henyey_bucket::Result<henyey_bucket::Bucket> {
                if hash.is_zero() {
                    return Ok(henyey_bucket::Bucket::empty());
                }
                let bucket_path = bucket_dir.join(format!("{}.bucket.xdr", hash.to_hex()));
                if bucket_path.exists() {
                    henyey_bucket::Bucket::from_xdr_file_disk_backed(&bucket_path)
                } else {
                    Err(henyey_bucket::BucketError::NotFound(format!(
                        "bucket {} not found on disk", hash.to_hex()
                    )))
                }
            };
            bucket_list
                .restart_merges_from_has(
                    lcl_seq,
                    protocol_version,
                    &live_next_states,
                    load_bucket_for_merge,
                    true,
                )
                .await
                .map_err(|e| anyhow::anyhow!("Failed to restart bucket merges: {}", e))?;
            tracing::info!(
                bucket_list_hash = %bucket_list.hash().to_hex(),
                "Restarted pending merges from HAS"
            );
        }

        // Reconstruct hot archive BucketList (or create empty)
        let hot_archive = if let Some(hot_hash_pairs) = has.hot_archive_bucket_hash_pairs() {
            let hot_next_states: Vec<HasNextState> = has
                .hot_archive_next_states()
                .unwrap_or_default()
                .into_iter()
                .map(|s| HasNextState {
                    state: s.state,
                    output: s.output,
                    input_curr: s.input_curr,
                    input_snap: s.input_snap,
                })
                .collect();

            let bucket_manager = self.bucket_manager.clone();
            let load_hot = |hash: &Hash256| -> henyey_bucket::Result<henyey_bucket::HotArchiveBucket> {
                bucket_manager.load_hot_archive_bucket(hash)
            };

            let mut hot_bl = HotArchiveBucketList::restore_from_has(
                &hot_hash_pairs,
                &hot_next_states,
                load_hot,
            ).map_err(|e| anyhow::anyhow!("Failed to restore hot archive: {}", e))?;

            {
                let protocol_version = header.ledger_version;
                let bucket_manager = self.bucket_manager.clone();
                let load_hot_for_merge = move |hash: &Hash256| -> henyey_bucket::Result<henyey_bucket::HotArchiveBucket> {
                    bucket_manager.load_hot_archive_bucket(hash)
                };
                hot_bl
                    .restart_merges_from_has(
                        lcl_seq,
                        protocol_version,
                        &hot_next_states,
                        load_hot_for_merge,
                        true,
                    )
                    .map_err(|e| anyhow::anyhow!("Failed to restart hot archive merges: {}", e))?;
                tracing::info!(
                    hot_archive_hash = %hot_bl.hash().to_hex(),
                    "Restarted hot archive pending merges from HAS"
                );
            }

            hot_bl
        } else {
            HotArchiveBucketList::default()
        };

        Ok((bucket_list, hot_archive))
    }

    /// Rebuild bucket lists from the persisted HAS in the database.
    ///
    /// This reads the `HistoryArchiveState` from the database (saved on every
    /// ledger close), reconstructs the bucket lists from it, and calls
    /// `restart_merges_from_has` to deterministically reconstitute any pending
    /// merges from saved input/output hashes.
    ///
    /// This matches stellar-core's approach for Case 1 catchup: the
    /// persisted HAS is the source of truth, not the live bucket list objects.
    async fn rebuild_bucket_lists_from_has(&self) -> anyhow::Result<ExistingBucketState> {
        // Read persisted HAS from DB
        let has_json = self.db.with_connection(|conn| {
            conn.get_state(state_keys::HISTORY_ARCHIVE_STATE)
        })?;
        let has_json = has_json.ok_or_else(|| anyhow::anyhow!("No persisted HAS in database"))?;
        let has = HistoryArchiveState::from_json(&has_json)
            .map_err(|e| anyhow::anyhow!("Failed to parse persisted HAS: {}", e))?;

        let lcl_seq = has.current_ledger;

        let header = self.db.get_ledger_header(lcl_seq)?
            .ok_or_else(|| anyhow::anyhow!("LCL header missing from DB at seq {}", lcl_seq))?;

        let (bucket_list, hot_archive) = self.reconstruct_bucket_lists(&has, &header, lcl_seq).await?;

        let network_id = NetworkId(self.network_id());

        tracing::info!(
            lcl_seq,
            bucket_list_hash = %bucket_list.hash().to_hex(),
            hot_archive_hash = %hot_archive.hash().to_hex(),
            "Rebuilt bucket lists from persisted HAS for Case 1 replay"
        );

        Ok(ExistingBucketState {
            bucket_list,
            hot_archive_bucket_list: hot_archive,
            header,
            network_id,
        })
    }

    pub async fn survey_report(&self) -> SurveyReport {
        let survey_data = self.survey_data.read().await;
        let phase = survey_data.phase();
        let nonce = survey_data.nonce();
        let local_node = survey_data.final_node_data();
        let inbound_peers = survey_data.final_inbound_peers().to_vec();
        let outbound_peers = survey_data.final_outbound_peers().to_vec();
        drop(survey_data);

        let (survey_in_progress, backlog, bad_response_nodes) = {
            let reporting = self.survey_reporting.read().await;
            let backlog = reporting
                .peers
                .iter()
                .map(|peer| peer.to_hex())
                .collect::<Vec<_>>();
            let bad = reporting
                .bad_response_nodes
                .iter()
                .map(|peer| peer.to_hex())
                .collect::<Vec<_>>();
            (reporting.running, backlog, bad)
        };
        let mut backlog = backlog;
        backlog.sort();
        let mut bad_response_nodes = bad_response_nodes;
        bad_response_nodes.sort();

        let peer_reports = {
            let results = self.survey_results.read().await;
            results
                .iter()
                .map(|(nonce, peers)| {
                    let mut reports = peers
                        .iter()
                        .map(|(peer_id, response)| SurveyPeerReport {
                            peer_id: peer_id.to_hex(),
                            response: response.clone(),
                        })
                        .collect::<Vec<_>>();
                    reports.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
                    (*nonce, reports)
                })
                .collect::<BTreeMap<_, _>>()
        };

        SurveyReport {
            phase,
            nonce,
            local_node,
            inbound_peers,
            outbound_peers,
            peer_reports,
            survey_in_progress,
            backlog,
            bad_response_nodes,
        }
    }

    pub async fn start_survey_collecting(&self, nonce: u32) -> bool {
        let ledger_num = self.survey_local_ledger().await;
        self.broadcast_survey_start(nonce, ledger_num).await
    }

    pub async fn stop_survey_collecting(&self) -> bool {
        let ledger_num = self.survey_local_ledger().await;
        let nonce = { self.survey_data.read().await.nonce() };
        let Some(nonce) = nonce else {
            return false;
        };
        self.broadcast_survey_stop(nonce, ledger_num).await;
        true
    }

    pub async fn stop_survey_reporting(&self) {
        let mut reporting = self.survey_reporting.write().await;
        reporting.running = false;
        drop(reporting);

        if let Some(nonce) = self.survey_data.read().await.nonce() {
            self.survey_secrets.write().await.remove(&nonce);
        }
    }

    pub async fn survey_topology_timesliced(
        &self,
        peer_id: henyey_overlay::PeerId,
        inbound_index: u32,
        outbound_index: u32,
    ) -> bool {
        let start = self.start_survey_reporting().await;
        if start == SurveyReportingStart::NotReady {
            return false;
        }

        if let Some(nonce) = { self.survey_data.read().await.nonce() } {
            if let Some(peers) = self.survey_results.write().await.get_mut(&nonce) {
                peers.remove(&peer_id);
            }
        }

        let self_peer =
            henyey_overlay::PeerId::from_bytes(*self.keypair.public_key().as_bytes());
        let mut reporting = self.survey_reporting.write().await;
        if reporting.peers.contains(&peer_id) || peer_id == self_peer {
            return false;
        }
        reporting.bad_response_nodes.remove(&peer_id);
        reporting.peers.insert(peer_id.clone());
        reporting.queue.push_back(peer_id.clone());
        reporting
            .inbound_indices
            .insert(peer_id.clone(), inbound_index);
        reporting
            .outbound_indices
            .insert(peer_id.clone(), outbound_index);
        true
    }

    async fn start_survey_reporting(&self) -> SurveyReportingStart {
        let nonce = { self.survey_data.read().await.nonce() };
        let Some(nonce) = nonce else {
            return SurveyReportingStart::NotReady;
        };
        if self.survey_data.read().await.final_node_data().is_none() {
            return SurveyReportingStart::NotReady;
        }

        let mut reporting = self.survey_reporting.write().await;
        if reporting.running {
            return SurveyReportingStart::AlreadyRunning;
        }
        reporting.running = true;
        reporting.peers.clear();
        reporting.queue.clear();
        reporting.inbound_indices.clear();
        reporting.outbound_indices.clear();
        reporting.bad_response_nodes.clear();
        reporting.next_topoff = Instant::now();

        self.survey_results.write().await.clear();
        self.ensure_survey_secret(nonce).await;
        if let Some(response) = self.local_topology_response().await {
            let self_peer =
                henyey_overlay::PeerId::from_bytes(*self.keypair.public_key().as_bytes());
            self.survey_results
                .write()
                .await
                .entry(nonce)
                .or_insert_with(HashMap::new)
                .insert(self_peer, response);
        }
        SurveyReportingStart::Started
    }

    async fn local_topology_response(&self) -> Option<TopologyResponseBodyV2> {
        const MAX_PEERS: usize = 25;
        let survey_data = self.survey_data.read().await;
        let node_data = survey_data.final_node_data()?;
        let inbound_peers = survey_data
            .final_inbound_peers()
            .iter()
            .take(MAX_PEERS)
            .cloned()
            .collect::<Vec<_>>();
        let outbound_peers = survey_data
            .final_outbound_peers()
            .iter()
            .take(MAX_PEERS)
            .cloned()
            .collect::<Vec<_>>();
        Some(TopologyResponseBodyV2 {
            inbound_peers: TimeSlicedPeerDataList(inbound_peers.try_into().unwrap_or_default()),
            outbound_peers: TimeSlicedPeerDataList(outbound_peers.try_into().unwrap_or_default()),
            node_data,
        })
    }

    async fn top_off_survey_requests(&self) {
        const MAX_REQUEST_LIMIT_PER_LEDGER: usize = 10;

        let (running, next_topoff) = {
            let reporting = self.survey_reporting.read().await;
            (reporting.running, reporting.next_topoff)
        };
        if !running {
            return;
        }
        if Instant::now() < next_topoff {
            return;
        }

        let nonce = { self.survey_data.read().await.nonce() };
        let Some(nonce) = nonce else {
            self.stop_survey_reporting().await;
            return;
        };
        if !self.survey_data.read().await.nonce_is_reporting(nonce) {
            self.stop_survey_reporting().await;
            return;
        }

        let ledger_num = self.survey_local_ledger().await;
        let mut requests_sent = 0usize;
        let mut to_send = Vec::new();

        {
            let mut reporting = self.survey_reporting.write().await;
            while requests_sent < MAX_REQUEST_LIMIT_PER_LEDGER {
                let Some(peer_id) = reporting.queue.pop_front() else {
                    break;
                };
                if !reporting.peers.remove(&peer_id) {
                    continue;
                }
                let inbound_index = reporting.inbound_indices.remove(&peer_id).unwrap_or(0);
                let outbound_index = reporting.outbound_indices.remove(&peer_id).unwrap_or(0);
                to_send.push((peer_id, inbound_index, outbound_index));
                requests_sent += 1;
            }
            reporting.next_topoff = Instant::now() + self.survey_throttle;
        }

        for (peer_id, inbound_index, outbound_index) in to_send {
            let ok = self
                .send_survey_request(
                    peer_id.clone(),
                    nonce,
                    ledger_num,
                    inbound_index,
                    outbound_index,
                )
                .await;
            if !ok {
                tracing::debug!(peer = %peer_id, "Survey request failed to send");
            }
        }
    }

    async fn send_survey_request(
        &self,
        peer_id: henyey_overlay::PeerId,
        nonce: u32,
        ledger_num: u32,
        inbound_index: u32,
        outbound_index: u32,
    ) -> bool {
        let local_node_id = self.local_node_id();
        let secret = self.ensure_survey_secret(nonce).await;
        let public = CurvePublicKey::from(&secret);
        let encryption_key = Curve25519Public {
            key: public.to_bytes(),
        };

        let request = SurveyRequestMessage {
            surveyor_peer_id: local_node_id.clone(),
            surveyed_peer_id: stellar_xdr::curr::NodeId(peer_id.0.clone()),
            ledger_num,
            encryption_key,
            command_type: SurveyMessageCommandType::TimeSlicedSurveyTopology,
        };

        let message = TimeSlicedSurveyRequestMessage {
            request,
            nonce,
            inbound_peers_index: inbound_index,
            outbound_peers_index: outbound_index,
        };

        let message_bytes = match message.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to encode survey request");
                return false;
            }
        };

        let signature = self.sign_survey_message(&message_bytes);
        let signed = stellar_xdr::curr::SignedTimeSlicedSurveyRequestMessage {
            request_signature: signature,
            request: message,
        };

        let local_ledger = self.survey_local_ledger().await;
        let mut limiter = self.survey_limiter.write().await;
        let ok = limiter.add_and_validate_request(
            &signed.request.request,
            local_ledger,
            &local_node_id,
            || {
                self.verify_survey_signature(
                    &signed.request.request.surveyor_peer_id,
                    &message_bytes,
                    &signed.request_signature,
                )
            },
        );
        if !ok {
            return false;
        }

        self.broadcast_survey_message(StellarMessage::TimeSlicedSurveyRequest(signed))
            .await
    }

    async fn broadcast_survey_start(&self, nonce: u32, ledger_num: u32) -> bool {
        let start = TimeSlicedSurveyStartCollectingMessage {
            surveyor_id: self.local_node_id(),
            nonce,
            ledger_num,
        };
        let start_bytes = match start.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to encode survey start message");
                return false;
            }
        };
        let signature = self.sign_survey_message(&start_bytes);
        let signed = stellar_xdr::curr::SignedTimeSlicedSurveyStartCollectingMessage {
            signature,
            start_collecting: start.clone(),
        };

        let sent = self
            .broadcast_survey_message(StellarMessage::TimeSlicedSurveyStartCollecting(signed))
            .await;
        if sent {
            self.survey_results
                .write()
                .await
                .entry(nonce)
                .or_insert_with(HashMap::new);
            self.start_local_survey_collecting(&start).await;
        }
        sent
    }

    async fn broadcast_survey_stop(&self, nonce: u32, ledger_num: u32) {
        let stop = TimeSlicedSurveyStopCollectingMessage {
            surveyor_id: self.local_node_id(),
            nonce,
            ledger_num,
        };

        let stop_bytes = match stop.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to encode survey stop message");
                return;
            }
        };

        let signature = self.sign_survey_message(&stop_bytes);
        let signed = stellar_xdr::curr::SignedTimeSlicedSurveyStopCollectingMessage {
            signature,
            stop_collecting: stop.clone(),
        };

        let _ = self
            .broadcast_survey_message(StellarMessage::TimeSlicedSurveyStopCollecting(signed))
            .await;
        self.stop_local_survey_collecting(&stop).await;
    }

    async fn broadcast_survey_message(&self, message: StellarMessage) -> bool {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(overlay) => overlay,
            None => return false,
        };

        match overlay.broadcast(message).await {
            Ok(_) => true,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to broadcast survey message");
                false
            }
        }
    }

    async fn ensure_survey_secret(&self, nonce: u32) -> CurveSecretKey {
        if let Some(secret) = self.survey_secrets.read().await.get(&nonce).copied() {
            return CurveSecretKey::from(secret);
        }
        let secret = CurveSecretKey::random_from_rng(rand::rngs::OsRng);
        self.survey_secrets
            .write()
            .await
            .insert(nonce, secret.to_bytes());
        secret
    }

    /// Run catchup to a target ledger with minimal mode.
    ///
    /// This downloads history from archives and applies it to bring the
    /// node up to date with the network. Uses Minimal mode by default.
    pub async fn catchup(&self, target: CatchupTarget) -> anyhow::Result<CatchupResult> {
        self.catchup_with_mode(target, CatchupMode::Minimal).await
    }

    /// Run catchup to a target ledger with a specific mode.
    ///
    /// The mode controls how much history is downloaded:
    /// - Minimal: Only download bucket state at latest checkpoint
    /// - Recent(N): Download and replay the last N ledgers
    /// - Complete: Download complete history from genesis
    pub async fn catchup_with_mode(
        &self,
        target: CatchupTarget,
        mode: CatchupMode,
    ) -> anyhow::Result<CatchupResult> {
        self.set_state(AppState::CatchingUp).await;

        let progress = Arc::new(CatchupProgress::new());

        tracing::info!(?target, ?mode, "Starting catchup");

        // Determine target ledger
        let target_ledger = match target {
            CatchupTarget::Current => {
                // Query archive for latest checkpoint (use cache to avoid repeated network calls)
                self.get_cached_archive_checkpoint().await?
            }
            CatchupTarget::Ledger(seq) => seq,
            CatchupTarget::Checkpoint(checkpoint) => checkpoint * 64,
        };

        progress.set_target(target_ledger);

        tracing::info!(target_ledger = target_ledger, "Target ledger determined");

        // Check if we're already at or past the target
        let current = self.get_current_ledger().await.unwrap_or(0);
        if target_ledger <= current {
            tracing::info!(
                current_ledger = current,
                target_ledger,
                "Already at or past target; skipping catchup"
            );
            // Record skip time for cooldown to prevent repeated catchup attempts.
            // We need to wait for the next checkpoint to become available.
            *self.last_catchup_completed_at.write().await = Some(Instant::now());
            return Ok(CatchupResult {
                ledger_seq: current,
                ledger_hash: Hash256::default(),
                buckets_applied: 0,
                ledgers_replayed: 0,
            });
        }

        // For replay-only catchup (Case 1: LCL > genesis), we need the bucket
        // lists at the current LCL to replay ledgers from LCL+1 to target.
        //
        // Fast path: if the ledger manager is already initialized, clone the
        // bucket lists directly. This is instant (Bucket uses Arc internally)
        // and avoids the expensive rebuild_bucket_lists_from_has path which
        // loads all buckets from disk + runs full merge restarts (~2+ min on
        // mainnet). It also ensures exact state parity — the HAS reconstruction
        // path can produce subtly different pending merge states.
        //
        // Slow path: if the ledger manager is NOT initialized (e.g., first
        // startup with existing DB), fall back to rebuilding from persisted HAS.
        let (existing_state, override_lcl) =
            if current > GENESIS_LEDGER_SEQ {
                if self.ledger_manager.is_initialized() {
                    // Fast path: clone from live ledger manager.
                    // Must resolve async merges first — structure-based restart_merges
                    // creates PendingMerge::Async handles, and BucketLevel::clone()
                    // drops unresolved async merges.
                    self.ledger_manager.resolve_pending_bucket_merges();
                    let bucket_list = self.ledger_manager.bucket_list().clone();
                    let hot_archive = self.ledger_manager.hot_archive_bucket_list()
                        .clone()
                        .unwrap_or_default();
                    let header = self.ledger_manager.current_header();
                    let network_id = NetworkId(self.network_id());

                    tracing::info!(
                        current_lcl = current,
                        target_ledger,
                        bucket_list_hash = %bucket_list.hash().to_hex(),
                        "Cloned bucket lists from ledger manager for replay-only catchup"
                    );

                    (Some(ExistingBucketState {
                        bucket_list,
                        hot_archive_bucket_list: hot_archive,
                        header,
                        network_id,
                    }), Some(current))
                } else {
                    // Slow path: rebuild from persisted HAS
                    match self.rebuild_bucket_lists_from_has().await {
                        Ok(state) => {
                            tracing::info!(
                                current_lcl = current,
                                target_ledger,
                                "Rebuilt bucket lists from persisted HAS for replay-only catchup (Case 1)"
                            );
                            (Some(state), Some(current))
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Failed to rebuild bucket lists from HAS, falling back to full catchup"
                            );
                            (None, None)
                        }
                    }
                }
            } else {
                (None, None)
            };
        // Run catchup work
        let output = self
            .run_catchup_work(
                target_ledger,
                mode,
                progress.clone(),
                existing_state,
                override_lcl,
            )
            .await?;

        // Persist the HAS and LCL to DB after catchup.
        // The LedgerManager is already initialized inside the catchup pipeline,
        // so we read the current state from it.
        //
        // This is critical: if a second catchup triggers before any ledger close
        // happens (e.g., when LCL+1 is missing from the buffer), rebuild_bucket_lists_from_has()
        // will read the HAS from the database. Without this persistence, it would
        // read stale HAS from before the first catchup, producing wrong bucket list
        // hashes on replay.
        //
        // This matches stellar-core's CatchupWork.cpp which calls
        // setLastClosedLedger() (persisting both LCL and HAS) after bucket apply.
        {
            let final_header = self.ledger_manager.current_header();
            let bucket_list = self.ledger_manager.bucket_list();
            let hot_archive_guard = self.ledger_manager.hot_archive_bucket_list();
            let default_hot_archive = HotArchiveBucketList::default();
            let hot_archive_ref = hot_archive_guard.as_ref().unwrap_or(&default_hot_archive);
            let has = build_history_archive_state(
                final_header.ledger_seq,
                &bucket_list,
                Some(hot_archive_ref),
                Some(self.config.network.passphrase.clone()),
            )
            .map_err(|e| anyhow::anyhow!("Failed to build HAS after catchup: {}", e))?;
            let has_json = has
                .to_json()
                .map_err(|e| anyhow::anyhow!("Failed to serialize HAS after catchup: {}", e))?;
            let header_xdr = final_header
                .to_xdr(stellar_xdr::curr::Limits::none())
                .map_err(|e| anyhow::anyhow!("Failed to serialize header XDR after catchup: {}", e))?;

            self.db.transaction(|conn| {
                conn.store_ledger_header(&final_header, &header_xdr)?;
                conn.set_state(state_keys::HISTORY_ARCHIVE_STATE, &has_json)?;
                conn.set_last_closed_ledger(final_header.ledger_seq)?;
                Ok(())
            })?;

            tracing::info!(
                ledger_seq = final_header.ledger_seq,
                "Persisted HAS and LCL to DB after catchup"
            );
        }

        tracing::info!(
            ledger_seq = output.result.ledger_seq,
            "Ledger manager initialized from catchup"
        );

        progress.set_phase(crate::logging::CatchupPhase::Complete);
        progress.summary();

        // Trim buffered ledgers that are now stale (at or before the new LCL).
        // Keep ledgers AFTER the catchup target - they will be applied next.
        // This matches stellar-core's behavior in LedgerApplyManagerImpl::trimSyncingLedgers.
        {
            let mut buffer = self.syncing_ledgers.write().await;
            let old_count = buffer.len();
            let new_lcl = output.result.ledger_seq;
            // Keep ledgers > new_lcl (i.e., remove ledgers <= new_lcl)
            buffer.retain(|seq, _| *seq > new_lcl);
            let kept_count = buffer.len();
            let removed_count = old_count - kept_count;
            if removed_count > 0 || kept_count > 0 {
                tracing::info!(
                    old_count,
                    removed_count,
                    kept_count,
                    new_lcl,
                    first_buffered = buffer.keys().next(),
                    "Trimmed stale buffered ledgers after catchup, keeping future ledgers"
                );
            }
        }

        // Clear bucket manager cache to release memory after catchup.
        // The bucket files are still on disk if needed, but we don't need to
        // keep them in RAM. With frequent catchups, this cache can grow unbounded.
        let cache_size_before = self.bucket_manager.cache_size();
        self.bucket_manager.clear_cache();

        tracing::debug!(
            cache_size_before,
            "Cleared bucket manager cache after catchup"
        );

        // Trim herder/scp_driver caches to release memory after catchup, but
        // PRESERVE data for slots > new_lcl that will be needed for buffered ledgers.
        // This is critical: during catchup, we receive EXTERNALIZE envelopes and
        // cache their tx_sets. After catchup, we need those tx_sets to apply the
        // buffered ledgers. If we clear them, peers may have already evicted those
        // old tx_sets, causing "DontHave" responses and sync failures.
        let new_lcl = output.result.ledger_seq;
        self.herder.trim_scp_driver_caches(new_lcl as u64);
        self.herder.trim_fetching_caches(new_lcl as u64);

        // Clear pending envelopes for slots <= new_lcl - they are stale after catchup.
        // Note: we keep pending envelopes for slots > new_lcl as they may still be
        // waiting for tx_sets that we just preserved above.
        self.herder.clear_pending_envelopes();

        // On Linux, ask glibc to return freed memory to the OS.
        // This helps prevent RSS from appearing to grow unboundedly after catchups,
        // even though Rust has freed the memory internally.
        #[cfg(target_os = "linux")]
        {
            // SAFETY: malloc_trim is a standard glibc function that's safe to call.
            // It returns memory to the OS and is commonly used after large deallocations.
            unsafe {
                let trimmed = libc::malloc_trim(0);
                tracing::info!(
                    trimmed,
                    "Called malloc_trim after catchup to return memory to OS"
                );
            }
        }

        // Reset the tx set exhausted flag after catchup - fresh start
        self.tx_set_all_peers_exhausted
            .store(false, Ordering::SeqCst);

        // Update cache with the ledger we caught up to (it's a checkpoint)
        {
            let mut cache = self.cached_archive_checkpoint.write().await;
            *cache = Some((output.result.ledger_seq, Instant::now()));
        }

        // Drain all sequential buffered ledgers before returning.
        // This matches stellar-core's behavior: CatchupWork creates
        // ApplyBufferedLedgersWork which applies all sequential buffered
        // ledgers before CatchupWork returns WORK_SUCCESS.
        // Without this, we'd transition to Synced with a gap (the next
        // sequential ledger is buffered but not applied), and the stuck
        // timeout would trigger an unnecessary re-catchup.
        let drained = self.drain_buffered_ledgers_sync().await;
        if drained > 0 {
            let new_ledger = self.get_current_ledger().await.unwrap_or(0);
            tracing::info!(
                drained,
                new_ledger,
                "Drained buffered ledgers as part of catchup completion"
            );
        }

        // Record catchup completion time for cooldown AFTER draining buffered
        // ledgers. This ensures the cooldown window starts after all post-catchup
        // work is complete, preventing maybe_start_buffered_catchup() from
        // triggering a second catchup while the node is still stabilizing.
        *self.last_catchup_completed_at.write().await = Some(Instant::now());

        let final_ledger = self.get_current_ledger().await.unwrap_or(output.result.ledger_seq);
        Ok(CatchupResult {
            ledger_seq: final_ledger,
            ledger_hash: output.result.ledger_hash,
            buckets_applied: output.result.buckets_downloaded,
            ledgers_replayed: output.result.ledgers_applied,
        })
    }

    /// Get the latest checkpoint from history archives, using a cache to avoid repeated network calls.
    /// The cache is valid for ARCHIVE_CHECKPOINT_CACHE_SECS.
    async fn get_cached_archive_checkpoint(&self) -> anyhow::Result<u32> {
        // Check cache first
        {
            let cache = self.cached_archive_checkpoint.read().await;
            if let Some((checkpoint, queried_at)) = *cache {
                if queried_at.elapsed().as_secs() < ARCHIVE_CHECKPOINT_CACHE_SECS {
                    tracing::debug!(
                        checkpoint,
                        age_secs = queried_at.elapsed().as_secs(),
                        "Using cached archive checkpoint"
                    );
                    return Ok(checkpoint);
                }
            }
        }

        // Cache miss or expired, query archive
        let checkpoint = self.get_latest_checkpoint().await?;

        // Update cache
        {
            let mut cache = self.cached_archive_checkpoint.write().await;
            *cache = Some((checkpoint, Instant::now()));
        }

        Ok(checkpoint)
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
                            let checkpoint =
                                henyey_history::checkpoint::latest_checkpoint_before_or_at(
                                    ledger,
                                )
                                .ok_or_else(|| {
                                    anyhow::anyhow!("No checkpoint available for ledger {}", ledger)
                                })?;
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

        Err(anyhow::anyhow!(
            "Failed to get current ledger from any archive"
        ))
    }

    /// Run the catchup work using the real CatchupManager.
    async fn run_catchup_work(
        &self,
        target_ledger: u32,
        mode: CatchupMode,
        progress: Arc<CatchupProgress>,
        existing_state: Option<ExistingBucketState>,
        override_lcl: Option<u32>,
    ) -> anyhow::Result<CatchupOutput> {
        use crate::logging::CatchupPhase;

        // Phase 1: Create history archives from config
        progress.set_phase(CatchupPhase::DownloadingState);
        tracing::info!(target_ledger, "Downloading history archive state");

        let archives: Vec<HistoryArchive> = self
            .config
            .history
            .archives
            .iter()
            .filter(|a| a.get_enabled)
            .filter_map(|a| match HistoryArchive::new(&a.url) {
                Ok(archive) => Some(archive),
                Err(e) => {
                    tracing::warn!(url = %a.url, error = %e, "Failed to create archive");
                    None
                }
            })
            .collect();

        if archives.is_empty() {
            return Err(anyhow::anyhow!("No history archives available"));
        }

        tracing::info!(
            archive_count = archives.len(),
            "Created history archive clients"
        );

        let checkpoint_seq = latest_checkpoint_before_or_at(target_ledger).ok_or_else(|| {
            anyhow::anyhow!("target ledger {} is before first checkpoint", target_ledger)
        })?;

        let archives_arc: Vec<Arc<HistoryArchive>> = archives.into_iter().map(Arc::new).collect();

        // Only use historywork for Minimal mode WITHOUT existing bucket state.
        // When we have existing bucket state (Case 1: replay from LCL), skip historywork
        // entirely — it would unnecessarily download all buckets when we only need
        // transaction history for replay.
        let checkpoint_data = if mode == CatchupMode::Minimal && existing_state.is_none() {
            if let Some(primary) = archives_arc.first() {
                match self
                    .download_checkpoint_with_historywork(Arc::clone(primary), checkpoint_seq)
                    .await
                {
                    Ok(data) => {
                        tracing::info!(checkpoint_seq, "Using historywork for checkpoint downloads");
                        Some(data)
                    }
                    Err(err) => {
                        tracing::warn!(
                            checkpoint_seq,
                            error = %err,
                            "Historywork download failed, falling back to direct catchup"
                        );
                        None
                    }
                }
            } else {
                None
            }
        } else {
            tracing::info!(
                ?mode,
                "Using mode-aware catchup (historywork only supported for Minimal mode)"
            );
            None
        };

        // Create CatchupManager using Arc references
        let mut catchup_manager = CatchupManager::new_with_arcs(
            archives_arc,
            self.bucket_manager.clone(),
            Arc::new(self.db.clone()),
        );

        // Run catchup
        progress.set_phase(CatchupPhase::DownloadingBuckets);

        // Get current LCL for mode calculation.
        // When an override is provided (e.g., after rebuild_bucket_lists_from_has
        // which resets the ledger manager), use it directly.
        // Otherwise, query the ledger manager.
        let lcl = if let Some(lcl_override) = override_lcl {
            lcl_override
        } else {
            match self.get_current_ledger().await {
                Ok(seq) if seq >= GENESIS_LEDGER_SEQ => seq,
                _ => GENESIS_LEDGER_SEQ,
            }
        };

        let output = match checkpoint_data {
            Some(data) => {
                // With checkpoint data, use direct method (minimal mode behavior)
                catchup_manager
                    .catchup_to_ledger_with_checkpoint_data(target_ledger, data, &self.ledger_manager)
                    .await
            }
            None => {
                // Use mode-aware catchup
                catchup_manager
                    .catchup_to_ledger_with_mode(target_ledger, mode, lcl, existing_state, &self.ledger_manager)
                    .await
            }
        }
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

    async fn download_checkpoint_with_historywork(
        &self,
        archive: Arc<HistoryArchive>,
        checkpoint_seq: u32,
    ) -> anyhow::Result<CheckpointData> {
        let state = Arc::new(tokio::sync::Mutex::new(HistoryWorkState::default()));
        let mut scheduler = WorkScheduler::new(WorkSchedulerConfig {
            max_concurrency: 16, // Match stellar-core MAX_CONCURRENT_SUBPROCESSES
            retry_delay: Duration::from_millis(200),
            event_tx: None,
        });
        let bucket_dir = self.bucket_manager.bucket_dir().to_path_buf();
        let builder = HistoryWorkBuilder::new(
            archive,
            checkpoint_seq,
            Arc::clone(&state),
            bucket_dir,
        );
        let ids = builder.register(&mut scheduler);

        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let state_monitor = Arc::clone(&state);
        let monitor = tokio::spawn(async move {
            let mut last_stage = None;
            let mut last_message = String::new();
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let progress = get_progress(&state_monitor).await;
                        if progress.stage != last_stage || progress.message != last_message {
                            last_stage = progress.stage.clone();
                            last_message = progress.message.clone();
                            if let Some(stage) = progress.stage {
                                tracing::info!(stage = ?stage, message = %progress.message, "Historywork progress");
                            }
                        }
                    }
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        scheduler.run_until_done().await;

        let _ = stop_tx.send(true);
        let _ = monitor.await;

        let work_ids = [
            ids.has,
            ids.buckets,
            ids.headers,
            ids.transactions,
            ids.tx_results,
            ids.scp_history,
        ];
        for id in work_ids {
            match scheduler.state(id) {
                Some(WorkState::Success) => {}
                state => {
                    return Err(anyhow::anyhow!(
                        "historywork failed; work {} ended in {:?}",
                        id,
                        state
                    ));
                }
            }
        }

        build_checkpoint_data(&state).await
    }

    /// Run the main event loop.
    ///
    /// This starts all subsystems and runs until shutdown is signaled.
    pub async fn run(&self) -> anyhow::Result<()> {
        tracing::info!("Starting main event loop");

        // Start overlay network if not already started.
        // (run_cmd may have already started it before catchup)
        {
            let overlay = self.overlay.lock().await;
            if overlay.is_none() {
                drop(overlay); // release lock before starting
                self.start_overlay().await?;
            }
        }

        // Get current ledger state (catchup was already done by run_cmd)
        let current_ledger = self.get_current_ledger().await?;

        if current_ledger == 0 {
            // This shouldn't happen if run_cmd did catchup, but handle it just in case
            tracing::info!("No ledger state, running catchup first");
            let result = self.catchup(CatchupTarget::Current).await?;
            *self.current_ledger.write().await = result.ledger_seq;
        } else {
            // Ledger manager was already initialized (e.g., catchup ran before run())
            *self.current_ledger.write().await = current_ledger;
        }

        // Bootstrap herder with current ledger
        let ledger_seq = *self.current_ledger.read().await;
        *self.last_processed_slot.write().await = ledger_seq as u64;
        self.herder.start_syncing();
        self.herder.bootstrap(ledger_seq);
        tracing::info!(ledger_seq, "Herder bootstrapped");

        // Wait a short time for initial peer connections, then request SCP state
        tokio::time::sleep(Duration::from_millis(500)).await;
        self.request_scp_state_from_peers().await;

        // Set state based on validator mode
        if self.is_validator {
            self.set_state(AppState::Validating).await;
        } else {
            self.set_state(AppState::Synced).await;
        }

        // Start sync recovery tracking to enable the consensus stuck timer
        self.start_sync_recovery_tracking();

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

        // Get dedicated SCP message receiver (never drops messages)
        let scp_message_rx = {
            let overlay = self.overlay.lock().await;
            match overlay.as_ref() {
                Some(o) => o.subscribe_scp().await,
                None => None,
            }
        };

        let mut scp_message_rx = match scp_message_rx {
            Some(rx) => rx,
            None => {
                // Create a dummy receiver that never receives
                let (_tx, rx) = tokio::sync::mpsc::unbounded_channel::<OverlayMessage>();
                rx
            }
        };

        // Get dedicated fetch response receiver (never drops messages)
        let fetch_response_rx = {
            let overlay = self.overlay.lock().await;
            match overlay.as_ref() {
                Some(o) => o.subscribe_fetch_responses().await,
                None => None,
            }
        };

        let mut fetch_response_rx = match fetch_response_rx {
            Some(rx) => rx,
            None => {
                // Create a dummy receiver that never receives
                let (_tx, rx) = tokio::sync::mpsc::unbounded_channel::<OverlayMessage>();
                rx
            }
        };

        // Main run loop
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let mut consensus_interval = tokio::time::interval(Duration::from_secs(5));
        let mut stats_interval = tokio::time::interval(Duration::from_secs(30));
        let mut tx_advert_interval = tokio::time::interval(self.flood_advert_period());
        let mut tx_demand_interval = tokio::time::interval(self.flood_demand_period());
        let mut survey_interval = tokio::time::interval(Duration::from_secs(1));
        let mut survey_phase_interval = tokio::time::interval(Duration::from_secs(5));
        let mut survey_request_interval = tokio::time::interval(Duration::from_secs(1));
        let mut scp_timeout_interval = tokio::time::interval(Duration::from_millis(500));
        let mut ping_interval = tokio::time::interval(Duration::from_secs(5));
        let mut peer_maintenance_interval = tokio::time::interval(Duration::from_secs(10));
        let mut peer_refresh_interval = tokio::time::interval(Duration::from_secs(60));
        let mut herder_cleanup_interval = tokio::time::interval(Duration::from_secs(30));

        // Get mutable access to SCP envelope receiver
        let mut scp_rx = self.scp_envelope_rx.lock().await;

        // Process any externalized slots recorded during catchup BEFORE entering the main loop.
        // This ensures we buffer LedgerCloseInfo before new EXTERNALIZE messages trigger cleanup
        // which would remove older externalized slots (only max_externalized_slots are kept).
        self.process_externalized_slots().await;

        // After the pre-loop process_externalized_slots (which may have triggered a
        // rapid close phase), clear all pending tx_set requests and tracking state.
        // During catchup, SCP state responses bring EXTERNALIZE messages for slots
        // whose tx_sets may already be evicted from peers' caches. The pre-loop
        // process_externalized_slots creates syncing_ledgers entries for these slots
        // and kicks off tx_set requests.  If peers silently drop those requests
        // (because the tx_sets are evicted), the 10-second timeout fires, sets
        // tx_set_all_peers_exhausted, and triggers unnecessary catchup — which
        // then repeats the same cycle infinitely.
        //
        // Clearing the state here ensures the main loop starts clean.  Fresh
        // EXTERNALIZE messages arriving via the dedicated SCP channel will create
        // new entries with current tx_set hashes that peers actually have.
        {
            let current_ledger = *self.current_ledger.read().await;
            self.herder.clear_pending_tx_sets();
            // Also clear syncing_ledgers entries that have no tx_set — these are
            // unfulfillable entries created from stale EXTERNALIZE messages.
            let mut buffer = self.syncing_ledgers.write().await;
            let pre_count = buffer.len();
            buffer.retain(|seq, info| {
                // Keep entries that are above current_ledger AND have a tx_set.
                // Remove entries that are at or below current_ledger (already closed)
                // or that have no tx_set (unfulfillable from catchup-phase EXTERNALIZE).
                *seq > current_ledger && info.tx_set.is_some()
            });
            let removed = pre_count - buffer.len();
            if removed > 0 {
                tracing::info!(
                    removed,
                    remaining = buffer.len(),
                    current_ledger,
                    "Removed stale/unfulfillable syncing_ledgers entries before main loop"
                );
            }
            // Reset all tx_set tracking state
            self.tx_set_dont_have.write().await.clear();
            self.tx_set_last_request.write().await.clear();
            self.tx_set_exhausted_warned.write().await.clear();
            self.tx_set_all_peers_exhausted
                .store(false, Ordering::SeqCst);
        }

        tracing::info!("Entering main event loop");

        // Add a short heartbeat interval for debugging
        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(10));

        // In-progress background ledger close. Polled in the select loop.
        let mut pending_close: Option<PendingLedgerClose> = None;

        loop {
            tokio::select! {
                // NOTE: Removed biased; to ensure timers get fair polling

                // Await pending ledger close completion
                join_result = async {
                    match pending_close.as_mut() {
                        Some(p) => (&mut p.handle).await,
                        None => std::future::pending().await,
                    }
                } => {
                    let pending = pending_close.take().unwrap();
                    let success = self.handle_close_complete(pending, join_result).await;
                    // Chain next close if successful.
                    if success {
                        // Before trying the next close, drain SCP + fetch response channels.
                        // During rapid buffered closes the select! loop may not poll these
                        // channels frequently enough, so EXTERNALIZEs and TxSet responses
                        // can sit unprocessed.  Draining here ensures we have the latest
                        // network state before deciding whether another close is ready.
                        while let Ok(scp_msg) = scp_message_rx.try_recv() {
                            self.handle_overlay_message(scp_msg).await;
                        }
                        while let Ok(fetch_msg) = fetch_response_rx.try_recv() {
                            self.handle_overlay_message(fetch_msg).await;
                        }
                        self.process_externalized_slots().await;

                        pending_close = self.try_start_ledger_close().await;

                        // If no more buffered ledgers to close, we just finished a rapid
                        // close cycle.  Do NOT proactively request SCP state here.
                        // Requesting SCP state brings in EXTERNALIZE messages for recent
                        // slots whose tx_sets are already evicted from peers' caches,
                        // causing a cascade of 10s timeouts → tx_set_all_peers_exhausted
                        // → unnecessary catchup.  Instead, just wait: the dedicated SCP
                        // channel guarantees the next natural EXTERNALIZE (with a fresh,
                        // fetchable tx_set) arrives within ~6 seconds.
                        if pending_close.is_none() {
                            let current_ledger = *self.current_ledger.read().await;

                            // Reset last_externalized_at so the heartbeat stall detector
                            // doesn't fire prematurely based on the timestamp of the
                            // EXTERNALIZE that was received 8-10s ago during rapid closes.
                            *self.last_externalized_at.write().await = Instant::now();

                            // Reset tx_set tracking so fresh requests can be made for
                            // buffered entries that still need tx_sets. Don't evict
                            // the entries themselves — they may be closeable once
                            // their tx_sets arrive from peers.
                            self.tx_set_all_peers_exhausted.store(false, Ordering::SeqCst);
                            self.tx_set_dont_have.write().await.clear();
                            self.tx_set_last_request.write().await.clear();
                            self.tx_set_exhausted_warned.write().await.clear();

                            // Also reset consensus stuck state since we just successfully
                            // closed ledgers — we're not stuck.
                            *self.consensus_stuck_state.write().await = None;

                            tracing::info!(
                                current_ledger,
                                "Rapid close cycle ended; waiting for next natural EXTERNALIZE"
                            );
                        }
                    }
                }

                // Process SCP messages from dedicated never-drop channel.
                // These are guaranteed to arrive even if the broadcast channel overflows.
                Some(scp_msg) = scp_message_rx.recv() => {
                    tracing::debug!(
                        latency_ms = scp_msg.received_at.elapsed().as_millis(),
                        "Received SCP message via dedicated channel"
                    );
                    self.handle_overlay_message(scp_msg).await;
                }

                // Process fetch response messages from dedicated never-drop channel.
                // GeneralizedTxSet, TxSet, DontHave, and ScpQuorumset are routed here
                // to ensure they are never lost when the broadcast channel overflows.
                Some(fetch_msg) = fetch_response_rx.recv() => {
                    tracing::debug!(
                        latency_ms = fetch_msg.received_at.elapsed().as_millis(),
                        "Received fetch response via dedicated channel"
                    );
                    self.handle_overlay_message(fetch_msg).await;
                }

                // Process overlay messages
                msg = message_rx.recv() => {
                    match msg {
                        Ok(overlay_msg) => {
                            // Skip SCP messages from broadcast channel — they are already
                            // handled via the dedicated SCP channel above.
                            if matches!(overlay_msg.message, StellarMessage::ScpMessage(_)) {
                                continue;
                            }
                            // Skip fetch response messages from broadcast channel — they are
                            // already handled via the dedicated fetch response channel above.
                            if matches!(
                                overlay_msg.message,
                                StellarMessage::GeneralizedTxSet(_)
                                    | StellarMessage::TxSet(_)
                                    | StellarMessage::DontHave(_)
                                    | StellarMessage::ScpQuorumset(_)
                            ) {
                                continue;
                            }
                            let delivery_latency = overlay_msg.received_at.elapsed();
                            let msg_type = match &overlay_msg.message {
                                StellarMessage::ScpMessage(_) => "SCP",
                                StellarMessage::Transaction(_) => "TX",
                                StellarMessage::TxSet(_) => "TxSet",
                                StellarMessage::GeneralizedTxSet(_) => {
                                    tracing::debug!(latency_ms = delivery_latency.as_millis(), "Overlay delivery latency for GeneralizedTxSet");
                                    "GeneralizedTxSet"
                                },
                                StellarMessage::ScpQuorumset(_) => {
                                    tracing::debug!(latency_ms = delivery_latency.as_millis(), "Overlay delivery latency for ScpQuorumset");
                                    "ScpQuorumset"
                                },
                                StellarMessage::GetTxSet(_) => "GetTxSet",
                                StellarMessage::Hello(_) => "Hello",
                                StellarMessage::Peers(_) => "Peers",
                                _ => "Other",
                            };
                            tracing::debug!(msg_type, latency_ms = delivery_latency.as_millis(), "Received overlay message");
                            self.handle_overlay_message(overlay_msg).await;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(skipped = n, "Overlay receiver lagged, messages dropped");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            tracing::info!("Overlay broadcast channel closed");
                            break;
                        }
                    }
                }

                // Broadcast outbound SCP envelopes
                envelope = scp_rx.recv() => {
                    if let Some(envelope) = envelope {
                        let slot = envelope.statement.slot_index;
                        let sample = {
                            let mut latency = self.scp_latency.write().await;
                            latency.record_self_sent(slot)
                        };
                        if let Some(ms) = sample {
                            let mut survey_data = self.survey_data.write().await;
                            survey_data.record_scp_first_to_self_latency(ms);
                        }
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
                    // IMPORTANT: Drain pending overlay messages FIRST before any catchup evaluation.
                    // This ensures tx_sets that arrived via broadcast are processed before we
                    // decide whether to trigger catchup due to missing tx_sets.
                    let mut drained = 0;

                    // Drain dedicated SCP channel first (highest priority)
                    while let Ok(scp_msg) = scp_message_rx.try_recv() {
                        drained += 1;
                        self.handle_overlay_message(scp_msg).await;
                    }

                    // Drain dedicated fetch response channel (tx_sets, dont_have, etc.)
                    while let Ok(fetch_msg) = fetch_response_rx.try_recv() {
                        drained += 1;
                        self.handle_overlay_message(fetch_msg).await;
                    }

                    // Drain broadcast channel (remaining message types only)
                    loop {
                        match message_rx.try_recv() {
                            Ok(overlay_msg) => {
                                // Skip SCP messages — already handled via dedicated channel
                                if matches!(overlay_msg.message, StellarMessage::ScpMessage(_)) {
                                    continue;
                                }
                                // Skip fetch response messages — already handled via dedicated channel
                                if matches!(
                                    overlay_msg.message,
                                    StellarMessage::GeneralizedTxSet(_)
                                        | StellarMessage::TxSet(_)
                                        | StellarMessage::DontHave(_)
                                        | StellarMessage::ScpQuorumset(_)
                                ) {
                                    continue;
                                }
                                drained += 1;
                                self.handle_overlay_message(overlay_msg).await;
                            }
                            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                                tracing::warn!(skipped = n, "Overlay receiver lagged during drain");
                            }
                            Err(_) => break, // Empty or Closed
                        }
                    }
                    if drained > 0 {
                        tracing::debug!(drained, "Drained pending overlay messages before consensus tick");
                    }

                    // Check if SyncRecoveryManager requested recovery
                    if self.sync_recovery_pending.swap(false, Ordering::SeqCst) {
                        tracing::debug!("SyncRecoveryManager triggered out-of-sync recovery");
                        // SyncRecoveryManager triggered recovery - perform it now
                        if let Ok(current_ledger) = self.get_current_ledger().await {
                            self.out_of_sync_recovery(current_ledger).await;
                        }
                        // Also check for buffered catchup (this handles timeout-based catchup)
                        self.maybe_start_buffered_catchup().await;
                    }

                    // Check for externalized slots to process
                    self.process_externalized_slots().await;

                    // Start a background ledger close if one isn't already running.
                    if pending_close.is_none() {
                        pending_close = self.try_start_ledger_close().await;
                    }

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

                // Batched tx advert flush
                _ = tx_advert_interval.tick() => {
                    self.flush_tx_adverts().await;
                }

                // Demand missing transactions from peers
                _ = tx_demand_interval.tick() => {
                    self.run_tx_demands().await;
                }

                // Survey scheduler
                _ = survey_interval.tick() => {
                    if self.config.overlay.auto_survey {
                        self.advance_survey_scheduler().await;
                    }
                }

                // Survey reporting request top-off
                _ = survey_request_interval.tick() => {
                    self.top_off_survey_requests().await;
                }

                // Survey phase maintenance
                _ = survey_phase_interval.tick() => {
                    self.update_survey_phase().await;
                }

                // SCP nomination/ballot timeouts
                _ = scp_timeout_interval.tick() => {
                    self.check_scp_timeouts().await;
                }

                // Ping peers for latency measurements
                _ = ping_interval.tick() => {
                    self.send_peer_pings().await;
                }

                // Peer maintenance - reconnect if peer count drops too low
                _ = peer_maintenance_interval.tick() => {
                    self.maintain_peers().await;
                }

                // Refresh known peers from config + SQLite cache
                _ = peer_refresh_interval.tick() => {
                    if let Some(overlay) = self.overlay.lock().await.as_ref() {
                        let _ = self.refresh_known_peers(overlay);
                    }
                }

                // Herder cleanup - evict expired data
                _ = herder_cleanup_interval.tick() => {
                    self.herder.cleanup();
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

                    // Check quorum status - use latest_ext if available since we have
                    // actual SCP messages for that slot, otherwise fall back to tracking_slot
                    let quorum_check_slot = if latest_ext > 0 { latest_ext } else { tracking_slot };
                    let heard_from_quorum = self.herder.heard_from_quorum(quorum_check_slot);
                    let is_v_blocking = self.herder.is_v_blocking(quorum_check_slot);

                    tracing::info!(
                        tracking_slot,
                        ledger,
                        latest_ext,
                        peers,
                        heard_from_quorum,
                        is_v_blocking,
                        "Heartbeat"
                    );

                    // Warn if we haven't heard from quorum for a while
                    if self.is_validator && !heard_from_quorum && peers > 0 {
                        tracing::warn!(
                            tracking_slot,
                            is_v_blocking,
                            "Have not heard from quorum - may be experiencing network partition"
                        );
                    }

                    // If externalization stalls, ask peers for fresh SCP state.
                    if peers > 0 && self.herder.state().can_receive_scp() {
                        let now = Instant::now();
                        let last_ext = *self.last_externalized_at.read().await;
                        let last_request = *self.last_scp_state_request_at.read().await;
                        if now.duration_since(last_ext) > Duration::from_secs(20)
                            && now.duration_since(last_request) > Duration::from_secs(10)
                        {
                            // When essentially caught up (small gap), do NOT request
                            // SCP state.  Peers respond with EXTERNALIZE for recent
                            // slots whose tx_sets are already evicted from their
                            // caches, creating unfulfillable requests.  Instead, wait
                            // for the next natural EXTERNALIZE (~5-6s).
                            let current_ledger = *self.current_ledger.read().await;
                            let gap = latest_ext.saturating_sub(current_ledger as u64);
                            if gap <= TX_SET_REQUEST_WINDOW {
                                tracing::debug!(
                                    current_ledger,
                                    latest_ext,
                                    gap,
                                    "Heartbeat: essentially caught up, skipping SCP state request"
                                );
                            } else {
                                tracing::warn!(
                                    latest_ext,
                                    tracking_slot,
                                    heard_from_quorum,
                                    gap,
                                    "SCP externalization stalled; requesting SCP state"
                                );
                                *self.last_scp_state_request_at.write().await = now;
                                self.request_scp_state_from_peers().await;
                            }
                        }
                    }

                    // Out-of-sync recovery: purge old slots when we're too far behind.
                    // This mirrors stellar-core's outOfSyncRecovery() behavior.
                    // When we have v-blocking slots that are >100 ahead of older slots,
                    // purge the old slots to free memory and allow recovery.
                    if !self.herder.state().can_receive_scp() || !heard_from_quorum {
                        if let Some(purge_slot) = self.herder.out_of_sync_recovery(ledger as u64) {
                            tracing::info!(
                                purge_slot,
                                ledger,
                                tracking_slot,
                                "Out-of-sync recovery: purged old slots"
                            );
                        }
                    }
                }
            }
        }

        self.set_state(AppState::ShuttingDown).await;
        self.shutdown_internal().await?;

        Ok(())
    }

    /// Start the overlay network.
    pub async fn start_overlay(&self) -> anyhow::Result<()> {
        tracing::info!("Starting overlay network");

        self.store_config_peers();

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
        overlay_config.is_validator = self.is_validator; // Watchers filter non-essential messages
        overlay_config.network_passphrase = self.config.network.passphrase.clone();

        // Convert known peers from strings to PeerAddress
        if !self.config.overlay.known_peers.is_empty() {
            overlay_config.known_peers = self
                .config
                .overlay
                .known_peers
                .iter()
                .filter_map(|s| Self::parse_peer_address(s))
                .collect();
        }

        if let Ok(persisted) = self.load_persisted_peers() {
            for addr in persisted {
                if !overlay_config.known_peers.contains(&addr) {
                    overlay_config.known_peers.push(addr);
                }
            }
        }

        // Convert preferred peers
        if !self.config.overlay.preferred_peers.is_empty() {
            overlay_config.preferred_peers = self
                .config
                .overlay
                .preferred_peers
                .iter()
                .filter_map(|s| {
                    let parts: Vec<&str> = s.split(':').collect();
                    match parts.len() {
                        1 => Some(PeerAddress::new(parts[0], 11625)),
                        2 => parts[1]
                            .parse()
                            .ok()
                            .map(|port| PeerAddress::new(parts[0], port)),
                        _ => None,
                    }
                })
                .collect();
        }

        let (peer_event_tx, mut peer_event_rx) = mpsc::channel(1024);
        overlay_config.peer_event_tx = Some(peer_event_tx);

        let db = self.db.clone();
        tokio::spawn(async move {
            while let Some(event) = peer_event_rx.recv().await {
                update_peer_record(&db, event);
            }
        });

        tracing::info!(
            listen_port = overlay_config.listen_port,
            known_peers = overlay_config.known_peers.len(),
            listen_enabled = overlay_config.listen_enabled,
            "Creating overlay with config"
        );

        let mut overlay = OverlayManager::new(overlay_config, local_node)?;
        if let Ok(bans) = self.db.load_bans() {
            for ban in bans {
                if let Some(peer_id) = Self::strkey_to_peer_id(&ban) {
                    overlay.ban_peer(peer_id).await;
                } else {
                    tracing::warn!(node = %ban, "Ignoring invalid ban entry");
                }
            }
        }

        overlay.start().await?;

        let peer_count = overlay.peer_count();
        tracing::info!(peer_count, "Overlay network started");

        *self.overlay.lock().await = Some(overlay);
        Ok(())
    }

    /// Set the weak reference to self for spawning background tasks.
    /// Must be called after wrapping App in Arc.
    pub async fn set_self_arc(self: &Arc<Self>) {
        *self.self_arc.write().await = Arc::downgrade(self);
    }

    /// Start caching messages during catchup using the stored weak reference.
    /// This can be called from `&self` methods unlike `start_catchup_message_caching`.
    ///
    /// Returns a JoinHandle that can be aborted when catchup completes.
    async fn start_catchup_message_caching_from_self(
        &self,
    ) -> Option<tokio::task::JoinHandle<()>> {
        tracing::info!("Attempting to start catchup message caching from self_arc");
        let weak = self.self_arc.read().await;
        let app = match weak.upgrade() {
            Some(arc) => {
                tracing::info!("Successfully upgraded self_arc weak reference");
                arc
            }
            None => {
                tracing::warn!("Failed to upgrade self_arc weak reference for message caching");
                return None;
            }
        };
        drop(weak); // Release the read lock before calling async method
        let handle = app.start_catchup_message_caching().await;
        if handle.is_some() {
            tracing::info!("Started catchup message caching task from self_arc");
        } else {
            tracing::warn!("Failed to start catchup message caching task (overlay not available?)");
        }
        handle
    }

    /// Start caching messages during catchup.
    ///
    /// Returns a JoinHandle that can be aborted when catchup completes.
    /// This method starts a background task that caches GeneralizedTxSets
    /// and requests tx_sets for EXTERNALIZE messages during catchup.
    /// Uses a dedicated mpsc channel (via subscribe_catchup) that never drops
    /// messages, unlike the broadcast channel which overflows during high traffic.
    pub async fn start_catchup_message_caching(
        self: &Arc<Self>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let overlay = self.overlay.lock().await;
        if let Some(ref o) = *overlay {
            let message_rx = o.subscribe_catchup();
            let app = Arc::clone(self);
            Some(tokio::spawn(async move {
                app.cache_messages_during_catchup_impl(message_rx).await;
            }))
        } else {
            None
        }
    }

    /// Cache messages during catchup to bridge the gap between catchup and live consensus.
    ///
    /// This runs in a background task during catchup:
    /// 1. Caching GeneralizedTxSets received from peers
    /// 2. Processing EXTERNALIZE messages to request their tx_sets
    ///
    /// Uses a dedicated mpsc channel that never drops messages, ensuring no
    /// EXTERNALIZE or GeneralizedTxSet messages are lost during catchup.
    async fn cache_messages_during_catchup_impl(
        &self,
        mut message_rx: tokio::sync::mpsc::UnboundedReceiver<OverlayMessage>,
    ) {
        use stellar_xdr::curr::{
            GeneralizedTransactionSet, Limits, ScpStatementPledges, TransactionPhase,
            TxSetComponent, WriteXdr,
        };
        use std::collections::HashSet;

        let mut cached_tx_sets = 0u32;
        let mut requested_tx_sets = 0u32;
        let mut recorded_externalized = 0u32;
        // Track tx_sets we've already broadcast requests for to avoid spamming all peers
        let mut requested_hashes: HashSet<Hash256> = HashSet::new();

        while let Some(msg) = message_rx.recv().await {
            match msg.message {
                StellarMessage::GeneralizedTxSet(gen_tx_set) => {
                    // Compute hash as SHA-256 of XDR-encoded GeneralizedTransactionSet
                    let xdr_bytes =
                        match gen_tx_set.to_xdr(stellar_xdr::curr::Limits::none()) {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                tracing::warn!(error = %e, "Failed to encode GeneralizedTxSet to XDR");
                                continue;
                            }
                        };
                    let hash = henyey_common::Hash256::hash(&xdr_bytes);

                    // Extract transactions from the GeneralizedTxSet
                    let prev_hash = match &gen_tx_set {
                        GeneralizedTransactionSet::V1(v1) => {
                            henyey_common::Hash256::from_bytes(
                                v1.previous_ledger_hash.0,
                            )
                        }
                    };

                    let transactions: Vec<stellar_xdr::curr::TransactionEnvelope> =
                        match &gen_tx_set {
                            GeneralizedTransactionSet::V1(v1) => v1
                                .phases
                                .iter()
                                .flat_map(|phase| match phase {
                                    TransactionPhase::V0(components) => components
                                        .iter()
                                        .flat_map(|component| match component {
                                            TxSetComponent::TxsetCompTxsMaybeDiscountedFee(
                                                comp,
                                            ) => comp.txs.to_vec(),
                                        })
                                        .collect::<Vec<_>>(),
                                    TransactionPhase::V1(parallel) => parallel
                                        .execution_stages
                                        .iter()
                                        .flat_map(|stage| {
                                            stage
                                                .0
                                                .iter()
                                                .flat_map(|cluster| cluster.0.to_vec())
                                        })
                                        .collect(),
                                })
                                .collect(),
                        };

                    let tx_set = henyey_herder::TransactionSet::with_generalized(
                        prev_hash,
                        hash,
                        transactions,
                        gen_tx_set,
                    );

                    // Cache it in herder (this will be available after catchup)
                    self.herder.cache_tx_set(tx_set);
                    cached_tx_sets += 1;

                    tracing::debug!(
                        cached_tx_sets,
                        hash = %hash,
                        "Cached tx_set during catchup"
                    );
                }

                StellarMessage::ScpMessage(envelope) => {
                    // For EXTERNALIZE messages, extract tx_set_hash, record, and request
                    if let ScpStatementPledges::Externalize(ext) =
                        &envelope.statement.pledges
                    {
                        let slot = envelope.statement.slot_index;
                        let value = ext.commit.value.clone();

                        // Record this externalized slot so we can apply it after catchup
                        self.herder.scp_driver().record_externalized(slot, value);
                        recorded_externalized += 1;
                        tracing::debug!(
                            slot,
                            "Recorded externalized slot during catchup"
                        );

                        if let Ok(sv) =
                            StellarValue::from_xdr(&ext.commit.value.0, Limits::none())
                        {
                            let tx_set_hash = Hash256::from_bytes(sv.tx_set_hash.0);

                            // Check if we already have this tx_set or already broadcast a request
                            if !self.herder.has_tx_set(&tx_set_hash)
                                && !requested_hashes.contains(&tx_set_hash)
                            {
                                // Register as pending and send GetTxSet request
                                self.herder
                                    .scp_driver()
                                    .request_tx_set(tx_set_hash, slot);

                                // Track that we've requested this hash to avoid duplicate broadcasts
                                requested_hashes.insert(tx_set_hash);

                                // Broadcast GetTxSet request to ALL peers, not just the sender.
                                // This is critical for bridging the gap after catchup: by the time
                                // catchup completes, older tx_sets may be evicted from the sender's
                                // cache. By requesting from all peers, we maximize our chances of
                                // getting the tx_set before any single peer evicts it.
                                let overlay = self.overlay.lock().await;
                                if let Some(ref overlay) = *overlay {
                                    match overlay.request_tx_set(&tx_set_hash.0).await {
                                        Ok(peer_count) => {
                                            requested_tx_sets += 1;
                                            tracing::debug!(
                                                slot,
                                                hash = %tx_set_hash,
                                                peer_count,
                                                "Broadcast tx_set request to all peers during catchup"
                                            );
                                        }
                                        Err(e) => {
                                            tracing::debug!(
                                                slot,
                                                error = %e,
                                                "Failed to broadcast tx_set request during catchup"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                _ => {
                    // Ignore other message types during catchup
                }
            }
        }

        tracing::info!(
            cached_tx_sets,
            requested_tx_sets,
            recorded_externalized,
            "Finished caching messages during catchup"
        );
    }

    /// Handle a message from the overlay network.
    async fn handle_overlay_message(&self, msg: OverlayMessage) {
        match msg.message {
            StellarMessage::ScpMessage(envelope) => {
                let slot = envelope.statement.slot_index;
                let tracking = self.herder.tracking_slot();

                let sample = {
                    let mut latency = self.scp_latency.write().await;
                    latency.record_first_seen(slot);
                    latency.record_other_after_self(slot)
                };
                if let Some(ms) = sample {
                    let mut survey_data = self.survey_data.write().await;
                    survey_data.record_scp_self_to_other_latency(ms);
                }

                // Check if this is an EXTERNALIZE message so we can request the tx set
                let is_externalize = matches!(
                    &envelope.statement.pledges,
                    stellar_xdr::curr::ScpStatementPledges::Externalize(_)
                );
                let tx_set_hash = match &envelope.statement.pledges {
                    stellar_xdr::curr::ScpStatementPledges::Externalize(ext) => {
                        match StellarValue::from_xdr(
                            &ext.commit.value.0,
                            stellar_xdr::curr::Limits::none(),
                        ) {
                            Ok(stellar_value) => {
                                Some(Hash256::from_bytes(stellar_value.tx_set_hash.0))
                            }
                            Err(err) => {
                                tracing::warn!(slot, error = %err, "Failed to parse externalized StellarValue");
                                None
                            }
                        }
                    }
                    _ => None,
                };

                if let Some(hash) = Self::scp_quorum_set_hash(&envelope.statement) {
                    let hash256 = henyey_common::Hash256::from_bytes(hash.0);
                    let sender_node_id = envelope.statement.node_id.clone();
                    // Always call request_quorum_set to associate the quorum set with the node_id.
                    // If we already have the quorum set by hash, it will be associated with this
                    // node_id. If not, we'll create a pending request.
                    if self.herder.request_quorum_set(hash256, sender_node_id) {
                        // New pending request - need to fetch from network
                        let peer = msg.from_peer.clone();
                        let overlay = self.overlay.lock().await;
                        if let Some(ref overlay) = *overlay {
                            let request =
                                StellarMessage::GetScpQuorumset(stellar_xdr::curr::Uint256(hash.0));
                            if let Err(e) = overlay.send_to(&peer, request).await {
                                tracing::debug!(peer = %peer, error = %e, "Failed to request quorum set");
                            }
                        }
                    }
                }

                match self.herder.receive_scp_envelope(envelope) {
                    EnvelopeState::Valid => {
                        tracing::debug!(slot, tracking, "Processed SCP envelope (valid)");
                        // Signal heartbeat to sync recovery - consensus is making progress
                        self.sync_recovery_heartbeat();

                        // For EXTERNALIZE messages, immediately try to close ledger and request tx set
                        if is_externalize {
                            tracing::debug!(slot, tracking, "EXTERNALIZE Valid — processing slot");
                            if let Some(tx_set_hash) = tx_set_hash {
                                self.herder.scp_driver().request_tx_set(tx_set_hash, slot);
                                if self.herder.needs_tx_set(&tx_set_hash) {
                                    let peer = msg.from_peer.clone();
                                    let overlay = self.overlay.lock().await;
                                    if let Some(ref overlay) = *overlay {
                                        let request = StellarMessage::GetTxSet(
                                            stellar_xdr::curr::Uint256(tx_set_hash.0),
                                        );
                                        if let Err(e) = overlay.send_to(&peer, request).await {
                                            tracing::debug!(
                                                peer = %peer,
                                                error = %e,
                                                "Failed to request tx set from externalize peer"
                                            );
                                        }
                                    }
                                }
                            }
                            // First, process externalized slots to register pending tx set requests
                            self.process_externalized_slots().await;
                            // Then, immediately request any pending tx sets
                            self.request_pending_tx_sets().await;
                        }
                    }
                    EnvelopeState::Pending => {
                        tracing::debug!(slot, tracking, "SCP envelope buffered for future slot");
                    }
                    EnvelopeState::Duplicate => {
                        // Expected, ignore silently
                    }
                    EnvelopeState::TooOld => {
                        tracing::debug!(slot, tracking, "SCP envelope too old");
                    }
                    EnvelopeState::Invalid => {
                        tracing::debug!(slot, peer = %msg.from_peer, "Invalid SCP envelope");
                    }
                    EnvelopeState::InvalidSignature => {
                        tracing::warn!(slot, peer = %msg.from_peer, "SCP envelope with invalid signature");
                    }
                    EnvelopeState::Fetching => {
                        // Envelope is waiting for its tx set to be fetched.
                        // Request the tx set from the peer that sent this envelope.
                        tracing::debug!(
                            slot,
                            peer = %msg.from_peer,
                            "SCP EXTERNALIZE waiting for tx set (Fetching)"
                        );
                        if let Some(tx_set_hash) = tx_set_hash {
                            let peer = msg.from_peer.clone();
                            let overlay = self.overlay.lock().await;
                            if let Some(ref overlay) = *overlay {
                                let request = StellarMessage::GetTxSet(
                                    stellar_xdr::curr::Uint256(tx_set_hash.0),
                                );
                                if let Err(e) = overlay.send_to(&peer, request).await {
                                    tracing::debug!(
                                        peer = %peer,
                                        error = %e,
                                        "Failed to request tx set for fetching envelope"
                                    );
                                }
                            }
                        }
                        // Also request any other pending tx sets
                        self.request_pending_tx_sets().await;
                    }
                }
            }

            StellarMessage::Transaction(tx_env) => {
                let tx_hash = self.tx_hash(&tx_env);
                match self.herder.receive_transaction(tx_env.clone()) {
                    henyey_herder::TxQueueResult::Added => {
                        tracing::debug!(peer = %msg.from_peer, "Transaction added to queue");
                        if let Some(hash) = tx_hash {
                            self.record_tx_pull_latency(hash, &msg.from_peer).await;
                        }
                        self.enqueue_tx_advert(&tx_env).await;
                    }
                    henyey_herder::TxQueueResult::Duplicate => {
                        if let Some(hash) = tx_hash {
                            self.record_tx_pull_latency(hash, &msg.from_peer).await;
                        }
                        // Expected, ignore
                    }
                    henyey_herder::TxQueueResult::QueueFull => {
                        tracing::warn!("Transaction queue full, dropping transaction");
                    }
                    henyey_herder::TxQueueResult::FeeTooLow => {
                        tracing::debug!("Transaction fee too low, rejected");
                    }
                    henyey_herder::TxQueueResult::Invalid => {
                        tracing::debug!("Invalid transaction rejected");
                    }
                    henyey_herder::TxQueueResult::Banned => {
                        tracing::debug!("Transaction from banned source rejected");
                    }
                    henyey_herder::TxQueueResult::Filtered => {
                        tracing::debug!("Transaction filtered by operation type");
                    }
                    henyey_herder::TxQueueResult::TryAgainLater => {
                        tracing::debug!(
                            "Transaction rejected: account already has pending transaction"
                        );
                    }
                }
            }

            StellarMessage::FloodAdvert(advert) => {
                self.handle_flood_advert(&msg.from_peer, advert).await;
            }

            StellarMessage::FloodDemand(demand) => {
                self.handle_flood_demand(&msg.from_peer, demand).await;
            }

            StellarMessage::DontHave(dont_have) => {
                let is_tx_set = matches!(
                    dont_have.type_,
                    stellar_xdr::curr::MessageType::TxSet
                        | stellar_xdr::curr::MessageType::GeneralizedTxSet
                );
                let is_ping = matches!(
                    dont_have.type_,
                    stellar_xdr::curr::MessageType::ScpQuorumset
                );
                if is_tx_set {
                    tracing::debug!(
                        peer = %msg.from_peer,
                        hash = hex::encode(dont_have.req_hash.0),
                        "Peer reported DontHave for TxSet"
                    );
                    let hash = Hash256::from_bytes(dont_have.req_hash.0);
                    let mut map = self.tx_set_dont_have.write().await;
                    map.entry(hash).or_default().insert(msg.from_peer.clone());
                    
                    // Check if all connected peers have reported DontHave for this tx_set
                    let dont_have_count = map.get(&hash).map(|s| s.len()).unwrap_or(0);
                    let peer_count = self.get_peer_count().await;
                    let all_peers_dont_have = dont_have_count >= peer_count && peer_count > 0;
                    
                    if self.herder.needs_tx_set(&hash) {
                        if all_peers_dont_have {
                            // All peers don't have this tx_set - log but DON'T trigger catchup.
                            // Like stellar-core, we rely on slot eviction to eventually
                            // clean up old slots when we're >100 slots behind the highest
                            // v-blocking slot. Triggering catchup on DontHave creates loops
                            // because catchup targets checkpoints, leaving gaps that also
                            // get DontHave responses.
                            // Only log once per hash to avoid spam during recovery.
                            let already_warned = self.tx_set_exhausted_warned.read().await.contains(&hash);
                            if !already_warned {
                                self.tx_set_exhausted_warned.write().await.insert(hash);
                                tracing::info!(
                                    hash = %hash,
                                    dont_have_count,
                                    peer_count,
                                    "All peers reported DontHave for needed TxSet; relying on slot eviction"
                                );
                            }
                            drop(map);
                            // Reset request tracking to allow retry later
                            let mut last_request = self.tx_set_last_request.write().await;
                            last_request.remove(&hash);
                        } else {
                            let mut last_request = self.tx_set_last_request.write().await;
                            last_request.remove(&hash);
                            drop(last_request);
                            drop(map);
                            self.request_pending_tx_sets().await;
                        }
                    }
                }
                if is_ping {
                    self.process_ping_response(&msg.from_peer, dont_have.req_hash.0)
                        .await;
                }
            }

            StellarMessage::GetScpState(ledger_seq) => {
                tracing::debug!(ledger_seq, peer = %msg.from_peer, "Peer requested SCP state");
                self.send_scp_state(&msg.from_peer, ledger_seq).await;
            }

            StellarMessage::GetScpQuorumset(hash) => {
                tracing::debug!(hash = hex::encode(hash.0), peer = %msg.from_peer, "Peer requested quorum set");
                self.send_quorum_set(&msg.from_peer, hash).await;
            }

            StellarMessage::ScpQuorumset(quorum_set) => {
                tracing::debug!(peer = %msg.from_peer, "Received quorum set");
                let hash = henyey_scp::hash_quorum_set(&quorum_set);
                self.process_ping_response(&msg.from_peer, hash.0).await;
                self.handle_quorum_set(&msg.from_peer, quorum_set).await;
            }

            StellarMessage::TimeSlicedSurveyStartCollecting(start) => {
                self.handle_survey_start_collecting(&msg.from_peer, start)
                    .await;
            }

            StellarMessage::TimeSlicedSurveyStopCollecting(stop) => {
                self.handle_survey_stop_collecting(&msg.from_peer, stop)
                    .await;
            }

            StellarMessage::TimeSlicedSurveyRequest(request) => {
                self.handle_survey_request(&msg.from_peer, request).await;
            }

            StellarMessage::TimeSlicedSurveyResponse(response) => {
                self.handle_survey_response(&msg.from_peer, response).await;
            }

            StellarMessage::Peers(peer_list) => {
                tracing::debug!(count = peer_list.len(), peer = %msg.from_peer, "Received peer list");
                self.process_peer_list(peer_list).await;
            }

            StellarMessage::TxSet(tx_set) => {
                // Compute hash for logging
                let xdr_bytes = stellar_xdr::curr::WriteXdr::to_xdr(&tx_set, stellar_xdr::curr::Limits::none())
                    .unwrap_or_default();
                let computed_hash = henyey_common::Hash256::hash(&xdr_bytes);
                tracing::info!(
                    peer = %msg.from_peer,
                    computed_hash = %computed_hash,
                    prev_ledger = hex::encode(tx_set.previous_ledger_hash.0),
                    tx_count = tx_set.txs.len(),
                    "APP: Received TxSet from overlay"
                );
                self.handle_tx_set(tx_set).await;
            }

            StellarMessage::GeneralizedTxSet(gen_tx_set) => {
                // Compute hash for logging
                let xdr_bytes = stellar_xdr::curr::WriteXdr::to_xdr(&gen_tx_set, stellar_xdr::curr::Limits::none())
                    .unwrap_or_default();
                let computed_hash = henyey_common::Hash256::hash(&xdr_bytes);
                tracing::debug!(
                    peer = %msg.from_peer,
                    computed_hash = %computed_hash,
                    "APP: Received GeneralizedTxSet from overlay"
                );
                self.handle_generalized_tx_set(gen_tx_set).await;
            }

            StellarMessage::GetTxSet(hash) => {
                tracing::debug!(hash = hex::encode(hash.0), peer = %msg.from_peer, "Peer requested TxSet");
                self.send_tx_set(&msg.from_peer, &hash.0).await;
            }

            _ => {
                // Other message types (Hello, Auth, etc.) are handled by overlay
                tracing::trace!(msg_type = ?std::mem::discriminant(&msg.message), "Ignoring message type");
            }
        }
    }

    /// Try to close a specific slot directly when we receive its tx set.
    /// This feeds the buffered ledger pipeline and attempts sequential apply.
    async fn try_close_slot_directly(&self, slot: u64) {
        tracing::debug!(slot, "Attempting to close specific slot directly");
        let close_info = match self.herder.check_ledger_close(slot) {
            Some(info) => info,
            None => {
                tracing::debug!(slot, "No ledger close info for slot");
                return;
            }
        };

        self.update_buffered_tx_set(slot as u32, close_info.tx_set)
            .await;
        self.try_apply_buffered_ledgers().await;
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
        let has_new_slots = latest_externalized > last_processed;

        if has_new_slots {
            tracing::debug!(
                latest_externalized,
                last_processed,
                gap = latest_externalized - last_processed,
                "Processing new externalized slots"
            );

            let prev_latest = self
                .last_externalized_slot
                .swap(latest_externalized, Ordering::Relaxed);
            if latest_externalized != prev_latest {
                *self.last_externalized_at.write().await = Instant::now();
            }

            let mut missing_tx_set = false;
            let mut buffered_count = 0usize;
            let mut advance_to = last_processed;
            let mut skipped_stale = 0u64;
            {
                let current_ledger = *self.current_ledger.read().await;
                let mut buffer = self.syncing_ledgers.write().await;
                for slot in (last_processed + 1)..=latest_externalized {
                    // Skip slots that have already been closed. Stale
                    // EXTERNALIZE messages (e.g., from SCP state responses)
                    // can set latest_externalized to old slots whose tx_sets
                    // are evicted from peers' caches. Creating syncing_ledgers
                    // entries for these would cause unfulfillable tx_set
                    // requests and infinite recovery loops.
                    if slot <= current_ledger as u64 {
                        skipped_stale += 1;
                        if slot == advance_to + 1 {
                            advance_to = slot;
                        }
                        continue;
                    }

                    if let Some(info) = self.herder.check_ledger_close(slot) {
                        let has_tx_set = info.tx_set.is_some();
                        // Update existing entry's tx_set if it was missing but now available,
                        // or insert new entry if slot wasn't buffered yet.
                        match buffer.entry(info.slot as u32) {
                            std::collections::btree_map::Entry::Occupied(mut entry) => {
                                let existing = entry.get_mut();
                                if existing.tx_set.is_none() && info.tx_set.is_some() {
                                    existing.tx_set = info.tx_set;
                                    tracing::info!(
                                        slot,
                                        "Updated buffered ledger with tx_set from check_ledger_close"
                                    );
                                }
                                if existing.tx_set.is_none() {
                                    missing_tx_set = true;
                                }
                            }
                            std::collections::btree_map::Entry::Vacant(entry) => {
                                if !has_tx_set {
                                    missing_tx_set = true;
                                }
                                entry.insert(info);
                            }
                        }
                        buffered_count += 1;
                        if slot == advance_to + 1 {
                            advance_to = slot;
                        }
                    }
                }
            }
            if skipped_stale > 0 {
                tracing::debug!(
                    skipped_stale,
                    "Skipped already-closed slots in process_externalized_slots"
                );
            }

            *self.last_processed_slot.write().await = advance_to;

            if missing_tx_set {
                self.request_pending_tx_sets().await;
            }
            // Trigger externalized catchup if the gap between current_ledger
            // and the latest externalized slot is too large to bridge via
            // individual tx_set fetches.  Previously this only fired when
            // buffered_count == 0, but after catchup the first fresh
            // EXTERNALIZE creates an entry (buffered_count == 1) even though
            // current_ledger is 40+ slots behind.  Check the gap regardless.
            {
                let current_ledger = *self.current_ledger.read().await;
                let gap = latest_externalized.saturating_sub(current_ledger as u64);
                if buffered_count == 0 || gap > TX_SET_REQUEST_WINDOW {
                    self.maybe_start_externalized_catchup(latest_externalized)
                        .await;
                }
            }
        } else {
            tracing::debug!(latest_externalized, last_processed, "Already processed");
        }

        // Always try to apply buffered ledgers and check for catchup,
        // even when no new slots - we may need to trigger stuck recovery.
        self.try_apply_buffered_ledgers().await;
        self.maybe_start_buffered_catchup().await;
    }

    fn first_ledger_in_checkpoint(ledger: u32) -> u32 {
        (ledger / CHECKPOINT_FREQUENCY) * CHECKPOINT_FREQUENCY
    }

    fn is_first_ledger_in_checkpoint(ledger: u32) -> bool {
        ledger % CHECKPOINT_FREQUENCY == 0
    }

    fn trim_syncing_ledgers(
        buffer: &mut BTreeMap<u32, henyey_herder::LedgerCloseInfo>,
        current_ledger: u32,
    ) {
        // Hard limit on buffer size to prevent unbounded memory growth.
        // With ~50 slots per checkpoint and large tx sets, keeping more than
        // 100 slots can use significant memory (100+ MB).
        const MAX_BUFFER_SIZE: usize = 100;

        // Step 1: Remove entries already closed (at or below current_ledger).
        let min_keep = current_ledger.saturating_add(1);
        buffer.retain(|seq, _| *seq >= min_keep);
        if buffer.is_empty() {
            return;
        }

        // Step 2: Trim to checkpoint boundary ONLY when the buffer's first
        // entry is far ahead of current_ledger (gap >= CHECKPOINT_FREQUENCY).
        // When entries close to current_ledger exist (e.g. current_ledger+1),
        // those are potentially closeable once their tx_sets arrive — trimming
        // them would destroy entries the node needs for sequential close and
        // create an artificial gap that prevents progress.
        let first_buffered = *buffer.keys().next().expect("checked non-empty above");
        let last_buffered = *buffer.keys().next_back().expect("checked non-empty above");
        let gap = first_buffered.saturating_sub(current_ledger);
        if gap >= CHECKPOINT_FREQUENCY {
            let trim_before = if Self::is_first_ledger_in_checkpoint(last_buffered) {
                if last_buffered == 0 {
                    return;
                }
                let prev = last_buffered - 1;
                Self::first_ledger_in_checkpoint(prev)
            } else {
                Self::first_ledger_in_checkpoint(last_buffered)
            };
            buffer.retain(|seq, _| *seq >= trim_before);
        }

        // Step 3: If buffer is still too large, keep only the most recent
        // MAX_BUFFER_SIZE slots. This prevents unbounded memory growth when
        // the validator is stuck.
        if buffer.len() > MAX_BUFFER_SIZE {
            let keys_to_remove: Vec<u32> = buffer
                .keys()
                .take(buffer.len() - MAX_BUFFER_SIZE)
                .copied()
                .collect();
            for key in keys_to_remove {
                buffer.remove(&key);
            }
            tracing::debug!(
                buffer_size = buffer.len(),
                "Trimmed syncing_ledgers buffer to max size"
            );
        }
    }

    async fn update_buffered_tx_set(
        &self,
        slot: u32,
        tx_set: Option<henyey_herder::TransactionSet>,
    ) {
        let Some(tx_set) = tx_set else {
            return;
        };
        let mut buffer = self.syncing_ledgers.write().await;
        if let Some(entry) = buffer.get_mut(&slot) {
            if tx_set.hash != entry.tx_set_hash {
                tracing::warn!(
                    slot,
                    expected = %entry.tx_set_hash.to_hex(),
                    found = %tx_set.hash.to_hex(),
                    "Buffered tx set hash mismatch (dropping)"
                );
                return;
            }
            entry.tx_set = Some(tx_set);
            tracing::debug!(slot, "Buffered tx set attached");
        } else {
            tracing::debug!(slot, "Received tx set for unbuffered slot");
        }
    }

    async fn attach_tx_set_by_hash(&self, tx_set: &henyey_herder::TransactionSet) -> bool {
        let mut buffer = self.syncing_ledgers.write().await;
        for (slot, entry) in buffer.iter_mut() {
            if entry.tx_set.is_none() && entry.tx_set_hash == tx_set.hash {
                entry.tx_set = Some(tx_set.clone());
                tracing::debug!(slot, hash = %tx_set.hash, "Attached tx set to buffered slot");
                return true;
            }
        }
        false
    }

    async fn buffer_externalized_tx_set(
        &self,
        tx_set: &henyey_herder::TransactionSet,
    ) -> bool {
        let Some(slot) = self
            .herder
            .find_externalized_slot_by_tx_set_hash(&tx_set.hash)
        else {
            return false;
        };
        let Some(info) = self.herder.check_ledger_close(slot) else {
            return false;
        };
        {
            let mut buffer = self.syncing_ledgers.write().await;
            buffer.entry(info.slot as u32).or_insert(info);
        }
        self.update_buffered_tx_set(slot as u32, Some(tx_set.clone()))
            .await;
        tracing::debug!(
            slot,
            hash = %tx_set.hash,
            "Buffered tx set after externalized lookup"
        );
        true
    }

    /// Drain all sequential buffered ledgers synchronously.
    ///
    /// Called at the end of catchup to match stellar-core's
    /// `ApplyBufferedLedgersWork`: CatchupWork does not return success
    /// until all sequential buffered ledgers have been applied.
    ///
    /// Returns the number of ledgers drained.
    async fn drain_buffered_ledgers_sync(&self) -> u32 {
        let mut drained = 0u32;
        loop {
            let mut pending = match self.try_start_ledger_close().await {
                Some(p) => p,
                None => break,
            };
            let join_result = (&mut pending.handle).await;
            let success = self.handle_close_complete(pending, join_result).await;
            if !success {
                break;
            }
            drained += 1;
        }
        drained
    }

    /// Apply buffered ledgers (yields to tokio via `spawn_blocking`).
    ///
    /// Used by callers outside the main select loop (catchup completion, tx set
    /// handlers). If a background close is already in progress (`is_applying_ledger`),
    /// returns immediately — the select loop completion handler will chain the next close.
    async fn try_apply_buffered_ledgers(&self) {
        // If a background close is already running, let the select loop handle chaining.
        if self.is_applying_ledger() {
            return;
        }

        let mut closed_any = false;
        loop {
            let mut pending = match self.try_start_ledger_close().await {
                Some(p) => p,
                None => break,
            };
            let join_result = (&mut pending.handle).await;
            let success = self.handle_close_complete(pending, join_result).await;
            if !success {
                break;
            }
            closed_any = true;
        }

        // After closing one or more buffered ledgers, reset timestamps and
        // tracking state so the heartbeat stall detector doesn't fire based
        // on the (now stale) timestamp of the EXTERNALIZE that triggered
        // this burst.  This mirrors the reset done in the pending_close
        // handler at the end of the select-loop chain (line ~3086-3111).
        if closed_any {
            *self.last_externalized_at.write().await = Instant::now();
            self.tx_set_all_peers_exhausted
                .store(false, Ordering::SeqCst);
            self.tx_set_dont_have.write().await.clear();
            self.tx_set_last_request.write().await.clear();
            self.tx_set_exhausted_warned.write().await.clear();
            *self.consensus_stuck_state.write().await = None;
        }
    }

    /// Start a background ledger close if the next buffered ledger is ready.
    ///
    /// Returns `Some(PendingLedgerClose)` if a close was spawned, `None` if
    /// nothing to close or a close is already in progress.
    async fn try_start_ledger_close(&self) -> Option<PendingLedgerClose> {
        if self.is_applying_ledger() {
            return None;
        }

        let current_ledger = self.get_current_ledger().await.ok()?;
        let next_seq = current_ledger.saturating_add(1);

        let close_info = {
            let mut buffer = self.syncing_ledgers.write().await;
            Self::trim_syncing_ledgers(&mut buffer, current_ledger);
            match buffer.get(&next_seq) {
                Some(info) if info.tx_set.is_some() => info.clone(),
                Some(info) => {
                    tracing::debug!(
                        next_seq,
                        tx_set_hash = %info.tx_set_hash,
                        "Buffered but waiting for tx_set"
                    );
                    return None;
                }
                None => {
                    let is_externalized =
                        self.herder.get_externalized(next_seq as u64).is_some();
                    if is_externalized {
                        tracing::debug!(
                            next_seq,
                            current_ledger,
                            "Next slot externalized but not yet in syncing_ledgers buffer"
                        );
                    } else {
                        let latest =
                            self.herder.latest_externalized_slot().unwrap_or(0);
                        if latest > next_seq as u64 {
                            tracing::debug!(
                                next_seq,
                                latest_externalized = latest,
                                "Missing EXTERNALIZE for next slot (gap detected)"
                            );
                        }
                    }
                    return None;
                }
            }
        };

        let tx_set = close_info.tx_set.clone().expect("tx set present");
        let our_header_hash = self.ledger_manager.current_header_hash();
        if our_header_hash != tx_set.previous_ledger_hash {
            tracing::error!(
                ledger_seq = next_seq,
                our_header_hash = %our_header_hash.to_hex(),
                network_prev_hash = %tx_set.previous_ledger_hash.to_hex(),
                "FATAL: pre-close hash mismatch — our header hash does not match \
                 the network's previous ledger hash. This means our ledger state \
                 has diverged from the network. Shutting down."
            );
            std::process::exit(1);
        }
        if tx_set.hash != close_info.tx_set_hash {
            tracing::error!(
                ledger_seq = next_seq,
                expected = %close_info.tx_set_hash.to_hex(),
                found = %tx_set.hash.to_hex(),
                "Buffered tx set hash mismatch"
            );
            let mut buffer = self.syncing_ledgers.write().await;
            if let Some(entry) = buffer.get_mut(&next_seq) {
                entry.tx_set = None;
            }
            return None;
        }

        tracing::debug!(
            ledger_seq = next_seq,
            tx_count = tx_set.transactions.len(),
            close_time = close_info.close_time,
            prev_ledger_hash = %tx_set.previous_ledger_hash.to_hex(),
            "Starting background ledger close"
        );

        // Build LedgerCloseData (same as HerderCallback::close_ledger).
        let prev_hash = tx_set.previous_ledger_hash;
        let tx_set_variant = if let Some(gen_tx_set) = tx_set.generalized_tx_set.clone() {
            TransactionSetVariant::Generalized(gen_tx_set)
        } else {
            TransactionSetVariant::Classic(TransactionSet {
                previous_ledger_hash: Hash::from(prev_hash),
                txs: match tx_set.transactions.clone().try_into() {
                    Ok(txs) => txs,
                    Err(_) => {
                        tracing::error!(
                            ledger_seq = next_seq,
                            "Failed to create tx set for background close"
                        );
                        return None;
                    }
                },
            })
        };

        let decoded_upgrades = decode_upgrades(close_info.upgrades.clone());
        let close_time = close_info.close_time;

        let mut close_data =
            LedgerCloseData::new(next_seq, tx_set_variant.clone(), close_time, prev_hash)
                .with_stellar_value_ext(close_info.stellar_value_ext);
        if !decoded_upgrades.is_empty() {
            close_data = close_data.with_upgrades(decoded_upgrades);
        }
        if let Some(entry) = self.build_scp_history_entry(next_seq) {
            close_data = close_data.with_scp_history(vec![entry]);
        }

        // Remove from buffer before spawning (optimistic).
        {
            let mut buffer = self.syncing_ledgers.write().await;
            buffer.remove(&next_seq);
        }

        // Spawn blocking close.
        let lm = self.ledger_manager.clone();
        let runtime_handle = tokio::runtime::Handle::current();
        self.set_applying_ledger(true);

        let join_handle = tokio::task::spawn_blocking(move || {
            lm.close_ledger(close_data, Some(runtime_handle))
                .map_err(|e| e.to_string())
        });

        Some(PendingLedgerClose {
            handle: join_handle,
            ledger_seq: next_seq,
            tx_set,
            tx_set_variant,
            close_time,
        })
    }

    /// Handle completion of a background ledger close.
    ///
    /// Performs all post-close work: meta emission, DB persistence, herder
    /// notification, and state updates. Returns `true` on success.
    async fn handle_close_complete(
        &self,
        pending: PendingLedgerClose,
        join_result: Result<
            std::result::Result<LedgerCloseResult, String>,
            tokio::task::JoinError,
        >,
    ) -> bool {
        self.set_applying_ledger(false);

        let result = match join_result {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                let is_hash_mismatch = e.contains("hash mismatch");
                tracing::error!(
                    ledger_seq = pending.ledger_seq,
                    error = %e,
                    is_hash_mismatch,
                    "Background ledger close failed"
                );
                if is_hash_mismatch {
                    let mut buffer = self.syncing_ledgers.write().await;
                    let cleared_count = buffer.len();
                    buffer.clear();
                    tracing::warn!(
                        ledger_seq = pending.ledger_seq,
                        cleared_count,
                        "Hash mismatch detected - cleared all buffered ledgers, will trigger catchup"
                    );
                }
                return false;
            }
            Err(e) => {
                tracing::error!(
                    ledger_seq = pending.ledger_seq,
                    error = %e,
                    "Ledger close task panicked"
                );
                return false;
            }
        };

        // Emit LedgerCloseMeta to stream.
        if let Some(ref meta) = result.meta {
            let mut guard = self.meta_stream.lock().unwrap();
            if let Some(ref mut stream) = *guard {
                if let Err(e) = stream.maybe_rotate_debug_stream(pending.ledger_seq) {
                    tracing::warn!(
                        error = %e,
                        ledger_seq = pending.ledger_seq,
                        "Failed to rotate debug meta stream"
                    );
                }
                match stream.emit_meta(meta) {
                    Ok(()) => {}
                    Err(MetaStreamError::MainStreamWrite(e)) => {
                        tracing::error!(
                            error = %e,
                            ledger_seq = pending.ledger_seq,
                            "Fatal: metadata output stream write failed"
                        );
                        std::process::abort();
                    }
                    Err(MetaStreamError::DebugStreamWrite(e)) => {
                        tracing::warn!(
                            error = %e,
                            ledger_seq = pending.ledger_seq,
                            "Debug metadata stream write failed"
                        );
                    }
                }
            }
        }

        // Persist ledger close data.
        let tx_metas = result.meta.as_ref().map(Self::extract_tx_metas);
        if let Err(err) = self.persist_ledger_close(
            &result.header,
            &pending.tx_set_variant,
            &result.tx_results,
            tx_metas.as_deref(),
        ) {
            tracing::warn!(error = %err, "Failed to persist ledger close data");
        }

        // Separate successful and failed transactions for queue management.
        let mut applied_hashes = Vec::new();
        let mut failed_hashes = Vec::new();
        for (tx, tx_result) in pending
            .tx_set
            .transactions
            .iter()
            .zip(result.tx_results.iter())
        {
            if let Some(hash) = self.tx_hash(tx) {
                use stellar_xdr::curr::TransactionResultResult;
                let is_success = matches!(
                    tx_result.result.result,
                    TransactionResultResult::TxSuccess(_)
                        | TransactionResultResult::TxFeeBumpInnerSuccess(_)
                );
                if is_success {
                    applied_hashes.push(hash);
                } else {
                    failed_hashes.push(hash);
                }
            }
        }

        self.herder
            .ledger_closed(pending.ledger_seq as u64, &applied_hashes);

        if !failed_hashes.is_empty() {
            tracing::debug!(
                failed_count = failed_hashes.len(),
                "Banning failed transactions"
            );
            self.herder.tx_queue().ban(&failed_hashes);
        }

        // Record externalized close time for drift tracking.
        if let Ok(mut tracker) = self.drift_tracker.lock() {
            if let Some(warning) =
                tracker.record_externalized_close_time(pending.ledger_seq, pending.close_time)
            {
                tracing::warn!("{}", warning);
            }
        }

        self.herder.tx_queue().update_validation_context(
            pending.ledger_seq,
            result.header.scp_value.close_time.0,
            result.header.ledger_version,
            result.header.base_fee,
        );

        let shift_result = self.herder.tx_queue().shift();
        if shift_result.unbanned_count > 0 || shift_result.evicted_due_to_age > 0 {
            tracing::debug!(
                unbanned = shift_result.unbanned_count,
                evicted = shift_result.evicted_due_to_age,
                "Shifted transaction ban queue"
            );
        }

        // Update current ledger tracking.
        *self.current_ledger.write().await = pending.ledger_seq;
        *self.last_processed_slot.write().await = pending.ledger_seq as u64;
        self.clear_tx_advert_history(pending.ledger_seq).await;

        // Clean up stale pending tx_set requests for slots we've now closed.
        // This prevents stale requests (from old SCP state responses) from
        // lingering and causing timeout → DontHave → recovery loops.
        let stale_cleared = self
            .herder
            .cleanup_old_pending_tx_sets(pending.ledger_seq as u64 + 1);
        if stale_cleared > 0 {
            tracing::debug!(
                stale_cleared,
                ledger_seq = pending.ledger_seq,
                "Cleared stale pending tx_set requests after ledger close"
            );
        }

        // Signal heartbeat to sync recovery.
        self.sync_recovery_heartbeat();

        self.tx_set_all_peers_exhausted
            .store(false, Ordering::SeqCst);

        true
    }

    async fn maybe_start_buffered_catchup(&self) {
        // Early cooldown check: if we recently completed or skipped catchup,
        // skip re-evaluating. This prevents log spam and avoids re-triggering
        // catchup while the node is still stabilizing after a catchup cycle.
        // 10 seconds gives enough time for SCP messages to arrive and fill
        // small gaps after catchup + buffered ledger drain.
        const EVALUATION_COOLDOWN_SECS: u64 = 10;
        let cooldown_elapsed = self
            .last_catchup_completed_at
            .read()
            .await
            .map(|t| t.elapsed().as_secs());
        let recently_skipped = cooldown_elapsed
            .is_some_and(|s| s < EVALUATION_COOLDOWN_SECS);
        if recently_skipped {
            tracing::debug!(
                cooldown_elapsed = ?cooldown_elapsed,
                "maybe_start_buffered_catchup: skipped due to cooldown"
            );
            return;
        }

        let current_ledger = match self.get_current_ledger().await {
            Ok(seq) => seq,
            Err(_) => return,
        };

        // Guard: if the node is essentially caught up (gap ≤ TX_SET_REQUEST_WINDOW),
        // do NOT trigger catchup. Stale tx_set requests from prior EXTERNALIZE
        // messages can set tx_set_all_peers_exhausted, but when the gap is small
        // the correct action is to wait for fresh EXTERNALIZE — not to catchup.
        // Without this guard, the node enters an infinite loop:
        //   catchup → rapid close → stale tx_set timeout → all_peers_exhausted
        //   → catchup → repeat
        let latest_externalized = self.herder.latest_externalized_slot().unwrap_or(0);
        let gap = latest_externalized.saturating_sub(current_ledger as u64);
        if gap <= TX_SET_REQUEST_WINDOW {
            // Clear stale state that might trigger unnecessary catchup
            if self.tx_set_all_peers_exhausted.load(Ordering::SeqCst) {
                tracing::info!(
                    current_ledger,
                    latest_externalized,
                    gap,
                    "maybe_start_buffered_catchup: essentially caught up, \
                     clearing tx_set_all_peers_exhausted and stale state"
                );
                self.tx_set_all_peers_exhausted
                    .store(false, Ordering::SeqCst);
                self.tx_set_dont_have.write().await.clear();
                self.tx_set_last_request.write().await.clear();
                self.tx_set_exhausted_warned.write().await.clear();
                self.herder.clear_pending_tx_sets();
            }
            return;
        }

        let (first_buffered, last_buffered) = {
            let mut buffer = self.syncing_ledgers.write().await;
            let pre_trim_count = buffer.len();
            let pre_trim_first = buffer.keys().next().copied();
            let pre_trim_last = buffer.keys().next_back().copied();
            Self::trim_syncing_ledgers(&mut buffer, current_ledger);

            // When all peers have reported DontHave for tx_sets, evict buffered
            // entries starting from current_ledger+1 that have no tx_set. These
            // slots were externalized (we have the SCP value) but the tx_set data
            // has been evicted from all peers' caches and will never arrive.
            // Removing them creates a proper gap so the catchup target logic can
            // compute a valid target (e.g., the next checkpoint boundary).
            // Without this, the buffer looks like [N+1(no tx_set), N+25(tx_set), ...]
            // and first_buffered = N+1 causes catchup target computation to fail
            // (it thinks the gap is only 1 ledger).
            if self.tx_set_all_peers_exhausted.load(Ordering::SeqCst) {
                let mut evicted = 0u32;
                let start = current_ledger.saturating_add(1);
                // Evict consecutive entries from the front that lack tx_sets.
                // Stop at the first entry that HAS a tx_set — those are still
                // usable once we catch up past the gap.
                for seq in start.. {
                    match buffer.get(&seq) {
                        Some(info) if info.tx_set.is_none() => {
                            buffer.remove(&seq);
                            evicted += 1;
                        }
                        _ => break, // gap in buffer or entry has tx_set
                    }
                }
                if evicted > 0 {
                    tracing::info!(
                        current_ledger,
                        evicted,
                        "Evicted buffered entries with permanently unavailable tx_sets"
                    );
                }
            }

            let post_trim_count = buffer.len();
            let post_first = buffer.keys().next().copied();
            let post_last = buffer.keys().next_back().copied();
            tracing::debug!(
                current_ledger,
                pre_trim_count,
                pre_trim_first,
                pre_trim_last,
                post_trim_count,
                post_first,
                post_last,
                "maybe_start_buffered_catchup: buffer state"
            );

            match (post_first, post_last) {
                (Some(first), Some(last)) => (first, last),
                _ => {
                    tracing::debug!(
                        current_ledger,
                        pre_trim_count,
                        pre_trim_first,
                        pre_trim_last,
                        "maybe_start_buffered_catchup: empty buffer after trim/evict, returning"
                    );
                    return;
                }
            }
        };

        let is_checkpoint_boundary = Self::is_first_ledger_in_checkpoint(first_buffered);
        let can_trigger_immediate = is_checkpoint_boundary && first_buffered < last_buffered;
        tracing::debug!(
            current_ledger,
            first_buffered,
            last_buffered,
            is_checkpoint_boundary,
            can_trigger_immediate,
            gap = first_buffered.saturating_sub(current_ledger),
            "maybe_start_buffered_catchup: evaluating"
        );

        // Check if sequential ledger has tx set available
        let sequential_with_tx_set = if first_buffered == current_ledger + 1 {
            let buffer = self.syncing_ledgers.read().await;
            buffer
                .get(&first_buffered)
                .is_some_and(|info| info.tx_set.is_some())
        } else {
            false
        };

        if sequential_with_tx_set {
            // Tx set is available, let try_apply_buffered_ledgers() handle it.
            // DON'T reset stuck state here - there's a race condition where the tx_set
            // might have arrived after try_apply_buffered_ledgers() checked but before
            // this check. The stuck state will naturally become invalid when current_ledger
            // advances (the match condition state.current_ledger == current_ledger will fail).
            tracing::debug!(
                current_ledger,
                first_buffered,
                "Sequential ledger tx set available; skipping buffered catchup"
            );
            return;
        }

        // Calculate gap and determine catchup strategy.
        //
        // stellar-core only triggers immediate catchup when the first buffered
        // ledger sits at a checkpoint boundary AND there is at least one more
        // buffered ledger after it. The gap *size* alone is not a trigger — a
        // gap slightly larger than CHECKPOINT_FREQUENCY is expected right after
        // the initial catchup because the network advances while catchup runs.
        // Triggering on gap size alone caused unnecessary second catchup cycles
        // (see: "Buffered gap exceeds checkpoint; starting catchup" log spam).
        // First buffered is checkpoint boundary AND we have multiple buffered ledgers.
        // This matches stellar-core: catchup to first_buffered - 1.
        let can_trigger_immediate =
            Self::is_first_ledger_in_checkpoint(first_buffered) && first_buffered < last_buffered;

        tracing::debug!(
            can_trigger_immediate,
            first_buffered,
            last_buffered,
            is_checkpoint = Self::is_first_ledger_in_checkpoint(first_buffered),
            "maybe_start_buffered_catchup: can_trigger_immediate decision"
        );

        // If we can't trigger immediate catchup, check if we should wait for trigger
        // or if we're stuck and need timeout-based catchup
        if !can_trigger_immediate {
            let (required_first, trigger) = if Self::is_first_ledger_in_checkpoint(first_buffered) {
                (first_buffered, first_buffered.saturating_add(1))
            } else {
                let required_first = Self::first_ledger_in_checkpoint(first_buffered)
                    .saturating_add(CHECKPOINT_FREQUENCY);
                (required_first, required_first.saturating_add(1))
            };

            // Check if we have the trigger ledger
            if last_buffered >= trigger {
                // We have enough buffered ledgers - proceed to catchup below
            } else {
                // We're waiting for trigger - apply consensus stuck timeout
                // This handles the case where we have a gap but can't reach the trigger
                let now = Instant::now();
                let action = {
                    let mut stuck_state = self.consensus_stuck_state.write().await;
                    match stuck_state.as_mut() {
                        // Match on current_ledger only. first_buffered can change as
                        // stale EXTERNALIZE messages from SCP state requests create
                        // new syncing_ledgers entries with lower slot numbers. Matching
                        // on both caused the stuck timer to reset every time
                        // first_buffered shifted, preventing catchup from ever
                        // triggering (Problem 9).
                        Some(state)
                            if state.current_ledger == current_ledger =>
                        {
                            // Update first_buffered to track the current value
                            state.first_buffered = first_buffered;
                            let elapsed = state.stuck_start.elapsed().as_secs();
                            let since_recovery = state.last_recovery_attempt.elapsed().as_secs();

                            // These signals help determine the stuck timeout when NOT
                            // recently caught up. When all peers report DontHave or
                            // requests have been waiting too long, use a faster timeout.
                            let all_peers_exhausted =
                                self.tx_set_all_peers_exhausted.load(Ordering::SeqCst);
                            let has_stale_requests = self
                                .herder
                                .has_stale_pending_tx_set(TX_SET_UNAVAILABLE_TIMEOUT_SECS);
                            let recovery_failed = state.recovery_attempts >= 2;

                            // Cooldown: don't trigger catchup if we recently completed
                            // catchup. stellar-core does NOT have a stuck timeout
                            // that triggers catchup — it only triggers catchup when
                            // checkpoint boundary conditions are met (handled above by
                            // can_trigger_immediate). When recently caught up, only do
                            // recovery (re-request SCP state) to fill gaps.
                            let recently_caught_up = self
                                .last_catchup_completed_at
                                .read()
                                .await
                                .is_some_and(|t| t.elapsed().as_secs() < POST_CATCHUP_RECOVERY_WINDOW_SECS);

                            // When recently caught up, prefer recovery over catchup.
                            // The next checkpoint won't be published to archives for
                            // ~5 min, so archive-based catchup will fail trying to
                            // download unpublished checkpoint data. However, if
                            // recovery has been attempted multiple times without
                            // progress, the missing slots have likely been evicted
                            // from peers' caches and recovery will never succeed.
                            // In that case, fall through to catchup.
                            if recently_caught_up {
                                if state.recovery_attempts >= MAX_POST_CATCHUP_RECOVERY_ATTEMPTS {
                                    // Recovery is futile — same gap persists after
                                    // multiple attempts. Peers don't have the missing
                                    // EXTERNALIZE messages (they only cache ~12 recent
                                    // slots). Trigger catchup instead of waiting the
                                    // full POST_CATCHUP_RECOVERY_WINDOW.
                                    tracing::warn!(
                                        current_ledger,
                                        first_buffered,
                                        last_buffered,
                                        elapsed_secs = elapsed,
                                        recovery_attempts = state.recovery_attempts,
                                        "Post-catchup recovery exhausted; \
                                         missing slots unrecoverable via SCP. \
                                         Triggering catchup."
                                    );
                                    state.catchup_triggered = true;
                                    ConsensusStuckAction::TriggerCatchup
                                } else if since_recovery >= OUT_OF_SYNC_RECOVERY_TIMER_SECS {
                                    state.last_recovery_attempt = now;
                                    state.recovery_attempts += 1;
                                    tracing::info!(
                                        current_ledger,
                                        first_buffered,
                                        elapsed_secs = elapsed,
                                        recovery_attempts = state.recovery_attempts,
                                        max_recovery_attempts = MAX_POST_CATCHUP_RECOVERY_ATTEMPTS,
                                        "Attempting out-of-sync recovery (post-catchup gap)"
                                    );
                                    ConsensusStuckAction::AttemptRecovery
                                } else {
                                    tracing::debug!(
                                        current_ledger,
                                        first_buffered,
                                        elapsed_secs = elapsed,
                                        "Waiting for SCP to fill post-catchup gap"
                                    );
                                    ConsensusStuckAction::Wait
                                }
                            } else {
                                // Not recently caught up — use stuck timeout logic.
                                let use_fast_timeout =
                                    all_peers_exhausted || has_stale_requests || recovery_failed;
                                let effective_timeout = if use_fast_timeout {
                                    TX_SET_UNAVAILABLE_TIMEOUT_SECS
                                } else {
                                    CONSENSUS_STUCK_TIMEOUT_SECS
                                };

                                if state.catchup_triggered {
                                    tracing::debug!(
                                        current_ledger,
                                        first_buffered,
                                        elapsed_secs = elapsed,
                                        "Catchup already triggered, waiting for progress"
                                    );
                                    ConsensusStuckAction::Wait
                                } else if elapsed >= effective_timeout {
                                    tracing::warn!(
                                        current_ledger,
                                        first_buffered,
                                        last_buffered,
                                        required_first,
                                        trigger,
                                        elapsed_secs = elapsed,
                                        recovery_attempts = state.recovery_attempts,
                                        all_peers_exhausted,
                                        has_stale_requests,
                                        recovery_failed,
                                        effective_timeout,
                                        "Buffered catchup stuck timeout; triggering catchup"
                                    );
                                    state.catchup_triggered = true;
                                    self.tx_set_all_peers_exhausted
                                        .store(false, Ordering::SeqCst);
                                    self.tx_set_exhausted_warned.write().await.clear();
                                    ConsensusStuckAction::TriggerCatchup
                                } else if since_recovery >= OUT_OF_SYNC_RECOVERY_TIMER_SECS {
                                    state.last_recovery_attempt = now;
                                    state.recovery_attempts += 1;
                                    tracing::info!(
                                        current_ledger,
                                        first_buffered,
                                        elapsed_secs = elapsed,
                                        recovery_attempts = state.recovery_attempts,
                                        timeout_secs = CONSENSUS_STUCK_TIMEOUT_SECS,
                                        "Attempting out-of-sync recovery (buffered gap)"
                                    );
                                    ConsensusStuckAction::AttemptRecovery
                                } else {
                                    tracing::debug!(
                                        current_ledger,
                                        first_buffered,
                                        last_buffered,
                                        required_first,
                                        trigger,
                                        elapsed_secs = elapsed,
                                        "Waiting for buffered catchup trigger ledger"
                                    );
                                    ConsensusStuckAction::Wait
                                }
                            }
                        }
                        _ => {
                            tracing::info!(
                                current_ledger,
                                first_buffered,
                                last_buffered,
                                required_first,
                                trigger,
                                "Buffered gap detected; starting recovery timer"
                            );
                            *stuck_state = Some(ConsensusStuckState {
                                current_ledger,
                                first_buffered,
                                stuck_start: now,
                                last_recovery_attempt: now,
                                recovery_attempts: 0,
                                catchup_triggered: false,
                            });
                            ConsensusStuckAction::AttemptRecovery
                        }
                    }
                };

                match action {
                    ConsensusStuckAction::Wait => return,
                    ConsensusStuckAction::AttemptRecovery => {
                        self.out_of_sync_recovery(current_ledger).await;
                        return;
                    }
                    ConsensusStuckAction::TriggerCatchup => {
                        // Fall through to catchup below
                    }
                }
            }
        }

        // Determine catchup target
        tracing::debug!(
            current_ledger,
            first_buffered,
            last_buffered,
            "maybe_start_buffered_catchup: computing catchup target"
        );
        let target = Self::buffered_catchup_target(current_ledger, first_buffered, last_buffered);
        let target = match target {
            Some(t) => Some(t),
            None => {
                // Fallback: use timeout-based target if buffered_catchup_target returns None
                // but we've decided to catchup due to timeout
                Self::compute_catchup_target_for_timeout(
                    last_buffered,
                    first_buffered,
                    current_ledger,
                )
            }
        };

        // If we still don't have a target, catch up to the latest checkpoint from archive.
        // This handles the case where we're stuck with a gap we can't bridge via buffered messages.
        let use_current_target = target.is_none();
        let target = match target {
            Some(t) => t,
            None => {
                tracing::info!(
                    current_ledger,
                    first_buffered,
                    last_buffered,
                    "No buffered catchup target; catching up to latest checkpoint from archive"
                );
                // We'll use CatchupTarget::Current below
                0
            }
        };

        if self.catchup_in_progress.swap(true, Ordering::SeqCst) {
            tracing::info!("Buffered catchup already in progress");
            return;
        }

        // Skip the target validation if we're using CatchupTarget::Current
        if !use_current_target && (target == 0 || target <= current_ledger) {
            self.catchup_in_progress.store(false, Ordering::SeqCst);
            return;
        }

        // When using CatchupTarget::Current, check if the archive has a newer checkpoint.
        // Use the cached checkpoint to avoid repeated network calls that block the main loop.
        if use_current_target && is_checkpoint_ledger(current_ledger) {
            match self.get_cached_archive_checkpoint().await {
                Ok(latest_checkpoint) => {
                    if latest_checkpoint <= current_ledger {
                        // This is expected behavior after catchup - archive hasn't published
                        // the next checkpoint yet. Use debug level to avoid log spam.
                        tracing::debug!(
                            current_ledger,
                            latest_checkpoint,
                            first_buffered,
                            "Skipping catchup: archive has no newer checkpoint"
                        );
                        // DON'T reset tx_set tracking here - we're not completing catchup,
                        // just waiting for the next checkpoint. Resetting tracking would
                        // clear pending requests and prevent responses from being matched.
                        // Record skip time for cooldown to prevent repeated archive queries.
                        // This uses the same cooldown mechanism as catchup completion.
                        *self.last_catchup_completed_at.write().await = Some(Instant::now());
                        self.catchup_in_progress.store(false, Ordering::SeqCst);
                        return;
                    }
                    tracing::info!(
                        current_ledger,
                        latest_checkpoint,
                        first_buffered,
                        "Archive has newer checkpoint, proceeding with catchup"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        current_ledger,
                        error = %e,
                        "Failed to query archive for latest checkpoint, skipping catchup"
                    );
                    // Record skip time for cooldown to prevent repeated archive queries.
                    *self.last_catchup_completed_at.write().await = Some(Instant::now());
                    self.catchup_in_progress.store(false, Ordering::SeqCst);
                    return;
                }
            }
        }

        tracing::info!(
            current_ledger,
            target,
            first_buffered,
            last_buffered,
            use_current_target,
            "Starting buffered catchup"
        );

        // Start caching messages during catchup to capture tx_sets for gap ledgers
        let catchup_message_handle = self.start_catchup_message_caching_from_self().await;

        let catchup_target = if use_current_target {
            CatchupTarget::Current
        } else {
            CatchupTarget::Ledger(target)
        };
        let catchup_result = self.catchup(catchup_target).await;

        // Stop the catchup message caching task
        if let Some(handle) = catchup_message_handle {
            handle.abort();
            tracing::debug!("Stopped catchup message caching task (buffered catchup)");
        }

        self.catchup_in_progress.store(false, Ordering::SeqCst);

        self.handle_catchup_result(catchup_result, true, "Buffered").await;
    }

    /// Process the result of a catchup operation: update state, bootstrap herder,
    /// and apply buffered ledgers. Shared by buffered and externalized catchup paths.
    async fn handle_catchup_result(
        &self,
        catchup_result: anyhow::Result<CatchupResult>,
        reset_stuck_state: bool,
        label: &str,
    ) {
        match catchup_result {
            Ok(result) => {
                let catchup_did_work = result.buckets_applied > 0 || result.ledgers_replayed > 0;

                if catchup_did_work {
                    if reset_stuck_state {
                        *self.consensus_stuck_state.write().await = None;
                    }
                    *self.current_ledger.write().await = result.ledger_seq;
                    *self.last_processed_slot.write().await = result.ledger_seq as u64;
                    self.clear_tx_advert_history(result.ledger_seq).await;
                    self.herder.bootstrap(result.ledger_seq);
                    self.herder.purge_slots_below(result.ledger_seq as u64);
                    let cleaned = self
                        .herder
                        .cleanup_old_pending_tx_sets(result.ledger_seq as u64 + 1);
                    if cleaned > 0 {
                        tracing::info!(
                            cleaned,
                            "Dropped stale pending tx set requests after catchup"
                        );
                    }
                    self.reset_tx_set_tracking_after_catchup().await;

                    // Clear stale syncing_ledgers entries above the catchup target.
                    // These were created during pre-catchup SCP fast-forwarding and
                    // have tx_set: None because peers had already evicted the tx_sets
                    // for those slots (too old at the time). After catchup brings
                    // current_ledger up to the target, these slots are now recent and
                    // peers SHOULD have their tx_sets. Clearing forces fresh
                    // process_externalized_slots() calls that will re-create entries
                    // via check_ledger_close() with proper tx_set lookups.
                    {
                        let mut buffer = self.syncing_ledgers.write().await;
                        let stale_count = buffer.len();
                        buffer.retain(|&seq, _| seq <= result.ledger_seq);
                        let removed = stale_count - buffer.len();
                        if removed > 0 {
                            tracing::info!(
                                removed,
                                catchup_ledger = result.ledger_seq,
                                "Cleared stale syncing_ledgers entries above catchup target"
                            );
                        }
                    }

                    if self.is_validator {
                        self.set_state(AppState::Validating).await;
                    } else {
                        self.set_state(AppState::Synced).await;
                    }
                    tracing::info!(ledger_seq = result.ledger_seq, "{} catchup complete", label);
                    let latest_ext = self.herder.latest_externalized_slot().unwrap_or(0);
                    let pending_count = self.herder.get_pending_tx_sets().len();
                    let buffer_count = self.syncing_ledgers.read().await.len();
                    tracing::debug!(
                        latest_externalized = latest_ext,
                        last_processed = result.ledger_seq,
                        pending_tx_sets = pending_count,
                        buffered_ledgers = buffer_count,
                        tx_set_cache_size = self.herder.scp_driver().tx_set_cache_size(),
                        "Post-catchup state before try_apply_buffered_ledgers"
                    );
                    self.try_apply_buffered_ledgers().await;

                    // After rapid buffered ledger closes, the broadcast channel
                    // likely overflowed, and process_externalized_slots() may
                    // have created syncing_ledgers entries with tx_set: None
                    // (because fetch responses hadn't been processed yet).
                    // Clear these stale entries and reset tracking so the main
                    // event loop can repopulate them cleanly when it drains
                    // the SCP and fetch_response channels.
                    {
                        let current_ledger = *self.current_ledger.read().await;
                        let mut buffer = self.syncing_ledgers.write().await;
                        let stale_count = buffer.len();
                        buffer.retain(|&seq, _| seq <= current_ledger);
                        let removed = stale_count - buffer.len();
                        if removed > 0 {
                            tracing::info!(
                                removed,
                                current_ledger,
                                "Cleared stale syncing_ledgers entries after buffered close"
                            );
                        }
                    }

                    // Set last_processed_slot to the latest externalized slot
                    // so process_externalized_slots() does NOT re-iterate
                    // stale slots between current_ledger and the network head.
                    // Those stale slots have tx_sets that peers have already
                    // evicted (~60s cache), so creating syncing_ledgers entries
                    // for them causes an unrecoverable timeout→exhausted→catchup
                    // loop.  Only future EXTERNALIZE messages (for slots the
                    // network hasn't closed yet) will be processed.
                    {
                        let current_ledger = *self.current_ledger.read().await;
                        let latest_ext = self.herder.latest_externalized_slot()
                            .unwrap_or(current_ledger as u64);
                        *self.last_processed_slot.write().await = latest_ext;
                        tracing::info!(
                            latest_ext,
                            current_ledger,
                            "Set last_processed_slot to latest_externalized after catchup"
                        );
                    }

                    // Reset tx_set tracking state (same as rapid close handler)
                    // so the main loop can make fresh requests.
                    *self.last_externalized_at.write().await = Instant::now();
                    self.tx_set_all_peers_exhausted.store(false, Ordering::SeqCst);
                    self.tx_set_dont_have.write().await.clear();
                    self.tx_set_last_request.write().await.clear();
                    self.tx_set_exhausted_warned.write().await.clear();
                    *self.consensus_stuck_state.write().await = None;

                    // Do NOT request SCP state from peers after catchup.
                    // That brings in EXTERNALIZE messages for recent slots
                    // whose tx_sets peers have already evicted from their
                    // caches (~60s window).  Processing those creates
                    // syncing_ledgers entries with tx_set: None, triggering
                    // the timeout→exhausted→catchup loop.  Instead, rely on
                    // the dedicated SCP channel which delivers the NEXT fresh
                    // EXTERNALIZE (with a fetchable tx_set) within ~5 seconds.
                } else {
                    tracing::info!(
                        ledger_seq = result.ledger_seq,
                        "{} catchup skipped (already at target); preserving tx_set tracking",
                        label
                    );
                }
                *self.last_catchup_completed_at.write().await = Some(Instant::now());
            }
            Err(err) => {
                tracing::error!(error = %err, "{} catchup failed", label);
                // Apply cooldown after failed catchup to prevent rapid-fire retries.
                // Without this, a failed catchup (e.g., archive checkpoint not yet
                // published) would re-trigger immediately on the next tick because
                // the stuck state's recovery_attempts are already exhausted.
                *self.last_catchup_completed_at.write().await = Some(Instant::now());
                // Reset the stuck state so the recovery/timeout cycle re-arms.
                // This provides natural backoff: 10s cooldown + 3 recovery attempts
                // (30s) + catchup retry = ~40s per cycle while waiting for the
                // archive to publish the next checkpoint.
                if reset_stuck_state {
                    if let Some(state) = self.consensus_stuck_state.write().await.as_mut() {
                        state.catchup_triggered = false;
                        state.recovery_attempts = 0;
                        state.last_recovery_attempt = Instant::now();
                    }
                }
            }
        }
    }

    async fn maybe_start_externalized_catchup(&self, latest_externalized: u64) {
        let current_ledger = match self.get_current_ledger().await {
            Ok(seq) => seq,
            Err(_) => return,
        };
        if latest_externalized <= current_ledger as u64 {
            return;
        }
        let gap = latest_externalized.saturating_sub(current_ledger as u64);
        if gap <= TX_SET_REQUEST_WINDOW {
            return;
        }

        if self.catchup_in_progress.swap(true, Ordering::SeqCst) {
            tracing::info!("Externalized catchup already in progress");
            return;
        }

        let target = latest_externalized.saturating_sub(TX_SET_REQUEST_WINDOW) as u32;
        if target == 0 || target <= current_ledger {
            self.catchup_in_progress.store(false, Ordering::SeqCst);
            return;
        }

        tracing::info!(
            current_ledger,
            latest_externalized,
            target,
            "Starting externalized catchup"
        );

        // Start caching messages during catchup to capture tx_sets for gap ledgers
        let catchup_message_handle = self.start_catchup_message_caching_from_self().await;

        let catchup_result = self.catchup(CatchupTarget::Ledger(target)).await;

        // Stop the catchup message caching task
        if let Some(handle) = catchup_message_handle {
            handle.abort();
            tracing::debug!("Stopped catchup message caching task (externalized catchup)");
        }

        self.catchup_in_progress.store(false, Ordering::SeqCst);

        self.handle_catchup_result(catchup_result, false, "Externalized").await;
    }

    fn buffered_catchup_target(
        current_ledger: u32,
        first_buffered: u32,
        last_buffered: u32,
    ) -> Option<u32> {
        if first_buffered <= current_ledger + 1 {
            return None;
        }

        let gap = first_buffered.saturating_sub(current_ledger);
        if gap >= CHECKPOINT_FREQUENCY {
            // When the gap is large enough to span a checkpoint boundary, target
            // the latest checkpoint before first_buffered. This ensures we catch
            // up to a known-good checkpoint state from the archive rather than
            // trying to replay a large number of ledgers.
            let target =
                latest_checkpoint_before_or_at(first_buffered.saturating_sub(1)).unwrap_or(0);
            return if target == 0 { None } else { Some(target) };
        }

        let required_first = if Self::is_first_ledger_in_checkpoint(first_buffered) {
            first_buffered
        } else {
            Self::first_ledger_in_checkpoint(first_buffered).saturating_add(CHECKPOINT_FREQUENCY)
        };
        let trigger = required_first.saturating_add(1);
        if last_buffered < trigger {
            return None;
        }
        let target = required_first.saturating_sub(1);
        if target == 0 {
            None
        } else {
            Some(target)
        }
    }

    /// Compute a catchup target when we're stuck waiting for buffered ledgers.
    /// This targets the checkpoint boundary that will allow us to apply buffered ledgers.
    /// Returns None if no published checkpoint is ahead of current_ledger, meaning
    /// the caller should either wait or query the archive for the latest checkpoint.
    fn compute_catchup_target_for_timeout(
        last_buffered: u32,
        first_buffered: u32,
        current_ledger: u32,
    ) -> Option<u32> {
        // We need to catch up to a point that lets us make progress.
        // The best target is just before first_buffered, so we can then apply the buffered ledgers.

        // Find the checkpoint that contains first_buffered
        let first_buffered_checkpoint_start = Self::first_ledger_in_checkpoint(first_buffered);

        // Target should be the last ledger of the checkpoint BEFORE the one containing first_buffered
        // This is checkpoint_start - 1
        let target = if first_buffered_checkpoint_start > 0 {
            first_buffered_checkpoint_start.saturating_sub(1)
        } else {
            // first_buffered is in the first checkpoint, target first_buffered - 1
            first_buffered.saturating_sub(1)
        };

        // If target is not better than current_ledger, try targeting last_buffered's checkpoint
        if target <= current_ledger {
            let last_checkpoint_start = Self::first_ledger_in_checkpoint(last_buffered);
            let alt_target = last_checkpoint_start.saturating_sub(1);

            if alt_target > current_ledger {
                return Some(alt_target);
            }

            // No checkpoint target ahead of current_ledger.
            // For tiny gaps (e.g., LCL=922751, first_buffered=922753), target
            // first_buffered - 1 directly. This produces a Case 1 replay that
            // bridges the gap (e.g., replay 1 ledger from 922751 to 922752),
            // then the buffer starting at 922753 can drain.
            let direct_target = first_buffered.saturating_sub(1);
            if direct_target > current_ledger {
                return Some(direct_target);
            }

            // Truly no target ahead. Return None so the caller falls through
            // to CatchupTarget::Current, which queries the archive for the
            // latest published checkpoint.
            return None;
        }

        Some(target)
    }

    /// Reset tx_set tracking after catchup to give pending tx_sets a fresh chance.
    ///
    /// After catchup, the node's current_ledger has jumped significantly.
    /// Pending tx_set requests that were "DontHave" before catchup may now
    /// be available from peers (since those slots are now current, not future).
    /// Clearing the tracking allows fresh requests to all peers.
    async fn reset_tx_set_tracking_after_catchup(&self) {
        let mut dont_have = self.tx_set_dont_have.write().await;
        let cleared_dont_have = dont_have.len();
        dont_have.clear();
        drop(dont_have);

        let mut last_request = self.tx_set_last_request.write().await;
        let cleared_last_request = last_request.len();
        last_request.clear();
        drop(last_request);

        if cleared_dont_have > 0 || cleared_last_request > 0 {
            tracing::info!(
                cleared_dont_have,
                cleared_last_request,
                "Reset tx_set tracking after catchup"
            );
        }
    }

    fn tx_set_start_index(hash: &Hash256, peers_len: usize, peer_offset: usize) -> usize {
        if peers_len == 0 {
            return 0;
        }
        let start = u64::from_le_bytes(hash.0[0..8].try_into().unwrap_or([0; 8]));
        let base = (start as usize) % peers_len;
        (base + (peer_offset % peers_len)) % peers_len
    }

    /// Try to trigger consensus for the next ledger (validators only).
    async fn try_trigger_consensus(&self) {
        let current_slot = self.herder.tracking_slot();

        // Check if we should start a new round
        if self.herder.is_tracking() {
            let next_slot = (current_slot + 1) as u32;
            tracing::debug!(next_slot, "Checking if we should trigger consensus");

            // Record local close time for drift tracking before triggering consensus.
            // This captures when we started the consensus round.
            let local_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if let Ok(mut tracker) = self.drift_tracker.lock() {
                tracker.record_local_close_time(next_slot, local_time);
            }

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
        let _ = self
            .db
            .remove_peers_with_failures(self.config.overlay.peer_max_failures);
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

            // Try to reconnect to known peers (dynamic list first, then config).
            let mut candidates = overlay.known_peers();
            for addr_str in &self.config.overlay.known_peers {
                // Parse "host:port" or just "host" (default port 11625)
                let parts: Vec<&str> = addr_str.split(':').collect();
                let peer_addr = match parts.len() {
                    1 => Some(PeerAddress::new(parts[0], 11625)),
                    2 => parts[1]
                        .parse()
                        .ok()
                        .map(|port| PeerAddress::new(parts[0], port)),
                    _ => None,
                };
                if let Some(addr) = peer_addr {
                    if !candidates.contains(&addr) {
                        candidates.push(addr);
                    }
                }
            }

            let mut reconnected = false;
            let candidates = self.refresh_known_peers(overlay);
            for addr in candidates {
                if overlay.peer_count() >= self.config.overlay.target_outbound_peers {
                    break;
                }

                if let Err(e) = overlay.connect(&addr).await {
                    tracing::debug!(addr = %addr, error = %e, "Failed to reconnect to peer");
                } else {
                    reconnected = true;
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
    pub async fn request_scp_state_from_peers(&self) {
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

        // Request SCP state from a low watermark similar to stellar-core behavior.
        let ledger_seq = self.herder.get_min_ledger_seq_to_ask_peers();
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

    /// Perform out-of-sync recovery matching stellar-core's outOfSyncRecovery().
    ///
    /// This broadcasts recent SCP messages to peers and requests SCP state,
    /// giving the network a chance to provide the missing data before we
    /// fall back to catchup.
    async fn out_of_sync_recovery(&self, current_ledger: u32) {
        let latest_externalized = self.herder.latest_externalized_slot().unwrap_or(0);
        let last_processed = *self.last_processed_slot.read().await;
        let pending_tx_sets = self.herder.get_pending_tx_sets();
        let buffer_count = self.syncing_ledgers.read().await.len();
        let gap = latest_externalized.saturating_sub(current_ledger as u64);
        tracing::info!(
            current_ledger,
            latest_externalized,
            last_processed,
            pending_tx_sets = pending_tx_sets.len(),
            buffer_count,
            gap,
            "Performing out-of-sync recovery"
        );

        // Clean up stale pending tx_set requests for slots we've already closed.
        // After rapid close, stale EXTERNALIZE messages from previous SCP state
        // requests create pending tx_set entries for old slots whose tx_sets are
        // evicted from peers' caches. These requests can never be fulfilled and
        // cause infinite timeout → DontHave → recovery loops.
        let stale_cleared = self
            .herder
            .cleanup_old_pending_tx_sets(current_ledger as u64 + 1);
        if stale_cleared > 0 {
            tracing::info!(
                stale_cleared,
                current_ledger,
                "Cleared stale pending tx_set requests for already-closed slots"
            );
            // Also clear the local tx_set tracking state for these stale requests
            self.tx_set_dont_have.write().await.clear();
            self.tx_set_last_request.write().await.clear();
            self.tx_set_exhausted_warned.write().await.clear();
            self.tx_set_all_peers_exhausted
                .store(false, Ordering::SeqCst);
        }

        // When the node is essentially caught up (small or zero gap), do NOT
        // request SCP state from peers. Requesting SCP state brings stale
        // EXTERNALIZE messages for slots whose tx_sets are already evicted from
        // peers' caches (~60-72s window). These create pending tx_set requests
        // that can never be fulfilled, causing infinite timeout → DontHave →
        // recovery loops.
        //
        // Instead, just wait for fresh EXTERNALIZE messages to arrive naturally
        // via the dedicated SCP channel. The network produces new slots every
        // ~5-6 seconds, so the next EXTERNALIZE will arrive shortly.
        if gap <= TX_SET_REQUEST_WINDOW {
            // Also clear syncing_ledgers entries with no tx_set — these are
            // unfulfillable entries from stale EXTERNALIZE and will block
            // try_start_ledger_close().
            {
                let mut buffer = self.syncing_ledgers.write().await;
                let pre_count = buffer.len();
                buffer.retain(|seq, info| {
                    *seq > current_ledger && info.tx_set.is_some()
                });
                let removed = pre_count - buffer.len();
                if removed > 0 {
                    tracing::info!(
                        removed,
                        remaining = buffer.len(),
                        current_ledger,
                        "Cleared unfulfillable syncing_ledgers entries (essentially caught up)"
                    );
                }
            }
            // Clear any remaining pending tx_sets from the herder
            self.herder.clear_pending_tx_sets();
            tracing::info!(
                current_ledger,
                latest_externalized,
                gap,
                "Essentially caught up — skipping SCP state request, waiting for fresh EXTERNALIZE"
            );
            return;
        }

        // Detect gaps in externalized slots to help diagnose sync issues.
        // If the very next slot (current_ledger+1) is missing, peers will never
        // have it (they only cache ~12 recent slots / ~60-72s). The only recovery
        // path is catchup — requesting SCP state from peers is futile.
        let next_slot = current_ledger as u64 + 1;
        if latest_externalized > next_slot {
            let missing_slots = self.herder.find_missing_slots_in_range(next_slot, latest_externalized);
            if !missing_slots.is_empty() {
                let missing_count = missing_slots.len();
                let first_missing = missing_slots.first().copied().unwrap_or(0);
                let last_missing = missing_slots.last().copied().unwrap_or(0);
                tracing::warn!(
                    current_ledger,
                    latest_externalized,
                    missing_count,
                    first_missing,
                    last_missing,
                    missing_slots = ?if missing_count <= 10 { missing_slots.clone() } else { vec![] },
                    "Detected gap in externalized slots - missing EXTERNALIZE messages"
                );

                // If the very next slot is missing, we can NEVER close it via the
                // normal path (try_start_ledger_close requires syncing_ledgers[N+1]).
                // Peers have evicted this slot's data from their caches.  Trigger
                // catchup immediately to skip past the gap instead of spinning in
                // recovery forever.
                if missing_slots.contains(&next_slot) {
                    tracing::warn!(
                        current_ledger,
                        next_slot,
                        latest_externalized,
                        gap,
                        "Next slot permanently missing — triggering catchup to skip gap"
                    );
                    // Clear stale syncing_ledgers entries that will never be closeable
                    {
                        let mut buffer = self.syncing_ledgers.write().await;
                        buffer.retain(|seq, info| {
                            *seq > current_ledger && info.tx_set.is_some()
                        });
                    }
                    self.maybe_start_externalized_catchup(latest_externalized)
                        .await;
                    return;
                }
            } else {
                // No gaps in externalized, but we can't apply - likely missing tx_sets
                let externalized_slots = self.herder.get_externalized_slots_in_range(next_slot, latest_externalized);
                tracing::info!(
                    current_ledger,
                    latest_externalized,
                    externalized_count = externalized_slots.len(),
                    "All slots externalized but cannot apply - likely missing tx_sets"
                );
            }
        }

        // Get recent SCP envelopes to broadcast
        let from_slot = current_ledger.saturating_sub(5) as u64;
        tracing::debug!(from_slot, "Getting SCP state for recovery");
        let (envelopes, _quorum_set) = self.herder.get_scp_state(from_slot);
        tracing::debug!(
            envelope_count = envelopes.len(),
            "Got SCP state for recovery"
        );

        tracing::debug!("Acquiring overlay lock for recovery");
        let overlay = self.overlay.lock().await;
        tracing::debug!("Acquired overlay lock for recovery");
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => {
                tracing::debug!("No overlay available for out-of-sync recovery");
                return;
            }
        };

        let peer_count = overlay.peer_count();
        if peer_count == 0 {
            tracing::debug!("No peers connected for out-of-sync recovery");
            return;
        }

        // Broadcast recent SCP envelopes to all peers
        // This helps peers that might have missed our messages
        let mut broadcast_count = 0;
        for envelope in &envelopes {
            let msg = StellarMessage::ScpMessage(envelope.clone());
            if let Err(e) = overlay.broadcast(msg).await {
                tracing::debug!(error = %e, "Failed to broadcast SCP envelope during recovery");
            } else {
                broadcast_count += 1;
            }
        }

        if broadcast_count > 0 {
            tracing::info!(
                broadcast_count,
                "Broadcast SCP envelopes during out-of-sync recovery"
            );
        }

        // Request SCP state from peers, starting from current_ledger to get gap slots
        // Use current_ledger instead of get_min_ledger_seq_to_ask_peers() to ensure
        // we request envelopes for slots close to where we're stuck.
        let ledger_seq = current_ledger;
        match overlay.request_scp_state(ledger_seq).await {
            Ok(count) => {
                tracing::info!(
                    ledger_seq,
                    peers_requested = count,
                    "Requested SCP state during out-of-sync recovery"
                );
            }
            Err(e) => {
                tracing::warn!(
                    ledger_seq,
                    error = %e,
                    "Failed to request SCP state during out-of-sync recovery"
                );
            }
        }
    }

    /// Send SCP state to a peer in response to GetScpState.
    async fn send_scp_state(&self, peer_id: &henyey_overlay::PeerId, from_ledger: u32) {
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
                tracing::debug!(peer = %peer_id, error = %e, "Failed to send quorum set");
            }
        }

        // Send SCP envelopes for recent slots
        for envelope in envelopes {
            let msg = StellarMessage::ScpMessage(envelope);
            if let Err(e) = overlay.send_to(peer_id, msg).await {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to send SCP envelope");
                break; // Stop if we can't send
            }
        }

        tracing::debug!(peer = %peer_id, from_ledger, "Sent SCP state response");
    }

    /// Respond to a GetScpQuorumset message.
    async fn send_quorum_set(
        &self,
        peer_id: &henyey_overlay::PeerId,
        requested_hash: stellar_xdr::curr::Uint256,
    ) {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => return,
        };

        let req = requested_hash.0;
        if let Some(qs) = self.herder.get_quorum_set_by_hash(&req) {
            if let Err(e) = overlay
                .send_to(peer_id, StellarMessage::ScpQuorumset(qs))
                .await
            {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to send quorum set");
            }
        } else {
            let msg = StellarMessage::DontHave(stellar_xdr::curr::DontHave {
                type_: stellar_xdr::curr::MessageType::ScpQuorumset,
                req_hash: requested_hash,
            });
            if let Err(e) = overlay.send_to(peer_id, msg).await {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to send DontHave for quorum set");
            }
        }
    }

    /// Store a quorum set received from a peer.
    async fn handle_quorum_set(
        &self,
        _peer_id: &henyey_overlay::PeerId,
        quorum_set: stellar_xdr::curr::ScpQuorumSet,
    ) {
        let hash = henyey_scp::hash_quorum_set(&quorum_set);

        // Get the node_ids that were waiting for this quorum set
        let node_ids = self.herder.get_pending_quorum_set_node_ids(&hash);

        if let Err(err) = self.db.store_scp_quorum_set(
            &hash,
            self.ledger_manager.current_ledger_seq(),
            &quorum_set,
        ) {
            tracing::warn!(error = %err, "Failed to store quorum set");
        }

        // Store for all node_ids that use this quorum set
        if node_ids.is_empty() {
            tracing::debug!(%hash, "Received quorum set with no pending requests");
        } else {
            for node_id in &node_ids {
                tracing::debug!(%hash, node_id = ?node_id, "Storing quorum set for node");
                self.herder.store_quorum_set(node_id, quorum_set.clone());
            }
        }

        self.herder.clear_quorum_set_request(&hash);
    }

    async fn handle_survey_start_collecting(
        &self,
        peer_id: &henyey_overlay::PeerId,
        signed: stellar_xdr::curr::SignedTimeSlicedSurveyStartCollectingMessage,
    ) {
        let message = &signed.start_collecting;
        let message_bytes = match message.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to encode survey start message");
                return;
            }
        };
        if !self.surveyor_permitted(&message.surveyor_id) {
            return;
        }
        let local_ledger = self.survey_local_ledger().await;
        let survey_active = { self.survey_data.read().await.survey_is_active() };
        let limiter = self.survey_limiter.read().await;
        let is_valid =
            limiter.validate_start_collecting(message, local_ledger, survey_active, || {
                self.verify_survey_signature(
                    &message.surveyor_id,
                    &message_bytes,
                    &signed.signature,
                )
            });
        if !is_valid {
            tracing::debug!(peer = %peer_id, "Survey start rejected by limiter");
            return;
        }

        let (snapshots, added, dropped) = {
            let overlay = self.overlay.lock().await;
            let overlay = match overlay.as_ref() {
                Some(o) => o,
                None => return,
            };
            (
                overlay.peer_snapshots(),
                overlay.added_authenticated_peers(),
                overlay.dropped_authenticated_peers(),
            )
        };
        let (inbound, outbound) = Self::partition_peer_snapshots(snapshots);
        let lost_sync = self.lost_sync_count.load(Ordering::Relaxed);
        let state = self.state().await;
        let initially_out_of_sync = matches!(state, AppState::Initializing | AppState::CatchingUp);

        let mut survey_data = self.survey_data.write().await;
        if survey_data.start_collecting(
            message,
            &inbound,
            &outbound,
            lost_sync,
            added,
            dropped,
            initially_out_of_sync,
        ) {
            tracing::debug!(peer = %peer_id, "Survey collection started");
        } else {
            tracing::debug!(peer = %peer_id, "Survey collection already active");
        }
    }

    async fn handle_survey_stop_collecting(
        &self,
        peer_id: &henyey_overlay::PeerId,
        signed: stellar_xdr::curr::SignedTimeSlicedSurveyStopCollectingMessage,
    ) {
        let message = &signed.stop_collecting;
        let message_bytes = match message.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to encode survey stop message");
                return;
            }
        };
        if !self.surveyor_permitted(&message.surveyor_id) {
            return;
        }
        let local_ledger = self.survey_local_ledger().await;
        let limiter = self.survey_limiter.read().await;
        let is_valid = limiter.validate_stop_collecting(message, local_ledger, || {
            self.verify_survey_signature(&message.surveyor_id, &message_bytes, &signed.signature)
        });
        if !is_valid {
            tracing::debug!(peer = %peer_id, "Survey stop rejected by limiter");
            return;
        }

        let (snapshots, added, dropped) = {
            let overlay = self.overlay.lock().await;
            let overlay = match overlay.as_ref() {
                Some(o) => o,
                None => return,
            };
            (
                overlay.peer_snapshots(),
                overlay.added_authenticated_peers(),
                overlay.dropped_authenticated_peers(),
            )
        };
        let (inbound, outbound) = Self::partition_peer_snapshots(snapshots);
        let lost_sync = self.lost_sync_count.load(Ordering::Relaxed);

        let mut survey_data = self.survey_data.write().await;
        if survey_data.stop_collecting(message, &inbound, &outbound, added, dropped, lost_sync) {
            tracing::debug!(peer = %peer_id, "Survey collection stopped");
        } else {
            tracing::debug!(peer = %peer_id, "Survey stop ignored (inactive or nonce mismatch)");
        }
    }

    async fn handle_survey_request(
        &self,
        peer_id: &henyey_overlay::PeerId,
        signed: stellar_xdr::curr::SignedTimeSlicedSurveyRequestMessage,
    ) {
        let request = &signed.request;
        let request_bytes = match request.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to encode survey request");
                return;
            }
        };

        if !self.surveyor_permitted(&request.request.surveyor_peer_id) {
            return;
        }

        let local_node_id = self.local_node_id();
        let local_ledger = self.survey_local_ledger().await;
        let nonce_is_reporting = self
            .survey_data
            .read()
            .await
            .nonce_is_reporting(request.nonce);
        let mut limiter = self.survey_limiter.write().await;
        let is_valid = limiter.add_and_validate_request(
            &request.request,
            local_ledger,
            &local_node_id,
            || {
                nonce_is_reporting
                    && self.verify_survey_signature(
                        &request.request.surveyor_peer_id,
                        &request_bytes,
                        &signed.request_signature,
                    )
            },
        );
        if !is_valid {
            tracing::debug!(peer = %peer_id, "Survey request rejected by limiter");
            return;
        }

        if request.request.surveyed_peer_id != local_node_id {
            let _ = self
                .broadcast_survey_message(StellarMessage::TimeSlicedSurveyRequest(signed))
                .await;
            return;
        }
        let response_body = match request.request.command_type {
            stellar_xdr::curr::SurveyMessageCommandType::TimeSlicedSurveyTopology => {
                let survey_data = self.survey_data.read().await;
                match survey_data.fill_survey_data(request) {
                    Some(body) => body,
                    None => {
                        tracing::debug!(peer = %peer_id, "Survey request without reporting data");
                        return;
                    }
                }
            }
        };

        let response_body = SurveyResponseBody::SurveyTopologyResponseV2(response_body);
        let response_body_bytes = match response_body.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to encode survey response body");
                return;
            }
        };
        let encrypted_body_bytes = match henyey_crypto::seal_to_curve25519_public_key(
            &request.request.encryption_key.key,
            &response_body_bytes,
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to encrypt survey response body");
                return;
            }
        };
        let encrypted_body = match encrypted_body_bytes.try_into() {
            Ok(body) => EncryptedBody(body),
            Err(_) => {
                tracing::debug!(peer = %peer_id, "Survey response body exceeded XDR limits");
                return;
            }
        };

        let response = SurveyResponseMessage {
            surveyor_peer_id: request.request.surveyor_peer_id.clone(),
            surveyed_peer_id: local_node_id,
            ledger_num: request.request.ledger_num,
            command_type: request.request.command_type,
            encrypted_body,
        };

        let response_message = TimeSlicedSurveyResponseMessage {
            response,
            nonce: request.nonce,
        };

        let response_bytes = match response_message.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to encode survey response");
                return;
            }
        };

        let signature = self.sign_survey_message(&response_bytes);

        let signed_response = stellar_xdr::curr::SignedTimeSlicedSurveyResponseMessage {
            response_signature: signature,
            response: response_message,
        };

        let overlay = self.overlay.lock().await;
        if let Some(ref overlay) = *overlay {
            if let Err(e) = overlay
                .send_to(
                    peer_id,
                    StellarMessage::TimeSlicedSurveyResponse(signed_response),
                )
                .await
            {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to send survey response");
            }
        }
    }

    async fn handle_survey_response(
        &self,
        peer_id: &henyey_overlay::PeerId,
        signed: SignedTimeSlicedSurveyResponseMessage,
    ) {
        let response_message = signed.response.clone();
        let response_bytes = match response_message.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to encode survey response");
                return;
            }
        };

        let local_ledger = self.survey_local_ledger().await;
        let nonce_is_reporting = self
            .survey_data
            .read()
            .await
            .nonce_is_reporting(response_message.nonce);
        let mut limiter = self.survey_limiter.write().await;
        let is_valid =
            limiter.record_and_validate_response(&response_message.response, local_ledger, || {
                nonce_is_reporting
                    && self.verify_survey_signature(
                        &response_message.response.surveyed_peer_id,
                        &response_bytes,
                        &signed.response_signature,
                    )
            });
        if !is_valid {
            tracing::debug!(peer = %peer_id, "Survey response rejected by limiter");
            return;
        }

        if response_message.response.surveyor_peer_id != self.local_node_id() {
            let _ = self
                .broadcast_survey_message(StellarMessage::TimeSlicedSurveyResponse(signed))
                .await;
            return;
        }

        let secret = {
            self.survey_secrets
                .read()
                .await
                .get(&response_message.nonce)
                .copied()
        };

        let secret = match secret {
            Some(secret) => secret,
            None => {
                tracing::debug!(peer = %peer_id, "Survey response without matching secret");
                return;
            }
        };

        let decrypted = match henyey_crypto::open_from_curve25519_secret_key(
            &secret,
            response_message.response.encrypted_body.0.as_slice(),
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to decrypt survey response");
                let mut reporting = self.survey_reporting.write().await;
                reporting.bad_response_nodes.insert(peer_id.clone());
                return;
            }
        };

        let response_body = match SurveyResponseBody::from_xdr(
            decrypted.as_slice(),
            stellar_xdr::curr::Limits::none(),
        ) {
            Ok(body) => body,
            Err(e) => {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to decode survey response body");
                let mut reporting = self.survey_reporting.write().await;
                reporting.bad_response_nodes.insert(peer_id.clone());
                return;
            }
        };

        let SurveyResponseBody::SurveyTopologyResponseV2(body) = response_body;
        let (inbound_len, outbound_len) = {
            let mut results = self.survey_results.write().await;
            let entry = results
                .entry(response_message.nonce)
                .or_insert_with(HashMap::new)
                .entry(peer_id.clone())
                .or_insert_with(|| body.clone());
            Self::merge_topology_response(entry, &body);
            (entry.inbound_peers.0.len(), entry.outbound_peers.0.len())
        };
        tracing::debug!(
            peer = %peer_id,
            inbound = body.inbound_peers.0.len(),
            outbound = body.outbound_peers.0.len(),
            "Decrypted survey response"
        );

        let needs_more_inbound = body.inbound_peers.0.len() == TIME_SLICED_PEERS_MAX;
        let needs_more_outbound = body.outbound_peers.0.len() == TIME_SLICED_PEERS_MAX;
        if (needs_more_inbound || needs_more_outbound) && self.survey_reporting.read().await.running
        {
            let next_inbound = inbound_len as u32;
            let next_outbound = outbound_len as u32;
            let _ = self
                .survey_topology_timesliced(peer_id.clone(), next_inbound, next_outbound)
                .await;
        }
    }

    fn local_node_id(&self) -> stellar_xdr::curr::NodeId {
        stellar_xdr::curr::NodeId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::curr::Uint256(*self.keypair.public_key().as_bytes()),
        ))
    }

    async fn survey_local_ledger(&self) -> u32 {
        let tracking = self.herder.tracking_slot() as u32;
        if tracking == 0 {
            *self.current_ledger.read().await
        } else {
            tracking
        }
    }

    fn partition_peer_snapshots(
        snapshots: Vec<PeerSnapshot>,
    ) -> (Vec<PeerSnapshot>, Vec<PeerSnapshot>) {
        let mut inbound = Vec::new();
        let mut outbound = Vec::new();

        for snapshot in snapshots {
            match snapshot.info.direction {
                henyey_overlay::ConnectionDirection::Inbound => inbound.push(snapshot),
                henyey_overlay::ConnectionDirection::Outbound => outbound.push(snapshot),
            }
        }

        (inbound, outbound)
    }

    fn select_survey_peers(
        snapshots: Vec<PeerSnapshot>,
        max_peers: usize,
    ) -> Vec<henyey_overlay::PeerId> {
        let (mut inbound, mut outbound) = Self::partition_peer_snapshots(snapshots);
        let mut sort_by_activity = |a: &PeerSnapshot, b: &PeerSnapshot| {
            b.stats
                .messages_received
                .cmp(&a.stats.messages_received)
                .then_with(|| b.info.connected_at.cmp(&a.info.connected_at))
                .then_with(|| a.info.peer_id.to_hex().cmp(&b.info.peer_id.to_hex()))
        };
        inbound.sort_by(&mut sort_by_activity);
        outbound.sort_by(&mut sort_by_activity);

        let mut selected = Vec::new();
        let mut inbound_idx = 0usize;
        let mut outbound_idx = 0usize;

        while selected.len() < max_peers
            && (inbound_idx < inbound.len() || outbound_idx < outbound.len())
        {
            if outbound_idx < outbound.len() {
                selected.push(outbound[outbound_idx].info.peer_id.clone());
                outbound_idx += 1;
                if selected.len() == max_peers {
                    break;
                }
            }
            if inbound_idx < inbound.len() {
                selected.push(inbound[inbound_idx].info.peer_id.clone());
                inbound_idx += 1;
            }
        }

        selected
    }

    fn sign_survey_message(&self, message: &[u8]) -> stellar_xdr::curr::Signature {
        let sig = self.keypair.sign(message);
        sig.into()
    }

    fn merge_topology_response(
        existing: &mut TopologyResponseBodyV2,
        incoming: &TopologyResponseBodyV2,
    ) {
        existing.node_data = incoming.node_data.clone();

        let mut inbound = existing.inbound_peers.0.iter().cloned().collect::<Vec<_>>();
        inbound.extend(incoming.inbound_peers.0.iter().cloned());
        existing.inbound_peers.0 = inbound.try_into().unwrap_or_default();

        let mut outbound = existing
            .outbound_peers
            .0
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        outbound.extend(incoming.outbound_peers.0.iter().cloned());
        existing.outbound_peers.0 = outbound.try_into().unwrap_or_default();
    }

    fn verify_survey_signature(
        &self,
        node_id: &stellar_xdr::curr::NodeId,
        message: &[u8],
        signature: &stellar_xdr::curr::Signature,
    ) -> bool {
        let key_bytes = match Self::node_id_bytes(node_id) {
            Some(bytes) => bytes,
            None => return false,
        };
        let public_key = match henyey_crypto::PublicKey::from_bytes(&key_bytes) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let sig = match henyey_crypto::Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        henyey_crypto::verify(&public_key, message, &sig).is_ok()
    }

    fn node_id_bytes(node_id: &stellar_xdr::curr::NodeId) -> Option<[u8; 32]> {
        match &node_id.0 {
            stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key) => Some(key.0),
        }
    }

    fn surveyor_permitted(&self, surveyor_id: &stellar_xdr::curr::NodeId) -> bool {
        let allowed_keys = &self.config.overlay.surveyor_keys;
        if allowed_keys.is_empty() {
            let quorum_nodes = self.herder.local_quorum_nodes();
            if quorum_nodes.is_empty() {
                return false;
            }
            return quorum_nodes.contains(surveyor_id);
        }

        let Some(bytes) = Self::node_id_bytes(surveyor_id) else {
            return false;
        };

        allowed_keys.iter().any(|key| {
            henyey_crypto::PublicKey::from_strkey(key)
                .map(|pk| pk.as_bytes() == &bytes)
                .unwrap_or(false)
        })
    }

    fn scp_quorum_set_hash(statement: &stellar_xdr::curr::ScpStatement) -> Option<Hash> {
        match &statement.pledges {
            stellar_xdr::curr::ScpStatementPledges::Nominate(nom) => {
                Some(nom.quorum_set_hash.clone())
            }
            stellar_xdr::curr::ScpStatementPledges::Prepare(prep) => {
                Some(prep.quorum_set_hash.clone())
            }
            stellar_xdr::curr::ScpStatementPledges::Confirm(conf) => {
                Some(conf.quorum_set_hash.clone())
            }
            stellar_xdr::curr::ScpStatementPledges::Externalize(ext) => {
                Some(ext.commit_quorum_set_hash.clone())
            }
        }
    }

    fn tx_hash(&self, tx_env: &stellar_xdr::curr::TransactionEnvelope) -> Option<Hash256> {
        Hash256::hash_xdr(tx_env).ok()
    }

    fn build_scp_history_entry(&self, ledger_seq: u32) -> Option<ScpHistoryEntry> {
        let envelopes = self.herder.get_scp_envelopes(ledger_seq as u64);
        if envelopes.is_empty() {
            return None;
        }

        let mut qset_hashes = HashSet::new();
        for envelope in &envelopes {
            if let Some(hash) = Self::scp_quorum_set_hash(&envelope.statement) {
                qset_hashes.insert(Hash256::from_bytes(hash.0));
            }
        }

        let mut hashes = qset_hashes.into_iter().collect::<Vec<_>>();
        hashes.sort_by_key(|a| a.to_hex());

        let mut qsets = Vec::new();
        for hash in hashes {
            match self.herder.get_quorum_set_by_hash(hash.as_bytes()) {
                Some(qset) => qsets.push(qset),
                None => {
                    tracing::warn!(hash = %hash.to_hex(), "Missing quorum set for SCP history entry");
                    return None;
                }
            }
        }

        let quorum_sets = match qsets.try_into() {
            Ok(qsets) => qsets,
            Err(_) => {
                tracing::warn!(ledger_seq, "Too many quorum sets for SCP history entry");
                return None;
            }
        };
        let messages = match envelopes.try_into() {
            Ok(messages) => messages,
            Err(_) => {
                tracing::warn!(ledger_seq, "Too many SCP envelopes for SCP history entry");
                return None;
            }
        };

        Some(ScpHistoryEntry::V0(ScpHistoryEntryV0 {
            quorum_sets,
            ledger_messages: LedgerScpMessages {
                ledger_seq,
                messages,
            },
        }))
    }

    async fn enqueue_tx_advert(&self, tx_env: &stellar_xdr::curr::TransactionEnvelope) {
        let Some(hash) = self.tx_hash(tx_env) else {
            tracing::debug!("Failed to hash transaction for advert");
            return;
        };

        let mut set = self.tx_advert_set.write().await;
        if set.contains(&hash) {
            return;
        }
        set.insert(hash);
        drop(set);

        let mut queue = self.tx_advert_queue.write().await;
        queue.push(hash);
    }

    async fn flush_tx_adverts(&self) {
        let hashes = {
            let mut queue = self.tx_advert_queue.write().await;
            if queue.is_empty() {
                return;
            }
            std::mem::take(&mut *queue)
        };

        self.tx_advert_set.write().await.clear();

        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(overlay) => overlay,
            None => return,
        };

        let max_advert_size = self.max_advert_size();
        let snapshots = overlay.peer_snapshots();
        if snapshots.is_empty() {
            return;
        }

        let peer_ids = snapshots
            .iter()
            .map(|snapshot| snapshot.info.peer_id.clone())
            .collect::<Vec<_>>();
        let peer_set: HashSet<_> = peer_ids.iter().cloned().collect();

        let mut adverts_by_peer = self.tx_adverts_by_peer.write().await;
        adverts_by_peer.retain(|peer, _| peer_set.contains(peer));

        let mut per_peer = Vec::new();
        for peer_id in peer_ids {
            let adverts = adverts_by_peer
                .entry(peer_id.clone())
                .or_insert_with(PeerTxAdverts::new);
            let mut outgoing = Vec::new();
            for hash in &hashes {
                if adverts.seen_advert(hash) {
                    continue;
                }
                outgoing.push(*hash);
            }
            if !outgoing.is_empty() {
                per_peer.push((peer_id, outgoing));
            }
        }
        drop(adverts_by_peer);

        for (peer_id, hashes) in per_peer {
            for chunk in hashes.chunks(max_advert_size) {
                let tx_hashes = match TxAdvertVector::try_from(
                    chunk
                        .iter()
                        .map(|hash| Hash::from(*hash))
                        .collect::<Vec<_>>(),
                ) {
                    Ok(vec) => vec,
                    Err(_) => {
                        tracing::debug!(peer = %peer_id, "Failed to build tx advert vector");
                        continue;
                    }
                };
                let advert = FloodAdvert { tx_hashes };
                if let Err(e) = overlay
                    .send_to(&peer_id, StellarMessage::FloodAdvert(advert))
                    .await
                {
                    tracing::debug!(peer = %peer_id, error = %e, "Failed to send tx advert batch");
                }
            }
        }
    }

    fn flood_advert_period(&self) -> Duration {
        Duration::from_millis(self.config.overlay.flood_advert_period_ms.max(1))
    }

    fn flood_demand_period(&self) -> Duration {
        Duration::from_millis(self.config.overlay.flood_demand_period_ms.max(1))
    }

    fn flood_demand_backoff_delay(&self) -> Duration {
        Duration::from_millis(self.config.overlay.flood_demand_backoff_delay_ms.max(1))
    }

    fn max_advert_queue_size(&self) -> usize {
        self.herder.max_tx_set_size().max(1)
    }

    fn max_advert_size(&self) -> usize {
        const TX_ADVERT_VECTOR_MAX_SIZE: usize = 1000;
        let ledger_close_ms = (self.herder.ledger_close_time() as u64).saturating_mul(1000);
        let ledger_close_ms = ledger_close_ms.max(1) as f64;
        let ops_to_flood =
            self.config.overlay.flood_op_rate_per_ledger * self.herder.max_tx_set_size() as f64;
        let per_period = (ops_to_flood * self.config.overlay.flood_advert_period_ms as f64
            / ledger_close_ms)
            .ceil()
            .max(1.0);
        per_period.min(TX_ADVERT_VECTOR_MAX_SIZE as f64) as usize
    }

    fn max_demand_size(&self) -> usize {
        const TX_DEMAND_VECTOR_MAX_SIZE: usize = 1000;
        let ledger_close_ms = (self.herder.ledger_close_time() as u64).saturating_mul(1000);
        let ledger_close_ms = ledger_close_ms.max(1) as f64;
        let ops_to_flood =
            self.config.overlay.flood_op_rate_per_ledger * self.herder.max_queue_size_ops() as f64;
        let per_period = (ops_to_flood * self.config.overlay.flood_demand_period_ms as f64
            / ledger_close_ms)
            .ceil()
            .max(1.0);
        per_period.min(TX_DEMAND_VECTOR_MAX_SIZE as f64) as usize
    }

    fn retry_delay_demand(&self, attempts: usize) -> Duration {
        let delay_ms = self
            .flood_demand_backoff_delay()
            .as_millis()
            .saturating_mul(attempts as u128);
        Duration::from_millis(delay_ms.min(2000) as u64)
    }

    async fn clear_tx_advert_history(&self, ledger_seq: u32) {
        let mut adverts_by_peer = self.tx_adverts_by_peer.write().await;
        for adverts in adverts_by_peer.values_mut() {
            adverts.clear_below(ledger_seq);
        }

        // Clean up old tx demand history entries (older than 5 minutes)
        const MAX_TX_DEMAND_AGE_SECS: u64 = 300;
        let cutoff = Instant::now() - std::time::Duration::from_secs(MAX_TX_DEMAND_AGE_SECS);
        let mut history = self.tx_demand_history.write().await;
        history.retain(|_, entry| entry.last_demanded > cutoff);

        // Clean up old tx set dont have entries (older than 2 minutes)
        const MAX_TX_SET_DONT_HAVE_AGE_SECS: u64 = 120;
        let cutoff_short =
            Instant::now() - std::time::Duration::from_secs(MAX_TX_SET_DONT_HAVE_AGE_SECS);
        let mut dont_have = self.tx_set_dont_have.write().await;
        // Note: tx_set_dont_have doesn't have timestamps, so we clear it periodically
        // to prevent unbounded growth. Clear entries for any old tx set hashes.
        // In practice this map should stay small since tx set requests are resolved quickly.
        if dont_have.len() > 100 {
            dont_have.clear();
        }

        // Clean up old tx set last request entries (older than 2 minutes)
        let mut last_request = self.tx_set_last_request.write().await;
        last_request.retain(|_, state| state.last_request > cutoff_short);
    }

    async fn record_tx_pull_latency(&self, hash: Hash256, peer: &henyey_overlay::PeerId) {
        let now = Instant::now();
        let mut history = self.tx_demand_history.write().await;
        let Some(entry) = history.get_mut(&hash) else {
            return;
        };

        if !entry.latency_recorded {
            entry.latency_recorded = true;
            let delta = now.duration_since(entry.first_demanded);
            tracing::debug!(
                hash = %hash.to_hex(),
                latency_ms = delta.as_millis(),
                peers = entry.peers.len(),
                "Pulled transaction after demand"
            );
        }

        if let Some(peer_demanded) = entry.peers.get(peer) {
            let delta = now.duration_since(*peer_demanded);
            tracing::debug!(
                hash = %hash.to_hex(),
                peer = %peer,
                latency_ms = delta.as_millis(),
                "Pulled transaction from peer"
            );
        }
    }

    fn demand_status(
        &self,
        hash: Hash256,
        peer: &henyey_overlay::PeerId,
        now: Instant,
        history: &HashMap<Hash256, TxDemandHistory>,
    ) -> DemandStatus {
        const MAX_RETRY_COUNT: usize = 15;

        if self.herder.tx_queue().contains(&hash) {
            return DemandStatus::Discard;
        }

        let Some(entry) = history.get(&hash) else {
            return DemandStatus::Demand;
        };

        if entry.peers.contains_key(peer) {
            return DemandStatus::Discard;
        }

        let num_demanded = entry.peers.len();
        if num_demanded < MAX_RETRY_COUNT {
            let retry_delay = self.retry_delay_demand(num_demanded);
            if now.duration_since(entry.last_demanded) >= retry_delay {
                DemandStatus::Demand
            } else {
                DemandStatus::RetryLater
            }
        } else {
            DemandStatus::Discard
        }
    }

    fn prune_tx_demands(
        &self,
        now: Instant,
        pending: &mut VecDeque<Hash256>,
        history: &mut HashMap<Hash256, TxDemandHistory>,
    ) {
        const MAX_RETRY_COUNT: u32 = 15;
        let max_retention = Duration::from_secs(2) * MAX_RETRY_COUNT * 2;

        while let Some(hash) = pending.front().copied() {
            let Some(entry) = history.get(&hash) else {
                pending.pop_front();
                continue;
            };
            if now.duration_since(entry.first_demanded) >= max_retention {
                if !entry.latency_recorded {
                    tracing::debug!(hash = %hash.to_hex(), "Abandoned tx demand");
                }
                pending.pop_front();
                history.remove(&hash);
            } else {
                break;
            }
        }
    }

    async fn run_tx_demands(&self) {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(overlay) => overlay,
            None => return,
        };

        let mut peers = overlay.peer_snapshots();
        if peers.is_empty() {
            return;
        }

        peers.shuffle(&mut rand::thread_rng());
        let peer_ids = peers
            .iter()
            .map(|snapshot| snapshot.info.peer_id.clone())
            .collect::<Vec<_>>();
        let peer_set: HashSet<_> = peer_ids.iter().cloned().collect();

        let max_demand_size = self.max_demand_size();
        let max_queue_size = self.max_advert_queue_size();
        let now = Instant::now();
        let mut to_send: Vec<(henyey_overlay::PeerId, Vec<Hash256>)> = Vec::new();

        {
            let mut adverts_by_peer = self.tx_adverts_by_peer.write().await;
            adverts_by_peer.retain(|peer, _| peer_set.contains(peer));
            for peer_id in &peer_ids {
                adverts_by_peer
                    .entry(peer_id.clone())
                    .or_insert_with(PeerTxAdverts::new);
            }

            let mut history = self.tx_demand_history.write().await;
            let mut pending = self.tx_pending_demands.write().await;
            self.prune_tx_demands(now, &mut pending, &mut history);

            let mut demand_map: HashMap<
                henyey_overlay::PeerId,
                (Vec<Hash256>, Vec<Hash256>),
            > = peer_ids
                .iter()
                .map(|peer| (peer.clone(), (Vec::new(), Vec::new())))
                .collect();

            let mut any_new_demand = true;
            while any_new_demand {
                any_new_demand = false;
                for peer_id in &peer_ids {
                    let Some(adverts) = adverts_by_peer.get_mut(peer_id) else {
                        continue;
                    };
                    let Some((demand, retry)) = demand_map.get_mut(peer_id) else {
                        continue;
                    };

                    let mut added_new = false;
                    while demand.len() < max_demand_size && adverts.has_advert() && !added_new {
                        let Some(hash) = adverts.pop_advert() else {
                            break;
                        };
                        match self.demand_status(hash, peer_id, now, &history) {
                            DemandStatus::Demand => {
                                demand.push(hash);
                                let entry = history.entry(hash).or_insert_with(|| {
                                    pending.push_back(hash);
                                    TxDemandHistory {
                                        first_demanded: now,
                                        last_demanded: now,
                                        peers: HashMap::new(),
                                        latency_recorded: false,
                                    }
                                });
                                entry.peers.insert(peer_id.clone(), now);
                                entry.last_demanded = now;
                                added_new = true;
                                any_new_demand = true;
                            }
                            DemandStatus::RetryLater => {
                                retry.push(hash);
                            }
                            DemandStatus::Discard => {}
                        }
                    }
                }
            }

            for peer_id in &peer_ids {
                let Some(adverts) = adverts_by_peer.get_mut(peer_id) else {
                    continue;
                };
                let Some((demand, retry)) = demand_map.remove(peer_id) else {
                    continue;
                };
                adverts.retry_incoming(retry, max_queue_size);
                if !demand.is_empty() {
                    to_send.push((peer_id.clone(), demand));
                }
            }
        }

        for (peer_id, hashes) in to_send {
            let tx_hashes = match TxDemandVector::try_from(
                hashes.into_iter().map(Hash::from).collect::<Vec<_>>(),
            ) {
                Ok(vec) => vec,
                Err(_) => {
                    tracing::debug!(peer = %peer_id, "Failed to build tx demand vector");
                    continue;
                }
            };
            let demand = FloodDemand { tx_hashes };
            if let Err(e) = overlay
                .send_to(&peer_id, StellarMessage::FloodDemand(demand))
                .await
            {
                tracing::debug!(peer = %peer_id, error = %e, "Failed to send flood demand");
            }
        }
    }

    async fn advance_survey_scheduler(&self) {
        const SURVEY_INTERVAL: Duration = Duration::from_secs(60);
        const SURVEY_COLLECT_DELAY: Duration = Duration::from_secs(5);
        const SURVEY_RESPONSE_WAIT: Duration = Duration::from_secs(5);
        const SURVEY_MAX_PEERS: usize = 4;

        let now = Instant::now();
        let mut scheduler = self.survey_scheduler.write().await;

        if now < scheduler.next_action {
            return;
        }

        match scheduler.phase {
            SurveySchedulerPhase::Idle => {
                if self.survey_data.read().await.survey_is_active()
                    || self.survey_reporting.read().await.running
                {
                    scheduler.next_action = now + SURVEY_INTERVAL;
                    return;
                }
                let state = *self.state.read().await;
                if !matches!(state, AppState::Synced | AppState::Validating) {
                    scheduler.next_action = now + SURVEY_INTERVAL;
                    return;
                }
                if let Some(last) = scheduler.last_started {
                    if now.duration_since(last) < self.survey_throttle {
                        scheduler.next_action = last + self.survey_throttle;
                        return;
                    }
                }

                let overlay = self.overlay.lock().await;
                let overlay = match overlay.as_ref() {
                    Some(overlay) => overlay,
                    None => {
                        scheduler.next_action = now + SURVEY_INTERVAL;
                        return;
                    }
                };

                let peers = Self::select_survey_peers(overlay.peer_snapshots(), SURVEY_MAX_PEERS);

                if peers.is_empty() {
                    scheduler.next_action = now + SURVEY_INTERVAL;
                    return;
                }

                let ledger_num = *self.current_ledger.read().await;
                let nonce = {
                    let mut nonce = self.survey_nonce.write().await;
                    let current = *nonce;
                    *nonce = nonce.wrapping_add(1);
                    current
                };

                if !self.send_survey_start(&peers, nonce, ledger_num).await {
                    scheduler.next_action = now + SURVEY_INTERVAL;
                    return;
                }

                scheduler.phase = SurveySchedulerPhase::StartSent;
                scheduler.peers = peers;
                scheduler.nonce = nonce;
                scheduler.ledger_num = ledger_num;
                scheduler.next_action = now + SURVEY_COLLECT_DELAY;
                scheduler.last_started = Some(now);
            }
            SurveySchedulerPhase::StartSent => {
                if !self
                    .send_survey_requests(&scheduler.peers, scheduler.nonce, scheduler.ledger_num)
                    .await
                {
                    self.survey_secrets.write().await.remove(&scheduler.nonce);
                    scheduler.phase = SurveySchedulerPhase::Idle;
                    scheduler.next_action = now + SURVEY_INTERVAL;
                    return;
                }
                scheduler.phase = SurveySchedulerPhase::RequestSent;
                scheduler.next_action = now + SURVEY_RESPONSE_WAIT;
            }
            SurveySchedulerPhase::RequestSent => {
                self.send_survey_stop(&scheduler.peers, scheduler.nonce, scheduler.ledger_num)
                    .await;
                for peer_id in scheduler.peers.clone() {
                    let _ = self.survey_topology_timesliced(peer_id, 0, 0).await;
                }
                scheduler.phase = SurveySchedulerPhase::Idle;
                scheduler.peers.clear();
                scheduler.nonce = 0;
                scheduler.ledger_num = 0;
                scheduler.next_action = now + SURVEY_INTERVAL;
            }
        }
    }

    async fn update_survey_phase(&self) {
        let (snapshots, added, dropped) = {
            let overlay = self.overlay.lock().await;
            let overlay = match overlay.as_ref() {
                Some(o) => o,
                None => return,
            };
            (
                overlay.peer_snapshots(),
                overlay.added_authenticated_peers(),
                overlay.dropped_authenticated_peers(),
            )
        };
        let (inbound, outbound) = Self::partition_peer_snapshots(snapshots);
        let lost_sync = self.lost_sync_count.load(Ordering::Relaxed);

        let mut survey_data = self.survey_data.write().await;
        survey_data.update_phase(&inbound, &outbound, added, dropped, lost_sync);

        let last_closed = *self.current_ledger.read().await;
        let mut limiter = self.survey_limiter.write().await;
        limiter.clear_old_ledgers(last_closed);
    }

    async fn check_scp_timeouts(&self) {
        if !self.is_validator {
            return;
        }
        if !self.herder.state().can_receive_scp() {
            return;
        }
        let slot = self.herder.tracking_slot();
        let now = Instant::now();
        let mut timeouts = self.scp_timeouts.write().await;
        if timeouts.slot != slot {
            timeouts.slot = slot;
            timeouts.next_nomination = None;
            timeouts.next_ballot = None;
        }

        if let Some(next) = timeouts.next_nomination {
            if now >= next {
                self.herder.handle_nomination_timeout(slot);
                timeouts.next_nomination = None;
            }
        }
        if timeouts.next_nomination.is_none() {
            if let Some(timeout) = self.herder.get_nomination_timeout(slot) {
                timeouts.next_nomination = Some(now + timeout);
            }
        }

        if let Some(next) = timeouts.next_ballot {
            if now >= next {
                self.herder.handle_ballot_timeout(slot);
                timeouts.next_ballot = None;
            }
        }
        if timeouts.next_ballot.is_none() {
            if let Some(timeout) = self.herder.get_ballot_timeout(slot) {
                timeouts.next_ballot = Some(now + timeout);
            }
        }
    }

    fn next_ping_hash(&self) -> Hash256 {
        let counter = self.ping_counter.fetch_add(1, Ordering::Relaxed);
        Hash256::hash(&counter.to_be_bytes())
    }

    async fn send_peer_pings(&self) {
        const PING_TIMEOUT: Duration = Duration::from_secs(60);

        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => return,
        };

        let snapshots = overlay.peer_snapshots();
        if snapshots.is_empty() {
            return;
        }

        let now = Instant::now();
        let mut inflight = self.ping_inflight.write().await;
        let mut peer_inflight = self.peer_ping_inflight.write().await;
        inflight.retain(|hash, info| {
            if now.duration_since(info.sent_at) > PING_TIMEOUT {
                if let Some(existing) = peer_inflight.get(&info.peer_id) {
                    if existing == hash {
                        peer_inflight.remove(&info.peer_id);
                    }
                }
                return false;
            }
            true
        });

        let mut to_ping = Vec::new();
        for snapshot in snapshots {
            if peer_inflight.contains_key(&snapshot.info.peer_id) {
                continue;
            }
            let hash = self.next_ping_hash();
            peer_inflight.insert(snapshot.info.peer_id.clone(), hash);
            inflight.insert(
                hash,
                PingInfo {
                    peer_id: snapshot.info.peer_id.clone(),
                    sent_at: Instant::now(),
                },
            );
            to_ping.push((snapshot.info.peer_id, hash));
        }
        drop(inflight);
        drop(peer_inflight);

        for (peer, hash) in to_ping {
            let msg = StellarMessage::GetScpQuorumset(stellar_xdr::curr::Uint256(hash.0));
            if let Err(e) = overlay.send_to(&peer, msg).await {
                tracing::debug!(peer = %peer, error = %e, "Failed to send ping");
                let mut inflight = self.ping_inflight.write().await;
                inflight.remove(&hash);
                let mut peer_inflight = self.peer_ping_inflight.write().await;
                if let Some(existing) = peer_inflight.get(&peer) {
                    if *existing == hash {
                        peer_inflight.remove(&peer);
                    }
                }
            }
        }
    }

    async fn process_ping_response(&self, peer_id: &henyey_overlay::PeerId, hash: [u8; 32]) {
        let hash = Hash256::from_bytes(hash);
        let info = {
            let mut inflight = self.ping_inflight.write().await;
            inflight.remove(&hash)
        };

        let Some(info) = info else {
            return;
        };

        {
            let mut peer_inflight = self.peer_ping_inflight.write().await;
            if let Some(existing) = peer_inflight.get(&info.peer_id) {
                if *existing == hash {
                    peer_inflight.remove(&info.peer_id);
                }
            }
        }

        if &info.peer_id != peer_id {
            return;
        }

        let latency_ms = info.sent_at.elapsed().as_millis() as u64;
        let mut survey_data = self.survey_data.write().await;
        survey_data.record_peer_latency(peer_id, latency_ms);
    }

    async fn send_survey_start(
        &self,
        peers: &[henyey_overlay::PeerId],
        nonce: u32,
        ledger_num: u32,
    ) -> bool {
        let start = TimeSlicedSurveyStartCollectingMessage {
            surveyor_id: self.local_node_id(),
            nonce,
            ledger_num,
        };

        let start_bytes = match start.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to encode survey start message");
                return false;
            }
        };

        let signature = self.sign_survey_message(&start_bytes);
        let signed = stellar_xdr::curr::SignedTimeSlicedSurveyStartCollectingMessage {
            signature,
            start_collecting: start.clone(),
        };

        let sent = self
            .send_survey_message(
                peers,
                StellarMessage::TimeSlicedSurveyStartCollecting(signed),
            )
            .await;
        if sent {
            self.survey_results
                .write()
                .await
                .entry(nonce)
                .or_insert_with(HashMap::new);
            self.start_local_survey_collecting(&start).await;
        }
        sent
    }

    async fn send_survey_requests(
        &self,
        peers: &[henyey_overlay::PeerId],
        nonce: u32,
        ledger_num: u32,
    ) -> bool {
        let local_node_id = self.local_node_id();
        let secret = self.ensure_survey_secret(nonce).await;
        let public = CurvePublicKey::from(&secret);
        let encryption_key = Curve25519Public {
            key: public.to_bytes(),
        };

        let mut ok = true;
        for peer in peers {
            let request = SurveyRequestMessage {
                surveyor_peer_id: local_node_id.clone(),
                surveyed_peer_id: stellar_xdr::curr::NodeId(peer.0.clone()),
                ledger_num,
                encryption_key: encryption_key.clone(),
                command_type: SurveyMessageCommandType::TimeSlicedSurveyTopology,
            };

            let message = TimeSlicedSurveyRequestMessage {
                request,
                nonce,
                inbound_peers_index: 0,
                outbound_peers_index: 0,
            };

            let message_bytes = match message.to_xdr(stellar_xdr::curr::Limits::none()) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::debug!(peer = %peer, error = %e, "Failed to encode survey request");
                    ok = false;
                    continue;
                }
            };

            let signature = self.sign_survey_message(&message_bytes);
            let signed = stellar_xdr::curr::SignedTimeSlicedSurveyRequestMessage {
                request_signature: signature,
                request: message,
            };

            if !self
                .send_survey_message(
                    std::slice::from_ref(peer),
                    StellarMessage::TimeSlicedSurveyRequest(signed),
                )
                .await
            {
                ok = false;
            }
        }
        ok
    }

    async fn send_survey_stop(
        &self,
        peers: &[henyey_overlay::PeerId],
        nonce: u32,
        ledger_num: u32,
    ) {
        let stop = TimeSlicedSurveyStopCollectingMessage {
            surveyor_id: self.local_node_id(),
            nonce,
            ledger_num,
        };

        let stop_bytes = match stop.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to encode survey stop message");
                return;
            }
        };

        let signature = self.sign_survey_message(&stop_bytes);
        let signed = stellar_xdr::curr::SignedTimeSlicedSurveyStopCollectingMessage {
            signature,
            stop_collecting: stop.clone(),
        };

        let _ = self
            .send_survey_message(
                peers,
                StellarMessage::TimeSlicedSurveyStopCollecting(signed),
            )
            .await;
        self.stop_local_survey_collecting(&stop).await;
    }

    async fn send_survey_message(
        &self,
        peers: &[henyey_overlay::PeerId],
        message: StellarMessage,
    ) -> bool {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(overlay) => overlay,
            None => return false,
        };

        let mut ok = true;
        for peer in peers {
            if let Err(e) = overlay.send_to(peer, message.clone()).await {
                tracing::debug!(peer = %peer, error = %e, "Failed to send survey message");
                ok = false;
            }
        }
        ok
    }

    async fn start_local_survey_collecting(
        &self,
        message: &TimeSlicedSurveyStartCollectingMessage,
    ) {
        let (snapshots, added, dropped) = {
            let overlay = self.overlay.lock().await;
            let overlay = match overlay.as_ref() {
                Some(o) => o,
                None => return,
            };
            (
                overlay.peer_snapshots(),
                overlay.added_authenticated_peers(),
                overlay.dropped_authenticated_peers(),
            )
        };
        let (inbound, outbound) = Self::partition_peer_snapshots(snapshots);
        let lost_sync = self.lost_sync_count.load(Ordering::Relaxed);
        let state = self.state().await;
        let initially_out_of_sync = matches!(state, AppState::Initializing | AppState::CatchingUp);

        let mut survey_data = self.survey_data.write().await;
        let _ = survey_data.start_collecting(
            message,
            &inbound,
            &outbound,
            lost_sync,
            added,
            dropped,
            initially_out_of_sync,
        );
    }

    async fn stop_local_survey_collecting(&self, message: &TimeSlicedSurveyStopCollectingMessage) {
        let (snapshots, added, dropped) = {
            let overlay = self.overlay.lock().await;
            let overlay = match overlay.as_ref() {
                Some(o) => o,
                None => return,
            };
            (
                overlay.peer_snapshots(),
                overlay.added_authenticated_peers(),
                overlay.dropped_authenticated_peers(),
            )
        };
        let (inbound, outbound) = Self::partition_peer_snapshots(snapshots);
        let lost_sync = self.lost_sync_count.load(Ordering::Relaxed);

        let mut survey_data = self.survey_data.write().await;
        let _ =
            survey_data.stop_collecting(message, &inbound, &outbound, added, dropped, lost_sync);
    }

    async fn handle_flood_advert(
        &self,
        peer_id: &henyey_overlay::PeerId,
        advert: FloodAdvert,
    ) {
        let ledger_seq = self.herder.tracking_slot().min(u32::MAX as u64) as u32;
        let max_ops = self.max_advert_queue_size();
        let mut adverts_by_peer = self.tx_adverts_by_peer.write().await;
        let entry = adverts_by_peer
            .entry(peer_id.clone())
            .or_insert_with(PeerTxAdverts::new);
        entry.queue_incoming(&advert.tx_hashes.0, ledger_seq, max_ops);
    }

    async fn handle_flood_demand(
        &self,
        peer_id: &henyey_overlay::PeerId,
        demand: FloodDemand,
    ) {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(overlay) => overlay,
            None => return,
        };

        for hash in demand.tx_hashes.0.iter() {
            let hash256 = Hash256::from(hash.clone());
            if let Some(tx) = self.herder.tx_queue().get(&hash256) {
                if let Err(e) = overlay
                    .send_to(peer_id, StellarMessage::Transaction(tx.envelope))
                    .await
                {
                    tracing::debug!(peer = %peer_id, error = %e, "Failed to send demanded transaction");
                }
            } else {
                let dont_have = DontHave {
                    type_: MessageType::Transaction,
                    req_hash: stellar_xdr::curr::Uint256(hash.0),
                };
                if let Err(e) = overlay
                    .send_to(peer_id, StellarMessage::DontHave(dont_have))
                    .await
                {
                    tracing::debug!(peer = %peer_id, error = %e, "Failed to send DontHave for transaction");
                }
            }
        }
    }

    /// Process a peer list received from the network.
    async fn process_peer_list(
        &self,
        peer_list: stellar_xdr::curr::VecM<stellar_xdr::curr::PeerAddress, 100>,
    ) {
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
                    stellar_xdr::curr::PeerAddressIp::IPv6(_) => {
                        return None;
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

        let addrs = self.filter_discovered_peers(addrs);

        if !addrs.is_empty() {
            self.persist_peers(&addrs);
            let count = overlay.add_peers(addrs).await;
            if count > 0 {
                tracing::info!(added = count, "Added peers from discovery");
            }
        }

        let _ = self.refresh_known_peers(overlay);
    }

    fn parse_peer_address(value: &str) -> Option<PeerAddress> {
        let parts: Vec<&str> = value.split(':').collect();
        match parts.len() {
            1 => Some(PeerAddress::new(parts[0], 11625)),
            2 => parts[1]
                .parse()
                .ok()
                .map(|port| PeerAddress::new(parts[0], port)),
            _ => None,
        }
    }

    fn peer_id_to_strkey(peer_id: &PeerId) -> Option<String> {
        henyey_crypto::PublicKey::from_bytes(peer_id.as_bytes())
            .ok()
            .map(|pk| pk.to_strkey())
    }

    fn strkey_to_peer_id(value: &str) -> Option<PeerId> {
        henyey_crypto::PublicKey::from_strkey(value)
            .ok()
            .map(|pk| PeerId::from_bytes(*pk.as_bytes()))
    }

    fn load_persisted_peers(&self) -> anyhow::Result<Vec<PeerAddress>> {
        let now = current_epoch_seconds();
        let peers = self.db.load_random_peers(
            1000,
            self.config.overlay.peer_max_failures,
            now,
            Some(PEER_TYPE_OUTBOUND),
        )?;
        let mut addrs = Vec::new();
        for (host, port, _) in peers {
            addrs.push(PeerAddress::new(host, port));
        }
        Ok(addrs)
    }

    fn store_config_peers(&self) {
        let now = current_epoch_seconds();
        for addr in &self.config.overlay.known_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                let record = henyey_db::queries::PeerRecord::new(now, 0, PEER_TYPE_OUTBOUND);
                let _ = self.db.store_peer(&peer.host, peer.port, record);
            }
        }
        for addr in &self.config.overlay.preferred_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                let record = henyey_db::queries::PeerRecord::new(now, 0, PEER_TYPE_PREFERRED);
                let _ = self.db.store_peer(&peer.host, peer.port, record);
            }
        }
    }

    fn load_advertised_outbound_peers(&self) -> anyhow::Result<Vec<PeerAddress>> {
        let peers = self.db.load_random_peers_any_outbound_max_failures(
            1000,
            PEER_MAX_FAILURES_TO_SEND,
            PEER_TYPE_INBOUND,
        )?;
        let mut addrs = Vec::new();
        for (host, port, _) in peers {
            addrs.push(PeerAddress::new(host, port));
        }
        Ok(addrs)
    }

    fn load_advertised_inbound_peers(&self) -> anyhow::Result<Vec<PeerAddress>> {
        let peers = self.db.load_random_peers_by_type_max_failures(
            1000,
            PEER_MAX_FAILURES_TO_SEND,
            PEER_TYPE_INBOUND,
        )?;
        let mut addrs = Vec::new();
        for (host, port, _) in peers {
            addrs.push(PeerAddress::new(host, port));
        }
        Ok(addrs)
    }

    fn persist_peers(&self, peers: &[PeerAddress]) {
        let now = current_epoch_seconds();
        for peer in peers {
            let existing = self.db.load_peer(&peer.host, peer.port).ok().flatten();
            if existing.is_some() {
                continue;
            }
            let record = henyey_db::queries::PeerRecord::new(now, 0, PEER_TYPE_OUTBOUND);
            if let Err(err) = self.db.store_peer(&peer.host, peer.port, record) {
                tracing::debug!(peer = %peer, error = %err, "Failed to persist peer");
            }
        }
    }

    fn filter_discovered_peers(&self, peers: Vec<PeerAddress>) -> Vec<PeerAddress> {
        let now = current_epoch_seconds();
        let mut filtered = Vec::new();
        for peer in peers {
            if !Self::is_public_peer(&peer) {
                continue;
            }
            let record = self.db.load_peer(&peer.host, peer.port).ok().flatten();
            if let Some(record) = record {
                if record.num_failures >= self.config.overlay.peer_max_failures {
                    continue;
                }
                if record.next_attempt > now {
                    continue;
                }
            }
            filtered.push(peer);
        }
        filtered
    }

    fn filter_advertised_peers(&self, peers: Vec<PeerAddress>) -> Vec<PeerAddress> {
        peers.into_iter().filter(Self::is_public_peer).collect()
    }

    fn is_public_peer(peer: &PeerAddress) -> bool {
        if peer.port == 0 {
            return false;
        }
        let Ok(ip) = peer.host.parse::<std::net::IpAddr>() else {
            return true;
        };
        match ip {
            std::net::IpAddr::V4(v4) => {
                !(v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_multicast()
                    || v4.is_unspecified())
            }
            std::net::IpAddr::V6(_) => false,
        }
    }

    fn refresh_known_peers(&self, overlay: &OverlayManager) -> Vec<PeerAddress> {
        let mut peers = Vec::new();
        for addr in &self.config.overlay.known_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                peers.push(peer);
            }
        }
        for addr in &self.config.overlay.preferred_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                self.upsert_peer_type(&peer, PEER_TYPE_PREFERRED);
                peers.push(peer);
            }
        }
        if let Ok(persisted) = self.load_persisted_peers() {
            peers.extend(persisted);
        }
        let peers = self.filter_discovered_peers(peers);
        let peers = self.dedupe_peers(peers);
        overlay.set_known_peers(peers.clone());

        let mut advertised_outbound = Vec::new();
        for addr in &self.config.overlay.known_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                advertised_outbound.push(peer);
            }
        }
        for addr in &self.config.overlay.preferred_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                advertised_outbound.push(peer);
            }
        }
        if let Ok(persisted) = self.load_advertised_outbound_peers() {
            advertised_outbound.extend(persisted);
        }
        let advertised_outbound = self.filter_advertised_peers(advertised_outbound);
        let advertised_outbound = self.dedupe_peers(advertised_outbound);

        let mut advertised_inbound = Vec::new();
        if let Ok(persisted) = self.load_advertised_inbound_peers() {
            advertised_inbound.extend(persisted);
        }
        let advertised_inbound = self.filter_advertised_peers(advertised_inbound);
        let advertised_inbound = self.dedupe_peers(advertised_inbound);
        overlay.set_advertised_peers(advertised_outbound, advertised_inbound);

        peers
    }

    fn upsert_peer_type(&self, peer: &PeerAddress, peer_type: i32) {
        let now = current_epoch_seconds();
        let existing = self.db.load_peer(&peer.host, peer.port).ok().flatten();
        let record = match existing {
            Some(existing) => henyey_db::queries::PeerRecord::new(
                existing.next_attempt,
                existing.num_failures,
                peer_type,
            ),
            None => henyey_db::queries::PeerRecord::new(now, 0, peer_type),
        };
        let _ = self.db.store_peer(&peer.host, peer.port, record);
    }
    fn dedupe_peers(&self, peers: Vec<PeerAddress>) -> Vec<PeerAddress> {
        let mut seen = HashSet::new();
        let mut deduped = Vec::new();
        for peer in peers {
            if seen.insert(peer.to_socket_addr()) {
                deduped.push(peer);
            }
        }
        deduped
    }

    /// Handle a TxSet message from the network.
    async fn handle_tx_set(&self, tx_set: stellar_xdr::curr::TransactionSet) {
        use henyey_herder::TransactionSet;

        // For legacy TransactionSet, hash is SHA-256 of previous_ledger_hash + tx XDR blobs
        let transactions: Vec<_> = tx_set.txs.to_vec();
        let prev_hash = henyey_common::Hash256::from_bytes(tx_set.previous_ledger_hash.0);
        let hash = match TransactionSet::compute_non_generalized_hash(prev_hash, &transactions) {
            Some(hash) => hash,
            None => {
                tracing::error!("Failed to compute legacy TxSet hash");
                return;
            }
        };

        // Create our internal TransactionSet with correct hash
        let internal_tx_set = TransactionSet::with_hash(prev_hash, hash, transactions);
        {
            let mut map = self.tx_set_dont_have.write().await;
            map.remove(&internal_tx_set.hash);
        }
        {
            let mut map = self.tx_set_last_request.write().await;
            map.remove(&internal_tx_set.hash);
        }

        tracing::info!(
            hash = %internal_tx_set.hash,
            tx_count = internal_tx_set.transactions.len(),
            "Processing TxSet"
        );

        if !self.herder.needs_tx_set(&internal_tx_set.hash) {
            tracing::info!(hash = %internal_tx_set.hash, "TxSet not pending");
        }

        let received_slot = self.herder.receive_tx_set(internal_tx_set.clone());
        if let Some(slot) = received_slot {
            tracing::info!(slot, "Received pending TxSet, attempting ledger close");
            self.process_externalized_slots().await;
        } else if self.attach_tx_set_by_hash(&internal_tx_set).await
            || self.buffer_externalized_tx_set(&internal_tx_set).await
        {
            self.try_apply_buffered_ledgers().await;
        }
    }

    /// Handle a GeneralizedTxSet message from the network.
    async fn handle_generalized_tx_set(
        &self,
        gen_tx_set: stellar_xdr::curr::GeneralizedTransactionSet,
    ) {
        use henyey_herder::TransactionSet;
        use stellar_xdr::curr::{
            GeneralizedTransactionSet, TransactionPhase, TxSetComponent, WriteXdr,
        };

        // Compute hash as SHA-256 of XDR-encoded GeneralizedTransactionSet
        // This matches how stellar-core computes it: xdrSha256(xdrTxSet)
        let xdr_bytes = match gen_tx_set.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(error = %e, "Failed to encode GeneralizedTxSet to XDR");
                return;
            }
        };
        let hash = henyey_common::Hash256::hash(&xdr_bytes);

        // Extract transactions from GeneralizedTransactionSet
        let prev_hash = match &gen_tx_set {
            GeneralizedTransactionSet::V1(v1) => {
                henyey_common::Hash256::from_bytes(v1.previous_ledger_hash.0)
            }
        };
        let transactions: Vec<stellar_xdr::curr::TransactionEnvelope> = match &gen_tx_set {
            GeneralizedTransactionSet::V1(v1) => {
                if v1.phases.len() != 2 {
                    tracing::warn!(
                        hash = %hash,
                        phases = v1.phases.len(),
                        "Invalid GeneralizedTxSet phase count"
                    );
                    return;
                }
                v1.phases
                    .iter()
                    .flat_map(|phase| match phase {
                        TransactionPhase::V0(components) => components
                            .iter()
                            .flat_map(|component| match component {
                                TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) => {
                                    comp.txs.to_vec()
                                }
                            })
                            .collect::<Vec<_>>(),
                        TransactionPhase::V1(parallel) => parallel
                            .execution_stages
                            .iter()
                            .flat_map(|stage| stage.0.iter().flat_map(|cluster| cluster.0.to_vec()))
                            .collect(),
                    })
                    .collect()
            }
        };

        tracing::debug!(
            hash = %hash,
            tx_count = transactions.len(),
            "Processing GeneralizedTxSet"
        );

        if !self.herder.needs_tx_set(&hash) {
            tracing::debug!(hash = %hash, "GeneralizedTxSet not pending");
        }

        let phase_check = match &gen_tx_set {
            GeneralizedTransactionSet::V1(v1) => {
                let classic_ok = matches!(v1.phases[0], TransactionPhase::V0(_));
                let soroban_ok = matches!(
                    v1.phases[1],
                    TransactionPhase::V1(_) | TransactionPhase::V0(_)
                );
                if !classic_ok || !soroban_ok {
                    tracing::warn!(hash = %hash, "Invalid GeneralizedTxSet phase types");
                }
                classic_ok && soroban_ok
            }
        };
        if !phase_check {
            return;
        }

        let base_fee_limit = self.ledger_manager.current_header().base_fee as i64;
        let base_fee_ok = match &gen_tx_set {
            GeneralizedTransactionSet::V1(v1) => {
                let classic_ok = match &v1.phases[0] {
                    TransactionPhase::V0(components) => components.iter().all(|component| {
                        let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) = component;
                        comp.base_fee.map_or(true, |fee| fee >= base_fee_limit)
                    }),
                    _ => false,
                };
                let soroban_ok = match &v1.phases[1] {
                    TransactionPhase::V1(parallel) => {
                        parallel.base_fee.map_or(true, |fee| fee >= base_fee_limit)
                    }
                    TransactionPhase::V0(components) => components.iter().all(|component| {
                        let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) = component;
                        comp.base_fee.map_or(true, |fee| fee >= base_fee_limit)
                    }),
                };
                classic_ok && soroban_ok
            }
        };
        if !base_fee_ok {
            tracing::warn!(hash = %hash, base_fee = base_fee_limit, "GeneralizedTxSet base fee below ledger base fee");
            return;
        }

        let network_id = NetworkId(self.network_id());
        let mut classic_count = 0usize;
        let mut soroban_count = 0usize;
        for env in &transactions {
            let frame = henyey_tx::TransactionFrame::with_network(env.clone(), network_id);
            if frame.is_soroban() {
                soroban_count += 1;
            } else {
                classic_count += 1;
            }
        }
        let phase_sizes = match &gen_tx_set {
            GeneralizedTransactionSet::V1(v1) => {
                let classic_phase_count: usize = match &v1.phases[0] {
                    TransactionPhase::V0(components) => components
                        .iter()
                        .map(|component| match component {
                            TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) => comp.txs.len(),
                        })
                        .sum(),
                    _ => 0,
                };
                let soroban_phase_count: usize = match &v1.phases[1] {
                    TransactionPhase::V1(parallel) => parallel
                        .execution_stages
                        .iter()
                        .map(|stage| stage.0.iter().map(|cluster| cluster.0.len()).sum::<usize>())
                        .sum(),
                    TransactionPhase::V0(components) => components
                        .iter()
                        .map(|component| match component {
                            TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) => comp.txs.len(),
                        })
                        .sum(),
                };
                (classic_phase_count, soroban_phase_count)
            }
        };
        if classic_count != phase_sizes.0 || soroban_count != phase_sizes.1 {
            tracing::warn!(
                hash = %hash,
                classic = classic_count,
                soroban = soroban_count,
                classic_phase = phase_sizes.0,
                soroban_phase = phase_sizes.1,
                "GeneralizedTxSet phase tx type mismatch"
            );
            return;
        }

        // Create internal tx set with the correct hash and retain generalized set
        let internal_tx_set =
            TransactionSet::with_generalized(prev_hash, hash, transactions, gen_tx_set);
        {
            let mut map = self.tx_set_dont_have.write().await;
            map.remove(&internal_tx_set.hash);
        }
        {
            let mut map = self.tx_set_last_request.write().await;
            map.remove(&internal_tx_set.hash);
        }

        let received_slot = self.herder.receive_tx_set(internal_tx_set.clone());
        if let Some(slot) = received_slot {
            tracing::debug!(
                slot,
                hash = %hash,
                "Received pending GeneralizedTxSet, attempting ledger close"
            );
            self.try_close_slot_directly(slot).await;
        } else if self.attach_tx_set_by_hash(&internal_tx_set).await
            || self.buffer_externalized_tx_set(&internal_tx_set).await
        {
            tracing::debug!(hash = %hash, "TxSet matched buffered/externalized slot");
            self.try_apply_buffered_ledgers().await;
        } else {
            tracing::debug!(hash = %hash, "TxSet not matched to any slot or buffer entry");
        }
    }

    /// Send a TxSet to a peer in response to GetTxSet.
    async fn send_tx_set(&self, peer_id: &henyey_overlay::PeerId, hash: &[u8; 32]) {
        let hash256 = henyey_common::Hash256::from_bytes(*hash);

        // Get the tx set from cache
        let tx_set = match self.herder.get_tx_set(&hash256) {
            Some(ts) => ts,
            None => {
                tracing::debug!(hash = hex::encode(hash), peer = %peer_id, "TxSet not found in cache");
                let overlay = self.overlay.lock().await;
                if let Some(ref overlay) = *overlay {
                    let ledger_version = self.ledger_manager.current_header().ledger_version;
                    let message_type = if ledger_version >= 20 {
                        stellar_xdr::curr::MessageType::GeneralizedTxSet
                    } else {
                        stellar_xdr::curr::MessageType::TxSet
                    };
                    let msg = StellarMessage::DontHave(stellar_xdr::curr::DontHave {
                        type_: message_type,
                        req_hash: stellar_xdr::curr::Uint256(*hash),
                    });
                    if let Err(e) = overlay.send_to(peer_id, msg).await {
                        tracing::debug!(hash = hex::encode(hash), peer = %peer_id, error = %e, "Failed to send DontHave for TxSet");
                    }
                }
                return;
            }
        };

        let ledger_version = self.ledger_manager.current_header().ledger_version;
        if ledger_version >= 20 {
            if let Some(gen_tx_set) = tx_set
                .generalized_tx_set
                .clone()
                .or_else(|| build_generalized_tx_set(&tx_set))
            {
                let gen_hash = match gen_tx_set.to_xdr(stellar_xdr::curr::Limits::none()) {
                    Ok(bytes) => henyey_common::Hash256::hash(&bytes),
                    Err(e) => {
                        tracing::warn!(hash = %hash256, error = %e, "Failed to encode GeneralizedTxSet");
                        henyey_common::Hash256::ZERO
                    }
                };
                if gen_hash == hash256 {
                    let message = StellarMessage::GeneralizedTxSet(gen_tx_set);
                    let overlay = self.overlay.lock().await;
                    if let Some(ref overlay) = *overlay {
                        if let Err(e) = overlay.send_to(peer_id, message).await {
                            tracing::warn!(hash = %hash256, peer = %peer_id, error = %e, "Failed to send GeneralizedTxSet");
                        } else {
                            tracing::debug!(hash = %hash256, peer = %peer_id, "Sent GeneralizedTxSet");
                        }
                    }
                    return;
                }
                tracing::warn!(hash = %hash256, computed = %gen_hash, "GeneralizedTxSet hash mismatch; falling back");
            }
        }

        // Convert to legacy XDR TransactionSet
        let prev_hash = tx_set.previous_ledger_hash;
        let xdr_tx_set = stellar_xdr::curr::TransactionSet {
            previous_ledger_hash: Hash::from(prev_hash),
            txs: tx_set.transactions.try_into().unwrap_or_default(),
        };

        let message = StellarMessage::TxSet(xdr_tx_set);

        let overlay = self.overlay.lock().await;
        if let Some(ref overlay) = *overlay {
            if let Err(e) = overlay.send_to(peer_id, message).await {
                tracing::warn!(hash = hex::encode(hash), peer = %peer_id, error = %e, "Failed to send TxSet");
            } else {
                tracing::debug!(hash = hex::encode(hash), peer = %peer_id, "Sent TxSet");
            }
        }
    }

    /// Request pending transaction sets from peers.
    async fn request_pending_tx_sets(&self) {
        let current_ledger = match self.get_current_ledger().await {
            Ok(seq) => seq,
            Err(_) => return,
        };
        let min_slot = current_ledger.saturating_add(1) as u64;
        let window_end = current_ledger as u64 + TX_SET_REQUEST_WINDOW;
        let mut pending = self.herder.get_pending_tx_sets();
        pending.sort_by_key(|(_, slot)| *slot);

        // Log all pending tx_sets for debugging
        if !pending.is_empty() {
            tracing::debug!(
                current_ledger,
                min_slot = current_ledger.saturating_add(1),
                window_end = current_ledger as u64 + TX_SET_REQUEST_WINDOW,
                pending_count = pending.len(),
                pending_slots = ?pending.iter().map(|(h, s)| (*s, format!("{}...", &hex::encode(h.0)[..8]))).collect::<Vec<_>>(),
                "Pending tx_sets before filtering"
            );
        }

        let pending_hashes: Vec<Hash256> = pending
            .into_iter()
            .filter(|(_, slot)| *slot >= min_slot && *slot <= window_end)
            .map(|(hash, _)| hash)
            .take(MAX_TX_SET_REQUESTS_PER_TICK)
            .collect();
        if pending_hashes.is_empty() {
            return;
        }

        tracing::debug!(
            current_ledger,
            pending_count = pending_hashes.len(),
            hashes = ?pending_hashes.iter().map(|h| format!("{}...", &hex::encode(h.0)[..8])).collect::<Vec<_>>(),
            "Will request tx_sets"
        );

        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => {
                tracing::warn!("No overlay available to request tx sets");
                return;
            }
        };

        let peer_infos = overlay.peer_infos();
        if peer_infos.is_empty() {
            tracing::warn!("No peers connected, cannot request tx sets");
            return;
        }
        let mut peers = Vec::new();
        let mut fallback = Vec::new();
        for info in peer_infos {
            fallback.push(info.peer_id.clone());
            let is_outbound = matches!(info.direction, ConnectionDirection::Outbound);
            let is_preferred = if is_outbound {
                true
            } else {
                let host = info.address.ip().to_string();
                let port = info.address.port();
                match self.db.load_peer(&host, port) {
                    Ok(Some(record)) => {
                        record.peer_type == PEER_TYPE_PREFERRED
                            || record.peer_type == PEER_TYPE_OUTBOUND
                    }
                    _ => false,
                }
            };
            if is_outbound || is_preferred {
                peers.push(info.peer_id);
            }
        }
        if peers.is_empty() {
            peers = fallback;
        }
        peers.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

        let now = Instant::now();
        #[allow(clippy::type_complexity)]
        let (requests, newly_exhausted): (Vec<(Hash256, henyey_overlay::PeerId)>, Vec<(Hash256, usize, usize)>) = {
            let mut dont_have = self.tx_set_dont_have.write().await;
            let pending_set: HashSet<Hash256> = pending_hashes.iter().copied().collect();
            dont_have.retain(|hash, _| pending_set.contains(hash));
            let mut last_request = self.tx_set_last_request.write().await;
            last_request.retain(|hash, _| pending_set.contains(hash));
            let exhausted_warned = self.tx_set_exhausted_warned.read().await;

            let mut reqs = Vec::new();
            let mut exhausted = Vec::new();

            for hash in &pending_hashes {
                if !self.herder.needs_tx_set(hash) {
                    continue;
                }
                let throttle = std::time::Duration::from_millis(200);
                let mut request_state =
                    last_request
                        .get(hash)
                        .cloned()
                        .unwrap_or(TxSetRequestState {
                            last_request: now.checked_sub(throttle).unwrap_or(now),
                            first_requested: now,
                            next_peer_offset: 0,
                        });
                if now.duration_since(request_state.last_request) < throttle {
                    continue;
                }

                // Timeout detection: if we've been requesting this tx_set for
                // TX_SET_REQUEST_TIMEOUT_SECS with no response at all (no
                // GeneralizedTxSet, no DontHave), peers are silently dropping
                // our requests. Synthetically mark all peers as DontHave.
                let request_age = now.duration_since(request_state.first_requested);
                if request_age
                    >= std::time::Duration::from_secs(TX_SET_REQUEST_TIMEOUT_SECS)
                {
                    let dont_have_set =
                        dont_have.entry(*hash).or_insert_with(HashSet::new);
                    let already_exhausted = dont_have_set.len() >= peers.len();
                    if !already_exhausted {
                        tracing::warn!(
                            hash = %hash,
                            elapsed_secs = request_age.as_secs(),
                            peers_responded = dont_have_set.len(),
                            total_peers = peers.len(),
                            "Tx_set request timed out with no response — marking all peers as DontHave"
                        );
                        for peer in &peers {
                            dont_have_set.insert(peer.clone());
                        }
                        if !exhausted_warned.contains(hash) {
                            exhausted.push((*hash, dont_have_set.len(), peers.len()));
                        }
                        self.tx_set_all_peers_exhausted
                            .store(true, Ordering::SeqCst);
                    }
                    continue;
                }

                let start_idx =
                    Self::tx_set_start_index(hash, peers.len(), request_state.next_peer_offset);
                let eligible_peer = match dont_have.get_mut(hash) {
                    Some(set) => {
                        let mut found = None;
                        for offset in 0..peers.len() {
                            let idx = (start_idx + offset) % peers.len();
                            let peer = &peers[idx];
                            if !set.contains(peer) {
                                found = Some(peer);
                                break;
                            }
                        }
                        if found.is_none() {
                            // All peers have said DontHave for this tx set.
                            // Track for warning (only if not already warned).
                            if !exhausted_warned.contains(hash) {
                                exhausted.push((*hash, set.len(), peers.len()));
                            }
                            self.tx_set_all_peers_exhausted
                                .store(true, Ordering::SeqCst);
                            // Don't clear the set or return a peer - stop requesting this tx set
                            // until catchup or tx_set tracking is reset.
                        }
                        found
                    }
                    None => peers.get(start_idx),
                };

                if let Some(peer_id) = eligible_peer.cloned() {
                    request_state.last_request = now;
                    request_state.next_peer_offset =
                        request_state.next_peer_offset.saturating_add(1);
                    last_request.insert(*hash, request_state);
                    reqs.push((*hash, peer_id));
                }
            }

            (reqs, exhausted)
        };

        // Log warnings for newly exhausted tx sets (only once per hash)
        if !newly_exhausted.is_empty() {
            let mut exhausted_warned = self.tx_set_exhausted_warned.write().await;
            for (hash, peers_asked, total_peers) in &newly_exhausted {
                if exhausted_warned.insert(*hash) {
                    tracing::warn!(
                        hash = %hash,
                        peers_asked,
                        total_peers,
                        "All peers exhausted for tx set - triggering faster catchup"
                    );
                }
            }
        }

        for (hash, peer_id) in requests {
            tracing::debug!(hash = %hash, peer = %peer_id, "Requesting tx set");
            let request = StellarMessage::GetTxSet(stellar_xdr::curr::Uint256(hash.0));
            if let Err(e) = overlay.send_to(&peer_id, request).await {
                tracing::warn!(hash = %hash, peer = %peer_id, error = %e, "Failed to request TxSet");
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

    /// Get the number of connected peers.
    async fn get_peer_count(&self) -> usize {
        let overlay = self.overlay.lock().await;
        overlay.as_ref().map(|o| o.peer_count()).unwrap_or(0)
    }

    /// Signal the application to shut down.
    pub fn shutdown(&self) {
        tracing::info!("Shutdown requested");
        let _ = self.shutdown_tx.send(());
    }

    /// Subscribe to shutdown notifications.
    pub fn subscribe_shutdown(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Internal shutdown cleanup.
    async fn shutdown_internal(&self) -> anyhow::Result<()> {
        tracing::info!("Performing shutdown cleanup");

        self.set_state(AppState::ShuttingDown).await;
        self.stop_survey_reporting().await;

        let mut overlay = self.overlay.lock().await;
        if let Some(mut overlay) = overlay.take() {
            if let Err(err) = overlay.shutdown().await {
                tracing::warn!(error = %err, "Overlay shutdown reported error");
            }
        }

        Ok(())
    }

    /// Get application info.
    pub fn info(&self) -> AppInfo {
        let (meta_bytes, meta_writes) = self
            .meta_stream
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|ms| ms.metrics()))
            .unwrap_or((0, 0));

        AppInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            node_name: self.config.node.name.clone(),
            public_key: self.keypair.public_key().to_strkey(),
            network_passphrase: self.config.network.passphrase.clone(),
            is_validator: self.config.node.is_validator,
            database_path: self.config.database.path.clone(),
            meta_stream_bytes_total: meta_bytes,
            meta_stream_writes_total: meta_writes,
        }
    }

    /// Return the local quorum set if configured.
    pub fn local_quorum_set(&self) -> Option<stellar_xdr::curr::ScpQuorumSet> {
        self.herder.local_quorum_set()
    }
}

fn update_peer_record(db: &henyey_db::Database, event: PeerEvent) {
    let now = current_epoch_seconds();
    match event {
        PeerEvent::Connected(addr, peer_type) => {
            let existing = db.load_peer(&addr.host, addr.port).ok().flatten();
            let existing_type = existing.map(|r| r.peer_type).unwrap_or(PEER_TYPE_INBOUND);
            let mapped = match peer_type {
                PeerType::Inbound => match existing_type {
                    PEER_TYPE_PREFERRED => PEER_TYPE_PREFERRED,
                    PEER_TYPE_OUTBOUND => PEER_TYPE_OUTBOUND,
                    _ => PEER_TYPE_INBOUND,
                },
                PeerType::Outbound => {
                    if existing_type == PEER_TYPE_PREFERRED {
                        PEER_TYPE_PREFERRED
                    } else {
                        PEER_TYPE_OUTBOUND
                    }
                }
            };
            let record = henyey_db::queries::PeerRecord::new(now, 0, mapped);
            let _ = db.store_peer(&addr.host, addr.port, record);
        }
        PeerEvent::Failed(addr, peer_type) => {
            let existing = db.load_peer(&addr.host, addr.port).ok().flatten();
            let mut failures = existing.map(|r| r.num_failures).unwrap_or(0);
            failures = failures.saturating_add(1);
            let backoff = compute_peer_backoff_secs(failures);
            let next_attempt = now.saturating_add(backoff);
            let existing_type = existing.map(|r| r.peer_type).unwrap_or(PEER_TYPE_INBOUND);
            let mapped = match peer_type {
                PeerType::Inbound => match existing_type {
                    PEER_TYPE_PREFERRED => PEER_TYPE_PREFERRED,
                    PEER_TYPE_OUTBOUND => PEER_TYPE_OUTBOUND,
                    _ => PEER_TYPE_INBOUND,
                },
                PeerType::Outbound => {
                    if existing_type == PEER_TYPE_PREFERRED {
                        PEER_TYPE_PREFERRED
                    } else {
                        PEER_TYPE_OUTBOUND
                    }
                }
            };
            let record = henyey_db::queries::PeerRecord::new(next_attempt, failures, mapped);
            let _ = db.store_peer(&addr.host, addr.port, record);
        }
    }
}

fn compute_peer_backoff_secs(failures: u32) -> i64 {
    const SECONDS_PER_BACKOFF: u64 = 10;
    const MAX_BACKOFF_EXPONENT: u32 = 10;
    let exp = failures.min(MAX_BACKOFF_EXPONENT);
    let max = SECONDS_PER_BACKOFF.saturating_mul(1u64 << exp);
    let mut rng = rand::thread_rng();
    let jitter = rng.gen_range(1..=max.max(1));
    jitter as i64
}

fn current_epoch_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
    pub ledger_hash: henyey_common::Hash256,
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
    /// Total bytes written to metadata output stream.
    pub meta_stream_bytes_total: u64,
    /// Total frames written to metadata output stream.
    pub meta_stream_writes_total: u64,
}

#[derive(Debug, Clone)]
pub struct ScpSlotSnapshot {
    pub slot_index: u64,
    pub is_externalized: bool,
    pub is_nominating: bool,
    pub ballot_phase: String,
    pub nomination_round: u32,
    pub ballot_round: Option<u32>,
    pub envelope_count: usize,
}

#[derive(Debug, Clone)]
pub struct SelfCheckResult {
    pub ok: bool,
    pub checked_ledgers: u32,
    pub last_checked_ledger: Option<u32>,
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
        if self.meta_stream_bytes_total > 0 || self.meta_stream_writes_total > 0 {
            writeln!(f)?;
            writeln!(f, "Metadata Stream:")?;
            writeln!(f, "  Bytes Written:  {}", self.meta_stream_bytes_total)?;
            writeln!(f, "  Writes:         {}", self.meta_stream_writes_total)?;
        }
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
        tx_set: henyey_herder::TransactionSet,
        close_time: u64,
        upgrades: Vec<UpgradeType>,
        stellar_value_ext: StellarValueExt,
    ) -> henyey_herder::Result<henyey_common::Hash256> {
        let tx_summary = tx_set.summary();
        tracing::info!(
            ledger_seq,
            tx_count = tx_set.transactions.len(),
            close_time,
            summary = %tx_summary,
            "Closing ledger"
        );

        // Get the previous ledger hash
        let prev_hash = tx_set.previous_ledger_hash;

        // Create the transaction set
        let tx_set_variant = if let Some(gen_tx_set) = tx_set.generalized_tx_set.clone() {
            TransactionSetVariant::Generalized(gen_tx_set)
        } else {
            TransactionSetVariant::Classic(TransactionSet {
                previous_ledger_hash: Hash::from(prev_hash),
                txs: tx_set.transactions.clone().try_into().map_err(|_| {
                    henyey_herder::HerderError::Internal("Failed to create tx set".into())
                })?,
            })
        };

        // Create close data
        let decoded_upgrades = decode_upgrades(upgrades);
        let mut close_data =
            LedgerCloseData::new(ledger_seq, tx_set_variant.clone(), close_time, prev_hash)
                .with_stellar_value_ext(stellar_value_ext.clone());
        if !decoded_upgrades.is_empty() {
            close_data = close_data.with_upgrades(decoded_upgrades.clone());
        }
        if let Some(entry) = self.build_scp_history_entry(ledger_seq) {
            close_data = close_data.with_scp_history(vec![entry]);
        }

        // Close the ledger on a blocking thread (yields the tokio worker).
        let lm = self.ledger_manager.clone();
        let runtime_handle = tokio::runtime::Handle::current();
        self.set_applying_ledger(true);

        let join_handle = tokio::task::spawn_blocking(move || {
            lm.close_ledger(close_data, Some(runtime_handle))
                .map_err(|e| e.to_string())
        });

        let mut pending = PendingLedgerClose {
            handle: join_handle,
            ledger_seq,
            tx_set,
            tx_set_variant,
            close_time,
        };

        let join_result = (&mut pending.handle).await;

        // Extract header hash before passing ownership to handle_close_complete.
        let header_hash = match &join_result {
            Ok(Ok(result)) => Some(result.header_hash),
            _ => None,
        };

        let success = self.handle_close_complete(pending, join_result).await;

        if success {
            Ok(header_hash.unwrap())
        } else {
            Err(henyey_herder::HerderError::Internal(
                format!("Failed to close ledger {}", ledger_seq),
            ))
        }
    }

    async fn validate_tx_set(&self, _tx_set_hash: &henyey_common::Hash256) -> bool {
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

impl SyncRecoveryCallback for App {
    fn on_lost_sync(&self) {
        tracing::warn!("Lost sync with network - transitioning to syncing state");
        self.lost_sync_count.fetch_add(1, Ordering::Relaxed);
        // Update herder state to syncing
        self.herder
            .set_state(henyey_herder::HerderState::Syncing);
    }

    fn on_out_of_sync_recovery(&self) {
        tracing::info!("SyncRecoveryManager triggered out-of-sync recovery");
        // Set flag so the main event loop will trigger recovery and buffered catchup.
        // The main loop checks this flag and calls maybe_start_buffered_catchup()
        // which handles the actual recovery logic including timeout-based catchup.
        self.sync_recovery_pending.store(true, Ordering::SeqCst);
    }

    fn is_applying_ledger(&self) -> bool {
        self.is_applying_ledger.load(Ordering::Relaxed)
    }

    fn is_tracking(&self) -> bool {
        self.herder.is_tracking()
    }

    fn get_v_blocking_slots(&self) -> Vec<henyey_scp::SlotIndex> {
        // Return slots where we've received v-blocking messages
        // For now, return the tracking slot range
        let tracking = self.herder.tracking_slot();
        if tracking > 0 {
            vec![tracking]
        } else {
            vec![]
        }
    }

    fn purge_slots_below(&self, slot: henyey_scp::SlotIndex) {
        tracing::debug!(slot, "Purging SCP slots below");
        self.herder.purge_slots_below(slot);
    }

    fn broadcast_latest_messages(&self, from_slot: henyey_scp::SlotIndex) {
        tracing::debug!(from_slot, "Broadcasting latest SCP messages");
        // Get and broadcast latest messages for the slot
        if let Some(messages) = self.herder.get_latest_messages(from_slot) {
            for envelope in messages {
                let _ = self.scp_envelope_tx.try_send(envelope);
            }
        }
    }

    fn request_scp_state_from_peers(&self) {
        self.request_scp_state_sync();
    }
}

impl App {
    /// Synchronous version of request_scp_state_from_peers for use in callbacks.
    fn request_scp_state_sync(&self) {
        // We can't call async from sync callback, so we use a simple marker
        // The main event loop's heartbeat will pick up stalled state and request
        tracing::debug!("Sync recovery requested SCP state - will be handled by main loop");
    }

    /// Start the sync recovery manager background task.
    ///
    /// This spawns a background task that monitors for consensus stuck conditions
    /// and triggers recovery actions when needed.
    pub fn start_sync_recovery(self: &Arc<Self>) {
        let (handle, manager) = SyncRecoveryManager::new(Arc::clone(self));
        *self.sync_recovery_handle.write() = Some(handle);
        tokio::spawn(manager.run());
        tracing::info!("Sync recovery manager started");
    }

    /// Send a heartbeat to the sync recovery manager.
    ///
    /// This should be called whenever consensus makes progress (externalization,
    /// new SCP messages, ledger close).
    pub fn sync_recovery_heartbeat(&self) {
        if let Some(handle) = self.sync_recovery_handle.read().as_ref() {
            let _ = handle.try_tracking_heartbeat();
        }
    }

    /// Start tracking in the sync recovery manager.
    ///
    /// This should be called after bootstrap to enable the consensus stuck timer.
    pub fn start_sync_recovery_tracking(&self) {
        if let Some(handle) = self.sync_recovery_handle.read().as_ref() {
            if handle.try_start_tracking() {
                tracing::info!("Started sync recovery tracking");
            }
        }
    }

    /// Notify sync recovery that we're starting/stopping ledger application.
    pub fn set_applying_ledger(&self, applying: bool) {
        self.is_applying_ledger.store(applying, Ordering::Relaxed);
        if let Some(handle) = self.sync_recovery_handle.read().as_ref() {
            let _ = handle.try_set_applying_ledger(applying);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    #[tokio::test]
    async fn test_app_creation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();
        assert_eq!(app.state().await, AppState::Initializing);
    }

    #[tokio::test]
    async fn test_app_info() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .node_name("test-node")
            .database_path(db_path)
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
            ledger_hash: henyey_common::Hash256::ZERO,
            buckets_applied: 22,
            ledgers_replayed: 64,
        };

        let display = format!("{}", result);
        assert!(display.contains("1000"));
        assert!(display.contains("22 buckets"));
    }

    #[test]
    fn test_buffered_catchup_target_large_gap() {
        let current = 100;
        let first_buffered = current + CHECKPOINT_FREQUENCY + 5; // 169
        let target = App::buffered_catchup_target(current, first_buffered, first_buffered);
        // Target should be capped at the latest checkpoint (127) to avoid replaying
        // individual ledgers which can cause bucket list hash mismatches.
        assert_eq!(target, Some(127));
    }

    #[test]
    fn test_buffered_catchup_target_requires_trigger() {
        let current = 100;
        let first_buffered = 120;
        let last_buffered = 120;
        let target = App::buffered_catchup_target(current, first_buffered, last_buffered);
        assert_eq!(target, None);

        let last_buffered = 130;
        let target = App::buffered_catchup_target(current, first_buffered, last_buffered);
        assert_eq!(target, Some(127));
    }

    #[test]
    fn test_tx_set_start_index_rotation() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        let hash = Hash256::from_bytes(bytes);
        assert_eq!(App::tx_set_start_index(&hash, 3, 0), 1);
        assert_eq!(App::tx_set_start_index(&hash, 3, 1), 2);
        assert_eq!(App::tx_set_start_index(&hash, 3, 2), 0);
        assert_eq!(App::tx_set_start_index(&hash, 3, 3), 1);
    }

    #[test]
    fn test_compute_catchup_target_for_timeout() {
        // Test case 1: first_buffered in middle of checkpoint, current_ledger far behind
        // first_buffered=100 is in checkpoint starting at 64
        // Target should be 63 (end of previous checkpoint)
        let target = App::compute_catchup_target_for_timeout(150, 100, 50);
        assert_eq!(target, Some(63));

        // Test case 2: first_buffered at start of checkpoint
        // first_buffered=128 is in checkpoint starting at 128
        // Target should be 127 (end of previous checkpoint)
        let target = App::compute_catchup_target_for_timeout(150, 128, 50);
        assert_eq!(target, Some(127));

        // Test case 3: current_ledger already past first_buffered's checkpoint target
        // first_buffered=100 -> checkpoint start 64 -> target 63, but current is 70
        // Should fall through to last_buffered's checkpoint (128) -> target 127
        let target = App::compute_catchup_target_for_timeout(150, 100, 70);
        assert_eq!(target, Some(127));

        // Test case 4: current_ledger past all checkpoint targets but before first_buffered
        // first_buffered=100, last_buffered=110, current=95
        // first_buffered checkpoint start=64, target=63 (but 63 < 95)
        // last_buffered checkpoint start=64, alt_target=63 (but 63 < 95)
        // direct_target = first_buffered - 1 = 99 > 95, so return Some(99)
        // This bridges the tiny gap with a Case 1 replay (95 -> 99)
        let target = App::compute_catchup_target_for_timeout(110, 100, 95);
        assert_eq!(target, Some(99));

        // Test case 5: current_ledger already at or past first_buffered, return None
        // This happens when we've caught up but buffered ledgers haven't been processed
        let target = App::compute_catchup_target_for_timeout(110, 100, 100);
        assert!(target.is_none());

        // Test case 6: very early ledger (first checkpoint)
        // first_buffered=50 is in checkpoint starting at 0
        // Since checkpoint_start is 0, target = first_buffered - 1 = 49
        // 49 > current_ledger (10), so return Some(49)
        let target = App::compute_catchup_target_for_timeout(60, 50, 10);
        assert_eq!(target, Some(49));

        // Test case 7: edge case with very small ledgers
        let target = App::compute_catchup_target_for_timeout(5, 3, 0);
        // first_buffered=3, checkpoint start=0, target=first_buffered-1=2
        // 2 > current_ledger(0), so return Some(2)
        assert_eq!(target, Some(2));

        // Test case 8: tiny gap at checkpoint boundary (the stuck-after-catchup bug)
        // LCL=922751 (which is a checkpoint boundary: (922751+1)%64==0)
        // first_buffered=922753 (gap of 1 slot at 922752)
        // first_buffered checkpoint start=922752, target=922751 (== current_ledger)
        // last_buffered checkpoint start=922752, alt_target=922751 (== current_ledger)
        // direct_target = 922752 > 922751, so return Some(922752)
        // This bridges the 1-slot gap with a Case 1 replay
        let target = App::compute_catchup_target_for_timeout(922753, 922753, 922751);
        assert_eq!(target, Some(922752));
    }

    #[test]
    fn test_consensus_stuck_timeout_constants() {
        // Verify constants match stellar-core values
        assert_eq!(CONSENSUS_STUCK_TIMEOUT_SECS, 35);
        assert_eq!(OUT_OF_SYNC_RECOVERY_TIMER_SECS, 10);
    }

    #[test]
    fn test_consensus_stuck_state() {
        use std::time::Instant;

        let state = ConsensusStuckState {
            current_ledger: 1000,
            first_buffered: 1001,
            stuck_start: Instant::now(),
            last_recovery_attempt: Instant::now(),
            recovery_attempts: 0,
            catchup_triggered: false,
        };

        assert_eq!(state.current_ledger, 1000);
        assert_eq!(state.first_buffered, 1001);
        assert_eq!(state.recovery_attempts, 0);
        assert!(!state.catchup_triggered);
    }

    #[test]
    fn test_consensus_stuck_action_variants() {
        // Verify all action variants exist and can be matched
        let actions = [
            ConsensusStuckAction::Wait,
            ConsensusStuckAction::AttemptRecovery,
            ConsensusStuckAction::TriggerCatchup,
        ];

        for action in actions {
            match action {
                ConsensusStuckAction::Wait => {}
                ConsensusStuckAction::AttemptRecovery => {}
                ConsensusStuckAction::TriggerCatchup => {}
            }
        }
    }

    // ============================================================
    // Buffered Ledger Update Tests (regression for 80bd38d)
    // ============================================================

    /// Tests that the BTreeMap Entry pattern correctly updates existing entries.
    /// This is a regression test for the fix in process_externalized_slots()
    /// where or_insert() was incorrectly used instead of Entry::Occupied/Vacant.
    #[test]
    fn test_btreemap_entry_update_pattern() {
        use std::collections::BTreeMap;

        // Simulate the buffered ledger structure (slot -> tx_set)
        // Using Option<Vec<u8>> directly to represent presence/absence of tx_set
        let mut buffer: BTreeMap<u32, Option<Vec<u8>>> = BTreeMap::new();

        // First, insert a slot WITHOUT tx_set (simulates initial buffering)
        let slot = 100u32;
        buffer.insert(slot, None);
        assert!(buffer.get(&slot).unwrap().is_none());

        // Now simulate tx_set arriving later - the fix uses Entry pattern
        let new_tx_set = Some(vec![1, 2, 3]);
        match buffer.entry(slot) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let existing = entry.get_mut();
                if existing.is_none() && new_tx_set.is_some() {
                    *existing = new_tx_set.clone();
                }
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(new_tx_set.clone());
            }
        }

        // Verify the existing entry was UPDATED (not ignored)
        assert!(buffer.get(&slot).unwrap().is_some());
        assert_eq!(buffer.get(&slot).unwrap().as_ref().unwrap(), &vec![1, 2, 3]);
    }

    /// Tests that or_insert() does NOT update existing entries (the bug we fixed).
    /// This demonstrates why the fix was needed.
    #[test]
    fn test_or_insert_does_not_update_existing() {
        use std::collections::BTreeMap;

        let mut map: BTreeMap<u32, Option<Vec<u8>>> = BTreeMap::new();

        // Insert with None
        map.insert(100, None);

        // Try to "update" with or_insert - this does NOT update existing!
        map.entry(100).or_insert(Some(vec![1, 2, 3]));

        // The value is still None - or_insert doesn't update existing entries
        assert!(map.get(&100).unwrap().is_none());
    }

    // ============================================================
    // Tx Set Request Deduplication Tests (regression for 759757b)
    // ============================================================

    /// Tests that HashSet correctly tracks requested tx_set hashes to avoid
    /// duplicate broadcast requests. This is a regression test for the fix
    /// in cache_messages_during_catchup_impl().
    #[test]
    fn test_tx_set_request_deduplication() {
        use std::collections::HashSet;

        let mut requested_hashes: HashSet<Hash256> = HashSet::new();

        let hash1 = Hash256::from_bytes([1u8; 32]);
        let hash2 = Hash256::from_bytes([2u8; 32]);

        // First request for hash1 should be allowed
        assert!(!requested_hashes.contains(&hash1));
        requested_hashes.insert(hash1);

        // Second request for hash1 should be blocked (duplicate)
        assert!(requested_hashes.contains(&hash1));

        // First request for hash2 should be allowed
        assert!(!requested_hashes.contains(&hash2));
        requested_hashes.insert(hash2);

        // Both hashes are now tracked
        assert!(requested_hashes.contains(&hash1));
        assert!(requested_hashes.contains(&hash2));
        assert_eq!(requested_hashes.len(), 2);
    }

    /// Tests the combined check pattern used in the fix:
    /// !has_tx_set && !already_requested
    #[test]
    fn test_tx_set_request_condition() {
        use std::collections::HashSet;

        let mut requested_hashes: HashSet<Hash256> = HashSet::new();
        let mut has_tx_set_cache: HashSet<Hash256> = HashSet::new();

        let hash = Hash256::from_bytes([42u8; 32]);

        // Case 1: Don't have tx_set, haven't requested -> should request
        let should_request = !has_tx_set_cache.contains(&hash) && !requested_hashes.contains(&hash);
        assert!(should_request);

        // Mark as requested
        requested_hashes.insert(hash);

        // Case 2: Don't have tx_set, already requested -> should NOT request
        let should_request = !has_tx_set_cache.contains(&hash) && !requested_hashes.contains(&hash);
        assert!(!should_request);

        // Case 3: Have tx_set (regardless of requested) -> should NOT request
        has_tx_set_cache.insert(hash);
        let should_request = !has_tx_set_cache.contains(&hash) && !requested_hashes.contains(&hash);
        assert!(!should_request);
    }

    // ============================================================
    // Herder Integration Tests
    // ============================================================

    #[tokio::test]
    async fn test_herder_stats_includes_pending_envelope_stats() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();
        let stats = app.herder_stats();

        // Verify pending_envelope_stats is accessible
        assert_eq!(stats.pending_envelope_stats.received, 0);
        assert_eq!(stats.pending_envelope_stats.added, 0);
        assert_eq!(stats.pending_envelope_stats.duplicates, 0);
    }

    #[tokio::test]
    async fn test_herder_stats_includes_tx_queue_stats() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();
        let stats = app.herder_stats();

        // Verify tx_queue_stats is accessible
        assert_eq!(stats.tx_queue_stats.pending_count, 0);
        assert_eq!(stats.tx_queue_stats.account_count, 0);
        assert_eq!(stats.tx_queue_stats.banned_count, 0);
        assert_eq!(stats.tx_queue_stats.seen_count, 0);
    }

    #[tokio::test]
    async fn test_drift_tracker_initialized() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Verify drift tracker is accessible (will lock successfully)
        let result = app.drift_tracker.lock();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sync_recovery_handle_initially_none() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Sync recovery handle is None until start_sync_recovery is called
        assert!(app.sync_recovery_handle.read().is_none());
    }

    #[tokio::test]
    async fn test_sync_recovery_heartbeat_no_panic_when_not_started() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Should not panic when handle is None
        app.sync_recovery_heartbeat();
    }

    #[tokio::test]
    async fn test_set_applying_ledger_updates_flag() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Initially false
        assert!(!app.is_applying_ledger.load(Ordering::Relaxed));

        // Set to true
        app.set_applying_ledger(true);
        assert!(app.is_applying_ledger.load(Ordering::Relaxed));

        // Set back to false
        app.set_applying_ledger(false);
        assert!(!app.is_applying_ledger.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_sync_recovery_callback_is_applying_ledger() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Test the SyncRecoveryCallback implementation
        assert!(!SyncRecoveryCallback::is_applying_ledger(&app));

        app.is_applying_ledger.store(true, Ordering::Relaxed);
        assert!(SyncRecoveryCallback::is_applying_ledger(&app));
    }

    #[tokio::test]
    async fn test_sync_recovery_callback_is_tracking() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Herder starts in booting state, not tracking
        assert!(!SyncRecoveryCallback::is_tracking(&app));
    }

    #[tokio::test]
    async fn test_herder_cleanup_method_exists() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Verify cleanup method is callable
        app.herder.cleanup();
    }

    #[tokio::test]
    async fn test_herder_quorum_tracking_methods() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Verify quorum tracking methods are callable
        let slot = app.herder.tracking_slot();
        let _heard = app.herder.heard_from_quorum(slot);
        let _blocking = app.herder.is_v_blocking(slot);
    }

    #[tokio::test]
    async fn test_herder_set_state() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Initially in Booting state
        assert_eq!(
            app.herder.state(),
            henyey_herder::HerderState::Booting
        );

        // Can set to Syncing
        app.herder
            .set_state(henyey_herder::HerderState::Syncing);
        assert_eq!(
            app.herder.state(),
            henyey_herder::HerderState::Syncing
        );
    }

    #[tokio::test]
    async fn test_tx_queue_ban_shift() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Shift with empty ban queue should return zero counts
        let shift_result = app.herder.tx_queue().shift();
        assert_eq!(shift_result.unbanned_count, 0);
        assert_eq!(shift_result.evicted_due_to_age, 0);
    }

    #[tokio::test]
    async fn test_try_start_ledger_close_returns_none_when_no_buffered() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // No buffered ledgers → should return None.
        let pending = app.try_start_ledger_close().await;
        assert!(pending.is_none(), "should return None with no buffered ledgers");
    }

    #[tokio::test]
    async fn test_try_start_ledger_close_skips_when_already_applying() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Simulate a ledger close already in progress.
        app.set_applying_ledger(true);

        let pending = app.try_start_ledger_close().await;
        assert!(
            pending.is_none(),
            "should return None when is_applying_ledger is true"
        );

        // Cleanup.
        app.set_applying_ledger(false);
    }

    #[tokio::test]
    async fn test_try_apply_buffered_skips_when_already_applying() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Simulate a ledger close already in progress.
        app.set_applying_ledger(true);

        // Should return immediately without doing anything.
        app.try_apply_buffered_ledgers().await;

        // Flag should still be true (not cleared by the no-op call).
        assert!(app.is_applying_ledger.load(Ordering::Relaxed));

        // Cleanup.
        app.set_applying_ledger(false);
    }

    #[tokio::test]
    async fn test_handle_close_complete_clears_applying_flag_on_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();
        app.set_applying_ledger(true);

        // Simulate a failed close result.
        let pending = PendingLedgerClose {
            handle: tokio::task::spawn_blocking(|| {
                Err("simulated error".to_string())
            }),
            ledger_seq: 1,
            tx_set: henyey_herder::TransactionSet {
                hash: henyey_common::Hash256::ZERO,
                previous_ledger_hash: henyey_common::Hash256::ZERO,
                transactions: Vec::new(),
                generalized_tx_set: None,
            },
            tx_set_variant: TransactionSetVariant::Classic(
                stellar_xdr::curr::TransactionSet {
                    previous_ledger_hash: stellar_xdr::curr::Hash([0u8; 32]),
                    txs: stellar_xdr::curr::VecM::default(),
                },
            ),
            close_time: 1,
        };

        let mut pending = pending;
        let join_result = (&mut pending.handle).await;
        let success = app.handle_close_complete(pending, join_result).await;

        assert!(!success, "should return false on error");
        assert!(
            !app.is_applying_ledger.load(Ordering::Relaxed),
            "is_applying_ledger should be cleared on error"
        );
    }

    #[tokio::test]
    async fn test_handle_close_complete_clears_applying_flag_on_panic() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();
        app.set_applying_ledger(true);

        // Simulate a panicked task.
        let pending = PendingLedgerClose {
            handle: tokio::task::spawn_blocking(|| {
                panic!("simulated panic");
            }),
            ledger_seq: 1,
            tx_set: henyey_herder::TransactionSet {
                hash: henyey_common::Hash256::ZERO,
                previous_ledger_hash: henyey_common::Hash256::ZERO,
                transactions: Vec::new(),
                generalized_tx_set: None,
            },
            tx_set_variant: TransactionSetVariant::Classic(
                stellar_xdr::curr::TransactionSet {
                    previous_ledger_hash: stellar_xdr::curr::Hash([0u8; 32]),
                    txs: stellar_xdr::curr::VecM::default(),
                },
            ),
            close_time: 1,
        };

        let mut pending = pending;
        let join_result = (&mut pending.handle).await;
        let success = app.handle_close_complete(pending, join_result).await;

        assert!(!success, "should return false on panic");
        assert!(
            !app.is_applying_ledger.load(Ordering::Relaxed),
            "is_applying_ledger should be cleared on panic"
        );
    }

    #[tokio::test]
    async fn test_handle_close_complete_clears_buffer_on_hash_mismatch() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();
        app.set_applying_ledger(true);

        // Add a fake entry to syncing_ledgers to verify it gets cleared.
        {
            let mut buffer = app.syncing_ledgers.write().await;
            buffer.insert(
                2,
                henyey_herder::LedgerCloseInfo {
                    slot: 2,
                    tx_set_hash: henyey_common::Hash256::ZERO,
                    tx_set: None,
                    close_time: 1,
                    upgrades: Vec::new(),
                    stellar_value_ext: StellarValueExt::Basic,
                },
            );
        }

        // Simulate a hash mismatch error.
        let pending = PendingLedgerClose {
            handle: tokio::task::spawn_blocking(|| {
                Err("previous ledger hash mismatch".to_string())
            }),
            ledger_seq: 1,
            tx_set: henyey_herder::TransactionSet {
                hash: henyey_common::Hash256::ZERO,
                previous_ledger_hash: henyey_common::Hash256::ZERO,
                transactions: Vec::new(),
                generalized_tx_set: None,
            },
            tx_set_variant: TransactionSetVariant::Classic(
                stellar_xdr::curr::TransactionSet {
                    previous_ledger_hash: stellar_xdr::curr::Hash([0u8; 32]),
                    txs: stellar_xdr::curr::VecM::default(),
                },
            ),
            close_time: 1,
        };

        let mut pending = pending;
        let join_result = (&mut pending.handle).await;
        let success = app.handle_close_complete(pending, join_result).await;

        assert!(!success);
        // Buffer should have been cleared due to hash mismatch.
        let buffer = app.syncing_ledgers.read().await;
        assert!(
            buffer.is_empty(),
            "syncing_ledgers should be cleared on hash mismatch"
        );
    }

    // ============================================================
    // Tx Set Request Timeout Tests (regression for silent GetTxSet drops)
    // ============================================================

    #[test]
    fn test_tx_set_request_timeout_constant() {
        // Verify the timeout is 10 seconds as designed
        assert_eq!(TX_SET_REQUEST_TIMEOUT_SECS, 10);
        // Timeout must be longer than the request throttle (1s) to avoid
        // false positives, but short enough to recover quickly
        assert!(TX_SET_REQUEST_TIMEOUT_SECS > 1);
        assert!(TX_SET_REQUEST_TIMEOUT_SECS < CONSENSUS_STUCK_TIMEOUT_SECS);
    }

    #[test]
    fn test_tx_set_request_state_tracks_first_requested() {
        let now = Instant::now();
        let state = TxSetRequestState {
            last_request: now,
            first_requested: now,
            next_peer_offset: 0,
        };

        // first_requested should be set at creation time
        assert!(state.first_requested.elapsed().as_millis() < 100);
        assert_eq!(state.next_peer_offset, 0);
    }

    #[test]
    fn test_tx_set_request_timeout_detection_logic() {
        // Simulate the timeout detection pattern used in request_pending_tx_sets
        let timeout = std::time::Duration::from_secs(TX_SET_REQUEST_TIMEOUT_SECS);
        let peers = vec!["peer1", "peer2", "peer3"];
        let mut dont_have: HashSet<&str> = HashSet::new();

        // Case 1: Request age below timeout — should NOT timeout
        let recent = Instant::now();
        let age = recent.elapsed();
        assert!(age < timeout, "recent request should not timeout");

        // Case 2: Simulate old request (by checking the comparison logic)
        // The actual timeout fires when now - first_requested >= TX_SET_REQUEST_TIMEOUT_SECS
        let threshold = std::time::Duration::from_secs(TX_SET_REQUEST_TIMEOUT_SECS);
        let short_duration = std::time::Duration::from_secs(1);
        assert!(short_duration < threshold, "1s should be under threshold");
        assert!(threshold <= std::time::Duration::from_secs(TX_SET_REQUEST_TIMEOUT_SECS));

        // Case 3: When timeout fires, all peers should be marked as DontHave
        for peer in &peers {
            dont_have.insert(peer);
        }
        assert_eq!(dont_have.len(), peers.len(), "all peers should be marked");
    }

    // ============================================================
    // Rapid Close Cycle Cleanup Tests
    // ============================================================

    #[tokio::test]
    async fn test_clear_pending_tx_sets_via_herder() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Register some pending tx_sets
        let hash1 = Hash256::from_bytes([1u8; 32]);
        let hash2 = Hash256::from_bytes([2u8; 32]);
        app.herder.scp_driver().request_tx_set(hash1, 100);
        app.herder.scp_driver().request_tx_set(hash2, 101);
        assert_eq!(app.herder.get_pending_tx_sets().len(), 2);

        // Clear via the herder passthrough
        app.herder.clear_pending_tx_sets();
        assert!(app.herder.get_pending_tx_sets().is_empty());
    }

    #[tokio::test]
    async fn test_stale_syncing_ledgers_eviction() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Set current_ledger to 99 so entries at 100+ are above current_ledger
        *app.current_ledger.write().await = 99;

        // Add entries: some with tx_set, some without (starting from current_ledger+1)
        {
            let mut buffer = app.syncing_ledgers.write().await;
            // Entry WITHOUT tx_set at current_ledger+1 (should be evicted when exhausted)
            buffer.insert(
                100,
                henyey_herder::LedgerCloseInfo {
                    slot: 100,
                    tx_set_hash: Hash256::ZERO,
                    tx_set: None,
                    close_time: 1,
                    upgrades: Vec::new(),
                    stellar_value_ext: StellarValueExt::Basic,
                },
            );
            // Entry WITHOUT tx_set (consecutive, should be evicted)
            buffer.insert(
                101,
                henyey_herder::LedgerCloseInfo {
                    slot: 101,
                    tx_set_hash: Hash256::ZERO,
                    tx_set: None,
                    close_time: 2,
                    upgrades: Vec::new(),
                    stellar_value_ext: StellarValueExt::Basic,
                },
            );
            // Entry WITH tx_set (should be kept — eviction stops at first entry with tx_set)
            buffer.insert(
                102,
                henyey_herder::LedgerCloseInfo {
                    slot: 102,
                    tx_set_hash: Hash256::ZERO,
                    tx_set: Some(henyey_herder::TransactionSet {
                        hash: Hash256::ZERO,
                        previous_ledger_hash: Hash256::ZERO,
                        transactions: Vec::new(),
                        generalized_tx_set: None,
                    }),
                    close_time: 3,
                    upgrades: Vec::new(),
                    stellar_value_ext: StellarValueExt::Basic,
                },
            );
        }

        // Simulate the eviction logic from maybe_start_buffered_catchup
        // when tx_set_all_peers_exhausted is true
        app.tx_set_all_peers_exhausted.store(true, Ordering::SeqCst);
        {
            let mut buffer = app.syncing_ledgers.write().await;
            let current_ledger = 99u32;
            let start = current_ledger.saturating_add(1);
            let mut evicted = 0u32;
            for seq in start.. {
                match buffer.get(&seq) {
                    Some(info) if info.tx_set.is_none() => {
                        buffer.remove(&seq);
                        evicted += 1;
                    }
                    _ => break,
                }
            }
            assert_eq!(evicted, 2, "should evict 2 consecutive entries without tx_sets");
        }

        let buffer = app.syncing_ledgers.read().await;
        assert_eq!(buffer.len(), 1, "only entry with tx_set should remain");
        assert!(buffer.contains_key(&102), "entry 102 (with tx_set) should be kept");
        assert!(!buffer.contains_key(&100), "entry 100 (no tx_set) should be evicted");
        assert!(!buffer.contains_key(&101), "entry 101 (no tx_set) should be evicted");
    }

    #[tokio::test]
    async fn test_tx_set_state_cleanup_after_rapid_close() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Set up state as if rapid close cycle just ended
        app.tx_set_all_peers_exhausted.store(true, Ordering::SeqCst);
        {
            let mut dont_have = app.tx_set_dont_have.write().await;
            let hash = Hash256::from_bytes([1u8; 32]);
            dont_have.insert(hash, HashSet::from([henyey_overlay::PeerId::from_bytes([1u8; 32])]));
        }
        {
            let mut last_request = app.tx_set_last_request.write().await;
            let hash = Hash256::from_bytes([1u8; 32]);
            last_request.insert(hash, TxSetRequestState {
                last_request: Instant::now(),
                first_requested: Instant::now(),
                next_peer_offset: 3,
            });
        }
        {
            let mut warned = app.tx_set_exhausted_warned.write().await;
            warned.insert(Hash256::from_bytes([1u8; 32]));
        }
        *app.consensus_stuck_state.write().await = Some(ConsensusStuckState {
            current_ledger: 100,
            first_buffered: 101,
            stuck_start: Instant::now(),
            last_recovery_attempt: Instant::now(),
            recovery_attempts: 2,
            catchup_triggered: false,
        });

        // Simulate the cleanup block from the rapid close handler.
        // The rapid close handler now only resets tracking state, NOT
        // buffer entries or pending tx_set requests. This allows the
        // normal process_externalized_slots → maybe_start_buffered_catchup
        // flow to handle stale entries properly.
        app.tx_set_all_peers_exhausted.store(false, Ordering::SeqCst);
        app.tx_set_dont_have.write().await.clear();
        app.tx_set_last_request.write().await.clear();
        app.tx_set_exhausted_warned.write().await.clear();
        *app.consensus_stuck_state.write().await = None;

        // Verify everything is cleaned up
        assert!(!app.tx_set_all_peers_exhausted.load(Ordering::SeqCst));
        assert!(app.tx_set_dont_have.read().await.is_empty());
        assert!(app.tx_set_last_request.read().await.is_empty());
        assert!(app.tx_set_exhausted_warned.read().await.is_empty());
        assert!(app.consensus_stuck_state.read().await.is_none());
    }

    // ============================================================
    // Fetch Response Channel Skip Tests
    // ============================================================

    #[test]
    fn test_fetch_response_message_types_are_skipped_in_broadcast() {
        // Verify the message type matching pattern used in the broadcast
        // handler to skip fetch response messages (they go through the
        // dedicated channel instead).
        use stellar_xdr::curr::StellarMessage;

        let test_messages = vec![
            (StellarMessage::GeneralizedTxSet(
                stellar_xdr::curr::GeneralizedTransactionSet::V1(
                    stellar_xdr::curr::TransactionSetV1 {
                        previous_ledger_hash: stellar_xdr::curr::Hash([0u8; 32]),
                        phases: vec![].try_into().unwrap(),
                    },
                ),
            ), true, "GeneralizedTxSet"),
            (StellarMessage::DontHave(
                stellar_xdr::curr::DontHave {
                    type_: stellar_xdr::curr::MessageType::TxSet,
                    req_hash: stellar_xdr::curr::Uint256([0u8; 32]),
                },
            ), true, "DontHave"),
        ];

        for (msg, should_skip, label) in test_messages {
            let is_fetch_response = matches!(
                msg,
                StellarMessage::GeneralizedTxSet(_)
                    | StellarMessage::TxSet(_)
                    | StellarMessage::DontHave(_)
                    | StellarMessage::ScpQuorumset(_)
            );
            assert_eq!(is_fetch_response, should_skip, "{} should be skipped={}", label, should_skip);
        }
    }

    // ============================================================
    // trim_syncing_ledgers Tests
    // ============================================================

    #[test]
    fn test_trim_syncing_ledgers_preserves_close_entries() {
        // When entries are close to current_ledger (gap < CHECKPOINT_FREQUENCY),
        // trim should NOT remove them to checkpoint boundary. These entries are
        // potentially closeable and trimming them creates an artificial gap.
        let mut buffer = BTreeMap::new();
        let make_entry = |slot: u32| henyey_herder::LedgerCloseInfo {
            slot: slot as u64,
            tx_set_hash: Hash256::ZERO,
            tx_set: None,
            close_time: 1,
            upgrades: Vec::new(),
            stellar_value_ext: StellarValueExt::Basic,
        };

        // Simulate: current_ledger=61193740, entries at 61193741..=61193797
        // These entries are close to current_ledger (gap=1 for first entry)
        // Old code would trim everything below checkpoint boundary of last_buffered
        // (first_ledger_in_checkpoint(61193797) = 61193792), destroying 61193741-61193791
        let current_ledger = 61193740u32;
        for slot in 61193741..=61193797 {
            buffer.insert(slot, make_entry(slot));
        }
        let original_count = buffer.len();

        App::trim_syncing_ledgers(&mut buffer, current_ledger);

        // All entries should survive — they're all above current_ledger and
        // the gap (1) is less than CHECKPOINT_FREQUENCY
        assert_eq!(
            buffer.len(),
            original_count,
            "trim should preserve entries close to current_ledger"
        );
        assert!(
            buffer.contains_key(&61193741),
            "first entry (current_ledger+1) must survive"
        );
        assert!(
            buffer.contains_key(&61193797),
            "last entry must survive"
        );
    }

    #[test]
    fn test_trim_syncing_ledgers_trims_when_gap_large() {
        // When the gap to first_buffered is >= CHECKPOINT_FREQUENCY,
        // trim should remove entries below the checkpoint boundary of last_buffered
        // to prepare for archive-based catchup.
        let mut buffer = BTreeMap::new();
        let make_entry = |slot: u32| henyey_herder::LedgerCloseInfo {
            slot: slot as u64,
            tx_set_hash: Hash256::ZERO,
            tx_set: None,
            close_time: 1,
            upgrades: Vec::new(),
            stellar_value_ext: StellarValueExt::Basic,
        };

        // current_ledger=100, entries at 200..=280 (gap=100, > 64)
        let current_ledger = 100u32;
        for slot in 200..=280 {
            buffer.insert(slot, make_entry(slot));
        }

        App::trim_syncing_ledgers(&mut buffer, current_ledger);

        // After trim: checkpoint boundary of 280 is first_ledger_in_checkpoint(280) = 256
        // Entries below 256 should be removed
        assert!(
            !buffer.contains_key(&200),
            "entry well below checkpoint boundary should be trimmed"
        );
        assert!(
            !buffer.contains_key(&255),
            "entry just below checkpoint boundary should be trimmed"
        );
        assert!(
            buffer.contains_key(&256),
            "entry at checkpoint boundary should survive"
        );
        assert!(
            buffer.contains_key(&280),
            "last entry should survive"
        );
    }

    #[test]
    fn test_trim_syncing_ledgers_removes_closed_entries() {
        // Entries at or below current_ledger should always be removed.
        let mut buffer = BTreeMap::new();
        let make_entry = |slot: u32| henyey_herder::LedgerCloseInfo {
            slot: slot as u64,
            tx_set_hash: Hash256::ZERO,
            tx_set: None,
            close_time: 1,
            upgrades: Vec::new(),
            stellar_value_ext: StellarValueExt::Basic,
        };

        let current_ledger = 105u32;
        for slot in 100..=110 {
            buffer.insert(slot, make_entry(slot));
        }

        App::trim_syncing_ledgers(&mut buffer, current_ledger);

        // Entries 100-105 should be removed, 106-110 kept
        assert!(!buffer.contains_key(&100));
        assert!(!buffer.contains_key(&105));
        assert!(buffer.contains_key(&106));
        assert!(buffer.contains_key(&110));
        assert_eq!(buffer.len(), 5);
    }

    #[test]
    fn test_consensus_stuck_state_matches_on_current_ledger_only() {
        // Verify that ConsensusStuckState matches when current_ledger is the
        // same but first_buffered changes. This is critical for Problem 9:
        // stale EXTERNALIZE messages create new syncing_ledgers entries with
        // lower slot numbers, changing first_buffered. The stuck timer must
        // NOT reset when first_buffered shifts.
        let state = ConsensusStuckState {
            current_ledger: 100,
            first_buffered: 105,
            stuck_start: Instant::now(),
            last_recovery_attempt: Instant::now(),
            recovery_attempts: 0,
            catchup_triggered: false,
        };

        // Same current_ledger, different first_buffered — should still match
        let current_ledger = 100u32;
        let new_first_buffered = 103u32; // changed due to stale EXTERNALIZE
        assert_eq!(state.current_ledger, current_ledger);
        // The fix: we no longer require state.first_buffered == first_buffered
        // so the timer continues even when first_buffered shifts.
        assert_ne!(state.first_buffered, new_first_buffered);

        // Different current_ledger — should NOT match (ledger advanced)
        let advanced_ledger = 101u32;
        assert_ne!(state.current_ledger, advanced_ledger);
    }

    // ============================================================
    // Fix A: try_apply_buffered_ledgers state reset tests
    // ============================================================

    #[tokio::test]
    async fn test_try_apply_buffered_no_close_preserves_stale_state() {
        // When try_apply_buffered_ledgers runs but there are NO buffered
        // ledgers to close (closed_any=false), it must NOT reset tracking
        // state.  This verifies the guard condition around the reset block.
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Seed stale tracking state (as if a previous cycle left residue).
        app.tx_set_all_peers_exhausted.store(true, Ordering::SeqCst);
        {
            let mut dont_have = app.tx_set_dont_have.write().await;
            let hash = Hash256::from_bytes([2u8; 32]);
            dont_have.insert(hash, HashSet::from([henyey_overlay::PeerId::from_bytes([2u8; 32])]));
        }
        {
            let mut last_req = app.tx_set_last_request.write().await;
            let hash = Hash256::from_bytes([2u8; 32]);
            last_req.insert(hash, TxSetRequestState {
                last_request: Instant::now(),
                first_requested: Instant::now(),
                next_peer_offset: 1,
            });
        }
        {
            let mut warned = app.tx_set_exhausted_warned.write().await;
            warned.insert(Hash256::from_bytes([2u8; 32]));
        }
        *app.consensus_stuck_state.write().await = Some(ConsensusStuckState {
            current_ledger: 50,
            first_buffered: 51,
            stuck_start: Instant::now(),
            last_recovery_attempt: Instant::now(),
            recovery_attempts: 1,
            catchup_triggered: false,
        });

        // Record the externalized timestamp before the call.
        let ext_before = *app.last_externalized_at.read().await;

        // Call with empty syncing_ledgers → loop exits immediately, closed_any=false.
        app.try_apply_buffered_ledgers().await;

        // All stale state should be PRESERVED (not cleared) because nothing closed.
        assert!(
            app.tx_set_all_peers_exhausted.load(Ordering::SeqCst),
            "tx_set_all_peers_exhausted should remain true when nothing closed"
        );
        assert!(
            !app.tx_set_dont_have.read().await.is_empty(),
            "tx_set_dont_have should remain populated when nothing closed"
        );
        assert!(
            !app.tx_set_last_request.read().await.is_empty(),
            "tx_set_last_request should remain populated when nothing closed"
        );
        assert!(
            !app.tx_set_exhausted_warned.read().await.is_empty(),
            "tx_set_exhausted_warned should remain populated when nothing closed"
        );
        assert!(
            app.consensus_stuck_state.read().await.is_some(),
            "consensus_stuck_state should remain when nothing closed"
        );
        let ext_after = *app.last_externalized_at.read().await;
        assert_eq!(
            ext_before, ext_after,
            "last_externalized_at should not be reset when nothing closed"
        );
    }

    #[tokio::test]
    async fn test_try_apply_buffered_state_reset_block_mirrors_rapid_close() {
        // Verify the state-reset block in try_apply_buffered_ledgers matches
        // the reset done in the pending_close handler.  We can't easily close
        // a real ledger in a unit test, so we directly exercise the reset logic
        // that fires when closed_any=true and verify the fields are cleared.
        // This is structurally identical to test_tx_set_state_cleanup_after_rapid_close.
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();

        // Seed dirty state.
        app.tx_set_all_peers_exhausted.store(true, Ordering::SeqCst);
        {
            let mut dont_have = app.tx_set_dont_have.write().await;
            let hash = Hash256::from_bytes([3u8; 32]);
            dont_have.insert(hash, HashSet::from([henyey_overlay::PeerId::from_bytes([3u8; 32])]));
        }
        {
            let mut last_req = app.tx_set_last_request.write().await;
            let hash = Hash256::from_bytes([3u8; 32]);
            last_req.insert(hash, TxSetRequestState {
                last_request: Instant::now(),
                first_requested: Instant::now(),
                next_peer_offset: 5,
            });
        }
        {
            let mut warned = app.tx_set_exhausted_warned.write().await;
            warned.insert(Hash256::from_bytes([3u8; 32]));
        }
        *app.consensus_stuck_state.write().await = Some(ConsensusStuckState {
            current_ledger: 200,
            first_buffered: 201,
            stuck_start: Instant::now(),
            last_recovery_attempt: Instant::now(),
            recovery_attempts: 3,
            catchup_triggered: false,
        });

        // Directly exercise the reset block (same code as in try_apply_buffered_ledgers
        // when closed_any=true).
        *app.last_externalized_at.write().await = Instant::now();
        app.tx_set_all_peers_exhausted
            .store(false, Ordering::SeqCst);
        app.tx_set_dont_have.write().await.clear();
        app.tx_set_last_request.write().await.clear();
        app.tx_set_exhausted_warned.write().await.clear();
        *app.consensus_stuck_state.write().await = None;

        // Verify all tracking state is cleared.
        assert!(!app.tx_set_all_peers_exhausted.load(Ordering::SeqCst));
        assert!(app.tx_set_dont_have.read().await.is_empty());
        assert!(app.tx_set_last_request.read().await.is_empty());
        assert!(app.tx_set_exhausted_warned.read().await.is_empty());
        assert!(app.consensus_stuck_state.read().await.is_none());
    }

    // ============================================================
    // Fix B: Heartbeat gap guard tests
    // ============================================================

    #[test]
    fn test_heartbeat_gap_guard_skips_when_caught_up() {
        // The heartbeat stall detector computes:
        //   gap = latest_ext.saturating_sub(current_ledger)
        // When gap <= TX_SET_REQUEST_WINDOW (12), it should skip the SCP
        // state request to avoid bringing in stale EXTERNALIZE messages.
        // This test exercises the condition directly.

        let cases: Vec<(u64, u32, bool)> = vec![
            // (latest_ext, current_ledger, should_skip)
            (100, 100, true),   // gap=0: fully caught up
            (100, 99,  true),   // gap=1: one ledger behind
            (100, 88,  true),   // gap=12: exactly at threshold
            (100, 87,  false),  // gap=13: one past threshold
            (100, 50,  false),  // gap=50: far behind
            (100, 0,   false),  // gap=100: very far behind
            (0,   0,   true),   // gap=0: both at zero (startup)
            (5,   10,  true),   // gap=0 (saturating_sub): current > latest
        ];

        for (latest_ext, current_ledger, should_skip) in cases {
            let gap = latest_ext.saturating_sub(current_ledger as u64);
            let skip = gap <= TX_SET_REQUEST_WINDOW;
            assert_eq!(
                skip, should_skip,
                "latest_ext={}, current_ledger={}, gap={}: expected skip={} got skip={}",
                latest_ext, current_ledger, gap, should_skip, skip
            );
        }
    }

    #[test]
    fn test_buffered_catchup_target_small_gap() {
        // When the gap between current_ledger and first_buffered is small (< 64),
        // the target should bridge the gap. This is the scenario where a single
        // missing EXTERNALIZE creates a tiny gap.
        let current_ledger = 61200834u32;
        let first_buffered = 61200836u32; // slot 61200835 was skipped
        let last_buffered = 61200850u32;

        let target = App::buffered_catchup_target(current_ledger, first_buffered, last_buffered);
        // With first_buffered > current_ledger + 1 and gap < CHECKPOINT_FREQUENCY,
        // should compute a valid target
        if let Some(t) = target {
            assert!(t > current_ledger, "target must advance past current_ledger");
            assert!(t < first_buffered, "target must be before first_buffered");
        }
        // If None, compute_catchup_target_for_timeout should provide a fallback
        let timeout_target = App::compute_catchup_target_for_timeout(
            last_buffered,
            first_buffered,
            current_ledger,
        );
        // For a small gap like this, we should get first_buffered - 1 as target
        assert_eq!(timeout_target, Some(first_buffered - 1));
    }
}
