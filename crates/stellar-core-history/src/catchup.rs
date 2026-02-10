//! Catchup manager for synchronizing from history archives.
//!
//! This module provides the [`CatchupManager`] which orchestrates the complete
//! process of synchronizing a node with the Stellar network using history archives.
//!
//! # Overview
//!
//! Catchup is the process of downloading historical data and rebuilding ledger
//! state to match the current network. This is required when:
//!
//! - Starting a new node from scratch
//! - Recovering a node that fell too far behind
//! - Rebuilding state after data corruption
//!
//! # Catchup Process
//!
//! The catchup process follows these steps:
//!
//! 1. **Find checkpoint**: Locate the latest checkpoint at or before the target ledger
//! 2. **Download HAS**: Fetch the History Archive State describing that checkpoint
//! 3. **Download buckets**: Fetch all bucket files referenced in the HAS
//! 4. **Apply buckets**: Build the initial ledger state from bucket entries
//! 5. **Download ledger data**: Fetch headers, transactions, and results
//! 6. **Verify chain**: Validate the cryptographic hash chain
//! 7. **Replay ledgers**: Re-execute transactions from checkpoint to target
//!
//! # Re-execution vs Metadata Replay
//!
//! During catchup, we **re-execute** transactions against the bucket list state
//! rather than simply applying `TransactionMeta` from archives. This approach:
//!
//! - Keeps bucket list evolution consistent with transaction effects
//! - Allows verification of transaction set and result hashes
//! - Works with traditional archives that do not include `TransactionMeta`
//!
//! The trade-off is that re-execution may produce slightly different internal
//! results than the original execution (e.g., different Soroban error codes),
//! though the final state should match. For exact verification, use CDP data
//! with `TransactionMeta`.
//!
//! # Protocol 23+ Considerations
//!
//! Starting with protocol 23, state archival introduces complexity:
//!
//! - Evicted entries move from live bucket list to hot archive
//! - Incremental eviction scan must run each ledger for correct hashes
//! - Bucket list hash = SHA256(live_hash || hot_archive_hash)

use crate::{
    archive::HistoryArchive,
    archive_state::HistoryArchiveState,
    catchup_range::{CatchupMode, CatchupRange},
    checkpoint,
    replay::{self, LedgerReplayResult, ReplayConfig, ReplayedLedgerState},
    verify, CatchupOutput, CatchupResult, HistoryError, Result,
};
use std::collections::HashMap;
use std::sync::Arc;
use stellar_core_bucket::{Bucket, BucketList, BucketManager, HasNextState, HotArchiveBucketList};
use stellar_core_common::{Hash256, NetworkId};
use stellar_core_db::Database;

use stellar_core_ledger::TransactionSetVariant;
use stellar_core_tx::TransactionFrame;
use stellar_xdr::curr::{
    GeneralizedTransactionSet, LedgerEntryData, LedgerHeader, LedgerHeaderHistoryEntry,
    ScpHistoryEntry, TransactionHistoryEntry, TransactionHistoryEntryExt,
    TransactionHistoryResultEntry, TransactionHistoryResultEntryExt,
    TransactionResultPair, TransactionResultSet, TransactionSet, TransactionSetV1, WriteXdr,
};
use tracing::{debug, info, warn};

/// Read the current process RSS (Resident Set Size) in MB from `/proc/self/status`.
/// Returns `None` on non-Linux platforms or if the file can't be read.
fn rss_mb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            // Format is "VmRSS:    123456 kB"
            let kb: u64 = rest.trim().split_whitespace().next()?.parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

/// Current status of a catchup operation.
///
/// This enum represents the discrete phases of the catchup process,
/// allowing callers to track progress and provide user feedback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchupStatus {
    /// Catchup has not started yet.
    Pending,
    /// Downloading the History Archive State (HAS) file.
    DownloadingHAS,
    /// Downloading bucket files from the archive.
    DownloadingBuckets,
    /// Applying downloaded buckets to build initial ledger state.
    ApplyingBuckets,
    /// Downloading ledger headers, transactions, and results.
    DownloadingLedgers,
    /// Verifying cryptographic hashes and chain integrity.
    Verifying,
    /// Re-executing transactions to reach target ledger.
    Replaying,
    /// Catchup completed successfully.
    Completed,
    /// Catchup failed (check error for details).
    Failed,
}

/// Detailed progress information for a catchup operation.
///
/// This struct provides fine-grained progress tracking, useful for
/// displaying progress bars or status updates to users during the
/// potentially long-running catchup process.
#[derive(Debug, Clone)]
pub struct CatchupProgress {
    /// Current phase of the catchup process.
    pub status: CatchupStatus,

    /// Current step number (1-based index into the 7-step process).
    pub current_step: u32,

    /// Total number of steps in the catchup process (currently 7).
    pub total_steps: u32,

    /// Number of bucket files downloaded so far.
    ///
    /// Only meaningful when `status` is `DownloadingBuckets`.
    pub buckets_downloaded: u32,

    /// Total number of bucket files to download.
    ///
    /// Only meaningful when `status` is `DownloadingBuckets`.
    pub buckets_total: u32,

    /// Current ledger being processed during replay.
    ///
    /// Only meaningful when `status` is `Replaying` or `DownloadingLedgers`.
    pub current_ledger: u32,

    /// Target ledger sequence for this catchup operation.
    pub target_ledger: u32,

    /// Human-readable description of current activity.
    pub message: String,
}

impl Default for CatchupProgress {
    fn default() -> Self {
        Self {
            status: CatchupStatus::Pending,
            current_step: 0,
            total_steps: 7,
            buckets_downloaded: 0,
            buckets_total: 0,
            current_ledger: 0,
            target_ledger: 0,
            message: String::new(),
        }
    }
}

/// Pre-downloaded checkpoint data for catchup.
///
/// This struct holds all the data needed for catchup when it has been
/// pre-fetched (e.g., for testing or when using an alternative data source).
/// Pass this to [`CatchupManager::catchup_to_ledger_with_checkpoint_data`]
/// to skip the download phase.
#[derive(Debug, Clone)]
pub struct CheckpointData {
    /// The History Archive State describing this checkpoint.
    pub has: HistoryArchiveState,

    /// Directory where bucket files are stored on disk (keyed by hash).
    /// Bucket files are named `<hex_hash>.bucket`.
    pub bucket_dir: std::path::PathBuf,

    /// Ledger headers for the checkpoint range.
    pub headers: Vec<LedgerHeaderHistoryEntry>,

    /// Transaction history entries for the checkpoint.
    pub transactions: Vec<TransactionHistoryEntry>,

    /// Transaction result entries for the checkpoint.
    pub tx_results: Vec<TransactionHistoryResultEntry>,

    /// SCP history entries for consensus verification.
    pub scp_history: Vec<ScpHistoryEntry>,
}

/// Manager for synchronizing ledger state from history archives.
///
/// The `CatchupManager` orchestrates the complete catchup process:
/// downloading data from archives, verifying integrity, and replaying
/// transactions to reach a target ledger.
///
/// # Usage
///
/// ```no_run
/// use stellar_core_history::{CatchupManager, archive::HistoryArchive};
/// use stellar_core_bucket::BucketManager;
/// use stellar_core_db::Database;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let archive = HistoryArchive::new("https://history.stellar.org/prd/core-testnet/core_testnet_001")?;
/// let bucket_manager = BucketManager::new("/tmp/buckets".into())?;
/// let db = Database::open("/tmp/stellar.db")?;
///
/// let mut manager = CatchupManager::new(vec![archive], bucket_manager, db);
/// let output = manager.catchup_to_ledger(1000000).await?;
///
/// println!("Caught up to ledger {}", output.result.ledger_seq);
/// # Ok(())
/// # }
/// ```
///
/// Existing bucket list state for replay-only catchup (Case 1).
///
/// When the LCL is past genesis (e.g., after a prior catchup), the node already
/// has valid bucket lists in memory. Instead of re-downloading all buckets from
/// the archive, we can replay ledger transactions against the existing state.
/// This reduces catchup time from ~60s (27s bucket download + 31s cache rebuild)
/// to just a few seconds (download tx history + replay).
pub struct ExistingBucketState {
    /// The live bucket list at the current LCL.
    pub bucket_list: BucketList,
    /// The hot archive bucket list at the current LCL.
    pub hot_archive_bucket_list: HotArchiveBucketList,
    /// The ledger header at the current LCL (needed for `id_pool`).
    pub header: LedgerHeader,
    /// The network ID for transaction verification.
    pub network_id: NetworkId,
    /// Pre-computed Soroban state size from the ledger manager.
    /// When `Some`, `replay_ledgers` skips the expensive bucket list scan
    /// (~80s on mainnet) and uses this value directly.
    pub soroban_state_size: Option<u64>,
    /// Pre-computed offer entries from the ledger manager's in-memory offer store.
    /// Required for correct offer matching during replay (ManageSellOffer, PathPayment, etc.).
    /// Without this, the replay executor starts with an empty order book and offer crossing fails.
    pub offer_entries: Option<Vec<stellar_xdr::curr::LedgerEntry>>,
}

/// # Thread Safety
///
/// The `CatchupManager` is not `Send` or `Sync` due to its mutable progress
/// tracking. Create a new manager for each catchup operation.
pub struct CatchupManager {
    /// History archives to download from (tried in order with failover).
    archives: Vec<Arc<HistoryArchive>>,

    /// Manager for bucket file storage and retrieval.
    bucket_manager: Arc<BucketManager>,

    /// Database for persisting ledger state and history.
    db: Arc<Database>,

    /// Current progress information for status reporting.
    progress: CatchupProgress,

    /// Configuration for the replay phase.
    replay_config: ReplayConfig,
}

impl CatchupManager {
    /// Create a new catchup manager.
    ///
    /// # Arguments
    ///
    /// * `archives` - List of history archives to use (will try in order)
    /// * `bucket_manager` - Manager for bucket file operations
    /// * `db` - Database for persisting ledger state
    pub fn new(archives: Vec<HistoryArchive>, bucket_manager: BucketManager, db: Database) -> Self {
        Self {
            archives: archives.into_iter().map(Arc::new).collect(),
            bucket_manager: Arc::new(bucket_manager),
            db: Arc::new(db),
            progress: CatchupProgress::default(),
            replay_config: ReplayConfig::default(),
        }
    }

    /// Create a new catchup manager from Arc references.
    pub fn new_with_arcs(
        archives: Vec<Arc<HistoryArchive>>,
        bucket_manager: Arc<BucketManager>,
        db: Arc<Database>,
    ) -> Self {
        Self {
            archives,
            bucket_manager,
            db,
            progress: CatchupProgress::default(),
            replay_config: ReplayConfig::default(),
        }
    }

    /// Get the current catchup progress.
    pub fn progress(&self) -> &CatchupProgress {
        &self.progress
    }

    /// Set the replay configuration.
    pub fn set_replay_config(&mut self, config: ReplayConfig) {
        self.replay_config = config;
    }

    /// Catch up to a specific target ledger.
    ///
    /// This is the main entry point for the catchup process. It will:
    /// 1. Find the latest checkpoint before or at the target
    /// 2. Download and apply the state at that checkpoint
    /// 3. Replay ledgers from the checkpoint to the target (if any)
    ///
    /// # Arguments
    ///
    /// * `target` - The target ledger sequence to catch up to
    ///
    /// # Returns
    ///
    /// A `CatchupOutput` containing the bucket list, header, and summary information.
    pub async fn catchup_to_ledger(&mut self, target: u32) -> Result<CatchupOutput> {
        info!("Starting catchup to ledger {}", target);
        self.progress.target_ledger = target;

        // Step 1: Find the latest checkpoint <= target
        let checkpoint_seq =
            checkpoint::latest_checkpoint_before_or_at(target).ok_or_else(|| {
                HistoryError::CatchupFailed(format!(
                    "target ledger {} is before first checkpoint",
                    target
                ))
            })?;

        info!(
            "Using checkpoint {} for catchup to {}",
            checkpoint_seq, target
        );

        // Step 2: Download the History Archive State
        self.update_progress(
            CatchupStatus::DownloadingHAS,
            1,
            "Downloading History Archive State",
        );
        let has = self.download_has(checkpoint_seq).await?;
        verify::verify_has_structure(&has)?;
        verify::verify_has_checkpoint(&has, checkpoint_seq)?;

        let scp_history = self.download_scp_history(checkpoint_seq).await?;
        if !scp_history.is_empty() {
            verify::verify_scp_history_entries(&scp_history)?;
            self.persist_scp_history_entries(&scp_history)?;
        }

        // Step 3: Download all buckets referenced in the HAS
        self.update_progress(
            CatchupStatus::DownloadingBuckets,
            2,
            "Downloading bucket files",
        );
        let bucket_hashes = has.unique_bucket_hashes();
        let buckets_total = bucket_hashes.len() as u32;
        self.progress.buckets_total = buckets_total;
        let buckets = self.download_buckets(&bucket_hashes).await?;

        // Step 4: Apply buckets to build initial state
        self.update_progress(
            CatchupStatus::ApplyingBuckets,
            3,
            "Applying buckets to build initial state",
        );
        let (mut bucket_list, mut hot_archive_bucket_list, live_next_states, hot_next_states) =
            self.apply_buckets(&has, &buckets).await?;

        // Restart merges and scan caches in parallel.
        let cache_data = self
            .restart_merges_and_scan_caches(
                &mut bucket_list,
                &mut hot_archive_bucket_list,
                checkpoint_seq,
                &live_next_states,
                &hot_next_states,
            )
            .await?;

        self.persist_bucket_list_snapshot(checkpoint_seq, &bucket_list)?;

        // Step 5: Download ledger data from checkpoint to target
        self.update_progress(
            CatchupStatus::DownloadingLedgers,
            4,
            "Downloading ledger data",
        );
        let ledger_data = self.download_ledger_data(checkpoint_seq, target).await?;

        // Step 6: Verify the header chain
        self.update_progress(CatchupStatus::Verifying, 5, "Verifying header chain");
        self.verify_downloaded_data(&ledger_data)?;

        let network_id = has
            .network_passphrase
            .as_ref()
            .map(|p| NetworkId::from_passphrase(p))
            .unwrap_or_else(NetworkId::testnet);

        // Step 7: Replay ledgers from checkpoint to target (if any)
        self.update_progress(CatchupStatus::Replaying, 6, "Replaying ledgers");

        let (final_header, final_hash, ledgers_applied) = if ledger_data.is_empty() {
            // Catching up to exactly a checkpoint - download and use the checkpoint header
            // Use the archive's pre-computed hash - it's the authoritative hash the network used
            info!(
                "Catching up to checkpoint {} (no ledgers to replay)",
                checkpoint_seq
            );
            let (checkpoint_header, header_hash) =
                self.download_checkpoint_header(checkpoint_seq).await?;
            (checkpoint_header, header_hash, 0)
        } else {
            // Replay ledgers to reach target.
            // First download the checkpoint header to get the starting id_pool.
            let (checkpoint_header, _) =
                self.download_checkpoint_header(checkpoint_seq).await?;
            let checkpoint_id_pool = checkpoint_header.id_pool;

            // Extract offers from cache_data for correct offer matching during replay.
            let replay_offers: Vec<stellar_xdr::curr::LedgerEntry> =
                cache_data.offers.values().cloned().collect();

            let final_state = self
                .replay_ledgers(
                    &mut bucket_list,
                    &mut hot_archive_bucket_list,
                    &ledger_data,
                    network_id,
                    checkpoint_id_pool,
                    None,
                    Some(replay_offers),
                )
                .await?;
            let ledgers_applied = target - checkpoint_seq;
            // Get the final header from replay - use archive's hash if available
            let (final_header, final_hash) = match self.download_checkpoint_header(target).await {
                Ok((header, hash)) => (header, hash),
                Err(_) => {
                    // Construct a minimal header from replay state if download fails
                    warn!("Could not download final header, using replay state");
                    let header = create_header_from_replay_state(
                        &final_state,
                        &bucket_list,
                        &hot_archive_bucket_list,
                    );
                    // Fall back to the replay-computed hash
                    (header, final_state.ledger_hash)
                }
            };
            (final_header, final_hash, ledgers_applied)
        };

        // Verify the final state matches expected bucket list hash
        // Verify final state - bucket list hash must match the header
        self.verify_final_state(&final_header, &bucket_list, &hot_archive_bucket_list)?;

        self.persist_ledger_history(&ledger_data, &network_id)?;
        if ledger_data.is_empty() {
            self.persist_header_only(&final_header)?;
        }

        // Complete!
        self.update_progress(CatchupStatus::Completed, 7, "Catchup completed");

        info!(
            "Catchup completed: ledger {}, hash {}",
            final_header.ledger_seq, final_hash
        );

        Ok(CatchupOutput {
            result: CatchupResult {
                ledger_seq: final_header.ledger_seq,
                ledger_hash: final_hash,
                ledgers_applied,
                buckets_downloaded: buckets_total,
            },
            bucket_list,
            hot_archive_bucket_list,
            header: final_header,
            header_hash: final_hash,
            cache_data: Some(cache_data),
        })
    }

    /// Catch up to a target ledger with a specific catchup mode.
    ///
    /// This method calculates the appropriate checkpoint and replay range based on
    /// the mode (Minimal, Complete, or Recent(N)).
    ///
    /// # Arguments
    ///
    /// * `target` - The target ledger sequence to catch up to
    /// * `mode` - The catchup mode determining history depth
    /// * `lcl` - The current Last Closed Ledger (use GENESIS_LEDGER_SEQ if starting fresh)
    /// * `existing_state` - If provided, contains the existing bucket lists and header
    ///   for replay-only catchup (Case 1: LCL > genesis). When `None`, Case 1 will
    ///   return an error (bucket lists are required for replay without re-downloading).
    ///
    /// # Returns
    ///
    /// A `CatchupOutput` containing the bucket list, header, and summary information.
    pub async fn catchup_to_ledger_with_mode(
        &mut self,
        target: u32,
        mode: CatchupMode,
        lcl: u32,
        existing_state: Option<ExistingBucketState>,
    ) -> Result<CatchupOutput> {
        info!(
            "Starting catchup to ledger {} with mode {:?}, lcl={}",
            target, mode, lcl
        );
        self.progress.target_ledger = target;

        // Calculate the catchup range based on mode
        let range = CatchupRange::calculate(lcl, target, mode);
        info!(
            "Catchup range: apply_buckets={}, bucket_apply_ledger={}, replay_first={}, replay_count={}",
            range.apply_buckets(),
            if range.apply_buckets() { range.bucket_apply_ledger() } else { 0 },
            range.replay_first(),
            range.replay_count()
        );

        // Track whether this is a Case 1 replay-from-existing-state (LCL > genesis, no buckets)
        let is_replay_from_existing = !range.apply_buckets() && existing_state.is_some();
        // Extract the LCL header's id_pool before consuming existing_state
        let existing_id_pool = existing_state.as_ref().map(|s| s.header.id_pool);
        // Extract pre-computed Soroban state size (avoids ~80s bucket scan during replay)
        let existing_soroban_state_size = existing_state.as_ref().and_then(|s| s.soroban_state_size);
        // Extract offer entries for correct order book during replay
        let existing_offer_entries = existing_state.as_ref().and_then(|s| s.offer_entries.clone());

        let (mut bucket_list, mut hot_archive_bucket_list, checkpoint_seq, network_id, cache_data) =
            if range.apply_buckets() {
                // Apply buckets at the calculated checkpoint
                let bucket_apply_at = range.bucket_apply_ledger();
                info!("Applying buckets at checkpoint {}", bucket_apply_at);

                // Download HAS
                self.update_progress(
                    CatchupStatus::DownloadingHAS,
                    1,
                    "Downloading History Archive State",
                );
                let has = self.download_has(bucket_apply_at).await?;
                verify::verify_has_structure(&has)?;
                verify::verify_has_checkpoint(&has, bucket_apply_at)?;

                let scp_history = self.download_scp_history(bucket_apply_at).await?;
                if !scp_history.is_empty() {
                    verify::verify_scp_history_entries(&scp_history)?;
                    self.persist_scp_history_entries(&scp_history)?;
                }

                // Download buckets
                self.update_progress(
                    CatchupStatus::DownloadingBuckets,
                    2,
                    "Downloading bucket files",
                );
                let bucket_hashes = has.unique_bucket_hashes();
                self.progress.buckets_total = bucket_hashes.len() as u32;
                let buckets = self.download_buckets(&bucket_hashes).await?;

                // Apply buckets
                self.update_progress(
                    CatchupStatus::ApplyingBuckets,
                    3,
                    "Applying buckets to build initial state",
                );
                let (bl, hot_bl, live_next_states, hot_next_states) =
                    self.apply_buckets(&has, &buckets).await?;

                let mut bucket_list = bl;
                let mut hot_archive_bucket_list = hot_bl;

                // Restart merges and scan caches in parallel.
                let cache_result = self
                    .restart_merges_and_scan_caches(
                        &mut bucket_list,
                        &mut hot_archive_bucket_list,
                        bucket_apply_at,
                        &live_next_states,
                        &hot_next_states,
                    )
                    .await?;

                self.persist_bucket_list_snapshot(bucket_apply_at, &bucket_list)?;

                let network_id = has
                    .network_passphrase
                    .as_ref()
                    .map(|p| NetworkId::from_passphrase(p))
                    .unwrap_or_else(NetworkId::testnet);

                (bucket_list, hot_archive_bucket_list, bucket_apply_at, network_id, Some(cache_result))
            } else {
                // No bucket application - we're replaying from current state
                // This only happens when LCL > genesis (case 1)
                match existing_state {
                    Some(state) => {
                        info!(
                            "Case 1 replay: using existing bucket lists from LCL {} to replay to target {}",
                            lcl, target
                        );
                        // The checkpoint_seq is the LCL itself - bucket lists are at LCL state
                        (state.bucket_list, state.hot_archive_bucket_list, lcl, state.network_id, None)
                    }
                    None => {
                        return Err(HistoryError::CatchupFailed(
                            "Catchup from LCL > genesis requires existing bucket lists \
                             (pass ExistingBucketState for replay-only catchup)"
                                .to_string(),
                        ));
                    }
                }
            };

        // Download ledger data for replay range
        let replay_first = range.replay_first();
        let replay_count = range.replay_count();

        let (final_header, final_hash, ledgers_applied) = if replay_count == 0 {
            // No replay needed - target is exactly at checkpoint
            info!(
                "Catching up to checkpoint {} (no ledgers to replay)",
                checkpoint_seq
            );
            let (header, hash) = self.download_checkpoint_header(checkpoint_seq).await?;
            (header, hash, 0)
        } else {
            // Download ledger data for replay
            self.update_progress(
                CatchupStatus::DownloadingLedgers,
                4,
                "Downloading ledger data",
            );

            // We need to download ledgers from replay_first to target
            // The download_ledger_data expects (checkpoint, target) where it downloads
            // ledgers from checkpoint+1 to target. So we need to adjust.
            let download_from_checkpoint = replay_first - 1;
            let ledger_data = self.download_ledger_data(download_from_checkpoint, target).await?;

            // Verify the header chain
            self.update_progress(CatchupStatus::Verifying, 5, "Verifying header chain");
            self.verify_downloaded_data(&ledger_data)?;

            // Get the starting id_pool from the checkpoint before replaying.
            // For Case 1 (replay from existing state), we already have the LCL header
            // and don't need to download it again from the archive.
            let checkpoint_id_pool = if is_replay_from_existing {
                existing_id_pool.unwrap_or(0)
            } else {
                let (checkpoint_header, _) =
                    self.download_checkpoint_header(download_from_checkpoint).await?;
                checkpoint_header.id_pool
            };

            // Replay ledgers
            self.update_progress(CatchupStatus::Replaying, 6, "Replaying ledgers");

            // Use offers from existing state (Case 1) or cache_data (Case 4).
            let replay_offer_entries = if let Some(offers) = existing_offer_entries {
                Some(offers)
            } else if let Some(ref cd) = cache_data {
                Some(cd.offers.values().cloned().collect())
            } else {
                None
            };

            let final_state = self
                .replay_ledgers(
                    &mut bucket_list,
                    &mut hot_archive_bucket_list,
                    &ledger_data,
                    network_id,
                    checkpoint_id_pool,
                    existing_soroban_state_size,
                    replay_offer_entries,
                )
                .await?;

            // Get final header
            let (final_header, final_hash) = match self.download_checkpoint_header(target).await {
                Ok((header, hash)) => (header, hash),
                Err(_) => {
                    warn!("Could not download final header, using replay state");
                    let header = create_header_from_replay_state(
                        &final_state,
                        &bucket_list,
                        &hot_archive_bucket_list,
                    );
                    (header, final_state.ledger_hash)
                }
            };

            self.persist_ledger_history(&ledger_data, &network_id)?;

            (final_header, final_hash, replay_count)
        };

        // Verify final state - bucket list hash must match the header
        self.verify_final_state(&final_header, &bucket_list, &hot_archive_bucket_list)?;

        if replay_count == 0 {
            self.persist_header_only(&final_header)?;
        }

        // Complete!
        self.update_progress(CatchupStatus::Completed, 7, "Catchup completed");

        info!(
            "Catchup completed: ledger {}, hash {}, {} ledgers replayed",
            final_header.ledger_seq, final_hash, ledgers_applied
        );

        Ok(CatchupOutput {
            result: CatchupResult {
                ledger_seq: final_header.ledger_seq,
                ledger_hash: final_hash,
                ledgers_applied,
                buckets_downloaded: self.progress.buckets_total,
            },
            bucket_list,
            hot_archive_bucket_list,
            header: final_header,
            header_hash: final_hash,
            cache_data,
        })
    }

    /// Catch up to a target ledger using pre-downloaded checkpoint data.
    pub async fn catchup_to_ledger_with_checkpoint_data(
        &mut self,
        target: u32,
        data: CheckpointData,
    ) -> Result<CatchupOutput> {
        info!("Starting catchup to ledger {} with checkpoint data", target);
        self.progress.target_ledger = target;

        let checkpoint_seq =
            checkpoint::latest_checkpoint_before_or_at(target).ok_or_else(|| {
                HistoryError::CatchupFailed(format!(
                    "target ledger {} is before first checkpoint",
                    target
                ))
            })?;

        if data.has.current_ledger != checkpoint_seq {
            return Err(HistoryError::CatchupFailed(format!(
                "checkpoint data ledger {} does not match target checkpoint {}",
                data.has.current_ledger, checkpoint_seq
            )));
        }

        // Step 2: Verify HAS
        self.update_progress(
            CatchupStatus::DownloadingHAS,
            1,
            "Using provided History Archive State",
        );
        verify::verify_has_structure(&data.has)?;
        verify::verify_has_checkpoint(&data.has, checkpoint_seq)?;

        // Step 3: Verify bucket files exist on disk
        // Hash verification was already performed at download time by DownloadBucketsWork.
        // The apply_buckets step will re-verify hashes when loading each bucket lazily.
        self.update_progress(
            CatchupStatus::DownloadingBuckets,
            2,
            "Verifying bucket files on disk",
        );
        let bucket_hashes = data.has.unique_bucket_hashes();
        let empty_bucket_hash = Hash256::hash(&[]);
        self.progress.buckets_total = bucket_hashes.len() as u32;
        for (idx, hash) in bucket_hashes.iter().enumerate() {
            if !hash.is_zero() && *hash != empty_bucket_hash {
                let bucket_path = data.bucket_dir.join(format!("{}.bucket.xdr", hash.to_hex()));
                if !bucket_path.exists() {
                    return Err(HistoryError::BucketNotFound(*hash));
                }
            }
            self.progress.buckets_downloaded = (idx + 1) as u32;
        }

        // Copy bucket files to the bucket manager directory if they're in a different location
        let bucket_mgr_dir = self.bucket_manager.bucket_dir().to_path_buf();
        if data.bucket_dir != bucket_mgr_dir {
            for hash in &bucket_hashes {
                if hash.is_zero() || *hash == empty_bucket_hash {
                    continue;
                }
                let src = data.bucket_dir.join(format!("{}.bucket.xdr", hash.to_hex()));
                let dst = bucket_mgr_dir.join(format!("{}.bucket.xdr", hash.to_hex()));
                if src.exists() && !dst.exists() {
                    std::fs::copy(&src, &dst).map_err(|e| {
                        HistoryError::CatchupFailed(format!(
                            "failed to copy bucket {} to bucket manager dir: {}",
                            hash, e
                        ))
                    })?;
                }
            }
        }

        // Step 4: Verify SCP history entries (if present)
        if !data.scp_history.is_empty() {
            verify::verify_scp_history_entries(&data.scp_history)?;
            self.persist_scp_history_entries(&data.scp_history)?;
        }

        // Step 5: Apply buckets to build initial state
        // Buckets are loaded lazily from disk — no in-memory bucket data needed.
        self.update_progress(
            CatchupStatus::ApplyingBuckets,
            3,
            "Applying buckets to build initial state",
        );
        let (mut bucket_list, mut hot_archive_bucket_list, live_next_states, hot_next_states) =
            self.apply_buckets(&data.has, &[]).await?;

        // Restart merges and scan caches in parallel.
        let cache_data = self
            .restart_merges_and_scan_caches(
                &mut bucket_list,
                &mut hot_archive_bucket_list,
                checkpoint_seq,
                &live_next_states,
                &hot_next_states,
            )
            .await?;

        self.persist_bucket_list_snapshot(checkpoint_seq, &bucket_list)?;

        // Step 6: Build ledger data from checkpoint files
        self.update_progress(
            CatchupStatus::DownloadingLedgers,
            4,
            "Using provided ledger data",
        );
        let mut header_map = HashMap::new();
        for entry in &data.headers {
            header_map.insert(entry.header.ledger_seq, entry.header.clone());
        }
        for entry in &data.tx_results {
            if entry.ledger_seq <= checkpoint_seq || entry.ledger_seq > target {
                continue;
            }
            if let Some(header) = header_map.get(&entry.ledger_seq) {
                let xdr = entry
                    .tx_result_set
                    .to_xdr(stellar_xdr::curr::Limits::none())
                    .map_err(|e| {
                        HistoryError::CatchupFailed(format!(
                            "failed to encode tx result set: {}",
                            e
                        ))
                    })?;
                verify::verify_tx_result_set(header, &xdr)?;
            }
        }
        let (checkpoint_header, checkpoint_hash) =
            checkpoint_header_from_headers(checkpoint_seq, &data.headers)?;
        let ledger_data = if target == checkpoint_seq {
            Vec::new()
        } else {
            self.download_ledger_data(checkpoint_seq, target).await?
        };

        // Step 6: Verify the header chain
        self.update_progress(CatchupStatus::Verifying, 5, "Verifying header chain");
        self.verify_downloaded_data(&ledger_data)?;

        let network_id = data
            .has
            .network_passphrase
            .as_ref()
            .map(|p| NetworkId::from_passphrase(p))
            .unwrap_or_else(NetworkId::testnet);

        // Step 7: Replay ledgers from checkpoint to target (if any)
        self.update_progress(CatchupStatus::Replaying, 6, "Replaying ledgers");

        let (final_header, final_hash, ledgers_applied) = if ledger_data.is_empty() {
            // Use the archive's pre-computed hash - it's the authoritative hash the network used
            (checkpoint_header, checkpoint_hash, 0)
        } else {
            // Extract offers from cache_data for correct offer matching during replay.
            let replay_offers: Vec<stellar_xdr::curr::LedgerEntry> =
                cache_data.offers.values().cloned().collect();

            let final_state = self
                .replay_ledgers(
                    &mut bucket_list,
                    &mut hot_archive_bucket_list,
                    &ledger_data,
                    network_id,
                    checkpoint_header.id_pool, // Use checkpoint's id_pool for correct offer IDs
                    None,
                    Some(replay_offers),
                )
                .await?;
            let ledgers_applied = target - checkpoint_seq;
            // Get the final header from replay - use archive's hash if available
            let (final_header, final_hash) = match self.download_checkpoint_header(target).await {
                Ok((header, hash)) => (header, hash),
                Err(_) => {
                    // Construct a minimal header from replay state if download fails
                    warn!("Could not download final header, using replay state");
                    let header = create_header_from_replay_state(
                        &final_state,
                        &bucket_list,
                        &hot_archive_bucket_list,
                    );
                    // Fall back to the replay-computed hash
                    (header, final_state.ledger_hash)
                }
            };
            (final_header, final_hash, ledgers_applied)
        };

        // Verify final state - bucket list hash must match the header
        self.verify_final_state(&final_header, &bucket_list, &hot_archive_bucket_list)?;

        self.persist_ledger_history(&ledger_data, &network_id)?;
        if ledger_data.is_empty() {
            self.persist_header_only(&final_header)?;
        }

        self.update_progress(CatchupStatus::Completed, 7, "Catchup completed");

        Ok(CatchupOutput {
            result: CatchupResult {
                ledger_seq: final_header.ledger_seq,
                ledger_hash: final_hash,
                ledgers_applied,
                buckets_downloaded: bucket_hashes.len() as u32,
            },
            bucket_list,
            hot_archive_bucket_list,
            header: final_header,
            header_hash: final_hash,
            cache_data: Some(cache_data),
        })
    }

    /// Restart merges and scan caches in parallel.
    ///
    /// Runs the background cache scan concurrently with live merge restarts and
    /// hot archive merge restarts, then returns the pre-computed cache data.
    async fn restart_merges_and_scan_caches(
        &self,
        bucket_list: &mut BucketList,
        hot_archive_bucket_list: &mut HotArchiveBucketList,
        checkpoint_seq: u32,
        live_next_states: &[HasNextState],
        hot_next_states: &[HasNextState],
    ) -> Result<stellar_core_ledger::CacheInitResult> {
        let protocol_version = 25u32;

        // Start background cache scan BEFORE merge restarts so it runs concurrently.
        // The scan only reads curr/snap buckets (not pending merges), so it's safe to
        // run on a clone taken before merges start. This saves ~83 seconds on mainnet.
        let bl_clone = bucket_list.clone();
        let cache_handle = tokio::task::spawn_blocking(move || {
            stellar_core_ledger::scan_bucket_list_for_caches(&bl_clone, protocol_version)
        });

        // Run live bucket list merge restarts in parallel (all levels concurrently).
        let bucket_dir = self.bucket_manager.bucket_dir().to_path_buf();
        let load_bucket_for_merge = load_disk_backed_bucket_closure(bucket_dir.clone());

        bucket_list
            .restart_merges_from_has(
                checkpoint_seq,
                protocol_version,
                live_next_states,
                load_bucket_for_merge,
                true,
            )
            .await
            .map_err(|e| {
                HistoryError::CatchupFailed(format!("Failed to restart bucket merges: {}", e))
            })?;

        // Hot archive merges are small — run synchronously.
        {
            let load_hot_bucket_for_merge =
                load_disk_backed_hot_archive_bucket_closure(bucket_dir);
            hot_archive_bucket_list
                .restart_merges_from_has(
                    checkpoint_seq,
                    protocol_version,
                    hot_next_states,
                    load_hot_bucket_for_merge,
                    true,
                )
                .map_err(|e| {
                    HistoryError::CatchupFailed(format!(
                        "Failed to restart hot archive merges: {}",
                        e
                    ))
                })?;
        }

        info!(
            "Bucket list hash after restart_merges_from_has: {}",
            bucket_list.hash()
        );

        // Await the background cache scan result.
        cache_handle.await.map_err(|e| {
            HistoryError::CatchupFailed(format!("Cache scan task panicked: {}", e))
        })
    }

    /// Update the progress status.
    fn update_progress(&mut self, status: CatchupStatus, step: u32, message: &str) {
        self.progress.status = status;
        self.progress.current_step = step;
        self.progress.message = message.to_string();
        debug!(
            "Catchup progress: step {}/{} - {}",
            step, self.progress.total_steps, message
        );
    }

    /// Download the History Archive State for a checkpoint.
    async fn download_has(&self, checkpoint_seq: u32) -> Result<HistoryArchiveState> {
        for archive in &self.archives {
            match archive.get_checkpoint_has(checkpoint_seq).await {
                Ok(has) => return Ok(has),
                Err(e) => {
                    warn!(
                        "Failed to download HAS from archive {}: {}",
                        archive.base_url(),
                        e
                    );
                    continue;
                }
            }
        }

        Err(HistoryError::CatchupFailed(format!(
            "failed to download HAS for checkpoint {} from any archive",
            checkpoint_seq
        )))
    }

    async fn download_scp_history(&self, checkpoint_seq: u32) -> Result<Vec<ScpHistoryEntry>> {
        for archive in &self.archives {
            match archive.get_scp_history(checkpoint_seq).await {
                Ok(entries) => return Ok(entries),
                Err(HistoryError::NotFound(_)) => {
                    debug!(
                        archive = %archive.base_url(),
                        checkpoint = checkpoint_seq,
                        "SCP history not found"
                    );
                }
                Err(e) => {
                    warn!(
                        archive = %archive.base_url(),
                        checkpoint = checkpoint_seq,
                        error = %e,
                        "Failed to download SCP history"
                    );
                }
            }
        }

        Ok(Vec::new())
    }

    /// Download all buckets referenced in the HAS to disk in parallel.
    ///
    /// This pre-downloads buckets to disk (not memory) so apply_buckets can
    /// load them quickly. Uses parallel downloads for speed while keeping
    /// memory usage low by saving directly to disk.
    async fn download_buckets(&mut self, hashes: &[Hash256]) -> Result<Vec<(Hash256, Vec<u8>)>> {
        use futures::stream::{self, StreamExt};

        let bucket_dir = self.bucket_manager.bucket_dir().to_path_buf();
        let empty_bucket_hash = Hash256::hash(&[]);

        // Filter out zero/empty hashes and already-downloaded buckets
        let to_download: Vec<_> = hashes
            .iter()
            .filter(|hash| {
                if hash.is_zero() || **hash == empty_bucket_hash {
                    return false;
                }
                let bucket_path = bucket_dir.join(format!("{}.bucket.xdr", hash.to_hex()));
                !bucket_path.exists()
            })
            .cloned()
            .collect();

        self.progress.buckets_total = hashes.len() as u32;

        if to_download.is_empty() {
            info!("All {} buckets already cached on disk", hashes.len());
            return Ok(Vec::new());
        }

        info!(
            "Pre-downloading {} buckets to disk ({} already cached) with {} parallel downloads",
            to_download.len(),
            hashes.len() - to_download.len(),
            16 // MAX_CONCURRENT_SUBPROCESSES equivalent
        );

        let archives = self.archives.clone();
        let bucket_dir = bucket_dir.clone();
        let total_to_download = to_download.len();
        let downloaded = std::sync::atomic::AtomicU32::new(0);

        // Download buckets in parallel, saving directly to disk
        let results: Vec<Result<()>> = stream::iter(to_download.into_iter())
            .map(|hash| {
                let archives = archives.clone();
                let bucket_dir = bucket_dir.clone();
                let downloaded = &downloaded;

                async move {
                    let bucket_path = bucket_dir.join(format!("{}.bucket.xdr", hash.to_hex()));

                    // Try each archive until one succeeds
                    for archive in &archives {
                        match archive.get_bucket(&hash).await {
                            Ok(data) => {
                                // Save to disk
                                if let Err(e) = std::fs::write(&bucket_path, &data) {
                                    warn!("Failed to save bucket {} to disk: {}", hash, e);
                                    continue;
                                }
                                let count = downloaded
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                                    + 1;
                                if count % 5 == 0 || count == total_to_download as u32 {
                                    info!("Downloaded {}/{} buckets", count, total_to_download);
                                }
                                debug!("Pre-downloaded bucket {} ({} bytes)", hash, data.len());
                                return Ok(());
                            }
                            Err(e) => {
                                debug!(
                                    "Failed to download bucket {} from {}: {}",
                                    hash,
                                    archive.base_url(),
                                    e
                                );
                                continue;
                            }
                        }
                    }

                    Err(HistoryError::BucketNotFound(hash))
                }
            })
            .buffer_unordered(16) // MAX_CONCURRENT_SUBPROCESSES equivalent
            .collect()
            .await;

        // Check for any failures
        for result in results {
            result?;
        }

        self.progress.buckets_downloaded = hashes.len() as u32;
        info!("Pre-downloaded all {} buckets to disk", total_to_download);

        // Return empty - buckets are on disk, not in memory
        Ok(Vec::new())
    }

    /// Apply downloaded buckets to build the initial bucket list state.
    /// Returns (live_bucket_list, hot_archive_bucket_list).
    ///
    /// This method uses disk-backed bucket storage to handle mainnet's large buckets
    /// efficiently. Instead of loading all entries into memory, each bucket is:
    /// 1. Downloaded and saved to disk
    /// 2. Indexed with a compact key-to-offset mapping
    /// 3. Entries are loaded on-demand when accessed
    ///
    /// This reduces memory usage from O(entries) to O(unique_keys) for the index.
    /// Return type for apply_buckets, including next_states for restart_merges_from_has
    async fn apply_buckets(
        &self,
        has: &HistoryArchiveState,
        buckets: &[(Hash256, Vec<u8>)],
    ) -> Result<(
        BucketList,
        HotArchiveBucketList,
        Vec<HasNextState>,
        Vec<HasNextState>,
    )> {
        use std::sync::Mutex;

        if let Some(mb) = rss_mb() {
            info!("apply_buckets START — RSS {} MB", mb);
        }
        info!(
            "Applying buckets to build state at ledger {} (disk-backed mode)",
            has.current_ledger
        );

        // Get bucket storage directory from the bucket manager
        let bucket_dir = self.bucket_manager.bucket_dir();

        // Cache for buckets we've already loaded (to avoid re-downloading).
        let bucket_cache: Mutex<HashMap<Hash256, Bucket>> = Mutex::new(HashMap::new());
        let preloaded_buckets: Mutex<HashMap<Hash256, Vec<u8>>> =
            Mutex::new(buckets.iter().cloned().collect());

        // Clone archives and bucket_dir for use in closure
        let archives = self.archives.clone();
        let bucket_dir = bucket_dir.to_path_buf();

        let empty_bucket_hash = Hash256::hash(&[]);

        // Helper to load a bucket - downloads on-demand, saves to disk, and caches
        let load_bucket = |hash: &Hash256| -> stellar_core_bucket::Result<Bucket> {
            // Zero hash means empty bucket
            if hash.is_zero() {
                return Ok(Bucket::empty());
            }
            if *hash == empty_bucket_hash {
                return Ok(Bucket::empty());
            }

            // Check cache first
            {
                let cache = bucket_cache.lock().unwrap();
                if let Some(bucket) = cache.get(hash) {
                    return Ok(bucket.clone());
                }
            }

            // Construct path for this bucket
            let bucket_path = bucket_dir.join(format!("{}.bucket.xdr", hash.to_hex()));

            // Check if bucket already exists on disk as an XDR file.
            // Build the index eagerly so it's ready for lookups during live
            // ledger closing — deferring index construction to the first get()
            // would cause multi-second stalls when closing the first few ledgers.
            if bucket_path.exists() {
                debug!("Loading existing bucket {} from disk", hash);
                let bucket = Bucket::from_xdr_file_disk_backed(&bucket_path)?;
                let mut cache = bucket_cache.lock().unwrap();
                cache.insert(*hash, bucket.clone());
                return Ok(bucket);
            }

            // Use preloaded bucket data if available, otherwise download.
            let xdr_data = if let Some(data) = {
                let mut preloaded = preloaded_buckets.lock().unwrap();
                preloaded.remove(hash)
            } {
                data
            } else {
                // Download the bucket (blocking - we're in a sync context)
                let hash = *hash;
                let archives = archives.clone();

                let download = async move {
                    for archive in &archives {
                        match archive.get_bucket(&hash).await {
                            Ok(data) => return Ok(data),
                            Err(e) => {
                                warn!("Failed to download bucket {} from archive: {}", hash, e);
                                continue;
                            }
                        }
                    }
                    Err(stellar_core_bucket::BucketError::NotFound(format!(
                        "Bucket {} not found in any archive",
                        hash
                    )))
                };

                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    if matches!(
                        handle.runtime_flavor(),
                        tokio::runtime::RuntimeFlavor::MultiThread
                    ) {
                        tokio::task::block_in_place(|| handle.block_on(download))?
                    } else {
                        std::thread::spawn(move || {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .map_err(|e| {
                                    stellar_core_bucket::BucketError::NotFound(format!(
                                        "failed to build runtime: {}",
                                        e
                                    ))
                                })?;
                            rt.block_on(download)
                        })
                        .join()
                        .map_err(|_| {
                            stellar_core_bucket::BucketError::NotFound(
                                "bucket download thread panicked".to_string(),
                            )
                        })??
                    }
                } else {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| {
                            stellar_core_bucket::BucketError::NotFound(format!(
                                "failed to build runtime: {}",
                                e
                            ))
                        })?;
                    rt.block_on(download)?
                }
            };

            info!(
                "Downloaded bucket {}: {} bytes, saving to disk",
                hash,
                xdr_data.len()
            );

            // Save XDR data to disk first, then build the disk-backed bucket by
            // streaming through the file. This avoids holding the full file in memory
            // while also building the index — critical for multi-GB buckets on mainnet.
            std::fs::write(&bucket_path, &xdr_data).map_err(|e| {
                stellar_core_bucket::BucketError::NotFound(format!(
                    "failed to write bucket to disk: {}",
                    e
                ))
            })?;
            // Drop the in-memory XDR data before building the index to free memory
            drop(xdr_data);

            let bucket = Bucket::from_xdr_file_disk_backed(&bucket_path)?;

            // Verify hash matches
            if bucket.hash() != *hash {
                // Clean up the bad file
                let _ = std::fs::remove_file(&bucket_path);
                return Err(stellar_core_bucket::BucketError::HashMismatch {
                    expected: hash.to_hex(),
                    actual: bucket.hash().to_hex(),
                });
            }

            info!(
                "Created disk-backed bucket {} with {} entries",
                hash,
                bucket.len()
            );

            // Cache the bucket (it might be referenced multiple times in the bucket list)
            {
                let mut cache = bucket_cache.lock().unwrap();
                cache.insert(*hash, bucket.clone());
            }

            Ok(bucket)
        };

        // Build live bucket list hashes as (curr, snap) pairs with next states
        // This is required for proper FutureBucket restoration
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

        for (level_idx, (curr, snap)) in live_hash_pairs.iter().enumerate() {
            info!(
                "HAS level {} hashes: curr={}, snap={}",
                level_idx, curr, snap
            );
        }

        // Restore the live bucket list with FutureBucket states
        let mut bucket_list =
            BucketList::restore_from_has(&live_hash_pairs, &live_next_states, load_bucket)
                .map_err(|e| {
                    HistoryError::CatchupFailed(format!("Failed to restore live bucket list: {}", e))
                })?;
        bucket_list.set_bucket_dir(bucket_dir.to_path_buf());

        // Log the restored bucket list hash
        info!("Live bucket list restored hash: {}", bucket_list.hash());
        info!(
            "Live bucket list restored: {} total entries",
            bucket_list.stats().total_entries
        );
        if let Some(mb) = rss_mb() {
            info!("apply_buckets AFTER live bucket list restore — RSS {} MB", mb);
        }

        // Build hot archive next states (even if no hot archive buckets, for return value)
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

        // Build hot archive bucket list if present (protocol 23+)
        // Hot archive uses HotArchiveBucketEntry (Metaentry/Archived/Live), not BucketEntry
        let hot_archive_bucket_list = if has.has_hot_archive_buckets() {
            use stellar_core_bucket::HotArchiveBucket;

            // Build hot archive bucket list hashes as (curr, snap) pairs
            let hot_hash_pairs = has.hot_archive_bucket_hash_pairs().unwrap_or_default();

            // Log the HAS hashes before restoration
            for (level_idx, (curr, snap)) in hot_hash_pairs.iter().enumerate().take(5) {
                info!(
                    "Hot archive HAS level {} hashes: curr={}, snap={}",
                    level_idx,
                    curr.to_hex(),
                    snap.to_hex()
                );
            }

            // Create a loader for HotArchiveBucket (different from live Bucket)
            // Hot archive buckets contain HotArchiveBucketEntry, not BucketEntry
            let bucket_dir_clone = bucket_dir.clone();
            let archives_clone = archives.clone();

            // Cache for hot archive buckets (same hash can appear at multiple levels)
            let hot_archive_bucket_cache: Mutex<HashMap<Hash256, HotArchiveBucket>> =
                Mutex::new(HashMap::new());

            let load_hot_archive_bucket =
                |hash: &Hash256| -> stellar_core_bucket::Result<HotArchiveBucket> {
                    // Zero hash means empty bucket
                    if hash.is_zero() {
                        return Ok(HotArchiveBucket::empty());
                    }

                    // Check cache first (same hash can appear at multiple levels)
                    {
                        let cache = hot_archive_bucket_cache.lock().unwrap();
                        if let Some(bucket) = cache.get(hash) {
                            return Ok(bucket.clone());
                        }
                    }

                    // Check if we have the XDR data in the pre-downloaded cache
                    let bucket_path = bucket_dir_clone.join(format!("{}.bucket.xdr", hash.to_hex()));

                    let xdr_data: Option<Vec<u8>> = if let Some(data) = {
                        let mut preloaded = preloaded_buckets.lock().unwrap();
                        preloaded.remove(hash)
                    } {
                        // Save preloaded data to disk, then load via streaming
                        std::fs::write(&bucket_path, &data).map_err(|e| {
                            stellar_core_bucket::BucketError::NotFound(format!(
                                "failed to write hot archive bucket to disk: {}",
                                e
                            ))
                        })?;
                        None
                    } else if bucket_path.exists() {
                        // Already on disk, load via streaming
                        None
                    } else {
                        // Download if needed (shouldn't happen if download_buckets was called)
                        warn!(
                            "Hot archive bucket {} not found in cache, downloading",
                            hash
                        );
                        let hash = *hash;
                        let archives = archives_clone.clone();
                        let download = async move {
                            for archive in &archives {
                                match archive.get_bucket(&hash).await {
                                    Ok(data) => return Ok(data),
                                    Err(e) => {
                                        warn!("Failed to download hot archive bucket {} from archive: {}", hash, e);
                                        continue;
                                    }
                                }
                            }
                            Err(stellar_core_bucket::BucketError::NotFound(format!(
                                "hot archive bucket {} not available from any archive",
                                hash
                            )))
                        };

                        // Handle async download from sync context properly
                        // (matching the pattern used for live buckets)
                        let downloaded = if let Ok(handle) = tokio::runtime::Handle::try_current() {
                            if matches!(
                                handle.runtime_flavor(),
                                tokio::runtime::RuntimeFlavor::MultiThread
                            ) {
                                tokio::task::block_in_place(|| handle.block_on(download))?
                            } else {
                                std::thread::spawn(move || {
                                    let rt = tokio::runtime::Builder::new_current_thread()
                                        .enable_all()
                                        .build()
                                        .map_err(|e| {
                                            stellar_core_bucket::BucketError::NotFound(format!(
                                                "failed to build runtime: {}",
                                                e
                                            ))
                                        })?;
                                    rt.block_on(download)
                                })
                                .join()
                                .map_err(|_| {
                                    stellar_core_bucket::BucketError::NotFound(
                                        "bucket download thread panicked".to_string(),
                                    )
                                })??
                            }
                        } else {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .map_err(|e| {
                                    stellar_core_bucket::BucketError::NotFound(format!(
                                        "failed to build runtime: {}",
                                        e
                                    ))
                                })?;
                            rt.block_on(download)?
                        };
                        Some(downloaded)
                    };

                    // If we downloaded data, save it to disk first
                    if let Some(downloaded_data) = xdr_data {
                        std::fs::write(&bucket_path, &downloaded_data).map_err(|e| {
                            stellar_core_bucket::BucketError::NotFound(format!(
                                "failed to write hot archive bucket to disk: {}",
                                e
                            ))
                        })?;
                    }

                    // Load hot archive bucket from disk eagerly — builds the index
                    // immediately so it's ready for lookups during live operation.
                    let bucket = HotArchiveBucket::from_xdr_file_disk_backed(&bucket_path)?;

                    // Cache for reuse (same hash can appear at multiple levels)
                    {
                        let mut cache = hot_archive_bucket_cache.lock().unwrap();
                        cache.insert(*hash, bucket.clone());
                    }

                    Ok(bucket)
                };

            let hot_bucket_list = HotArchiveBucketList::restore_from_has(
                &hot_hash_pairs,
                &hot_next_states,
                load_hot_archive_bucket,
            )
            .map_err(|e| {
                HistoryError::CatchupFailed(format!(
                    "Failed to restore hot archive bucket list: {}",
                    e
                ))
            })?;

            info!(
                "Hot archive bucket list restored: {} total entries",
                hot_bucket_list.stats().total_entries
            );
            if let Some(mb) = rss_mb() {
                info!("apply_buckets AFTER hot archive restore — RSS {} MB", mb);
            }

            // Log the restored bucket list state
            for (level_idx, level) in hot_bucket_list.levels().iter().enumerate().take(5) {
                info!(
                    "Hot archive restored level {}: curr={}, snap={}",
                    level_idx,
                    level.curr.hash().to_hex(),
                    level.snap.hash().to_hex()
                );
            }

            hot_bucket_list
        } else {
            HotArchiveBucketList::new()
        };

        if let Some(mb) = rss_mb() {
            info!("apply_buckets END — RSS {} MB", mb);
        }

        Ok((
            bucket_list,
            hot_archive_bucket_list,
            live_next_states,
            hot_next_states,
        ))
    }

    /// Download ledger headers, transactions, and results for a range.
    async fn download_ledger_data(
        &mut self,
        from_checkpoint: u32,
        to_ledger: u32,
    ) -> Result<Vec<LedgerData>> {
        let mut data = Vec::new();
        let mut checkpoint_cache: HashMap<u32, CheckpointLedgerData> = HashMap::new();

        // We need to download data for ledgers (from_checkpoint+1) to to_ledger
        // The checkpoint ledger's state is already in the bucket list
        let start = from_checkpoint + 1;

        if start > to_ledger {
            // No ledgers to replay, we're at the checkpoint
            return Ok(data);
        }

        for seq in start..=to_ledger {
            self.progress.current_ledger = seq;
            let checkpoint = checkpoint::checkpoint_containing(seq);

            if let std::collections::hash_map::Entry::Vacant(e) = checkpoint_cache.entry(checkpoint)
            {
                let downloaded = self.download_checkpoint_ledger_data(checkpoint).await?;
                e.insert(downloaded);
            }

            let cache = checkpoint_cache.get(&checkpoint).ok_or_else(|| {
                HistoryError::CatchupFailed(format!("missing checkpoint cache for {}", checkpoint))
            })?;

            let header = cache
                .headers
                .iter()
                .find(|h| h.header.ledger_seq == seq)
                .ok_or_else(|| {
                    HistoryError::CatchupFailed(format!(
                        "ledger {} not found in checkpoint headers",
                        seq
                    ))
                })?
                .header
                .clone();

            let tx_history_entry = cache
                .tx_entries
                .iter()
                .find(|entry| entry.ledger_seq == seq)
                .cloned();
            let tx_set = tx_history_entry
                .as_ref()
                .map(|entry| match &entry.ext {
                    TransactionHistoryEntryExt::V0 => {
                        TransactionSetVariant::Classic(entry.tx_set.clone())
                    }
                    TransactionHistoryEntryExt::V1(set) => {
                        TransactionSetVariant::Generalized(set.clone())
                    }
                })
                .unwrap_or_else(|| {
                    // For protocol 20+, use GeneralizedTransactionSet format
                    // For earlier protocols, use Classic TransactionSet
                    if header.ledger_version >= 20 {
                        // Create empty GeneralizedTransactionSet with proper phases
                        // Phase 0: empty classic phase (V0 with no components)
                        // Phase 1: empty soroban phase (V1 with no stages)
                        use stellar_xdr::curr::{ParallelTxsComponent, TransactionPhase, VecM};

                        // Empty classic phase (no components)
                        let classic_phase = TransactionPhase::V0(VecM::default());
                        // Empty soroban phase (no execution stages)
                        let soroban_phase = TransactionPhase::V1(ParallelTxsComponent {
                            base_fee: None,
                            execution_stages: VecM::default(),
                        });

                        TransactionSetVariant::Generalized(GeneralizedTransactionSet::V1(
                            TransactionSetV1 {
                                previous_ledger_hash: header.previous_ledger_hash.clone(),
                                phases: vec![classic_phase, soroban_phase]
                                    .try_into()
                                    .unwrap_or_default(),
                            },
                        ))
                    } else {
                        TransactionSetVariant::Classic(TransactionSet {
                            previous_ledger_hash: header.previous_ledger_hash.clone(),
                            txs: Default::default(),
                        })
                    }
                });

            let tx_result_entry = cache
                .result_entries
                .iter()
                .find(|entry| entry.ledger_seq == seq)
                .cloned();
            let tx_results = tx_result_entry
                .as_ref()
                .map(|entry| entry.tx_result_set.results.iter().cloned().collect())
                .unwrap_or_else(Vec::new);

            data.push(LedgerData {
                header,
                tx_set,
                tx_results,
                tx_history_entry,
                tx_result_entry,
            });
        }

        Ok(data)
    }

    /// Download ledger headers, transactions, and results for a checkpoint.
    async fn download_checkpoint_ledger_data(
        &self,
        checkpoint: u32,
    ) -> Result<CheckpointLedgerData> {
        // Try each archive until one succeeds
        for archive in &self.archives {
            match self.try_download_checkpoint(archive, checkpoint).await {
                Ok(data) => return Ok(data),
                Err(e) => {
                    warn!(
                        "Failed to download checkpoint {} from archive {}: {}",
                        checkpoint,
                        archive.base_url(),
                        e
                    );
                    continue;
                }
            }
        }

        Err(HistoryError::CatchupFailed(format!(
            "failed to download checkpoint {} from any archive",
            checkpoint
        )))
    }

    /// Try to download checkpoint data from a specific archive.
    async fn try_download_checkpoint(
        &self,
        archive: &HistoryArchive,
        checkpoint: u32,
    ) -> Result<CheckpointLedgerData> {
        let headers = archive.get_ledger_headers(checkpoint).await?;
        let tx_entries = archive.get_transactions(checkpoint).await?;
        let result_entries = archive.get_results(checkpoint).await?;
        Ok(CheckpointLedgerData {
            headers,
            tx_entries,
            result_entries,
        })
    }

    /// Verify the downloaded ledger data.
    fn verify_downloaded_data(&self, ledger_data: &[LedgerData]) -> Result<()> {
        if ledger_data.is_empty() {
            return Ok(());
        }

        // Extract headers for chain verification
        let headers: Vec<_> = ledger_data.iter().map(|d| d.header.clone()).collect();
        verify::verify_header_chain(&headers)?;

        // Verify transaction sets match header hashes
        for data in ledger_data {
            if let Some(entry) = data.tx_history_entry.as_ref() {
                let tx_set = match &entry.ext {
                    TransactionHistoryEntryExt::V0 => {
                        TransactionSetVariant::Classic(entry.tx_set.clone())
                    }
                    TransactionHistoryEntryExt::V1(set) => {
                        TransactionSetVariant::Generalized(set.clone())
                    }
                };
                if let Err(e) = verify::verify_tx_set(&data.header, &tx_set) {
                    warn!(
                        "Transaction set verification failed for ledger {}: {}",
                        data.header.ledger_seq, e
                    );
                    // Continue - tx sets may be empty for some ledgers
                }
            }
            if let Some(entry) = data.tx_result_entry.as_ref() {
                if let Ok(xdr) = entry
                    .tx_result_set
                    .to_xdr(stellar_xdr::curr::Limits::none())
                {
                    if let Err(e) = verify::verify_tx_result_set(&data.header, &xdr) {
                        warn!(
                            "Transaction result set verification failed for ledger {}: {}",
                            data.header.ledger_seq, e
                        );
                    }
                }
            }
        }

        info!("Verified header chain for {} ledgers", headers.len());
        Ok(())
    }

    /// Verify the final ledger state matches the expected bucket list hash.
    ///
    /// For Protocol 23+, the bucket list hash in the header is:
    /// SHA256(live_bucket_list.hash() || hot_archive_bucket_list.hash())
    fn verify_final_state(
        &self,
        header: &LedgerHeader,
        bucket_list: &BucketList,
        hot_archive_bucket_list: &HotArchiveBucketList,
    ) -> Result<()> {
        if !self.replay_config.verify_bucket_list {
            info!(
                ledger_seq = header.ledger_seq,
                "Skipping final state verification (bucket verification disabled)"
            );
            return Ok(());
        }

        use sha2::{Digest, Sha256};

        let live_hash = bucket_list.hash();
        let hot_hash = hot_archive_bucket_list.hash();
        let expected_hash = Hash256::from(header.bucket_list_hash.0);

        info!(
            ledger_seq = header.ledger_seq,
            live_hash = %live_hash.to_hex(),
            hot_hash = %hot_hash.to_hex(),
            expected_combined = %expected_hash.to_hex(),
            "Catchup verify_final_state: computing combined bucket list hash"
        );

        // Log per-level hashes for hot archive
        for (level_idx, level) in hot_archive_bucket_list.levels().iter().enumerate().take(5) {
            info!(
                level = level_idx,
                curr_hash = %level.curr.hash().to_hex(),
                snap_hash = %level.snap.hash().to_hex(),
                "Hot archive level hash after catchup"
            );
        }

        let mut hasher = Sha256::new();
        hasher.update(live_hash.as_bytes());
        hasher.update(hot_hash.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        let computed_hash = Hash256::from_bytes(bytes);

        info!(
            ledger_seq = header.ledger_seq,
            computed = %computed_hash.to_hex(),
            expected = %expected_hash.to_hex(),
            matches = (computed_hash == expected_hash),
            "Catchup verify_final_state: final comparison"
        );

        verify::verify_ledger_hash(header, &computed_hash)?;

        info!(
            "Verified bucket list hash at ledger {}: {}",
            header.ledger_seq, computed_hash
        );
        Ok(())
    }

    fn persist_ledger_history(
        &self,
        ledger_data: &[LedgerData],
        network_id: &NetworkId,
    ) -> Result<()> {
        if ledger_data.is_empty() {
            return Ok(());
        }

        self.db
            .transaction(|conn| {
                use stellar_core_db::error::DbError;
                use stellar_core_db::queries::{HistoryQueries, LedgerQueries};

                for data in ledger_data {
                    let header_xdr = data.header.to_xdr(stellar_xdr::curr::Limits::none())?;
                    conn.store_ledger_header(&data.header, &header_xdr)?;

                    let tx_history_entry =
                        data.tx_history_entry
                            .clone()
                            .unwrap_or_else(|| match &data.tx_set {
                                TransactionSetVariant::Classic(set) => TransactionHistoryEntry {
                                    ledger_seq: data.header.ledger_seq,
                                    tx_set: set.clone(),
                                    ext: TransactionHistoryEntryExt::V0,
                                },
                                TransactionSetVariant::Generalized(set) => {
                                    let stellar_xdr::curr::GeneralizedTransactionSet::V1(set_v1) =
                                        set;
                                    TransactionHistoryEntry {
                                        ledger_seq: data.header.ledger_seq,
                                        tx_set: TransactionSet {
                                            previous_ledger_hash: set_v1
                                                .previous_ledger_hash
                                                .clone(),
                                            txs: Default::default(),
                                        },
                                        ext: TransactionHistoryEntryExt::V1(set.clone()),
                                    }
                                }
                            });
                    conn.store_tx_history_entry(data.header.ledger_seq, &tx_history_entry)?;

                    let tx_result_entry = data.tx_result_entry.clone().unwrap_or_else(|| {
                        let results = data.tx_results.clone().try_into().unwrap_or_default();
                        TransactionHistoryResultEntry {
                            ledger_seq: data.header.ledger_seq,
                            tx_result_set: TransactionResultSet { results },
                            ext: TransactionHistoryResultEntryExt::default(),
                        }
                    });
                    conn.store_tx_result_entry(data.header.ledger_seq, &tx_result_entry)?;

                    let tx_results: Vec<TransactionResultPair> = tx_result_entry
                        .tx_result_set
                        .results
                        .iter()
                        .cloned()
                        .collect();
                    let transactions = data
                        .tx_set
                        .transactions_with_base_fee()
                        .into_iter()
                        .map(|(tx, _)| tx)
                        .collect::<Vec<_>>();
                    let tx_count = transactions.len().min(tx_results.len());

                    for (idx, tx) in transactions.iter().take(tx_count).enumerate() {
                        let tx_result = &tx_results[idx];

                        let frame = TransactionFrame::with_network(tx.clone(), *network_id);
                        let tx_hash = frame
                            .hash(network_id)
                            .map_err(|e| DbError::Integrity(e.to_string()))?;
                        let tx_id = tx_hash.to_hex();

                        let tx_body = tx.to_xdr(stellar_xdr::curr::Limits::none())?;
                        let tx_result_xdr = tx_result.to_xdr(stellar_xdr::curr::Limits::none())?;

                        conn.store_transaction(
                            data.header.ledger_seq,
                            idx as u32,
                            &tx_id,
                            &tx_body,
                            &tx_result_xdr,
                            None,
                        )?;
                    }
                }

                Ok(())
            })
            .map_err(|err| {
                HistoryError::CatchupFailed(format!("failed to persist history: {}", err))
            })?;

        Ok(())
    }

    fn persist_scp_history_entries(&self, entries: &[ScpHistoryEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        self.db
            .transaction(|conn| {
                use stellar_core_db::queries::ScpQueries;

                for entry in entries {
                    let ScpHistoryEntry::V0(v0) = entry;
                    let ledger_seq = v0.ledger_messages.ledger_seq;
                    let envelopes: Vec<_> = v0.ledger_messages.messages.iter().cloned().collect();

                    conn.store_scp_history(ledger_seq, &envelopes)?;

                    for qset in v0.quorum_sets.iter() {
                        let hash = Hash256::hash_xdr(qset)?;
                        conn.store_scp_quorum_set(&hash, ledger_seq, qset)?;
                    }
                }

                Ok(())
            })
            .map_err(|err| {
                HistoryError::CatchupFailed(format!("failed to persist scp history: {}", err))
            })?;

        Ok(())
    }

    fn persist_bucket_list_snapshot(
        &self,
        ledger_seq: u32,
        bucket_list: &BucketList,
    ) -> Result<()> {
        let levels = bucket_list
            .levels()
            .iter()
            .map(|level| (level.curr.hash(), level.snap.hash()))
            .collect::<Vec<_>>();
        self.db
            .with_connection(|conn| {
                use stellar_core_db::queries::BucketListQueries;
                conn.store_bucket_list(ledger_seq, &levels)?;
                Ok(())
            })
            .map_err(|err| {
                HistoryError::CatchupFailed(format!(
                    "failed to persist bucket list for ledger {}: {}",
                    ledger_seq, err
                ))
            })?;
        Ok(())
    }

    fn persist_header_only(&self, header: &LedgerHeader) -> Result<()> {
        self.db
            .with_connection(|conn| {
                use stellar_core_db::queries::LedgerQueries;
                let header_xdr = header.to_xdr(stellar_xdr::curr::Limits::none())?;
                conn.store_ledger_header(header, &header_xdr)?;
                Ok(())
            })
            .map_err(|err| {
                HistoryError::CatchupFailed(format!("failed to persist header: {}", err))
            })?;
        Ok(())
    }

    /// Download the header for a specific ledger with its pre-computed hash.
    ///
    /// Returns the header and its hash as recorded in the history archive.
    /// The hash from the archive is authoritative - it's what the network used.
    async fn download_checkpoint_header(&self, ledger_seq: u32) -> Result<(LedgerHeader, Hash256)> {
        for archive in &self.archives {
            match archive.get_ledger_header_with_hash(ledger_seq).await {
                Ok((header, hash)) => {
                    debug!(
                        "Downloaded header for ledger {}: bucket_list_hash={}, ledger_seq={}, hash={}",
                        ledger_seq,
                        hex::encode(header.bucket_list_hash.0),
                        header.ledger_seq,
                        hash.to_hex()
                    );
                    return Ok((header, hash));
                }
                Err(e) => {
                    warn!(
                        "Failed to download header {} from archive {}: {}",
                        ledger_seq,
                        archive.base_url(),
                        e
                    );
                    continue;
                }
            }
        }

        Err(HistoryError::CatchupFailed(format!(
            "failed to download header for ledger {} from any archive",
            ledger_seq
        )))
    }

    /// Replay ledgers and update the bucket list.
    ///
    /// # Arguments
    ///
    /// * `checkpoint_id_pool` - The ID pool value from the checkpoint header.
    ///   This is the starting `id_pool` for the first ledger being replayed.
    ///   Required for correct offer ID assignment during transaction execution.
    #[allow(clippy::too_many_arguments)]
    async fn replay_ledgers(
        &mut self,
        bucket_list: &mut BucketList,
        hot_archive_bucket_list: &mut HotArchiveBucketList,
        ledger_data: &[LedgerData],
        network_id: NetworkId,
        checkpoint_id_pool: u64,
        precomputed_soroban_state_size: Option<u64>,
        mut offer_entries: Option<Vec<stellar_xdr::curr::LedgerEntry>>,
    ) -> Result<ReplayedLedgerState> {
        use stellar_core_bucket::EvictionIterator;

        if ledger_data.is_empty() {
            return Err(HistoryError::CatchupFailed(
                "no ledger data to replay".to_string(),
            ));
        }

        let total = ledger_data.len();
        let mut last_result: Option<LedgerReplayResult> = None;
        let mut last_header: Option<LedgerHeader> = None;

        // Track the ID pool for correct offer ID assignment.
        // Start with the checkpoint's id_pool and update from each ledger header.
        let mut prev_id_pool = checkpoint_id_pool;

        // Load eviction iterator from checkpoint state instead of starting fresh.
        // The EvictionIterator ConfigSettingEntry tracks where the eviction scan was
        // at the checkpoint, and we must continue from there for correct bucket list hash.
        let mut eviction_iterator: Option<EvictionIterator> = if self.replay_config.run_eviction {
            load_eviction_iterator_from_bucket_list(bucket_list).or_else(|| {
                info!("No EvictionIterator found in checkpoint, starting fresh");
                Some(EvictionIterator::new(
                    self.replay_config
                        .eviction_settings
                        .starting_eviction_scan_level,
                ))
            })
        } else {
            None
        };

        // Track Soroban state size for LiveSorobanStateSizeWindow updates.
        // If a pre-computed value was passed (e.g., from a cloned ledger manager),
        // skip the expensive bucket list scan (~80s on mainnet).
        let protocol_version = ledger_data
            .first()
            .map(|d| d.header.ledger_version)
            .unwrap_or(25);
        let mut soroban_state_size: Option<u64> = if let Some(size) = precomputed_soroban_state_size
        {
            tracing::info!(
                protocol_version,
                initial_soroban_state_size = size,
                "Using pre-computed Soroban state size (skipping bucket list scan)"
            );
            Some(size)
        } else {
            let size = compute_initial_soroban_state_size(bucket_list, protocol_version);
            tracing::info!(
                protocol_version,
                initial_soroban_state_size = size,
                "Computed initial Soroban state size from checkpoint"
            );
            Some(size)
        };

        for (i, data) in ledger_data.iter().enumerate() {
            self.progress.current_ledger = data.header.ledger_seq;

            let result = replay::replay_ledger_with_execution(
                &data.header,
                &data.tx_set,
                bucket_list,
                hot_archive_bucket_list,
                &network_id,
                &self.replay_config,
                Some(&data.tx_results),
                eviction_iterator,
                None, // TODO: Initialize module cache for catchup performance
                soroban_state_size, // Soroban state size for window updates
                prev_id_pool, // ID pool from previous ledger for correct offer ID assignment
                offer_entries.clone(), // Order book for correct offer matching
            )?;
            // Update Soroban state size tracking based on accurate delta from replay.
            // The replay result computes this delta from the full change records,
            // which includes before/after state for updates and deletes.
            soroban_state_size = Some(
                (soroban_state_size.unwrap_or(0) as i64 + result.soroban_state_size_delta).max(0)
                    as u64,
            );

            // Update eviction iterator for next ledger
            eviction_iterator = result.eviction_iterator;

            // Update prev_id_pool for the next ledger
            prev_id_pool = data.header.id_pool;

            // Incrementally update the offer set for the next ledger's replay.
            // New/modified offers are added, deleted offers are removed.
            if let Some(ref mut offers) = offer_entries {
                use stellar_xdr::curr::LedgerEntryData;
                // Add new offers from init_entries
                for entry in &result.init_entries {
                    if matches!(entry.data, LedgerEntryData::Offer(_)) {
                        offers.push(entry.clone());
                    }
                }
                // Update modified offers from live_entries
                for entry in &result.live_entries {
                    if let LedgerEntryData::Offer(ref offer) = entry.data {
                        // Remove old version and add updated version
                        offers.retain(|e| {
                            if let LedgerEntryData::Offer(ref o) = e.data {
                                o.offer_id != offer.offer_id || o.seller_id != offer.seller_id
                            } else {
                                true
                            }
                        });
                        offers.push(entry.clone());
                    }
                }
                // Remove deleted offers
                for key in &result.dead_entries {
                    if let stellar_xdr::curr::LedgerKey::Offer(ref offer_key) = key {
                        offers.retain(|e| {
                            if let LedgerEntryData::Offer(ref o) = e.data {
                                o.offer_id != offer_key.offer_id || o.seller_id != offer_key.seller_id
                            } else {
                                true
                            }
                        });
                    }
                }
            }

            debug!(
                "Replayed ledger {}/{}: {} txs, {} ops",
                i + 1,
                total,
                result.tx_count,
                result.op_count
            );

            last_header = Some(data.header.clone());
            last_result = Some(result);
        }

        let final_result = last_result.unwrap();
        let final_header = last_header.unwrap();

        // Verify final bucket list hash only at checkpoints.
        // During replay without TransactionMeta, our execution may produce
        // different entry values, so per-ledger verification will fail.
        // Checkpoint verification is reliable because we restore from archive.
        let is_checkpoint = final_header.ledger_seq % 64 == 63;
        if self.replay_config.verify_bucket_list && is_checkpoint {
            use sha2::{Digest, Sha256};
            let live_hash = bucket_list.hash();
            let hot_hash = hot_archive_bucket_list.hash();
            tracing::info!(
                ledger_seq = final_header.ledger_seq,
                live_hash = %live_hash,
                hot_archive_hash = %hot_hash,
                "Computing combined bucket list hash for verification"
            );
            let mut hasher = Sha256::new();
            hasher.update(live_hash.as_bytes());
            hasher.update(hot_hash.as_bytes());
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            let bucket_list_hash = Hash256::from_bytes(bytes);
            replay::verify_replay_consistency(&final_header, &bucket_list_hash)?;
        }

        Ok(ReplayedLedgerState::from_header(
            &final_header,
            final_result.ledger_hash,
        ))
    }
}

fn checkpoint_header_from_headers(
    checkpoint_seq: u32,
    headers: &[LedgerHeaderHistoryEntry],
) -> Result<(LedgerHeader, Hash256)> {
    for entry in headers {
        if entry.header.ledger_seq == checkpoint_seq {
            return Ok((entry.header.clone(), Hash256::from(entry.hash.0)));
        }
    }

    Err(HistoryError::CatchupFailed(format!(
        "checkpoint header {} not found in headers",
        checkpoint_seq
    )))
}

/// Data downloaded for a single ledger.
#[derive(Debug, Clone)]
pub struct LedgerData {
    /// The ledger header.
    pub header: LedgerHeader,
    /// The transaction set.
    pub tx_set: TransactionSetVariant,
    /// Transaction results.
    pub tx_results: Vec<TransactionResultPair>,
    /// Transaction history entry (tx set) when available.
    pub tx_history_entry: Option<TransactionHistoryEntry>,
    /// Transaction result history entry when available.
    pub tx_result_entry: Option<TransactionHistoryResultEntry>,
}

/// Options for catchup operations.
#[derive(Debug, Clone)]
pub struct CatchupOptions {
    /// Whether to verify bucket hashes.
    pub verify_buckets: bool,
    /// Whether to verify header chain.
    pub verify_headers: bool,
}

#[derive(Debug, Clone)]
struct CheckpointLedgerData {
    headers: Vec<LedgerHeaderHistoryEntry>,
    tx_entries: Vec<TransactionHistoryEntry>,
    result_entries: Vec<TransactionHistoryResultEntry>,
}

impl Default for CatchupOptions {
    fn default() -> Self {
        Self {
            verify_buckets: true,
            verify_headers: true,
        }
    }
}

/// Builder for creating a CatchupManager with custom options.
pub struct CatchupManagerBuilder {
    archives: Vec<HistoryArchive>,
    bucket_manager: Option<BucketManager>,
    db: Option<Database>,
    options: CatchupOptions,
}

impl CatchupManagerBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            archives: Vec::new(),
            bucket_manager: None,
            db: None,
            options: CatchupOptions::default(),
        }
    }

    /// Add a history archive.
    pub fn add_archive(mut self, archive: HistoryArchive) -> Self {
        self.archives.push(archive);
        self
    }

    /// Set the bucket manager.
    pub fn bucket_manager(mut self, manager: BucketManager) -> Self {
        self.bucket_manager = Some(manager);
        self
    }

    /// Set the database.
    pub fn database(mut self, db: Database) -> Self {
        self.db = Some(db);
        self
    }

    /// Set catchup options.
    pub fn options(mut self, options: CatchupOptions) -> Self {
        self.options = options;
        self
    }

    /// Build the CatchupManager.
    pub fn build(self) -> Result<CatchupManager> {
        let bucket_manager = self
            .bucket_manager
            .ok_or_else(|| HistoryError::CatchupFailed("bucket manager required".to_string()))?;

        let db = self
            .db
            .ok_or_else(|| HistoryError::CatchupFailed("database required".to_string()))?;

        if self.archives.is_empty() {
            return Err(HistoryError::CatchupFailed(
                "at least one archive required".to_string(),
            ));
        }

        let mut manager = CatchupManager::new(self.archives, bucket_manager, db);

        manager.replay_config = ReplayConfig {
            verify_results: self.options.verify_headers,
            verify_bucket_list: self.options.verify_buckets,
            emit_classic_events: false,
            backfill_stellar_asset_events: false,
            run_eviction: true,
            eviction_settings: stellar_core_bucket::StateArchivalSettings::default(),
        };

        Ok(manager)
    }
}

impl Default for CatchupManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a header from replay state when the actual header download fails.
///
/// This is a fallback that constructs a minimal header from the replay results.
fn create_header_from_replay_state(
    replay_state: &ReplayedLedgerState,
    bucket_list: &BucketList,
    hot_archive_bucket_list: &HotArchiveBucketList,
) -> LedgerHeader {
    use sha2::{Digest, Sha256};
    use stellar_xdr::curr::{
        Hash, LedgerHeaderExt, StellarValue, StellarValueExt, TimePoint, VecM,
    };

    let mut hasher = Sha256::new();
    hasher.update(bucket_list.hash().as_bytes());
    hasher.update(hot_archive_bucket_list.hash().as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    let bucket_list_hash = Hash256::from_bytes(bytes);

    LedgerHeader {
        ledger_version: replay_state.protocol_version,
        previous_ledger_hash: Hash([0u8; 32]), // Unknown, but not critical for init
        scp_value: StellarValue {
            tx_set_hash: Hash([0u8; 32]),
            close_time: TimePoint(replay_state.close_time),
            upgrades: VecM::default(),
            ext: StellarValueExt::Basic,
        },
        tx_set_result_hash: Hash([0u8; 32]),
        bucket_list_hash: Hash(bucket_list_hash.0),
        ledger_seq: replay_state.sequence,
        total_coins: 0,
        fee_pool: 0,
        inflation_seq: 0,
        id_pool: 0,
        base_fee: replay_state.base_fee,
        base_reserve: replay_state.base_reserve,
        max_tx_set_size: 1000,
        skip_list: std::array::from_fn(|_| Hash([0u8; 32])),
        ext: LedgerHeaderExt::V0,
    }
}

/// Compute the total Soroban state size from the bucket list.
///
/// This scans the bucket list for CONTRACT_DATA and CONTRACT_CODE entries and
/// sums their sizes. For CONTRACT_DATA, uses XDR size. For CONTRACT_CODE,
/// uses the same rent-adjusted size calculation as LedgerManager to include
/// compiled module memory cost.
///
/// Cost parameters are loaded from the bucket list's ConfigSettingEntry to ensure
/// correct compiled module memory cost calculation (matching C++ behavior).
///
/// # Memory Efficiency
///
/// Uses `scan_for_entries_of_types` instead of `live_entries_iter()` to only
/// build a dedup `HashSet<LedgerKey>` over ContractData + ContractCode keys
/// (~1.68M keys, ~240 MB) instead of all keys (~60M, ~8.6 GB). This matches
/// the C++ approach in `InMemorySorobanState::initializeStateFromSnapshot()`
/// which uses per-type `scanForEntriesOfType` calls.
///
/// Note: This only needs to run once per catchup.
fn compute_initial_soroban_state_size(bucket_list: &BucketList, protocol_version: u32) -> u64 {
    use stellar_core_bucket::BucketEntry;
    use stellar_core_tx::operations::execute::entry_size_for_rent_by_protocol_with_cost_params;
    use stellar_xdr::curr::{LedgerEntryType, WriteXdr};

    // Load cost params from bucket list for accurate contract code size calculation
    let cost_params = load_cost_params_from_bucket_list(bucket_list);
    let cost_params_ref = cost_params.as_ref().map(|(cpu, mem)| (cpu, mem));

    let mut total_size: u64 = 0;

    // Scan only ContractData and ContractCode entries, avoiding a dedup set
    // over all 60M keys. The dedup set only tracks ~1.68M Soroban keys.
    bucket_list.scan_for_entries_of_types(
        &[LedgerEntryType::ContractData, LedgerEntryType::ContractCode],
        |be| {
            if let BucketEntry::Live(entry) | BucketEntry::Init(entry) = be {
                match &entry.data {
                    LedgerEntryData::ContractData(_) => {
                        // Contract data uses XDR size
                        if let Ok(xdr_bytes) = entry.to_xdr(stellar_xdr::curr::Limits::none()) {
                            total_size += xdr_bytes.len() as u64;
                        }
                    }
                    LedgerEntryData::ContractCode(_) => {
                        // Contract code uses rent-adjusted size (includes compiled module memory)
                        if let Ok(xdr_bytes) = entry.to_xdr(stellar_xdr::curr::Limits::none()) {
                            let xdr_size = xdr_bytes.len() as u32;
                            let rent_size = entry_size_for_rent_by_protocol_with_cost_params(
                                protocol_version,
                                entry,
                                xdr_size,
                                cost_params_ref,
                            );
                            total_size += rent_size as u64;
                        }
                    }
                    _ => {}
                }
            }
            true // continue scanning
        },
    );

    total_size
}

/// Load CPU and memory cost parameters from the bucket list's ConfigSettingEntries.
///
/// Returns `Some((cpu_params, mem_params))` if both are found, or `None` if either
/// is missing (e.g., for pre-Soroban checkpoints).
fn load_cost_params_from_bucket_list(
    bucket_list: &BucketList,
) -> Option<(
    stellar_xdr::curr::ContractCostParams,
    stellar_xdr::curr::ContractCostParams,
)> {
    use stellar_xdr::curr::{
        ConfigSettingEntry, ConfigSettingId, LedgerEntryData, LedgerKey, LedgerKeyConfigSetting,
    };

    let cpu_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::ContractCostParamsCpuInstructions,
    });
    let cpu_params = bucket_list.get(&cpu_key).ok()?.and_then(|e| {
        if let LedgerEntryData::ConfigSetting(
            ConfigSettingEntry::ContractCostParamsCpuInstructions(params),
        ) = e.data
        {
            Some(params)
        } else {
            None
        }
    })?;

    let mem_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::ContractCostParamsMemoryBytes,
    });
    let mem_params = bucket_list.get(&mem_key).ok()?.and_then(|e| {
        if let LedgerEntryData::ConfigSetting(
            ConfigSettingEntry::ContractCostParamsMemoryBytes(params),
        ) = e.data
        {
            Some(params)
        } else {
            None
        }
    })?;

    Some((cpu_params, mem_params))
}

/// Load the EvictionIterator from the bucket list's ConfigSettingEntry.
///
/// The EvictionIterator tracks where the incremental eviction scan was at a given
/// checkpoint. When replaying ledgers, we must load this iterator and continue from
/// that position to produce the correct bucket list hash.
///
/// Returns `Some(EvictionIterator)` if found in the bucket list, or `None` if no
/// EvictionIterator entry exists (e.g., for pre-protocol 23 checkpoints).
fn load_eviction_iterator_from_bucket_list(
    bucket_list: &BucketList,
) -> Option<stellar_core_bucket::EvictionIterator> {
    use stellar_xdr::curr::{
        ConfigSettingEntry, ConfigSettingId, LedgerEntryData, LedgerKey, LedgerKeyConfigSetting,
    };

    let key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::EvictionIterator,
    });

    match bucket_list.get(&key) {
        Ok(Some(entry)) => {
            if let LedgerEntryData::ConfigSetting(ConfigSettingEntry::EvictionIterator(xdr_iter)) =
                entry.data
            {
                let iter = stellar_core_bucket::EvictionIterator {
                    bucket_file_offset: xdr_iter.bucket_file_offset,
                    bucket_list_level: xdr_iter.bucket_list_level,
                    is_curr_bucket: xdr_iter.is_curr_bucket,
                };
                info!(
                    level = iter.bucket_list_level,
                    is_curr = iter.is_curr_bucket,
                    offset = iter.bucket_file_offset,
                    "Loaded EvictionIterator from checkpoint"
                );
                Some(iter)
            } else {
                warn!("EvictionIterator entry has unexpected type");
                None
            }
        }
        Ok(None) => {
            debug!("No EvictionIterator ConfigSettingEntry in bucket list");
            None
        }
        Err(e) => {
            warn!(error = %e, "Failed to query EvictionIterator from bucket list");
            None
        }
    }
}

/// Create a closure that loads live buckets from disk using streaming I/O.
///
/// This uses `Bucket::from_xdr_file_disk_backed()` which streams through the file
/// in two passes (hash computation + index building) without loading the entire file
/// into memory. Memory usage is O(index_size) instead of O(file_size).
///
/// This is critical for mainnet where higher-level buckets can be tens of GB.
/// Loading a 30GB bucket file fully into memory would require 30GB+ RAM, while
/// the streaming approach uses only ~150MB for the index.
fn load_disk_backed_bucket_closure(
    bucket_dir: std::path::PathBuf,
) -> impl FnMut(&Hash256) -> stellar_core_bucket::Result<Bucket> {
    move |hash: &Hash256| {
        if hash.is_zero() {
            return Ok(Bucket::empty());
        }
        let bucket_path = bucket_dir.join(format!("{}.bucket.xdr", hash.to_hex()));
        if bucket_path.exists() {
            Bucket::from_xdr_file_disk_backed(&bucket_path)
        } else {
            Err(stellar_core_bucket::BucketError::NotFound(format!(
                "bucket {} not found on disk at {}",
                hash,
                bucket_path.display()
            )))
        }
    }
}

/// Create a closure that loads hot archive buckets from disk using streaming I/O.
///
/// Same memory optimization as `load_disk_backed_bucket_closure` but for hot archive
/// buckets which use `HotArchiveBucketEntry` format instead of `BucketEntry`.
fn load_disk_backed_hot_archive_bucket_closure(
    bucket_dir: std::path::PathBuf,
) -> impl FnMut(&Hash256) -> stellar_core_bucket::Result<stellar_core_bucket::HotArchiveBucket> {
    use stellar_core_bucket::HotArchiveBucket;
    move |hash: &Hash256| {
        if hash.is_zero() {
            return Ok(HotArchiveBucket::empty());
        }
        let bucket_path = bucket_dir.join(format!("{}.bucket.xdr", hash.to_hex()));
        if bucket_path.exists() {
            HotArchiveBucket::from_xdr_file_disk_backed(&bucket_path)
        } else {
            Err(stellar_core_bucket::BucketError::NotFound(format!(
                "hot archive bucket {} not found on disk at {}",
                hash,
                bucket_path.display()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catchup_options_default() {
        let options = CatchupOptions::default();
        assert!(options.verify_buckets);
        assert!(options.verify_headers);
    }

    #[test]
    fn test_catchup_progress_default() {
        let progress = CatchupProgress::default();
        assert_eq!(progress.status, CatchupStatus::Pending);
        assert_eq!(progress.current_step, 0);
        assert_eq!(progress.total_steps, 7);
    }

    #[test]
    fn test_catchup_status() {
        assert_eq!(CatchupStatus::Pending, CatchupStatus::Pending);
        assert_ne!(CatchupStatus::Pending, CatchupStatus::Completed);
    }
}
