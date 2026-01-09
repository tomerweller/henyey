//! History work items for Stellar Core catchup and publish workflows.
//!
//! This crate provides the building blocks for downloading and publishing Stellar
//! history archive data. It implements a work-item based architecture that integrates
//! with the [`stellar_core_work`] scheduler to orchestrate complex multi-step operations
//! with proper dependency management and retry logic.
//!
//! # Overview
//!
//! History archives store snapshots of the Stellar ledger at regular checkpoint intervals
//! (every 64 ledgers). This crate provides work items to:
//!
//! - **Download** history data: HAS (History Archive State), buckets, ledger headers,
//!   transactions, transaction results, and SCP consensus history
//! - **Verify** downloaded data: hash verification for buckets, header chain validation,
//!   and transaction set integrity checks
//! - **Publish** history data: write checkpoint data back to archives for archival nodes
//!
//! # Architecture
//!
//! Work items are organized as a directed acyclic graph (DAG) of dependencies:
//!
//! ```text
//!                    ┌─────────────┐
//!                    │  Fetch HAS  │
//!                    └──────┬──────┘
//!                           │
//!           ┌───────────────┼───────────────┐
//!           │               │               │
//!           ▼               ▼               ▼
//!    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
//!    │  Download   │ │  Download   │ │  Download   │
//!    │  Buckets    │ │  Headers    │ │    SCP      │
//!    └─────────────┘ └──────┬──────┘ └─────────────┘
//!                           │
//!                    ┌──────┴──────┐
//!                    ▼             ▼
//!             ┌─────────────┐ ┌─────────────┐
//!             │  Download   │ │  Download   │
//!             │Transactions │ │  Results    │
//!             └─────────────┘ └─────────────┘
//! ```
//!
//! All work items share state through [`SharedHistoryState`], a thread-safe container
//! that accumulates downloaded data as work progresses.
//!
//! # Usage
//!
//! ## Downloading checkpoint data
//!
//! Use [`HistoryWorkBuilder`] to register download work items with a scheduler:
//!
//! ```rust,ignore
//! use stellar_core_historywork::{HistoryWorkBuilder, SharedHistoryState};
//! use stellar_core_work::WorkScheduler;
//!
//! // Create shared state for work items
//! let state: SharedHistoryState = Default::default();
//!
//! // Build and register work items
//! let builder = HistoryWorkBuilder::new(archive, checkpoint, state.clone());
//! let work_ids = builder.register(&mut scheduler);
//!
//! // Run the scheduler to completion
//! scheduler.run_to_completion().await?;
//!
//! // Extract downloaded data for catchup
//! let checkpoint_data = build_checkpoint_data(&state).await?;
//! ```
//!
//! ## Publishing checkpoint data
//!
//! For archival nodes that need to publish history:
//!
//! ```rust,ignore
//! use stellar_core_historywork::{HistoryWorkBuilder, LocalArchiveWriter};
//!
//! // Create a writer for the target archive
//! let writer = Arc::new(LocalArchiveWriter::new(archive_path));
//!
//! // Register publish work after download work completes
//! let download_ids = builder.register(&mut scheduler);
//! let publish_ids = builder.register_publish(&mut scheduler, writer, download_ids);
//! ```
//!
//! # Key Types
//!
//! - [`HistoryWorkState`]: Shared container for downloaded history data
//! - [`HistoryWorkBuilder`]: Factory for registering work items with proper dependencies
//! - [`ArchiveWriter`]: Trait for publishing data to history archives
//! - [`CheckpointData`]: Complete snapshot of a checkpoint for catchup operations

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use flate2::{write::GzEncoder, Compression};
use tokio::sync::Mutex;

use stellar_core_common::Hash256;
use stellar_core_history::{
    archive::HistoryArchive,
    archive_state::HistoryArchiveState,
    paths::{bucket_path, checkpoint_path},
    verify,
    CheckpointData,
};
use stellar_core_ledger::TransactionSetVariant;
use stellar_core_work::{Work, WorkContext, WorkId, WorkOutcome, WorkScheduler};
use stellar_xdr::curr::{
    LedgerHeaderHistoryEntry, ScpHistoryEntry, TransactionHistoryEntry, TransactionHistoryEntryExt,
    TransactionHistoryResultEntry, WriteXdr,
};

/// Shared state container for history work items.
///
/// This struct accumulates data as download work items complete. Each field
/// is populated by its corresponding download work item and consumed by
/// either verification steps or the final [`build_checkpoint_data`] call.
///
/// # Thread Safety
///
/// This type is wrapped in [`SharedHistoryState`] (an `Arc<Mutex<...>>`) for
/// safe sharing between concurrent work items. Work items acquire the lock
/// briefly to read dependencies or write their output.
///
/// # Fields
///
/// - `has`: The History Archive State describing the checkpoint's bucket list
/// - `buckets`: Raw bucket data keyed by hash, used to reconstruct ledger state
/// - `headers`: Ledger headers for all ledgers in the checkpoint range
/// - `transactions`: Transaction sets for each ledger
/// - `tx_results`: Transaction results (meta) for each ledger
/// - `scp_history`: SCP consensus messages for the checkpoint
/// - `progress`: Current work stage and status message for monitoring
#[derive(Debug, Default)]
pub struct HistoryWorkState {
    /// The History Archive State (HAS) for this checkpoint.
    ///
    /// Contains the bucket list structure that describes the complete ledger
    /// state at the checkpoint boundary.
    pub has: Option<HistoryArchiveState>,

    /// Downloaded bucket data, keyed by SHA-256 hash.
    ///
    /// Buckets contain the actual ledger entries (accounts, trustlines, etc.)
    /// organized in a multi-level structure for efficient incremental updates.
    pub buckets: HashMap<Hash256, Vec<u8>>,

    /// Ledger header history entries for the checkpoint range.
    ///
    /// Contains headers for 64 consecutive ledgers, linking each ledger to
    /// its predecessor via the `previous_ledger_hash` field.
    pub headers: Vec<LedgerHeaderHistoryEntry>,

    /// Transaction history entries containing transaction sets.
    ///
    /// Each entry contains all transactions applied in a single ledger,
    /// either as a classic transaction set or a generalized (phase-based) set.
    pub transactions: Vec<TransactionHistoryEntry>,

    /// Transaction result entries containing execution results and metadata.
    ///
    /// Stores the outcome of each transaction including fee charges,
    /// operation results, and ledger changes.
    pub tx_results: Vec<TransactionHistoryResultEntry>,

    /// SCP consensus history for the checkpoint.
    ///
    /// Records the consensus messages exchanged to close each ledger,
    /// useful for auditing and debugging consensus behavior.
    pub scp_history: Vec<ScpHistoryEntry>,

    /// Current progress indicator for monitoring work execution.
    pub progress: HistoryWorkProgress,
}

/// Thread-safe handle to shared history work state.
///
/// This type alias wraps [`HistoryWorkState`] in an `Arc<Mutex<...>>` for
/// safe sharing between work items. Use `state.lock().await` to access
/// the underlying state.
///
/// # Example
///
/// ```rust,ignore
/// let state: SharedHistoryState = Default::default();
///
/// // In a work item:
/// let mut guard = state.lock().await;
/// guard.has = Some(downloaded_has);
/// ```
pub type SharedHistoryState = Arc<Mutex<HistoryWorkState>>;

/// Identifies the current stage of history work execution.
///
/// This enum is used for progress reporting and monitoring. Each variant
/// corresponds to a specific work item in the download or publish pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryWorkStage {
    /// Fetching the History Archive State (HAS) JSON file.
    FetchHas,
    /// Downloading bucket files referenced by the HAS.
    DownloadBuckets,
    /// Downloading ledger header XDR files.
    DownloadHeaders,
    /// Downloading transaction set XDR files.
    DownloadTransactions,
    /// Downloading transaction result XDR files.
    DownloadResults,
    /// Downloading SCP consensus history XDR files.
    DownloadScp,
    /// Publishing the History Archive State to the target archive.
    PublishHas,
    /// Publishing bucket files to the target archive.
    PublishBuckets,
    /// Publishing ledger header files to the target archive.
    PublishHeaders,
    /// Publishing transaction files to the target archive.
    PublishTransactions,
    /// Publishing transaction result files to the target archive.
    PublishResults,
    /// Publishing SCP history files to the target archive.
    PublishScp,
}

/// Progress indicator for history work execution.
///
/// This struct provides a snapshot of the current work stage and a
/// human-readable status message. Use [`get_progress`] to retrieve
/// the current progress from shared state.
///
/// # Example
///
/// ```rust,ignore
/// let progress = get_progress(&state).await;
/// if let Some(stage) = progress.stage {
///     println!("Stage: {:?}, Status: {}", stage, progress.message);
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct HistoryWorkProgress {
    /// The current work stage, if any work is in progress.
    pub stage: Option<HistoryWorkStage>,
    /// Human-readable status message describing the current operation.
    pub message: String,
}

/// Updates the progress indicator in shared state.
///
/// This is an internal helper used by work items to report their current
/// stage and status message.
async fn set_progress(state: &SharedHistoryState, stage: HistoryWorkStage, message: &str) {
    let mut guard = state.lock().await;
    guard.progress.stage = Some(stage);
    guard.progress.message = message.to_string();
}

/// Work item to fetch the History Archive State (HAS) for a checkpoint.
///
/// The HAS is a JSON document that describes the complete bucket list structure
/// at a checkpoint boundary. It is the starting point for catchup operations,
/// as it lists all bucket hashes needed to reconstruct ledger state.
///
/// This work item must complete before any other download work can proceed,
/// as the HAS is required to know which buckets to download.
///
/// # Dependencies
///
/// None - this is the root of the download work graph.
///
/// # Output
///
/// On success, populates `state.has` with the parsed [`HistoryArchiveState`].
pub struct GetHistoryArchiveStateWork {
    archive: Arc<HistoryArchive>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl GetHistoryArchiveStateWork {
    /// Creates a new HAS download work item.
    ///
    /// # Arguments
    ///
    /// * `archive` - The history archive to fetch from
    /// * `checkpoint` - The checkpoint ledger sequence number
    /// * `state` - Shared state to store the downloaded HAS
    pub fn new(archive: Arc<HistoryArchive>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            archive,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for GetHistoryArchiveStateWork {
    fn name(&self) -> &str {
        "get-history-archive-state"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::FetchHas, "fetching HAS").await;
        match self.archive.get_checkpoint_has(self.checkpoint).await {
            Ok(has) => {
                let mut guard = self.state.lock().await;
                guard.has = Some(has);
                WorkOutcome::Success
            }
            Err(err) => WorkOutcome::Failed(format!("failed to fetch HAS: {}", err)),
        }
    }
}

/// Work item to download and verify bucket files referenced in the HAS.
///
/// Buckets contain the actual ledger entries (accounts, trustlines, offers,
/// contract data, etc.) organized in a multi-level structure. This work item
/// downloads all unique buckets referenced by the HAS and verifies each
/// bucket's SHA-256 hash.
///
/// # Parallelism
///
/// Downloads are performed concurrently with up to 16 parallel requests,
/// matching the C++ stellar-core `MAX_CONCURRENT_SUBPROCESSES` limit.
///
/// # Dependencies
///
/// Requires [`GetHistoryArchiveStateWork`] to complete first, as the HAS
/// contains the list of bucket hashes to download.
///
/// # Output
///
/// On success, populates `state.buckets` with a map of hash -> bucket data.
pub struct DownloadBucketsWork {
    archive: Arc<HistoryArchive>,
    state: SharedHistoryState,
}

impl DownloadBucketsWork {
    /// Creates a new bucket download work item.
    ///
    /// # Arguments
    ///
    /// * `archive` - The history archive to fetch buckets from
    /// * `state` - Shared state containing the HAS and where buckets will be stored
    pub fn new(archive: Arc<HistoryArchive>, state: SharedHistoryState) -> Self {
        Self { archive, state }
    }
}

#[async_trait]
impl Work for DownloadBucketsWork {
    fn name(&self) -> &str {
        "download-buckets"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        use futures::stream::{self, StreamExt};

        set_progress(&self.state, HistoryWorkStage::DownloadBuckets, "downloading buckets").await;
        let has = {
            let guard = self.state.lock().await;
            guard.has.clone()
        };

        let Some(has) = has else {
            return WorkOutcome::Failed("missing HAS".to_string());
        };

        let hashes = has.unique_bucket_hashes();
        let total = hashes.len();
        let archive = self.archive.clone();

        // Download buckets in parallel (16 concurrent downloads, matching C++ MAX_CONCURRENT_SUBPROCESSES)
        let results: Vec<Result<(Hash256, Vec<u8>), String>> = stream::iter(hashes)
            .map(|hash| {
                let archive = archive.clone();
                async move {
                    match archive.get_bucket(&hash).await {
                        Ok(data) => {
                            if let Err(err) = verify::verify_bucket_hash(&data, &hash) {
                                Err(format!("bucket {} hash mismatch: {}", hash, err))
                            } else {
                                Ok((hash, data))
                            }
                        }
                        Err(err) => Err(format!("failed to download bucket {}: {}", hash, err)),
                    }
                }
            })
            .buffer_unordered(16)
            .collect()
            .await;

        // Check for failures and collect successful downloads
        let mut buckets = HashMap::new();
        for result in results {
            match result {
                Ok((hash, data)) => {
                    buckets.insert(hash, data);
                }
                Err(err) => {
                    return WorkOutcome::Failed(err);
                }
            }
        }

        tracing::info!("Downloaded {} buckets in parallel", total);

        let mut guard = self.state.lock().await;
        guard.buckets = buckets;
        WorkOutcome::Success
    }
}

/// Work item to download and verify ledger headers for a checkpoint.
///
/// Downloads the ledger header history file for a checkpoint range (64 ledgers)
/// and verifies the header chain integrity by checking that each header's
/// `previous_ledger_hash` matches the hash of the preceding header.
///
/// Ledger headers are essential for:
/// - Verifying transaction set hashes
/// - Verifying transaction result hashes
/// - Establishing the ledger sequence and timing
///
/// # Dependencies
///
/// Requires [`GetHistoryArchiveStateWork`] to complete first.
///
/// # Output
///
/// On success, populates `state.headers` with verified header entries.
pub struct DownloadLedgerHeadersWork {
    archive: Arc<HistoryArchive>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl DownloadLedgerHeadersWork {
    /// Creates a new ledger headers download work item.
    ///
    /// # Arguments
    ///
    /// * `archive` - The history archive to fetch headers from
    /// * `checkpoint` - The checkpoint ledger sequence number
    /// * `state` - Shared state where headers will be stored
    pub fn new(archive: Arc<HistoryArchive>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            archive,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for DownloadLedgerHeadersWork {
    fn name(&self) -> &str {
        "download-ledger-headers"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::DownloadHeaders, "downloading headers").await;
        match self.archive.get_ledger_headers(self.checkpoint).await {
            Ok(headers) => {
                let header_chain: Vec<_> = headers.iter().map(|entry| entry.header.clone()).collect();
                if let Err(err) = verify::verify_header_chain(&header_chain) {
                    return WorkOutcome::Failed(format!("header chain verification failed: {}", err));
                }
                let mut guard = self.state.lock().await;
                guard.headers = headers;
                WorkOutcome::Success
            }
            Err(err) => WorkOutcome::Failed(format!("failed to download headers: {}", err)),
        }
    }
}

/// Work item to download and verify transaction sets for a checkpoint.
///
/// Downloads the transaction history file containing all transactions applied
/// during the checkpoint range. Each transaction set is verified against its
/// corresponding ledger header's `tx_set_result_hash`.
///
/// Transaction sets come in two variants:
/// - Classic: original format with a simple list of transactions
/// - Generalized: phase-based format supporting Soroban transactions
///
/// # Dependencies
///
/// Requires [`DownloadLedgerHeadersWork`] to complete first, as headers are
/// needed to verify transaction set hashes.
///
/// # Output
///
/// On success, populates `state.transactions` with verified transaction entries.
pub struct DownloadTransactionsWork {
    archive: Arc<HistoryArchive>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl DownloadTransactionsWork {
    /// Creates a new transactions download work item.
    ///
    /// # Arguments
    ///
    /// * `archive` - The history archive to fetch transactions from
    /// * `checkpoint` - The checkpoint ledger sequence number
    /// * `state` - Shared state where transactions will be stored
    pub fn new(archive: Arc<HistoryArchive>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            archive,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for DownloadTransactionsWork {
    fn name(&self) -> &str {
        "download-transactions"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::DownloadTransactions, "downloading transactions").await;
        match self.archive.get_transactions(self.checkpoint).await {
            Ok(entries) => {
                let headers = {
                    let guard = self.state.lock().await;
                    guard.headers.clone()
                };
                for entry in &entries {
                    if let Some(header) = headers.iter().find(|h| h.header.ledger_seq == entry.ledger_seq) {
                        let tx_set = match &entry.ext {
                            TransactionHistoryEntryExt::V0 => {
                                TransactionSetVariant::Classic(entry.tx_set.clone())
                            }
                            TransactionHistoryEntryExt::V1(set) => {
                                TransactionSetVariant::Generalized(set.clone())
                            }
                        };
                        if let Err(err) = verify::verify_tx_set(&header.header, &tx_set) {
                            return WorkOutcome::Failed(format!("tx set hash mismatch: {}", err));
                        }
                    }
                }
                let mut guard = self.state.lock().await;
                guard.transactions = entries;
                WorkOutcome::Success
            }
            Err(err) => WorkOutcome::Failed(format!("failed to download transactions: {}", err)),
        }
    }
}

/// Work item to download and verify transaction results for a checkpoint.
///
/// Downloads the transaction results history file containing the execution
/// outcomes and ledger changes (metadata) for all transactions in the
/// checkpoint range. Each result set is verified against its corresponding
/// ledger header's result hash.
///
/// Transaction results include:
/// - Fee charges and refunds
/// - Operation-level success/failure results
/// - Ledger entry changes (creates, updates, deletes)
/// - Soroban contract execution metadata
///
/// # Dependencies
///
/// Requires both [`DownloadLedgerHeadersWork`] and [`DownloadTransactionsWork`]
/// to complete first.
///
/// # Output
///
/// On success, populates `state.tx_results` with verified result entries.
pub struct DownloadTxResultsWork {
    archive: Arc<HistoryArchive>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl DownloadTxResultsWork {
    /// Creates a new transaction results download work item.
    ///
    /// # Arguments
    ///
    /// * `archive` - The history archive to fetch results from
    /// * `checkpoint` - The checkpoint ledger sequence number
    /// * `state` - Shared state where results will be stored
    pub fn new(archive: Arc<HistoryArchive>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            archive,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for DownloadTxResultsWork {
    fn name(&self) -> &str {
        "download-tx-results"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        let headers = {
            let guard = self.state.lock().await;
            guard.headers.clone()
        };

        set_progress(&self.state, HistoryWorkStage::DownloadResults, "downloading transaction results").await;
        match self.archive.get_results(self.checkpoint).await {
            Ok(results) => {
                for entry in &results {
                    if let Some(header) = headers.iter().find(|h| h.header.ledger_seq == entry.ledger_seq) {
                        if let Ok(xdr) = entry.tx_result_set.to_xdr(stellar_xdr::curr::Limits::none()) {
                            if let Err(err) = verify::verify_tx_result_set(&header.header, &xdr) {
                                return WorkOutcome::Failed(format!("tx result set hash mismatch: {}", err));
                            }
                        }
                    }
                }
                let mut guard = self.state.lock().await;
                guard.tx_results = results;
                WorkOutcome::Success
            }
            Err(err) => WorkOutcome::Failed(format!("failed to download tx results: {}", err)),
        }
    }
}

/// Work item to download SCP consensus history for a checkpoint.
///
/// Downloads the SCP history file containing the consensus protocol messages
/// exchanged to close each ledger in the checkpoint range. This data is
/// optional for catchup but useful for:
///
/// - Auditing consensus behavior and vote distribution
/// - Debugging network issues or validator performance
/// - Historical analysis of the consensus process
///
/// # Dependencies
///
/// Requires [`DownloadLedgerHeadersWork`] to complete first.
///
/// # Output
///
/// On success, populates `state.scp_history` with SCP entries.
pub struct DownloadScpHistoryWork {
    archive: Arc<HistoryArchive>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl DownloadScpHistoryWork {
    /// Creates a new SCP history download work item.
    ///
    /// # Arguments
    ///
    /// * `archive` - The history archive to fetch SCP history from
    /// * `checkpoint` - The checkpoint ledger sequence number
    /// * `state` - Shared state where SCP history will be stored
    pub fn new(archive: Arc<HistoryArchive>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            archive,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for DownloadScpHistoryWork {
    fn name(&self) -> &str {
        "download-scp-history"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::DownloadScp, "downloading SCP history").await;
        match self.archive.get_scp_history(self.checkpoint).await {
            Ok(entries) => {
                let mut guard = self.state.lock().await;
                guard.scp_history = entries;
                WorkOutcome::Success
            }
            Err(err) => WorkOutcome::Failed(format!("failed to download SCP history: {}", err)),
        }
    }
}

/// Trait for writing data to a history archive.
///
/// This trait abstracts the storage backend for publish operations, allowing
/// the same publish work items to write to local filesystems, cloud storage,
/// or any other destination.
///
/// # Implementing Custom Writers
///
/// Implement this trait for custom storage backends:
///
/// ```rust,ignore
/// use stellar_core_historywork::ArchiveWriter;
///
/// struct S3ArchiveWriter {
///     bucket: String,
///     client: S3Client,
/// }
///
/// #[async_trait]
/// impl ArchiveWriter for S3ArchiveWriter {
///     async fn put_bytes(&self, path: &str, data: &[u8]) -> Result<()> {
///         self.client.put_object(&self.bucket, path, data).await
///     }
/// }
/// ```
#[async_trait]
pub trait ArchiveWriter: Send + Sync {
    /// Writes raw bytes to the given path in the archive.
    ///
    /// The path is relative to the archive root and follows the standard
    /// history archive directory structure (e.g., `bucket/00/00/00/...`).
    ///
    /// Implementations should create any necessary parent directories.
    async fn put_bytes(&self, path: &str, data: &[u8]) -> Result<()>;
}

/// Local filesystem implementation of [`ArchiveWriter`].
///
/// Writes history archive files to a local directory. Primarily useful for:
/// - Local testing and development
/// - Populating a local archive for offline use
/// - Debugging publish operations
///
/// # Example
///
/// ```rust,ignore
/// use stellar_core_historywork::LocalArchiveWriter;
/// use std::path::PathBuf;
///
/// let writer = LocalArchiveWriter::new(PathBuf::from("/var/stellar/history"));
/// writer.put_bytes("history/00/00/00/history-0000003f.json", &json_bytes).await?;
/// ```
pub struct LocalArchiveWriter {
    base_dir: PathBuf,
}

impl LocalArchiveWriter {
    /// Creates a new local archive writer with the given base directory.
    ///
    /// All paths written through this writer will be relative to this directory.
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Resolves a relative archive path to an absolute filesystem path.
    fn full_path(&self, path: &str) -> PathBuf {
        self.base_dir.join(path)
    }
}

#[async_trait]
impl ArchiveWriter for LocalArchiveWriter {
    async fn put_bytes(&self, path: &str, data: &[u8]) -> Result<()> {
        let full_path = self.full_path(path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(full_path, data)?;
        Ok(())
    }
}

/// Compresses data using gzip with default compression level.
///
/// History archive files are stored gzip-compressed to reduce bandwidth
/// and storage requirements.
fn gzip_bytes(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    use std::io::Write;
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// Serializes a slice of XDR-encodable entries into concatenated binary form.
///
/// History archive files contain sequences of XDR-encoded entries without
/// length prefixes, relying on XDR's self-delimiting format.
fn serialize_entries<T: WriteXdr>(entries: &[T]) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    for entry in entries {
        let xdr = entry.to_xdr(stellar_xdr::curr::Limits::none())?;
        data.extend_from_slice(&xdr);
    }
    Ok(data)
}

/// Work item to publish the History Archive State (HAS) to an archive.
///
/// Serializes the HAS to JSON format and writes it to the standard history
/// archive path. The HAS is the entry point for catchup operations and must
/// be published last to ensure all referenced data is available.
///
/// # Dependencies
///
/// Requires [`GetHistoryArchiveStateWork`] to have completed with a valid HAS.
pub struct PublishHistoryArchiveStateWork {
    writer: Arc<dyn ArchiveWriter>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl PublishHistoryArchiveStateWork {
    /// Creates a new HAS publish work item.
    ///
    /// # Arguments
    ///
    /// * `writer` - The archive writer to publish to
    /// * `checkpoint` - The checkpoint ledger sequence number
    /// * `state` - Shared state containing the HAS to publish
    pub fn new(writer: Arc<dyn ArchiveWriter>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            writer,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for PublishHistoryArchiveStateWork {
    fn name(&self) -> &str {
        "publish-has"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::PublishHas, "publishing HAS").await;
        let has = {
            let guard = self.state.lock().await;
            guard.has.clone()
        };
        let Some(has) = has else {
            return WorkOutcome::Failed("HAS not available".to_string());
        };

        match has.to_json() {
            Ok(json) => {
                let path = checkpoint_path("history", self.checkpoint, "json");
                if let Err(err) = self.writer.put_bytes(&path, json.as_bytes()).await {
                    return WorkOutcome::Failed(format!("failed to publish HAS: {}", err));
                }
                WorkOutcome::Success
            }
            Err(err) => WorkOutcome::Failed(format!("failed to serialize HAS: {}", err)),
        }
    }
}

/// Work item to publish bucket files from downloaded state.
///
/// Compresses each bucket with gzip and writes it to the standard bucket
/// directory structure (e.g., `bucket/00/00/00/bucket-<hash>.xdr.gz`).
///
/// # Dependencies
///
/// Requires [`DownloadBucketsWork`] to have completed with valid bucket data.
pub struct PublishBucketsWork {
    writer: Arc<dyn ArchiveWriter>,
    state: SharedHistoryState,
}

impl PublishBucketsWork {
    /// Creates a new bucket publish work item.
    ///
    /// # Arguments
    ///
    /// * `writer` - The archive writer to publish to
    /// * `state` - Shared state containing the buckets to publish
    pub fn new(writer: Arc<dyn ArchiveWriter>, state: SharedHistoryState) -> Self {
        Self { writer, state }
    }
}

/// Work item to publish ledger headers to an archive.
///
/// Serializes ledger headers to XDR format, compresses with gzip, and writes
/// to the standard checkpoint path (e.g., `ledger/00/00/00/ledger-0000003f.xdr.gz`).
///
/// # Dependencies
///
/// Requires [`DownloadLedgerHeadersWork`] to have completed with valid headers.
pub struct PublishLedgerHeadersWork {
    writer: Arc<dyn ArchiveWriter>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl PublishLedgerHeadersWork {
    /// Creates a new ledger headers publish work item.
    ///
    /// # Arguments
    ///
    /// * `writer` - The archive writer to publish to
    /// * `checkpoint` - The checkpoint ledger sequence number
    /// * `state` - Shared state containing the headers to publish
    pub fn new(writer: Arc<dyn ArchiveWriter>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            writer,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for PublishLedgerHeadersWork {
    fn name(&self) -> &str {
        "publish-ledger-headers"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::PublishHeaders, "publishing headers").await;
        let headers = {
            let guard = self.state.lock().await;
            guard.headers.clone()
        };

        let data = match serialize_entries(&headers) {
            Ok(data) => data,
            Err(err) => return WorkOutcome::Failed(format!("failed to serialize headers: {}", err)),
        };
        let gz = match gzip_bytes(&data) {
            Ok(gz) => gz,
            Err(err) => return WorkOutcome::Failed(format!("failed to gzip headers: {}", err)),
        };

        let path = checkpoint_path("ledger", self.checkpoint, "xdr.gz");
        if let Err(err) = self.writer.put_bytes(&path, &gz).await {
            return WorkOutcome::Failed(format!("failed to publish headers: {}", err));
        }

        WorkOutcome::Success
    }
}

/// Work item to publish transaction history entries to an archive.
///
/// Serializes transaction entries to XDR format, compresses with gzip, and writes
/// to the standard checkpoint path (e.g., `transactions/00/00/00/transactions-0000003f.xdr.gz`).
///
/// # Dependencies
///
/// Requires [`DownloadTransactionsWork`] to have completed with valid transactions.
pub struct PublishTransactionsWork {
    writer: Arc<dyn ArchiveWriter>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl PublishTransactionsWork {
    /// Creates a new transactions publish work item.
    ///
    /// # Arguments
    ///
    /// * `writer` - The archive writer to publish to
    /// * `checkpoint` - The checkpoint ledger sequence number
    /// * `state` - Shared state containing the transactions to publish
    pub fn new(writer: Arc<dyn ArchiveWriter>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            writer,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for PublishTransactionsWork {
    fn name(&self) -> &str {
        "publish-transactions"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(
            &self.state,
            HistoryWorkStage::PublishTransactions,
            "publishing transactions",
        )
        .await;
        let transactions = {
            let guard = self.state.lock().await;
            guard.transactions.clone()
        };

        let data = match serialize_entries(&transactions) {
            Ok(data) => data,
            Err(err) => {
                return WorkOutcome::Failed(format!(
                    "failed to serialize transactions: {}",
                    err
                ))
            }
        };
        let gz = match gzip_bytes(&data) {
            Ok(gz) => gz,
            Err(err) => {
                return WorkOutcome::Failed(format!("failed to gzip transactions: {}", err))
            }
        };

        let path = checkpoint_path("transactions", self.checkpoint, "xdr.gz");
        if let Err(err) = self.writer.put_bytes(&path, &gz).await {
            return WorkOutcome::Failed(format!("failed to publish transactions: {}", err));
        }

        WorkOutcome::Success
    }
}

/// Work item to publish transaction results to an archive.
///
/// Serializes transaction result entries to XDR format, compresses with gzip,
/// and writes to the standard checkpoint path
/// (e.g., `results/00/00/00/results-0000003f.xdr.gz`).
///
/// # Dependencies
///
/// Requires [`DownloadTxResultsWork`] to have completed with valid results.
pub struct PublishResultsWork {
    writer: Arc<dyn ArchiveWriter>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl PublishResultsWork {
    /// Creates a new transaction results publish work item.
    ///
    /// # Arguments
    ///
    /// * `writer` - The archive writer to publish to
    /// * `checkpoint` - The checkpoint ledger sequence number
    /// * `state` - Shared state containing the results to publish
    pub fn new(writer: Arc<dyn ArchiveWriter>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            writer,
            checkpoint,
            state,
        }
    }
}

/// Work item to publish SCP consensus history to an archive.
///
/// Serializes SCP history entries to XDR format, compresses with gzip, and
/// writes to the standard checkpoint path (e.g., `scp/00/00/00/scp-0000003f.xdr.gz`).
///
/// # Dependencies
///
/// Requires [`DownloadScpHistoryWork`] to have completed with valid SCP history.
pub struct PublishScpHistoryWork {
    writer: Arc<dyn ArchiveWriter>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl PublishScpHistoryWork {
    /// Creates a new SCP history publish work item.
    ///
    /// # Arguments
    ///
    /// * `writer` - The archive writer to publish to
    /// * `checkpoint` - The checkpoint ledger sequence number
    /// * `state` - Shared state containing the SCP history to publish
    pub fn new(writer: Arc<dyn ArchiveWriter>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            writer,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for PublishResultsWork {
    fn name(&self) -> &str {
        "publish-results"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::PublishResults, "publishing results").await;
        let results = {
            let guard = self.state.lock().await;
            guard.tx_results.clone()
        };

        let data = match serialize_entries(&results) {
            Ok(data) => data,
            Err(err) => return WorkOutcome::Failed(format!("failed to serialize results: {}", err)),
        };
        let gz = match gzip_bytes(&data) {
            Ok(gz) => gz,
            Err(err) => return WorkOutcome::Failed(format!("failed to gzip results: {}", err)),
        };

        let path = checkpoint_path("results", self.checkpoint, "xdr.gz");
        if let Err(err) = self.writer.put_bytes(&path, &gz).await {
            return WorkOutcome::Failed(format!("failed to publish results: {}", err));
        }

        WorkOutcome::Success
    }
}

#[async_trait]
impl Work for PublishScpHistoryWork {
    fn name(&self) -> &str {
        "publish-scp-history"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::PublishScp, "publishing SCP history").await;
        let entries = {
            let guard = self.state.lock().await;
            guard.scp_history.clone()
        };

        if entries.is_empty() {
            return WorkOutcome::Failed("SCP history not available".to_string());
        }

        let data = match serialize_entries(&entries) {
            Ok(data) => data,
            Err(err) => return WorkOutcome::Failed(format!("failed to serialize SCP history: {}", err)),
        };
        let gz = match gzip_bytes(&data) {
            Ok(gz) => gz,
            Err(err) => return WorkOutcome::Failed(format!("failed to gzip SCP history: {}", err)),
        };

        let path = checkpoint_path("scp", self.checkpoint, "xdr.gz");
        if let Err(err) = self.writer.put_bytes(&path, &gz).await {
            return WorkOutcome::Failed(format!("failed to publish SCP history: {}", err));
        }

        WorkOutcome::Success
    }
}

#[async_trait]
impl Work for PublishBucketsWork {
    fn name(&self) -> &str {
        "publish-buckets"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::PublishBuckets, "publishing buckets").await;
        let buckets = {
            let guard = self.state.lock().await;
            guard.buckets.clone()
        };

        if buckets.is_empty() {
            return WorkOutcome::Failed("buckets not available".to_string());
        }

        for (hash, data) in buckets {
            match gzip_bytes(&data) {
                Ok(gz) => {
                    let path = bucket_path(&hash);
                    if let Err(err) = self.writer.put_bytes(&path, &gz).await {
                        return WorkOutcome::Failed(format!("failed to publish bucket: {}", err));
                    }
                }
                Err(err) => return WorkOutcome::Failed(format!("failed to gzip bucket: {}", err)),
            }
        }

        WorkOutcome::Success
    }
}

/// IDs for registered download work items.
///
/// Returned by [`HistoryWorkBuilder::register`] to identify the work items
/// in the scheduler. These IDs can be used to:
/// - Query work status
/// - Add dependent work items
/// - Pass to [`HistoryWorkBuilder::register_publish`] as dependencies
#[derive(Debug, Clone, Copy)]
pub struct HistoryWorkIds {
    /// ID of the HAS download work item.
    pub has: WorkId,
    /// ID of the bucket download work item.
    pub buckets: WorkId,
    /// ID of the ledger headers download work item.
    pub headers: WorkId,
    /// ID of the transactions download work item.
    pub transactions: WorkId,
    /// ID of the transaction results download work item.
    pub tx_results: WorkId,
    /// ID of the SCP history download work item.
    pub scp_history: WorkId,
}

/// IDs for registered publish work items.
///
/// Returned by [`HistoryWorkBuilder::register_publish`] to identify the
/// publish work items in the scheduler.
#[derive(Debug, Clone, Copy)]
pub struct PublishWorkIds {
    /// ID of the HAS publish work item.
    pub has: WorkId,
    /// ID of the bucket publish work item.
    pub buckets: WorkId,
    /// ID of the ledger headers publish work item.
    pub headers: WorkId,
    /// ID of the transactions publish work item.
    pub transactions: WorkId,
    /// ID of the transaction results publish work item.
    pub results: WorkId,
    /// ID of the SCP history publish work item.
    pub scp_history: WorkId,
}

/// Builder for registering history work items with a scheduler.
///
/// This is the primary interface for setting up history download and publish
/// workflows. It creates work items with the correct dependency relationships
/// and registers them with a [`WorkScheduler`].
///
/// # Example
///
/// ```rust,ignore
/// use stellar_core_historywork::{HistoryWorkBuilder, SharedHistoryState};
/// use stellar_core_work::WorkScheduler;
/// use std::sync::Arc;
///
/// // Create shared state and builder
/// let state: SharedHistoryState = Default::default();
/// let builder = HistoryWorkBuilder::new(archive.clone(), checkpoint, state.clone());
///
/// // Register download work items
/// let mut scheduler = WorkScheduler::new();
/// let download_ids = builder.register(&mut scheduler);
///
/// // Optionally register publish work items
/// let writer = Arc::new(LocalArchiveWriter::new(output_path));
/// let publish_ids = builder.register_publish(&mut scheduler, writer, download_ids);
///
/// // Run all work to completion
/// scheduler.run_to_completion().await?;
///
/// // Build checkpoint data from completed downloads
/// let data = build_checkpoint_data(&state).await?;
/// ```
pub struct HistoryWorkBuilder {
    archive: Arc<HistoryArchive>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl HistoryWorkBuilder {
    /// Creates a new history work builder.
    ///
    /// # Arguments
    ///
    /// * `archive` - The history archive to download from
    /// * `checkpoint` - The checkpoint ledger sequence number
    /// * `state` - Shared state that will be populated by download work
    pub fn new(archive: Arc<HistoryArchive>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            archive,
            checkpoint,
            state,
        }
    }

    /// Registers download work items with the scheduler.
    ///
    /// Creates and registers all download work items (HAS, buckets, headers,
    /// transactions, results, SCP) with proper dependency ordering. Each work
    /// item is configured with 3 retry attempts.
    ///
    /// # Returns
    ///
    /// [`HistoryWorkIds`] containing the scheduler IDs for all registered work.
    pub fn register(&self, scheduler: &mut WorkScheduler) -> HistoryWorkIds {
        let has_id = scheduler.add_work(
            Box::new(GetHistoryArchiveStateWork::new(
                Arc::clone(&self.archive),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![],
            3,
        );

        let buckets_id = scheduler.add_work(
            Box::new(DownloadBucketsWork::new(
                Arc::clone(&self.archive),
                Arc::clone(&self.state),
            )),
            vec![has_id],
            3,
        );

        let headers_id = scheduler.add_work(
            Box::new(DownloadLedgerHeadersWork::new(
                Arc::clone(&self.archive),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![has_id],
            3,
        );

        let tx_id = scheduler.add_work(
            Box::new(DownloadTransactionsWork::new(
                Arc::clone(&self.archive),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![headers_id],
            3,
        );

        let tx_results_id = scheduler.add_work(
            Box::new(DownloadTxResultsWork::new(
                Arc::clone(&self.archive),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![headers_id, tx_id],
            3,
        );

        let scp_id = scheduler.add_work(
            Box::new(DownloadScpHistoryWork::new(
                Arc::clone(&self.archive),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![headers_id],
            3,
        );

        HistoryWorkIds {
            has: has_id,
            buckets: buckets_id,
            headers: headers_id,
            transactions: tx_id,
            tx_results: tx_results_id,
            scp_history: scp_id,
        }
    }

    /// Registers publish work items with the scheduler.
    ///
    /// Creates and registers all publish work items, each depending on its
    /// corresponding download work item. Each publish work item is configured
    /// with 2 retry attempts.
    ///
    /// # Arguments
    ///
    /// * `scheduler` - The work scheduler to register with
    /// * `writer` - The archive writer to publish data to
    /// * `deps` - Work IDs from a prior [`register`] call to use as dependencies
    ///
    /// # Returns
    ///
    /// [`PublishWorkIds`] containing the scheduler IDs for all registered work.
    pub fn register_publish(
        &self,
        scheduler: &mut WorkScheduler,
        writer: Arc<dyn ArchiveWriter>,
        deps: HistoryWorkIds,
    ) -> PublishWorkIds {
        let has_id = scheduler.add_work(
            Box::new(PublishHistoryArchiveStateWork::new(
                Arc::clone(&writer),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![deps.has],
            2,
        );

        let buckets_id = scheduler.add_work(
            Box::new(PublishBucketsWork::new(
                Arc::clone(&writer),
                Arc::clone(&self.state),
            )),
            vec![deps.buckets],
            2,
        );

        let headers_id = scheduler.add_work(
            Box::new(PublishLedgerHeadersWork::new(
                Arc::clone(&writer),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![deps.headers],
            2,
        );

        let transactions_id = scheduler.add_work(
            Box::new(PublishTransactionsWork::new(
                Arc::clone(&writer),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![deps.transactions],
            2,
        );

        let results_id = scheduler.add_work(
            Box::new(PublishResultsWork::new(
                Arc::clone(&writer),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![deps.tx_results],
            2,
        );

        let scp_id = scheduler.add_work(
            Box::new(PublishScpHistoryWork::new(
                Arc::clone(&writer),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![deps.scp_history],
            2,
        );

        PublishWorkIds {
            has: has_id,
            buckets: buckets_id,
            headers: headers_id,
            transactions: transactions_id,
            results: results_id,
            scp_history: scp_id,
        }
    }
}

// ============================================================================
// Helper functions for accessing shared state
// ============================================================================

/// Retrieves the History Archive State from shared state.
///
/// # Errors
///
/// Returns an error if the HAS has not been downloaded yet.
pub async fn get_has(state: &SharedHistoryState) -> Result<HistoryArchiveState> {
    let guard = state.lock().await;
    guard
        .has
        .clone()
        .ok_or_else(|| anyhow::anyhow!("HAS not available"))
}

/// Retrieves downloaded buckets from shared state.
///
/// # Errors
///
/// Returns an error if buckets have not been downloaded yet.
pub async fn get_buckets(state: &SharedHistoryState) -> Result<HashMap<Hash256, Vec<u8>>> {
    let guard = state.lock().await;
    if guard.buckets.is_empty() {
        anyhow::bail!("buckets not available");
    }
    Ok(guard.buckets.clone())
}

/// Retrieves downloaded ledger headers from shared state.
///
/// # Errors
///
/// Returns an error if headers have not been downloaded yet.
pub async fn get_headers(state: &SharedHistoryState) -> Result<Vec<LedgerHeaderHistoryEntry>> {
    let guard = state.lock().await;
    if guard.headers.is_empty() {
        anyhow::bail!("headers not available");
    }
    Ok(guard.headers.clone())
}

/// Retrieves downloaded transactions from shared state.
///
/// # Errors
///
/// Returns an error if transactions have not been downloaded yet.
pub async fn get_transactions(state: &SharedHistoryState) -> Result<Vec<TransactionHistoryEntry>> {
    let guard = state.lock().await;
    if guard.transactions.is_empty() {
        anyhow::bail!("transactions not available");
    }
    Ok(guard.transactions.clone())
}

/// Retrieves downloaded transaction results from shared state.
///
/// # Errors
///
/// Returns an error if transaction results have not been downloaded yet.
pub async fn get_tx_results(state: &SharedHistoryState) -> Result<Vec<TransactionHistoryResultEntry>> {
    let guard = state.lock().await;
    if guard.tx_results.is_empty() {
        anyhow::bail!("tx results not available");
    }
    Ok(guard.tx_results.clone())
}

/// Retrieves downloaded SCP history from shared state.
///
/// # Errors
///
/// Returns an error if SCP history has not been downloaded yet.
pub async fn get_scp_history(state: &SharedHistoryState) -> Result<Vec<ScpHistoryEntry>> {
    let guard = state.lock().await;
    if guard.scp_history.is_empty() {
        anyhow::bail!("scp history not available");
    }
    Ok(guard.scp_history.clone())
}

/// Retrieves the current progress indicator from shared state.
///
/// This function never fails and returns default progress if no work
/// has started yet.
pub async fn get_progress(state: &SharedHistoryState) -> HistoryWorkProgress {
    let guard = state.lock().await;
    guard.progress.clone()
}

// ============================================================================
// Batch Download Support
// ============================================================================

/// File type for batch download operations.
///
/// This enum identifies the type of history archive file being downloaded,
/// used to construct the correct archive paths and manage downloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoryFileType {
    /// Ledger header files (ledger-*.xdr.gz)
    Ledger,
    /// Transaction set files (transactions-*.xdr.gz)
    Transactions,
    /// Transaction result files (results-*.xdr.gz)
    Results,
    /// SCP consensus history files (scp-*.xdr.gz)
    Scp,
}

impl HistoryFileType {
    /// Returns the string representation used in archive paths.
    pub fn type_string(&self) -> &'static str {
        match self {
            HistoryFileType::Ledger => "ledger",
            HistoryFileType::Transactions => "transactions",
            HistoryFileType::Results => "results",
            HistoryFileType::Scp => "scp",
        }
    }
}

impl std::fmt::Display for HistoryFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.type_string())
    }
}

/// A range of checkpoints for batch download operations.
///
/// Represents a contiguous range of checkpoints from `first` (inclusive)
/// to `last` (inclusive). The range always spans complete checkpoints,
/// where each checkpoint covers 64 ledgers.
///
/// # Example
///
/// ```rust
/// use stellar_core_historywork::CheckpointRange;
///
/// // Range covering checkpoints 64, 128, 192, 256
/// let range = CheckpointRange::new(64, 256);
/// assert_eq!(range.count(), 4);
///
/// let checkpoints: Vec<_> = range.iter().collect();
/// assert_eq!(checkpoints, vec![64, 128, 192, 256]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointRange {
    /// First checkpoint in the range (inclusive).
    pub first: u32,
    /// Last checkpoint in the range (inclusive).
    pub last: u32,
}

/// The frequency of checkpoints in ledger sequences.
pub const CHECKPOINT_FREQUENCY: u32 = 64;

impl CheckpointRange {
    /// Creates a new checkpoint range.
    ///
    /// Both `first` and `last` should be valid checkpoint ledger sequences
    /// (multiples of 64, or 63 for the genesis checkpoint).
    ///
    /// # Panics
    ///
    /// Panics if `first > last`.
    pub fn new(first: u32, last: u32) -> Self {
        assert!(first <= last, "first checkpoint must be <= last");
        Self { first, last }
    }

    /// Returns the number of checkpoints in this range.
    pub fn count(&self) -> usize {
        let first_idx = self.first / CHECKPOINT_FREQUENCY;
        let last_idx = self.last / CHECKPOINT_FREQUENCY;
        (last_idx - first_idx + 1) as usize
    }

    /// Returns an iterator over all checkpoint ledger sequences in this range.
    pub fn iter(&self) -> impl Iterator<Item = u32> {
        let first = self.first;
        let last = self.last;
        (0..).map(move |i| first + i * CHECKPOINT_FREQUENCY)
            .take_while(move |&cp| cp <= last)
    }

    /// Returns the ledger range covered by this checkpoint range.
    ///
    /// The first ledger is `first - 63` (the start of the first checkpoint)
    /// and the last ledger is `last` (the end of the last checkpoint).
    pub fn ledger_range(&self) -> (u32, u32) {
        let first_ledger = if self.first <= CHECKPOINT_FREQUENCY {
            1
        } else {
            self.first - CHECKPOINT_FREQUENCY + 1
        };
        (first_ledger, self.last)
    }
}

/// Shared state container for batch download operations.
///
/// Similar to [`HistoryWorkState`] but designed for multi-checkpoint
/// downloads where data accumulates across many checkpoints.
///
/// # Thread Safety
///
/// This type is wrapped in [`SharedBatchDownloadState`] for safe sharing
/// between concurrent download tasks.
#[derive(Debug, Default)]
pub struct BatchDownloadState {
    /// Downloaded ledger headers, keyed by checkpoint ledger sequence.
    pub headers: HashMap<u32, Vec<LedgerHeaderHistoryEntry>>,
    /// Downloaded transactions, keyed by checkpoint ledger sequence.
    pub transactions: HashMap<u32, Vec<TransactionHistoryEntry>>,
    /// Downloaded transaction results, keyed by checkpoint ledger sequence.
    pub tx_results: HashMap<u32, Vec<TransactionHistoryResultEntry>>,
    /// Downloaded SCP history, keyed by checkpoint ledger sequence.
    pub scp_history: HashMap<u32, Vec<ScpHistoryEntry>>,
    /// Download progress tracking.
    pub progress: BatchDownloadProgress,
}

/// Thread-safe handle to shared batch download state.
pub type SharedBatchDownloadState = Arc<Mutex<BatchDownloadState>>;

/// Progress tracking for batch download operations.
#[derive(Debug, Clone, Default)]
pub struct BatchDownloadProgress {
    /// File type being downloaded.
    pub file_type: Option<HistoryFileType>,
    /// Total checkpoints to download.
    pub total: usize,
    /// Checkpoints downloaded so far.
    pub completed: usize,
    /// Current checkpoint being downloaded.
    pub current: Option<u32>,
}

impl BatchDownloadProgress {
    /// Returns a human-readable progress message.
    pub fn message(&self) -> String {
        if let Some(file_type) = &self.file_type {
            format!(
                "downloading {} files: {}/{} checkpoints",
                file_type, self.completed, self.total
            )
        } else {
            "batch download not started".to_string()
        }
    }
}

/// Work item to download files of a specific type for a checkpoint range.
///
/// This is the Rust equivalent of the C++ `BatchDownloadWork` class. It downloads
/// history archive files (ledger headers, transactions, results, or SCP history)
/// for a contiguous range of checkpoints, with parallel downloads for efficiency.
///
/// # Parallelism
///
/// Downloads are performed concurrently with up to 16 parallel requests per
/// batch, matching the C++ `MAX_CONCURRENT_SUBPROCESSES` limit.
///
/// # Dependencies
///
/// - For ledger headers: None (can be downloaded first)
/// - For transactions: Requires headers to be downloaded first for verification
/// - For results: Requires headers and transactions for verification
/// - For SCP: Requires headers for context
///
/// # Output
///
/// On success, populates the corresponding field in [`BatchDownloadState`]
/// with downloaded data keyed by checkpoint sequence.
///
/// # Example
///
/// ```rust,ignore
/// use stellar_core_historywork::{BatchDownloadWork, CheckpointRange, HistoryFileType};
///
/// // Download ledger headers for checkpoints 64-256
/// let range = CheckpointRange::new(64, 256);
/// let work = BatchDownloadWork::new(
///     archive.clone(),
///     range,
///     HistoryFileType::Ledger,
///     state.clone(),
/// );
/// ```
pub struct BatchDownloadWork {
    archive: Arc<HistoryArchive>,
    range: CheckpointRange,
    file_type: HistoryFileType,
    state: SharedBatchDownloadState,
}

impl BatchDownloadWork {
    /// Creates a new batch download work item.
    ///
    /// # Arguments
    ///
    /// * `archive` - The history archive to download from
    /// * `range` - The checkpoint range to download
    /// * `file_type` - The type of files to download
    /// * `state` - Shared state where downloaded data will be stored
    pub fn new(
        archive: Arc<HistoryArchive>,
        range: CheckpointRange,
        file_type: HistoryFileType,
        state: SharedBatchDownloadState,
    ) -> Self {
        Self {
            archive,
            range,
            file_type,
            state,
        }
    }

    /// Returns a formatted status string showing download progress.
    pub fn get_status(&self) -> String {
        format!(
            "batch-download-{}-{:08x}-{:08x}",
            self.file_type, self.range.first, self.range.last
        )
    }
}

#[async_trait]
impl Work for BatchDownloadWork {
    fn name(&self) -> &str {
        "batch-download"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        use futures::stream::{self, StreamExt};

        let checkpoints: Vec<u32> = self.range.iter().collect();
        let total = checkpoints.len();

        // Update progress
        {
            let mut guard = self.state.lock().await;
            guard.progress = BatchDownloadProgress {
                file_type: Some(self.file_type),
                total,
                completed: 0,
                current: checkpoints.first().copied(),
            };
        }

        let archive = self.archive.clone();
        let file_type = self.file_type;
        let state = self.state.clone();

        // Download all checkpoints in parallel (16 concurrent)
        let results: Vec<Result<(u32, DownloadedCheckpointData), String>> = stream::iter(checkpoints)
            .map(|checkpoint| {
                let archive = archive.clone();
                let state = state.clone();
                async move {
                    let result = download_checkpoint_file(&archive, checkpoint, file_type).await;

                    // Update progress
                    {
                        let mut guard = state.lock().await;
                        guard.progress.completed += 1;
                        guard.progress.current = Some(checkpoint);
                    }

                    result.map(|data| (checkpoint, data))
                }
            })
            .buffer_unordered(16)
            .collect()
            .await;

        // Process results and store in state
        let mut guard = self.state.lock().await;
        for result in results {
            match result {
                Ok((checkpoint, data)) => {
                    match data {
                        DownloadedCheckpointData::Headers(headers) => {
                            guard.headers.insert(checkpoint, headers);
                        }
                        DownloadedCheckpointData::Transactions(txs) => {
                            guard.transactions.insert(checkpoint, txs);
                        }
                        DownloadedCheckpointData::Results(results) => {
                            guard.tx_results.insert(checkpoint, results);
                        }
                        DownloadedCheckpointData::Scp(scp) => {
                            guard.scp_history.insert(checkpoint, scp);
                        }
                    }
                }
                Err(err) => {
                    return WorkOutcome::Failed(err);
                }
            }
        }

        tracing::info!(
            "Downloaded {} {} files for checkpoint range {:08x}-{:08x}",
            total,
            file_type,
            self.range.first,
            self.range.last
        );

        WorkOutcome::Success
    }
}

/// Downloaded data for a single checkpoint.
enum DownloadedCheckpointData {
    Headers(Vec<LedgerHeaderHistoryEntry>),
    Transactions(Vec<TransactionHistoryEntry>),
    Results(Vec<TransactionHistoryResultEntry>),
    Scp(Vec<ScpHistoryEntry>),
}

/// Downloads a specific file type for a single checkpoint.
async fn download_checkpoint_file(
    archive: &HistoryArchive,
    checkpoint: u32,
    file_type: HistoryFileType,
) -> Result<DownloadedCheckpointData, String> {
    match file_type {
        HistoryFileType::Ledger => {
            archive
                .get_ledger_headers(checkpoint)
                .await
                .map(DownloadedCheckpointData::Headers)
                .map_err(|e| format!("failed to download headers for {}: {}", checkpoint, e))
        }
        HistoryFileType::Transactions => {
            archive
                .get_transactions(checkpoint)
                .await
                .map(DownloadedCheckpointData::Transactions)
                .map_err(|e| format!("failed to download transactions for {}: {}", checkpoint, e))
        }
        HistoryFileType::Results => {
            archive
                .get_results(checkpoint)
                .await
                .map(DownloadedCheckpointData::Results)
                .map_err(|e| format!("failed to download results for {}: {}", checkpoint, e))
        }
        HistoryFileType::Scp => {
            archive
                .get_scp_history(checkpoint)
                .await
                .map(DownloadedCheckpointData::Scp)
                .map_err(|e| format!("failed to download SCP for {}: {}", checkpoint, e))
        }
    }
}

/// Builder for registering batch download work items with a scheduler.
///
/// This builder creates work items for downloading history archive data
/// across a range of checkpoints, suitable for multi-checkpoint catchup
/// operations.
///
/// # Example
///
/// ```rust,ignore
/// use stellar_core_historywork::{BatchDownloadWorkBuilder, CheckpointRange};
///
/// let range = CheckpointRange::new(64, 512);
/// let builder = BatchDownloadWorkBuilder::new(archive, range);
///
/// let state = builder.state();
/// let ids = builder.register(&mut scheduler);
///
/// scheduler.run_to_completion().await?;
///
/// // Access downloaded data from state
/// let guard = state.lock().await;
/// let all_headers = &guard.headers;
/// ```
pub struct BatchDownloadWorkBuilder {
    archive: Arc<HistoryArchive>,
    range: CheckpointRange,
    state: SharedBatchDownloadState,
}

/// IDs for registered batch download work items.
#[derive(Debug, Clone, Copy)]
pub struct BatchDownloadWorkIds {
    /// ID of the ledger headers batch download work item.
    pub headers: WorkId,
    /// ID of the transactions batch download work item.
    pub transactions: WorkId,
    /// ID of the transaction results batch download work item.
    pub results: WorkId,
    /// ID of the SCP history batch download work item.
    pub scp: WorkId,
}

impl BatchDownloadWorkBuilder {
    /// Creates a new batch download work builder.
    ///
    /// # Arguments
    ///
    /// * `archive` - The history archive to download from
    /// * `range` - The checkpoint range to download
    pub fn new(archive: Arc<HistoryArchive>, range: CheckpointRange) -> Self {
        Self {
            archive,
            range,
            state: Default::default(),
        }
    }

    /// Returns a clone of the shared state for accessing downloaded data.
    pub fn state(&self) -> SharedBatchDownloadState {
        self.state.clone()
    }

    /// Registers all batch download work items with the scheduler.
    ///
    /// Creates four work items for downloading headers, transactions, results,
    /// and SCP history, with proper dependency ordering:
    /// - Headers download first (no dependencies)
    /// - Transactions depend on headers (for verification)
    /// - Results depend on headers and transactions (for verification)
    /// - SCP depends on headers (for context)
    ///
    /// Each work item is configured with 3 retry attempts.
    ///
    /// # Returns
    ///
    /// [`BatchDownloadWorkIds`] containing the scheduler IDs for all registered work.
    pub fn register(&self, scheduler: &mut WorkScheduler) -> BatchDownloadWorkIds {
        let headers_id = scheduler.add_work(
            Box::new(BatchDownloadWork::new(
                self.archive.clone(),
                self.range,
                HistoryFileType::Ledger,
                self.state.clone(),
            )),
            vec![],
            3,
        );

        let transactions_id = scheduler.add_work(
            Box::new(BatchDownloadWork::new(
                self.archive.clone(),
                self.range,
                HistoryFileType::Transactions,
                self.state.clone(),
            )),
            vec![headers_id],
            3,
        );

        let results_id = scheduler.add_work(
            Box::new(BatchDownloadWork::new(
                self.archive.clone(),
                self.range,
                HistoryFileType::Results,
                self.state.clone(),
            )),
            vec![headers_id, transactions_id],
            3,
        );

        let scp_id = scheduler.add_work(
            Box::new(BatchDownloadWork::new(
                self.archive.clone(),
                self.range,
                HistoryFileType::Scp,
                self.state.clone(),
            )),
            vec![headers_id],
            3,
        );

        BatchDownloadWorkIds {
            headers: headers_id,
            transactions: transactions_id,
            results: results_id,
            scp: scp_id,
        }
    }
}

// ============================================================================
// Helper functions for accessing shared state
// ============================================================================

/// Builds a complete [`CheckpointData`] snapshot from shared state.
///
/// This is the primary way to extract downloaded data for use in catchup
/// operations. Call this after all download work items have completed.
///
/// # Example
///
/// ```rust,ignore
/// // After scheduler completes all work...
/// let checkpoint_data = build_checkpoint_data(&state).await?;
/// catchup_manager
///     .catchup_to_ledger_with_checkpoint_data(target, checkpoint_data)
///     .await?;
/// ```
///
/// # Errors
///
/// Returns an error if the HAS is not available (other fields may be empty).
pub async fn build_checkpoint_data(state: &SharedHistoryState) -> Result<CheckpointData> {
    let guard = state.lock().await;
    let has = guard
        .has
        .clone()
        .ok_or_else(|| anyhow!("missing History Archive State"))?;

    Ok(CheckpointData {
        has,
        buckets: guard.buckets.clone(),
        headers: guard.headers.clone(),
        transactions: guard.transactions.clone(),
        tx_results: guard.tx_results.clone(),
        scp_history: guard.scp_history.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_range_count() {
        // Single checkpoint
        let range = CheckpointRange::new(64, 64);
        assert_eq!(range.count(), 1);

        // Two checkpoints
        let range = CheckpointRange::new(64, 128);
        assert_eq!(range.count(), 2);

        // Multiple checkpoints
        let range = CheckpointRange::new(64, 256);
        assert_eq!(range.count(), 4);
    }

    #[test]
    fn test_checkpoint_range_iter() {
        let range = CheckpointRange::new(64, 256);
        let checkpoints: Vec<_> = range.iter().collect();
        assert_eq!(checkpoints, vec![64, 128, 192, 256]);
    }

    #[test]
    fn test_checkpoint_range_ledger_range() {
        let range = CheckpointRange::new(64, 128);
        let (first, last) = range.ledger_range();
        assert_eq!(first, 1); // 64 - 63 = 1
        assert_eq!(last, 128);

        let range = CheckpointRange::new(192, 256);
        let (first, last) = range.ledger_range();
        assert_eq!(first, 129); // 192 - 64 + 1 = 129
        assert_eq!(last, 256);
    }

    #[test]
    fn test_history_file_type_display() {
        assert_eq!(HistoryFileType::Ledger.type_string(), "ledger");
        assert_eq!(HistoryFileType::Transactions.type_string(), "transactions");
        assert_eq!(HistoryFileType::Results.type_string(), "results");
        assert_eq!(HistoryFileType::Scp.type_string(), "scp");
    }

    #[test]
    fn test_batch_download_progress_message() {
        let progress = BatchDownloadProgress {
            file_type: Some(HistoryFileType::Ledger),
            total: 10,
            completed: 5,
            current: Some(320),
        };
        assert_eq!(progress.message(), "downloading ledger files: 5/10 checkpoints");

        let empty = BatchDownloadProgress::default();
        assert_eq!(empty.message(), "batch download not started");
    }
}
