//! History archive access and catchup for rs-stellar-core.
//!
//! This crate provides the infrastructure for interacting with Stellar history archives,
//! enabling nodes to synchronize with the network by downloading and verifying historical
//! ledger data.
//!
//! # Overview
//!
//! Stellar validators publish their ledger history to "history archives" - HTTP-accessible
//! repositories containing checkpoints of network state. This crate handles:
//!
//! - **Archive Access**: Downloading ledger headers, transactions, results, and bucket files
//! - **Catchup**: Synchronizing a node from genesis or a recent checkpoint
//! - **Replay**: Re-executing transactions to verify state transitions
//! - **Publishing**: Writing new checkpoints to history archives (for validators)
//! - **Verification**: Ensuring data integrity via cryptographic hash chains
//!
//! # History Archive Structure
//!
//! Archives are organized around **checkpoints** - snapshots taken every 64 ledgers.
//! Each checkpoint includes:
//!
//! - **Ledger headers**: Metadata for each ledger in the checkpoint
//! - **Transaction sets**: All transactions executed in the checkpoint
//! - **Transaction results**: Outcomes of each transaction
//! - **Bucket files**: Serialized ledger state (accounts, trustlines, offers, etc.)
//! - **SCP messages**: Consensus protocol messages for verification
//!
//! Files are organized hierarchically by their hex-encoded sequence number:
//! ```text
//! history/00/00/00/history-0000003f.json  # Checkpoint 63
//! ledger/00/00/00/ledger-0000003f.xdr.gz  # Ledger headers
//! bucket/e1/13/f8/bucket-e113f8...fd.xdr.gz  # Bucket by hash
//! ```
//!
//! # Quick Start
//!
//! ```no_run
//! use stellar_core_history::archive::HistoryArchive;
//!
//! # async fn example() -> Result<(), stellar_core_history::HistoryError> {
//! // Connect to a testnet archive
//! let archive = HistoryArchive::new(
//!     "https://history.stellar.org/prd/core-testnet/core_testnet_001"
//! )?;
//!
//! // Get the current archive state (History Archive State / HAS)
//! let has = archive.get_root_has().await?;
//! println!("Current ledger: {}", has.current_ledger());
//!
//! // Get all bucket hashes needed for catchup
//! let buckets = has.all_bucket_hashes();
//! println!("Need {} buckets", buckets.len());
//!
//! // Download ledger headers for a checkpoint
//! let headers = archive.get_ledger_headers(63).await?;
//! println!("Got {} ledger headers", headers.len());
//! # Ok(())
//! # }
//! ```
//!
//! # Catchup Modes
//!
//! The catchup process supports different synchronization strategies:
//!
//! - **Minimal**: Download only the latest checkpoint state to start validating new ledgers
//!   immediately. Best for validators that do not need historical data.
//!
//! - **Complete**: Download full history from genesis. Required for archival nodes that
//!   need to serve historical queries.
//!
//! - **Recent**: Download the last N ledgers of history. Useful for nodes that need
//!   some historical context but not the complete chain.
//!
//! # Key Types
//!
//! - [`HistoryArchive`]: Client for accessing a single history archive
//! - [`HistoryManager`]: Manages multiple archives with failover support
//! - [`HistoryArchiveState`]: Parsed checkpoint metadata (HAS file)
//! - [`CatchupManager`]: Orchestrates the full catchup process
//! - [`ReplayConfig`]: Configuration for ledger replay and verification
//!
//! # Verification
//!
//! All downloaded data is cryptographically verified:
//!
//! 1. Bucket hashes are verified against their content
//! 2. Ledger headers form a hash chain (each references the previous)
//! 3. Transaction sets and results match the hashes in headers
//! 4. The final bucket list hash matches the target ledger header
//!
//! [`HistoryArchive`]: archive::HistoryArchive
//! [`HistoryArchiveState`]: archive_state::HistoryArchiveState
//! [`CatchupManager`]: catchup::CatchupManager
//! [`ReplayConfig`]: replay::ReplayConfig

// Module declarations with brief descriptions
//
// Archive access and data retrieval
pub mod archive;
pub mod archive_state;
pub mod download;
pub mod paths;

// Catchup and synchronization
pub mod catchup;
pub mod checkpoint;
pub mod replay;
pub mod verify;

// Publishing and external data sources
pub mod cdp;
pub mod publish;

// Error handling
pub mod error;

// Re-export main types at crate root
pub use archive::HistoryArchive;
pub use archive_state::HistoryArchiveState;
pub use catchup::{
    CatchupManager, CatchupOptions, CatchupProgress, CatchupStatus, CheckpointData, LedgerData,
};
pub use cdp::{
    extract_ledger_header, extract_transaction_envelopes, extract_transaction_metas, CdpDataLake,
};
pub use checkpoint::{
    checkpoint_containing, is_checkpoint_ledger, latest_checkpoint_before_or_at,
    CHECKPOINT_FREQUENCY,
};
pub use download::DownloadConfig;
pub use error::HistoryError;
pub use paths::{bucket_path, checkpoint_ledger, checkpoint_path};
pub use replay::{LedgerReplayResult, ReplayConfig, ReplayedLedgerState};
pub use verify::{compute_header_hash, verify_bucket_hash, verify_header_chain};

/// Result type for history operations.
pub type Result<T> = std::result::Result<T, HistoryError>;

/// Configuration for a single history archive.
///
/// Archives can be configured for reading (get), writing (put), or both.
/// Validators typically configure multiple archives with different capabilities:
/// - Public archives for reading during catchup
/// - Private archives for publishing their own history
#[derive(Debug, Clone)]
pub struct ArchiveConfig {
    /// Base URL of the archive (e.g., `https://history.stellar.org/prd/core-live/core_live_001`).
    pub url: url::Url,
    /// Whether this archive can be used for downloading history data.
    pub get_enabled: bool,
    /// Whether this archive can be used for publishing history data.
    pub put_enabled: bool,
}

/// Manager for multiple history archives with failover support.
///
/// The `HistoryManager` wraps multiple [`HistoryArchive`] instances and provides
/// automatic failover: if one archive fails to respond, the manager tries the next
/// archive in the list until one succeeds or all archives have been exhausted.
///
/// This is essential for reliable catchup since individual archives may be temporarily
/// unavailable or have incomplete data.
///
/// # Example
///
/// ```no_run
/// use stellar_core_history::{HistoryManager, archive::testnet};
///
/// # async fn example() -> Result<(), stellar_core_history::HistoryError> {
/// let manager = HistoryManager::from_urls(testnet::ARCHIVE_URLS)?;
///
/// // Automatically tries each archive until one succeeds
/// let has = manager.get_root_has().await?;
/// println!("Network at ledger {}", has.current_ledger());
/// # Ok(())
/// # }
/// ```
pub struct HistoryManager {
    archives: Vec<HistoryArchive>,
}

impl HistoryManager {
    /// Create a new history manager with the given archives.
    pub fn new(archives: Vec<HistoryArchive>) -> Self {
        Self { archives }
    }

    /// Create a history manager from a list of URLs.
    pub fn from_urls(urls: &[&str]) -> Result<Self> {
        let archives: Result<Vec<_>> = urls.iter().map(|url| HistoryArchive::new(url)).collect();
        Ok(Self::new(archives?))
    }

    /// Add an archive to the manager.
    pub fn add_archive(&mut self, archive: HistoryArchive) {
        self.archives.push(archive);
    }

    /// Get the number of archives.
    pub fn archive_count(&self) -> usize {
        self.archives.len()
    }

    /// Get the root HAS from any available archive.
    ///
    /// Tries each archive in sequence until one succeeds.
    pub async fn get_root_has(&self) -> Result<HistoryArchiveState> {
        for archive in &self.archives {
            match archive.get_root_has().await {
                Ok(has) => return Ok(has),
                Err(e) => {
                    tracing::warn!(
                        url = %archive.base_url(),
                        error = %e,
                        "Failed to get HAS from archive"
                    );
                    continue;
                }
            }
        }
        Err(HistoryError::NoArchiveAvailable)
    }

    /// Get the checkpoint HAS from any available archive.
    pub async fn get_checkpoint_has(&self, ledger: u32) -> Result<HistoryArchiveState> {
        for archive in &self.archives {
            match archive.get_checkpoint_has(ledger).await {
                Ok(has) => return Ok(has),
                Err(e) => {
                    tracing::warn!(
                        url = %archive.base_url(),
                        ledger = ledger,
                        error = %e,
                        "Failed to get checkpoint HAS from archive"
                    );
                    continue;
                }
            }
        }
        Err(HistoryError::CheckpointNotFound(ledger))
    }

    /// Download a bucket from any available archive.
    pub async fn get_bucket(&self, hash: &stellar_core_common::Hash256) -> Result<Vec<u8>> {
        for archive in &self.archives {
            match archive.get_bucket(hash).await {
                Ok(data) => return Ok(data),
                Err(e) => {
                    tracing::warn!(
                        url = %archive.base_url(),
                        hash = %hash,
                        error = %e,
                        "Failed to get bucket from archive"
                    );
                    continue;
                }
            }
        }
        Err(HistoryError::BucketNotFound(*hash))
    }

    /// Get ledger headers for a checkpoint from any available archive.
    pub async fn get_ledger_headers(
        &self,
        checkpoint: u32,
    ) -> Result<Vec<stellar_xdr::curr::LedgerHeaderHistoryEntry>> {
        for archive in &self.archives {
            match archive.get_ledger_headers(checkpoint).await {
                Ok(headers) => return Ok(headers),
                Err(e) => {
                    tracing::warn!(
                        url = %archive.base_url(),
                        checkpoint = checkpoint,
                        error = %e,
                        "Failed to get ledger headers from archive"
                    );
                    continue;
                }
            }
        }
        Err(HistoryError::CheckpointNotFound(checkpoint))
    }

    /// Get transactions for a checkpoint from any available archive.
    pub async fn get_transactions(
        &self,
        checkpoint: u32,
    ) -> Result<Vec<stellar_xdr::curr::TransactionHistoryEntry>> {
        for archive in &self.archives {
            match archive.get_transactions(checkpoint).await {
                Ok(txs) => return Ok(txs),
                Err(e) => {
                    tracing::warn!(
                        url = %archive.base_url(),
                        checkpoint = checkpoint,
                        error = %e,
                        "Failed to get transactions from archive"
                    );
                    continue;
                }
            }
        }
        Err(HistoryError::CheckpointNotFound(checkpoint))
    }

    /// Get transaction results for a checkpoint from any available archive.
    pub async fn get_results(
        &self,
        checkpoint: u32,
    ) -> Result<Vec<stellar_xdr::curr::TransactionHistoryResultEntry>> {
        for archive in &self.archives {
            match archive.get_results(checkpoint).await {
                Ok(results) => return Ok(results),
                Err(e) => {
                    tracing::warn!(
                        url = %archive.base_url(),
                        checkpoint = checkpoint,
                        error = %e,
                        "Failed to get transaction results from archive"
                    );
                    continue;
                }
            }
        }
        Err(HistoryError::CheckpointNotFound(checkpoint))
    }
}

/// Catchup mode determining how much history to download.
///
/// The catchup mode controls the trade-off between synchronization time and
/// historical data availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchupMode {
    /// Download only the latest checkpoint state.
    ///
    /// This is the fastest mode - downloads only the bucket list and a few
    /// ledger headers needed to start validating. Suitable for validators
    /// that do not need to serve historical queries.
    Minimal,

    /// Download complete history from genesis.
    ///
    /// Downloads all checkpoints from ledger 0 to the current tip. Required
    /// for archival nodes that need to serve any historical query. This can
    /// take hours or days depending on network age.
    Complete,

    /// Download the last N ledgers of history.
    ///
    /// A middle ground that provides some historical context while limiting
    /// sync time. The value specifies how many ledgers of history to retain.
    Recent(u32),
}

/// Summary result of a successful catchup operation.
///
/// This provides high-level statistics about the catchup process. For the
/// full state needed to initialize the ledger manager, see [`CatchupOutput`].
#[derive(Debug)]
pub struct CatchupResult {
    /// The ledger sequence that was caught up to.
    pub ledger_seq: u32,

    /// The SHA-256 hash of the final ledger header.
    pub ledger_hash: stellar_core_common::Hash256,

    /// Number of ledgers replayed from checkpoint to target.
    ///
    /// Zero if the target was exactly at a checkpoint boundary.
    pub ledgers_applied: u32,

    /// Number of bucket files downloaded during catchup.
    pub buckets_downloaded: u32,
}

impl std::fmt::Display for CatchupResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Caught up to ledger {} (hash: {}, {} buckets, {} ledgers applied)",
            self.ledger_seq,
            &self.ledger_hash.to_hex()[..16],
            self.buckets_downloaded,
            self.ledgers_applied
        )
    }
}

/// Complete output of a catchup operation, including state needed for initialization.
///
/// This contains everything needed to initialize the ledger manager after catchup:
/// - The bucket list representing current ledger state
/// - The ledger header for the target ledger
/// - Statistics about the catchup process
///
/// # Protocol 23+ Changes
///
/// Starting with protocol 23, Stellar introduced state archival. The ledger state is
/// now split into:
/// - **Live bucket list**: Active entries that can be accessed by transactions
/// - **Hot archive bucket list**: Recently evicted entries that can be restored
///
/// The bucket list hash in the ledger header is computed as:
/// `SHA256(live_hash || hot_archive_hash)` for protocol 23+.
pub struct CatchupOutput {
    /// Summary statistics of the catchup operation.
    pub result: CatchupResult,

    /// The live bucket list state at the target ledger.
    ///
    /// This contains all active ledger entries (accounts, trustlines, offers,
    /// contract data, etc.) that can be accessed by transactions.
    pub bucket_list: stellar_core_bucket::BucketList,

    /// The hot archive bucket list state (protocol 23+ only).
    ///
    /// Contains recently evicted persistent entries that can be restored
    /// via the `RestoreFootprint` operation.
    pub hot_archive_bucket_list: Option<stellar_core_bucket::BucketList>,

    /// The ledger header at the target ledger.
    ///
    /// This header has been verified to match the downloaded state.
    pub header: stellar_xdr::curr::LedgerHeader,
}

impl CatchupOutput {
    /// Compute the combined bucket list hash for verification.
    ///
    /// For protocol 23+, this is SHA256(live_hash || hot_archive_hash).
    /// For earlier protocols, this is just the live bucket list hash.
    pub fn combined_bucket_list_hash(&self) -> stellar_core_common::Hash256 {
        use sha2::{Digest, Sha256};

        let live_hash = self.bucket_list.hash();

        if let Some(ref hot_archive) = self.hot_archive_bucket_list {
            // Protocol 23+: combine both hashes
            let hot_hash = hot_archive.hash();
            let mut hasher = Sha256::new();
            hasher.update(live_hash.as_bytes());
            hasher.update(hot_hash.as_bytes());
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            stellar_core_common::Hash256::from_bytes(bytes)
        } else {
            // Pre-protocol 23: just live hash
            live_hash
        }
    }
}

/// Testnet archive configuration.
pub mod testnet {
    pub use crate::archive::testnet::*;
}

/// Mainnet archive configuration.
pub mod mainnet {
    pub use crate::archive::mainnet::*;
}
