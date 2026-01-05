//! History archive and catchup for rs-stellar-core.
//!
//! This crate handles interaction with Stellar history archives, enabling:
//!
//! - Downloading ledger history from archives
//! - Catching up from archives (downloading and applying history)
//! - Verifying history integrity via hash chains
//! - Managing multiple archive sources for redundancy
//!
//! ## History Archive Structure
//!
//! History archives contain:
//! - Ledger headers organized in checkpoints (every 64 ledgers)
//! - Transaction sets for each ledger
//! - Bucket files for BucketList state
//! - SCP messages for consensus verification
//!
//! ## Usage
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
//! // Get the current archive state
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
//! ## Catchup Modes
//!
//! - **Minimal**: Download only recent state (BucketList) to start validating
//! - **Complete**: Download full history for archival nodes
//! - **Recent**: Download last N ledgers of history

// Core modules
pub mod archive;
pub mod archive_state;
pub mod catchup;
pub mod cdp;
pub mod checkpoint;
pub mod download;
pub mod error;
pub mod paths;
pub mod publish;
pub mod replay;
pub mod verify;

// Re-export main types at crate root
pub use archive::HistoryArchive;
pub use archive_state::HistoryArchiveState;
pub use catchup::{
    CatchupManager, CatchupOptions, CatchupProgress, CatchupStatus, CheckpointData, LedgerData,
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
pub use cdp::{CdpDataLake, extract_transaction_metas, extract_ledger_header};

/// Result type for history operations.
pub type Result<T> = std::result::Result<T, HistoryError>;

/// Configuration for a history archive.
#[derive(Debug, Clone)]
pub struct ArchiveConfig {
    /// Base URL of the archive.
    pub url: url::Url,
    /// Whether this archive can be used for getting history.
    pub get_enabled: bool,
    /// Whether this archive can be used for publishing history.
    pub put_enabled: bool,
}

/// Manager for multiple history archives.
///
/// Provides failover and load balancing across multiple archive sources.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchupMode {
    /// Download only the latest state (minimal sync time).
    Minimal,
    /// Download complete history from genesis.
    Complete,
    /// Download the last N ledgers of history.
    Recent(u32),
}

/// Result of a successful catchup operation.
#[derive(Debug)]
pub struct CatchupResult {
    /// The ledger sequence we caught up to.
    pub ledger_seq: u32,
    /// Hash of the ledger we caught up to.
    pub ledger_hash: stellar_core_common::Hash256,
    /// Number of ledgers applied.
    pub ledgers_applied: u32,
    /// Number of buckets downloaded.
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

/// Full output of a catchup operation, including state needed for initialization.
///
/// This is used when the caller needs both the catchup result and the
/// bucket list/header for initializing the ledger manager.
pub struct CatchupOutput {
    /// Summary result of the catchup.
    pub result: CatchupResult,
    /// The live bucket list state at the caught-up ledger.
    pub bucket_list: stellar_core_bucket::BucketList,
    /// The hot archive bucket list state at the caught-up ledger (protocol 23+).
    pub hot_archive_bucket_list: Option<stellar_core_bucket::BucketList>,
    /// The ledger header at the caught-up ledger.
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
