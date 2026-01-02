//! History archive publishing.
//!
//! This module handles publishing ledger data to history archives.
//! Validators publish:
//! - Ledger headers (organized in checkpoints)
//! - Transaction sets
//! - Transaction results
//! - Bucket files
//! - SCP messages
//!
//! Publishing is typically done at checkpoint boundaries (every 64 ledgers).

use crate::{
    archive_state::{HASBucketLevel, HASBucketNext, HistoryArchiveState},
    checkpoint::is_checkpoint_ledger,
    paths,
    HistoryError, Result,
};
use stellar_core_bucket::BucketList;
use stellar_core_common::Hash256;
use stellar_xdr::curr::{
    LedgerHeaderHistoryEntry, TransactionHistoryEntry, TransactionHistoryResultEntry, WriteXdr,
};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Configuration for history publishing.
#[derive(Debug, Clone)]
pub struct PublishConfig {
    /// Local directory to write history files.
    pub local_path: PathBuf,
    /// Network passphrase for HAS files.
    pub network_passphrase: Option<String>,
    /// Whether to publish to remote archives.
    pub publish_remote: bool,
    /// Remote archive URLs for publishing (S3, GCS, etc.).
    pub remote_urls: Vec<String>,
    /// Maximum number of parallel uploads.
    pub max_parallel_uploads: usize,
}

impl Default for PublishConfig {
    fn default() -> Self {
        Self {
            local_path: PathBuf::from("history"),
            network_passphrase: None,
            publish_remote: false,
            remote_urls: Vec::new(),
            max_parallel_uploads: 4,
        }
    }
}

/// State of a checkpoint being published.
#[derive(Debug, Clone)]
pub struct PublishState {
    /// Ledger sequence of the checkpoint.
    pub checkpoint_ledger: u32,
    /// Current status.
    pub status: PublishStatus,
    /// Number of files written.
    pub files_written: u32,
    /// Number of files to write.
    pub files_total: u32,
}

/// Status of publishing operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishStatus {
    /// Queued for publishing.
    Queued,
    /// Currently publishing.
    Publishing,
    /// Successfully published.
    Completed,
    /// Publishing failed.
    Failed,
}

/// Manager for publishing history to archives.
pub struct PublishManager {
    config: PublishConfig,
}

/// Build a history archive state from a bucket list snapshot.
pub fn build_history_archive_state(
    checkpoint_ledger: u32,
    bucket_list: &BucketList,
    network_passphrase: Option<String>,
) -> Result<HistoryArchiveState> {
    let current_buckets: Vec<HASBucketLevel> = bucket_list
        .levels()
        .iter()
        .map(|level| HASBucketLevel {
            curr: level.curr.hash().to_hex(),
            snap: level.snap.hash().to_hex(),
            next: HASBucketNext::default(),
        })
        .collect();

    Ok(HistoryArchiveState {
        version: 2,
        server: Some("rs-stellar-core".to_string()),
        current_ledger: checkpoint_ledger,
        network_passphrase,
        current_buckets,
        hot_archive_buckets: None,
    })
}

impl PublishManager {
    /// Create a new publish manager.
    pub fn new(config: PublishConfig) -> Self {
        Self { config }
    }

    /// Publish a checkpoint to history archives.
    ///
    /// This writes all files for a checkpoint:
    /// - Ledger headers for the checkpoint range
    /// - Transaction sets for each ledger
    /// - Transaction results for each ledger
    /// - Bucket files referenced by the bucket list
    /// - History Archive State (HAS) file
    pub async fn publish_checkpoint(
        &self,
        checkpoint_ledger: u32,
        headers: &[LedgerHeaderHistoryEntry],
        tx_entries: &[TransactionHistoryEntry],
        tx_results: &[TransactionHistoryResultEntry],
        bucket_list: &BucketList,
    ) -> Result<PublishState> {
        if !is_checkpoint_ledger(checkpoint_ledger) {
            return Err(HistoryError::NotCheckpointLedger(checkpoint_ledger));
        }

        info!(
            checkpoint = checkpoint_ledger,
            "Publishing checkpoint to history"
        );

        let mut state = PublishState {
            checkpoint_ledger,
            status: PublishStatus::Publishing,
            files_written: 0,
            files_total: 0,
        };

        // Create directory structure
        self.ensure_directories(checkpoint_ledger)?;

        // Write ledger headers
        let headers_path = self.ledger_path(checkpoint_ledger, "ledger");
        self.write_ledger_headers(&headers_path, headers)?;
        state.files_written += 1;

        // Write transaction sets
        let txset_path = self.ledger_path(checkpoint_ledger, "transactions");
        self.write_transaction_entries(&txset_path, tx_entries)?;
        state.files_written += 1;

        // Write transaction results
        let results_path = self.ledger_path(checkpoint_ledger, "results");
        self.write_transaction_results(&results_path, tx_results)?;
        state.files_written += 1;

        // Write bucket files from each level
        for level in bucket_list.levels() {
            // Write curr bucket if non-empty
            if !level.curr.is_empty() {
                let hash = level.curr.hash();
                let bucket_path = self.bucket_path(&hash);
                self.write_bucket_from_entries(&bucket_path, &level.curr)?;
                state.files_written += 1;
            }
            // Write snap bucket if non-empty
            if !level.snap.is_empty() {
                let hash = level.snap.hash();
                let bucket_path = self.bucket_path(&hash);
                self.write_bucket_from_entries(&bucket_path, &level.snap)?;
                state.files_written += 1;
            }
        }

        // Write History Archive State
        let has = self.create_has(checkpoint_ledger, headers, bucket_list)?;
        let has_path = self.has_path(checkpoint_ledger);
        self.write_has(&has_path, &has)?;
        state.files_written += 1;

        state.status = PublishStatus::Completed;
        state.files_total = state.files_written;

        info!(
            checkpoint = checkpoint_ledger,
            files = state.files_written,
            "Checkpoint published successfully"
        );

        Ok(state)
    }

    /// Ensure directory structure exists for a checkpoint.
    fn ensure_directories(&self, checkpoint_ledger: u32) -> Result<()> {
        let base = &self.config.local_path;

        // Create checkpoint directories for each category.
        for category in ["ledger", "transactions", "results", "history", "scp"] {
            let path = base.join(paths::checkpoint_file_path(checkpoint_ledger, category));
            let dir = path.parent().ok_or_else(|| {
                HistoryError::VerificationFailed("missing checkpoint directory".to_string())
            })?;
            std::fs::create_dir_all(dir)?;
        }

        // Create bucket directories (organized by first 2 hex chars)
        let bucket_base = base.join("bucket");
        for i in 0..=255u8 {
            let subdir = bucket_base.join(format!("{:02x}", i));
            std::fs::create_dir_all(&subdir)?;
        }

        Ok(())
    }

    /// Get the path for a ledger file.
    fn ledger_path(&self, checkpoint_ledger: u32, file_type: &str) -> PathBuf {
        let base = &self.config.local_path;
        base.join(paths::checkpoint_file_path(checkpoint_ledger, file_type))
    }

    /// Get the path for a bucket file.
    fn bucket_path(&self, hash: &Hash256) -> PathBuf {
        let base = &self.config.local_path;
        base.join(paths::bucket_path(hash))
    }

    /// Get the path for a HAS file.
    fn has_path(&self, checkpoint_ledger: u32) -> PathBuf {
        let base = &self.config.local_path;
        base.join(paths::has_path(checkpoint_ledger))
    }

    /// Write ledger headers to a file.
    fn write_ledger_headers(&self, path: &Path, headers: &[LedgerHeaderHistoryEntry]) -> Result<()> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let file = std::fs::File::create(path.with_extension("xdr.gz"))?;
        let mut encoder = GzEncoder::new(file, Compression::default());

        for header in headers {
            let xdr = header
                .to_xdr(stellar_xdr::curr::Limits::none())
                .map_err(|e| HistoryError::VerificationFailed(e.to_string()))?;
            encoder.write_all(&xdr)?;
        }

        encoder.finish()?;
        debug!("Wrote {} ledger headers to {:?}", headers.len(), path);
        Ok(())
    }

    /// Write transaction sets to a file.
    fn write_transaction_entries(
        &self,
        path: &Path,
        tx_entries: &[TransactionHistoryEntry],
    ) -> Result<()> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let file = std::fs::File::create(path.with_extension("xdr.gz"))?;
        let mut encoder = GzEncoder::new(file, Compression::default());

        for entry in tx_entries {
            let xdr = entry
                .to_xdr(stellar_xdr::curr::Limits::none())
                .map_err(|e| HistoryError::VerificationFailed(e.to_string()))?;
            encoder.write_all(&xdr)?;
        }

        encoder.finish()?;
        debug!("Wrote {} transaction entries to {:?}", tx_entries.len(), path);
        Ok(())
    }

    /// Write transaction results to a file.
    fn write_transaction_results(
        &self,
        path: &Path,
        results: &[TransactionHistoryResultEntry],
    ) -> Result<()> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let file = std::fs::File::create(path.with_extension("xdr.gz"))?;
        let mut encoder = GzEncoder::new(file, Compression::default());

        for entry in results {
            let xdr = entry
                .to_xdr(stellar_xdr::curr::Limits::none())
                .map_err(|e| HistoryError::VerificationFailed(e.to_string()))?;
            encoder.write_all(&xdr)?;
        }

        encoder.finish()?;
        debug!("Wrote {} result sets to {:?}", results.len(), path);
        Ok(())
    }

    /// Write a bucket from a Bucket struct by serializing its entries.
    fn write_bucket_from_entries(
        &self,
        path: &Path,
        bucket: &stellar_core_bucket::Bucket,
    ) -> Result<()> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        // Skip if already exists
        let gz_path = path.with_extension("xdr.gz");
        if gz_path.exists() {
            debug!("Bucket already exists: {:?}", gz_path);
            return Ok(());
        }

        let file = std::fs::File::create(&gz_path)?;
        let mut encoder = GzEncoder::new(file, Compression::default());

        // Serialize each bucket entry to XDR
        // Note: use iter() instead of entries() to support disk-backed buckets
        for entry in bucket.iter() {
            let xdr_entry = entry.to_xdr_entry();
            let xdr = xdr_entry
                .to_xdr(stellar_xdr::curr::Limits::none())
                .map_err(|e| HistoryError::VerificationFailed(e.to_string()))?;
            encoder.write_all(&xdr)?;
        }

        encoder.finish()?;
        debug!("Wrote bucket to {:?}", gz_path);
        Ok(())
    }

    /// Write a History Archive State file.
    fn write_has(&self, path: &Path, has: &HistoryArchiveState) -> Result<()> {
        let json = serde_json::to_string_pretty(has)
            .map_err(|e| HistoryError::VerificationFailed(e.to_string()))?;
        std::fs::write(path, json)?;
        debug!("Wrote HAS to {:?}", path);
        Ok(())
    }

    /// Create a History Archive State from checkpoint data.
    fn create_has(
        &self,
        checkpoint_ledger: u32,
        _headers: &[LedgerHeaderHistoryEntry],
        bucket_list: &BucketList,
    ) -> Result<HistoryArchiveState> {
        build_history_archive_state(
            checkpoint_ledger,
            bucket_list,
            self.config.network_passphrase.clone(),
        )
    }

    /// Check if a checkpoint has been published.
    pub fn is_published(&self, checkpoint_ledger: u32) -> bool {
        let has_path = self.has_path(checkpoint_ledger);
        has_path.exists()
    }

    /// Get the latest published checkpoint.
    pub fn latest_published_checkpoint(&self) -> Option<u32> {
        // Scan the history directory for published checkpoints
        let base = &self.config.local_path;
        let has_dir = base.join("history");

        if !has_dir.exists() {
            return None;
        }

        fn scan_dir(path: &Path, latest: &mut Option<u32>) {
            let Ok(entries) = std::fs::read_dir(path) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    scan_dir(&path, latest);
                } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if let Some(hex) = name
                        .strip_prefix("history-")
                        .and_then(|n| n.strip_suffix(".json"))
                    {
                        if let Ok(seq) = u32::from_str_radix(hex, 16) {
                            if is_checkpoint_ledger(seq) {
                                *latest = Some(latest.map_or(seq, |l| l.max(seq)));
                            }
                        }
                    }
                }
            }
        }

        let mut latest: Option<u32> = None;
        scan_dir(&has_dir, &mut latest);
        latest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_publish_config_default() {
        let config = PublishConfig::default();
        assert!(!config.publish_remote);
        assert!(config.remote_urls.is_empty());
        assert!(config.network_passphrase.is_none());
    }

    #[test]
    fn test_publish_status() {
        let state = PublishState {
            checkpoint_ledger: 64,
            status: PublishStatus::Queued,
            files_written: 0,
            files_total: 10,
        };
        assert_eq!(state.status, PublishStatus::Queued);
    }

    #[test]
    fn test_ensure_directories() {
        let temp = TempDir::new().unwrap();
        let config = PublishConfig {
            local_path: temp.path().to_path_buf(),
            ..Default::default()
        };
        let manager = PublishManager::new(config);

        manager.ensure_directories(64).unwrap();

        // Check that ledger directory was created
        let ledger_dir = temp.path().join("ledger/00/00/00");
        assert!(ledger_dir.exists());

        // Check that bucket directories were created
        let bucket_dir = temp.path().join("bucket/00");
        assert!(bucket_dir.exists());
    }
}
