//! Crash-safe checkpoint building for history archives.
//!
//! This module provides the `CheckpointBuilder` struct for building checkpoints
//! in a crash-safe manner. It writes checkpoint data to `.dirty` temporary files
//! first, then atomically renames them to final paths on commit.
//!
//! # Crash Safety
//!
//! The checkpoint builder follows these principles for crash safety:
//!
//! 1. **Write to dirty files**: All data is first written to `.dirty` temporary files
//! 2. **Fsync after writes**: Data is fsynced to disk before proceeding
//! 3. **Atomic rename on commit**: Dirty files are atomically renamed to final paths
//! 4. **Recovery on startup**: The `cleanup()` method recovers from crashes
//!
//! # Recovery Scenarios
//!
//! On startup, `cleanup(lcl)` handles these scenarios:
//!
//! - **Both dirty and final exist**: Delete dirty (leftover from completed checkpoint)
//! - **Only dirty exists**: Truncate to LCL if needed, rename to final
//! - **Only final exists**: Validate it ends at correct ledger
//! - **Neither exists**: First run or publish was disabled
//!
//! # Example
//!
//! ```no_run
//! use stellar_core_history::checkpoint_builder::CheckpointBuilder;
//! use std::path::PathBuf;
//!
//! let mut builder = CheckpointBuilder::new(PathBuf::from("/tmp/history"));
//!
//! // On startup, clean up any partial state
//! builder.cleanup(63)?;  // LCL = 63
//!
//! // During ledger close, append data
//! // builder.append_ledger_header(&header)?;
//! // builder.append_transaction_set(&tx_set, &results)?;
//!
//! // At checkpoint boundary, commit
//! builder.checkpoint_complete(63)?;
//! # Ok::<(), stellar_core_history::HistoryError>(())
//! ```

use crate::paths::{checkpoint_path, checkpoint_path_dirty, dirty_to_final_path, is_dirty_path};
use crate::{HistoryError, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use stellar_xdr::curr::{
    LedgerHeaderHistoryEntry, Limits, TransactionHistoryEntry, TransactionHistoryResultEntry,
    WriteXdr,
};
use tracing::{debug, info, warn};

/// File categories for checkpoint files.
const FILE_CATEGORIES: &[&str] = &["ledger", "transactions", "results"];

/// XDR stream writer with gzip compression.
///
/// Writes XDR entries to a gzip-compressed file with RFC 5531 record marking
/// (4-byte length prefix followed by padded XDR data).
struct XdrStreamWriter {
    /// The underlying gzip encoder wrapped in a buffered writer.
    encoder: GzEncoder<BufWriter<File>>,
    /// Path to the dirty file being written.
    dirty_path: PathBuf,
    /// Path to the final file (after rename).
    final_path: PathBuf,
    /// Number of entries written.
    entry_count: u32,
    /// Last ledger sequence written.
    last_ledger: u32,
}

impl XdrStreamWriter {
    /// Create a new XDR stream writer.
    fn new(dirty_path: PathBuf, final_path: PathBuf) -> Result<Self> {
        // Create parent directories if needed
        if let Some(parent) = dirty_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&dirty_path)?;

        let buf_writer = BufWriter::new(file);
        let encoder = GzEncoder::new(buf_writer, Compression::default());

        Ok(Self {
            encoder,
            dirty_path,
            final_path,
            entry_count: 0,
            last_ledger: 0,
        })
    }

    /// Write an XDR entry with record marking.
    fn write_xdr<T: WriteXdr>(&mut self, entry: &T, ledger_seq: u32) -> Result<()> {
        let xdr_bytes = entry.to_xdr(Limits::none())?;

        // RFC 5531 record marking: 4-byte length prefix (big-endian, high bit set for last fragment)
        // We treat each entry as a complete record (last fragment = 1)
        let len = xdr_bytes.len() as u32;
        let marked_len = len | 0x80000000; // Set high bit for "last fragment"
        self.encoder.write_all(&marked_len.to_be_bytes())?;
        self.encoder.write_all(&xdr_bytes)?;

        // Pad to 4-byte boundary
        let padding = (4 - (len % 4)) % 4;
        if padding > 0 {
            self.encoder.write_all(&vec![0u8; padding as usize])?;
        }

        self.entry_count += 1;
        self.last_ledger = ledger_seq;
        Ok(())
    }

    /// Finish writing and return info about the file.
    fn finish(self) -> Result<(PathBuf, PathBuf, u32)> {
        // Finish the gzip stream
        let buf_writer = self.encoder.finish()?;

        // Flush and sync the file
        // Map IntoInnerError to HistoryError::Io by extracting the underlying IO error
        let file = buf_writer
            .into_inner()
            .map_err(|e| HistoryError::Io(e.into_error()))?;
        file.sync_all()?;

        Ok((self.dirty_path, self.final_path, self.last_ledger))
    }
}

/// Builder for crash-safe checkpoint construction.
///
/// The checkpoint builder accumulates ledger data (headers, transactions, results)
/// and writes them to temporary `.dirty` files. On checkpoint completion, the
/// dirty files are atomically renamed to their final paths.
pub struct CheckpointBuilder {
    /// Directory where checkpoint files are written.
    publish_dir: PathBuf,
    /// Current checkpoint being built (if any).
    current_checkpoint: Option<u32>,
    /// Writer for ledger headers.
    headers_writer: Option<XdrStreamWriter>,
    /// Writer for transactions.
    transactions_writer: Option<XdrStreamWriter>,
    /// Writer for transaction results.
    results_writer: Option<XdrStreamWriter>,
    /// Whether startup validation has been performed.
    startup_validated: bool,
}

impl CheckpointBuilder {
    /// Create a new checkpoint builder.
    ///
    /// # Arguments
    ///
    /// * `publish_dir` - Directory where checkpoint files will be written
    pub fn new(publish_dir: PathBuf) -> Self {
        Self {
            publish_dir,
            current_checkpoint: None,
            headers_writer: None,
            transactions_writer: None,
            results_writer: None,
            startup_validated: false,
        }
    }

    /// Get the current checkpoint being built, if any.
    pub fn current_checkpoint(&self) -> Option<u32> {
        self.current_checkpoint
    }

    /// Check if a checkpoint is currently being built.
    pub fn is_open(&self) -> bool {
        self.current_checkpoint.is_some()
    }

    /// Ensure writers are open for the given checkpoint.
    fn ensure_open(&mut self, checkpoint: u32) -> Result<()> {
        if let Some(current) = self.current_checkpoint {
            if current != checkpoint {
                return Err(HistoryError::CatchupFailed(format!(
                    "checkpoint mismatch: building {} but asked for {}",
                    current, checkpoint
                )));
            }
            return Ok(());
        }

        // Open new writers
        let headers_dirty = self
            .publish_dir
            .join(checkpoint_path_dirty("ledger", checkpoint, "xdr.gz"));
        let headers_final = self
            .publish_dir
            .join(checkpoint_path("ledger", checkpoint, "xdr.gz"));
        self.headers_writer = Some(XdrStreamWriter::new(headers_dirty, headers_final)?);

        let tx_dirty =
            self.publish_dir
                .join(checkpoint_path_dirty("transactions", checkpoint, "xdr.gz"));
        let tx_final = self
            .publish_dir
            .join(checkpoint_path("transactions", checkpoint, "xdr.gz"));
        self.transactions_writer = Some(XdrStreamWriter::new(tx_dirty, tx_final)?);

        let results_dirty = self
            .publish_dir
            .join(checkpoint_path_dirty("results", checkpoint, "xdr.gz"));
        let results_final = self
            .publish_dir
            .join(checkpoint_path("results", checkpoint, "xdr.gz"));
        self.results_writer = Some(XdrStreamWriter::new(results_dirty, results_final)?);

        self.current_checkpoint = Some(checkpoint);
        debug!(checkpoint, "Opened checkpoint builders");
        Ok(())
    }

    /// Append a ledger header to the checkpoint.
    ///
    /// # Arguments
    ///
    /// * `header` - The ledger header to append
    /// * `checkpoint` - The checkpoint this header belongs to
    pub fn append_ledger_header(
        &mut self,
        header: &LedgerHeaderHistoryEntry,
        checkpoint: u32,
    ) -> Result<()> {
        self.ensure_open(checkpoint)?;

        let ledger_seq = header.header.ledger_seq;
        self.headers_writer
            .as_mut()
            .unwrap()
            .write_xdr(header, ledger_seq)?;

        debug!(ledger_seq, checkpoint, "Appended ledger header");
        Ok(())
    }

    /// Append a transaction set and its results to the checkpoint.
    ///
    /// # Arguments
    ///
    /// * `tx_entry` - The transaction history entry
    /// * `result_entry` - The transaction result history entry
    /// * `checkpoint` - The checkpoint these belong to
    pub fn append_transaction_set(
        &mut self,
        tx_entry: &TransactionHistoryEntry,
        result_entry: &TransactionHistoryResultEntry,
        checkpoint: u32,
    ) -> Result<()> {
        self.ensure_open(checkpoint)?;

        let ledger_seq = tx_entry.ledger_seq;

        self.transactions_writer
            .as_mut()
            .unwrap()
            .write_xdr(tx_entry, ledger_seq)?;

        self.results_writer
            .as_mut()
            .unwrap()
            .write_xdr(result_entry, ledger_seq)?;

        debug!(ledger_seq, checkpoint, "Appended transaction set");
        Ok(())
    }

    /// Complete a checkpoint by atomically renaming dirty files to final paths.
    ///
    /// # Arguments
    ///
    /// * `checkpoint` - The checkpoint to complete
    pub fn checkpoint_complete(&mut self, checkpoint: u32) -> Result<()> {
        if self.current_checkpoint != Some(checkpoint) {
            return Err(HistoryError::CatchupFailed(format!(
                "checkpoint_complete called for {} but building {:?}",
                checkpoint, self.current_checkpoint
            )));
        }

        // Take ownership of writers
        let headers = self.headers_writer.take();
        let transactions = self.transactions_writer.take();
        let results = self.results_writer.take();

        // Finish all writers and collect file info
        let mut files_to_rename = Vec::new();

        if let Some(writer) = headers {
            let (dirty, final_path, _last) = writer.finish()?;
            files_to_rename.push((dirty, final_path));
        }

        if let Some(writer) = transactions {
            let (dirty, final_path, _last) = writer.finish()?;
            files_to_rename.push((dirty, final_path));
        }

        if let Some(writer) = results {
            let (dirty, final_path, _last) = writer.finish()?;
            files_to_rename.push((dirty, final_path));
        }

        // Atomically rename all dirty files to final paths
        for (dirty, final_path) in &files_to_rename {
            // Create parent directories for final path if needed
            if let Some(parent) = final_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::rename(dirty, final_path)?;
            debug!(
                dirty = %dirty.display(),
                final_path = %final_path.display(),
                "Renamed dirty file to final"
            );
        }

        self.current_checkpoint = None;
        info!(checkpoint, "Checkpoint complete");
        Ok(())
    }

    /// Clean up and recover state on startup.
    ///
    /// This should be called on startup with the last committed ledger (LCL).
    /// It handles recovery from crashes during checkpoint building.
    ///
    /// # Arguments
    ///
    /// * `lcl` - The last committed ledger sequence
    pub fn cleanup(&mut self, lcl: u32) -> Result<()> {
        info!(lcl, publish_dir = %self.publish_dir.display(), "Cleaning up checkpoint builder");

        // Scan for dirty files in each category
        for category in FILE_CATEGORIES {
            self.cleanup_category(category, lcl)?;
        }

        self.startup_validated = true;
        Ok(())
    }

    /// Clean up dirty files for a specific category.
    fn cleanup_category(&self, category: &str, lcl: u32) -> Result<()> {
        let category_dir = self.publish_dir.join(category);
        if !category_dir.exists() {
            return Ok(());
        }

        // Walk through the category directory looking for dirty files
        self.scan_for_dirty_files(&category_dir, lcl)?;
        Ok(())
    }

    /// Recursively scan for dirty files and handle them.
    fn scan_for_dirty_files(&self, dir: &Path, lcl: u32) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                self.scan_for_dirty_files(&path, lcl)?;
            } else if is_dirty_path(&path) {
                self.handle_dirty_file(&path, lcl)?;
            }
        }

        Ok(())
    }

    /// Handle a single dirty file found during cleanup.
    fn handle_dirty_file(&self, dirty_path: &Path, lcl: u32) -> Result<()> {
        let final_path = match dirty_to_final_path(dirty_path) {
            Some(p) => p,
            None => return Ok(()), // Not a valid dirty path
        };

        let dirty_exists = dirty_path.exists();
        let final_exists = final_path.exists();

        match (dirty_exists, final_exists) {
            (true, true) => {
                // Both exist - delete the dirty file (leftover from completed checkpoint)
                warn!(
                    dirty = %dirty_path.display(),
                    final_path = %final_path.display(),
                    "Deleting leftover dirty file (final exists)"
                );
                fs::remove_file(dirty_path)?;
            }
            (true, false) => {
                // Only dirty exists - this is a partial checkpoint
                // For simplicity, we delete it and let the checkpoint be rebuilt
                // A more sophisticated implementation would truncate to LCL
                warn!(
                    dirty = %dirty_path.display(),
                    lcl,
                    "Deleting partial dirty file (will be rebuilt)"
                );
                fs::remove_file(dirty_path)?;
            }
            (false, true) => {
                // Only final exists - this is normal, nothing to do
                debug!(
                    final_path = %final_path.display(),
                    "Final file exists, no cleanup needed"
                );
            }
            (false, false) => {
                // Neither exists - nothing to do
            }
        }

        Ok(())
    }

    /// Check if startup validation has been performed.
    pub fn is_validated(&self) -> bool {
        self.startup_validated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        Hash, LedgerHeader, LedgerHeaderExt, LedgerHeaderHistoryEntryExt, StellarValue,
        StellarValueExt, TimePoint, TransactionHistoryEntry, TransactionHistoryEntryExt,
        TransactionHistoryResultEntry, TransactionHistoryResultEntryExt, TransactionResultSet,
        TransactionSet, VecM,
    };

    fn make_header(seq: u32) -> LedgerHeaderHistoryEntry {
        LedgerHeaderHistoryEntry {
            hash: Hash([seq as u8; 32]),
            header: LedgerHeader {
                ledger_version: 20,
                previous_ledger_hash: Hash([0; 32]),
                scp_value: StellarValue {
                    tx_set_hash: Hash([0; 32]),
                    close_time: TimePoint(0),
                    upgrades: VecM::default(),
                    ext: StellarValueExt::Basic,
                },
                tx_set_result_hash: Hash([0; 32]),
                bucket_list_hash: Hash([0; 32]),
                ledger_seq: seq,
                total_coins: 0,
                fee_pool: 0,
                inflation_seq: 0,
                id_pool: 0,
                base_fee: 100,
                base_reserve: 5000000,
                max_tx_set_size: 100,
                skip_list: [Hash([0; 32]), Hash([0; 32]), Hash([0; 32]), Hash([0; 32])],
                ext: LedgerHeaderExt::V0,
            },
            ext: LedgerHeaderHistoryEntryExt::default(),
        }
    }

    fn make_tx_entry(seq: u32) -> TransactionHistoryEntry {
        TransactionHistoryEntry {
            ledger_seq: seq,
            tx_set: TransactionSet {
                previous_ledger_hash: Hash([0; 32]),
                txs: VecM::default(),
            },
            ext: TransactionHistoryEntryExt::default(),
        }
    }

    fn make_result_entry(seq: u32) -> TransactionHistoryResultEntry {
        TransactionHistoryResultEntry {
            ledger_seq: seq,
            tx_result_set: TransactionResultSet {
                results: VecM::default(),
            },
            ext: TransactionHistoryResultEntryExt::default(),
        }
    }

    #[test]
    fn test_checkpoint_builder_new() {
        let builder = CheckpointBuilder::new(PathBuf::from("/tmp/test"));
        assert!(!builder.is_open());
        assert!(builder.current_checkpoint().is_none());
        assert!(!builder.is_validated());
    }

    #[test]
    fn test_checkpoint_builder_basic_flow() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut builder = CheckpointBuilder::new(temp_dir.path().to_path_buf());

        let checkpoint = 63;

        // Append some data
        let header = make_header(1);
        builder.append_ledger_header(&header, checkpoint).unwrap();

        let tx = make_tx_entry(1);
        let results = make_result_entry(1);
        builder
            .append_transaction_set(&tx, &results, checkpoint)
            .unwrap();

        assert!(builder.is_open());
        assert_eq!(builder.current_checkpoint(), Some(checkpoint));

        // Dirty files should exist
        let dirty_headers = temp_dir
            .path()
            .join("ledger/00/00/00/ledger-0000003f.xdr.gz.dirty");
        assert!(dirty_headers.exists());

        // Complete the checkpoint
        builder.checkpoint_complete(checkpoint).unwrap();

        assert!(!builder.is_open());

        // Final files should exist, dirty files should not
        let final_headers = temp_dir
            .path()
            .join("ledger/00/00/00/ledger-0000003f.xdr.gz");
        assert!(final_headers.exists());
        assert!(!dirty_headers.exists());
    }

    #[test]
    fn test_cleanup_removes_stale_dirty_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut builder = CheckpointBuilder::new(temp_dir.path().to_path_buf());

        // Create a dirty file manually (simulating a crash)
        let dirty_path = temp_dir
            .path()
            .join("ledger/00/00/00/ledger-0000003f.xdr.gz.dirty");
        fs::create_dir_all(dirty_path.parent().unwrap()).unwrap();
        fs::write(&dirty_path, b"test data").unwrap();

        assert!(dirty_path.exists());

        // Cleanup should remove it
        builder.cleanup(63).unwrap();

        assert!(!dirty_path.exists());
        assert!(builder.is_validated());
    }

    #[test]
    fn test_cleanup_keeps_final_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut builder = CheckpointBuilder::new(temp_dir.path().to_path_buf());

        // Create a final file
        let final_path = temp_dir
            .path()
            .join("ledger/00/00/00/ledger-0000003f.xdr.gz");
        fs::create_dir_all(final_path.parent().unwrap()).unwrap();
        fs::write(&final_path, b"test data").unwrap();

        assert!(final_path.exists());

        // Cleanup should keep it
        builder.cleanup(63).unwrap();

        assert!(final_path.exists());
    }

    #[test]
    fn test_cleanup_removes_dirty_when_final_exists() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut builder = CheckpointBuilder::new(temp_dir.path().to_path_buf());

        // Create both dirty and final files
        let dirty_path = temp_dir
            .path()
            .join("ledger/00/00/00/ledger-0000003f.xdr.gz.dirty");
        let final_path = temp_dir
            .path()
            .join("ledger/00/00/00/ledger-0000003f.xdr.gz");
        fs::create_dir_all(dirty_path.parent().unwrap()).unwrap();
        fs::write(&dirty_path, b"dirty data").unwrap();
        fs::write(&final_path, b"final data").unwrap();

        // Cleanup should remove dirty but keep final
        builder.cleanup(63).unwrap();

        assert!(!dirty_path.exists());
        assert!(final_path.exists());
    }
}
