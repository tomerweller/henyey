//! Error types for history operations.
//!
//! This module defines the error types used throughout the history crate.
//! Errors are categorized by their source:
//!
//! - **Network errors**: HTTP failures, timeouts, unavailable archives
//! - **Parsing errors**: Malformed XDR, JSON, or URL data
//! - **Verification errors**: Hash mismatches, broken chains, invalid sequences
//! - **Catchup errors**: Process failures during synchronization

use stellar_core_common::Hash256;
use thiserror::Error;

/// Errors that can occur during history operations.
///
/// These errors cover the full range of failures that can occur when
/// interacting with history archives, from network issues to data
/// integrity problems.
#[derive(Debug, Error)]
pub enum HistoryError {
    /// Archive not reachable.
    #[error("archive not reachable: {0}")]
    ArchiveUnreachable(String),

    /// Checkpoint not found.
    #[error("checkpoint not found: {0}")]
    CheckpointNotFound(u32),

    /// History verification failed.
    #[error("history verification failed: {0}")]
    VerificationFailed(String),

    /// Catchup failed.
    #[error("catchup failed: {0}")]
    CatchupFailed(String),

    /// HTTP error from reqwest.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// HTTP status error.
    #[error("HTTP status {status} for {url}")]
    HttpStatus {
        /// The URL that returned the error.
        url: String,
        /// The HTTP status code.
        status: u16,
    },

    /// Resource not found (404).
    #[error("not found: {0}")]
    NotFound(String),

    /// Download failed after retries.
    #[error("download failed: {0}")]
    DownloadFailed(String),

    /// Invalid response.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// URL parse error.
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// JSON parse error.
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    /// XDR error.
    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::curr::Error),

    /// XDR parsing error.
    #[error("XDR parsing error: {0}")]
    XdrParsing(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Bucket not found.
    #[error("bucket not found: {0}")]
    BucketNotFound(Hash256),

    /// No archive available.
    #[error("no archive available")]
    NoArchiveAvailable,

    /// Invalid ledger sequence.
    #[error("invalid sequence: expected {expected}, got {got}")]
    InvalidSequence {
        /// Expected ledger sequence.
        expected: u32,
        /// Actual ledger sequence.
        got: u32,
    },

    /// Invalid previous hash in ledger chain.
    #[error("invalid previous hash at ledger {ledger}")]
    InvalidPreviousHash {
        /// The ledger with the invalid previous hash.
        ledger: u32,
    },

    /// Invalid transaction set hash.
    #[error("invalid tx set hash at ledger {ledger}")]
    InvalidTxSetHash {
        /// The ledger with the invalid transaction set hash.
        ledger: u32,
    },

    /// Not a checkpoint ledger.
    #[error("not a checkpoint ledger: {0}")]
    NotCheckpointLedger(u32),

    /// Unsupported mode.
    #[error("unsupported mode: {0}")]
    UnsupportedMode(String),

    /// Bucket error from stellar-core-bucket crate.
    #[error("bucket error: {0}")]
    Bucket(#[from] stellar_core_bucket::BucketError),

    /// Database error from stellar-core-db crate.
    #[error("database error: {0}")]
    Database(#[from] stellar_core_db::DbError),
}
