//! Cryptographic verification utilities for history data.
//!
//! This module provides functions to verify the integrity of all data downloaded
//! from history archives. Verification is essential for security: while we download
//! from trusted archives, we cryptographically verify everything to detect corruption
//! or tampering.
//!
//! # Verification Layers
//!
//! ## Header Chain Verification
//!
//! Ledger headers form a cryptographic hash chain where each header contains
//! `previous_ledger_hash` - the SHA-256 hash of the previous header. This
//! ensures that any modification to historical headers would be detected.
//!
//! ## Bucket Hash Verification
//!
//! Each bucket file is identified by its SHA-256 content hash. After downloading,
//! we verify that `SHA256(bucket_content) == expected_hash`. This prevents both
//! accidental corruption and malicious substitution.
//!
//! ## Transaction Set Verification
//!
//! The transaction set hash in the SCP value must match the hash of the
//! downloaded transaction set. For classic sets, this is computed over the
//! concatenation of previous_ledger_hash and transaction XDR. For generalized
//! sets, it is the hash of the entire set XDR.
//!
//! ## Bucket List Hash Verification
//!
//! The final verification: the computed bucket list hash from our reconstructed
//! state must match `header.bucket_list_hash`. This proves that we have correctly
//! rebuilt the entire ledger state.

use crate::{archive_state::HistoryArchiveState, checkpoint, HistoryError, Result, GENESIS_LEDGER_SEQ};
use henyey_common::Hash256;
use henyey_crypto::Sha256Hasher;
use henyey_ledger::TransactionSetVariant;
use stellar_xdr::curr::{
    LedgerHeader, Limits, ScpHistoryEntry, ScpStatement,
    TransactionHistoryResultEntry, WriteXdr,
};

/// Verify that a chain of ledger headers is correctly linked.
///
/// Each header's `previous_ledger_hash` must match the hash of the previous header.
/// Headers must be in ascending order by sequence number.
///
/// # Arguments
///
/// * `headers` - Slice of ledger headers in sequence order (oldest first)
///
/// # Returns
///
/// Ok(()) if the chain is valid, or an error describing the verification failure.
pub fn verify_header_chain(headers: &[LedgerHeader]) -> Result<()> {
    if headers.is_empty() {
        return Ok(());
    }

    for i in 1..headers.len() {
        let prev_header = &headers[i - 1];
        let curr_header = &headers[i];

        // Check sequence numbers are consecutive
        if curr_header.ledger_seq != prev_header.ledger_seq + 1 {
            return Err(HistoryError::InvalidSequence {
                expected: prev_header.ledger_seq + 1,
                got: curr_header.ledger_seq,
            });
        }

        // Compute hash of previous header
        let prev_hash = compute_header_hash(prev_header)?;

        // Check that current header's previous_ledger_hash matches
        let expected_prev_hash = Hash256::from(curr_header.previous_ledger_hash.clone());
        if prev_hash != expected_prev_hash {
            return Err(HistoryError::InvalidPreviousHash {
                ledger: curr_header.ledger_seq,
            });
        }
    }

    Ok(())
}

/// Verify that a bucket's content matches its expected hash.
///
/// # Arguments
///
/// * `data` - Raw bucket data (typically decompressed XDR)
/// * `expected_hash` - The expected SHA-256 hash of the bucket
///
/// # Returns
///
/// Ok(()) if the hash matches, or an error if it doesn't.
pub fn verify_bucket_hash(data: &[u8], expected_hash: &Hash256) -> Result<()> {
    let actual_hash = Hash256::hash(data);

    if actual_hash != *expected_hash {
        return Err(HistoryError::VerificationFailed(format!(
            "bucket hash mismatch: expected {}, got {}",
            expected_hash, actual_hash
        )));
    }

    Ok(())
}

/// Verify that a ledger header's bucket list hash matches the expected value.
///
/// This verifies that the ledger state (represented by the BucketList) matches
/// what the header claims.
///
/// # Arguments
///
/// * `header` - The ledger header to verify
/// * `bucket_list_hash` - The computed hash of the BucketList
///
/// # Returns
///
/// Ok(()) if the hashes match, or an error if they don't.
pub fn verify_ledger_hash(header: &LedgerHeader, bucket_list_hash: &Hash256) -> Result<()> {
    let header_bucket_hash = Hash256::from(header.bucket_list_hash.clone());

    if header_bucket_hash != *bucket_list_hash {
        return Err(HistoryError::VerificationFailed(format!(
            "bucket list hash mismatch at ledger {}: header claims {}, computed {}",
            header.ledger_seq, header_bucket_hash, bucket_list_hash
        )));
    }

    Ok(())
}

/// Compute the SHA-256 hash of a ledger header.
///
/// This is the hash that gets stored in the next ledger's `previous_ledger_hash`.
pub fn compute_header_hash(header: &LedgerHeader) -> Result<Hash256> {
    let xdr_bytes = header
        .to_xdr(stellar_xdr::curr::Limits::none())
        .map_err(|e| HistoryError::VerificationFailed(format!("failed to encode header: {}", e)))?;

    Ok(Hash256::hash(&xdr_bytes))
}

/// Verify a transaction result set against the ledger header.
///
/// The hash of the transaction result set must match what's in the header.
/// For the genesis ledger (seq == 1), an empty result set is accepted without
/// hash verification, matching stellar-core's `VerifyTxResultsWork`.
///
/// # Arguments
///
/// * `header` - The ledger header
/// * `tx_result_set_xdr` - XDR-encoded transaction result set
pub fn verify_tx_result_set(header: &LedgerHeader, tx_result_set_xdr: &[u8]) -> Result<()> {
    // Genesis ledger exception: stellar-core skips verification when the result
    // set is empty at the genesis ledger because it has no transactions.
    if header.ledger_seq == GENESIS_LEDGER_SEQ && tx_result_set_xdr.is_empty() {
        return Ok(());
    }

    let actual_hash = Hash256::hash(tx_result_set_xdr);
    let expected_hash = Hash256::from(header.tx_set_result_hash.clone());

    if actual_hash != expected_hash {
        return Err(HistoryError::VerificationFailed(format!(
            "transaction result set hash mismatch at ledger {}: expected {}, got {}",
            header.ledger_seq, expected_hash, actual_hash
        )));
    }

    Ok(())
}

/// Compute the transaction set hash according to protocol rules.
pub fn compute_tx_set_hash(tx_set: &TransactionSetVariant) -> Result<Hash256> {
    match tx_set {
        TransactionSetVariant::Classic(set) => {
            let mut hasher = Sha256Hasher::new();
            hasher.update(&set.previous_ledger_hash.0);
            for tx in set.txs.iter() {
                let bytes = tx.to_xdr(Limits::none()).map_err(|e| {
                    HistoryError::CatchupFailed(format!("failed to encode tx: {}", e))
                })?;
                hasher.update(&bytes);
            }
            Ok(hasher.finalize())
        }
        TransactionSetVariant::Generalized(set) => {
            let bytes = set.to_xdr(Limits::none()).map_err(|e| {
                HistoryError::CatchupFailed(format!("failed to encode tx set: {}", e))
            })?;
            Ok(Hash256::hash(&bytes))
        }
    }
}

/// Verify a transaction set against the ledger header.
///
/// The hash of the transaction set must match what's in the header.
///
/// # Arguments
///
/// * `header` - The ledger header
/// * `tx_set` - Transaction set variant
pub fn verify_tx_set(header: &LedgerHeader, tx_set: &TransactionSetVariant) -> Result<()> {
    let actual_hash = compute_tx_set_hash(tx_set)?;
    // The scpValue contains the tx set hash
    let expected_hash = Hash256::from(header.scp_value.tx_set_hash.clone());

    if actual_hash != expected_hash {
        return Err(HistoryError::InvalidTxSetHash {
            ledger: header.ledger_seq,
        });
    }

    Ok(())
}

/// Verify that a header links correctly to a known trusted header.
///
/// This is used to verify headers downloaded from history against
/// a header we received via SCP (which we trust).
///
/// # Arguments
///
/// * `downloaded_header` - Header downloaded from history archive
/// * `trusted_header` - Header received via SCP consensus
pub fn verify_header_matches_trusted(
    downloaded_header: &LedgerHeader,
    trusted_header: &LedgerHeader,
) -> Result<()> {
    if downloaded_header.ledger_seq != trusted_header.ledger_seq {
        return Err(HistoryError::InvalidSequence {
            expected: trusted_header.ledger_seq,
            got: downloaded_header.ledger_seq,
        });
    }

    let downloaded_hash = compute_header_hash(downloaded_header)?;
    let trusted_hash = compute_header_hash(trusted_header)?;

    if downloaded_hash != trusted_hash {
        return Err(HistoryError::VerificationFailed(format!(
            "header hash mismatch at ledger {}: downloaded {}, trusted {}",
            downloaded_header.ledger_seq, downloaded_hash, trusted_hash
        )));
    }

    Ok(())
}

/// Result of verifying a complete catchup dataset.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Number of headers verified.
    pub headers_verified: u32,
    /// Number of buckets verified.
    pub buckets_verified: u32,
    /// Number of ledgers verified.
    pub ledgers_verified: u32,
    /// The final ledger hash.
    pub final_ledger_hash: Hash256,
}

/// Verify the History Archive State (HAS) structure.
///
/// The HAS contains bucket hashes for each level of the BucketList.
/// This function verifies the structure is well-formed.
pub fn verify_has_structure(has: &HistoryArchiveState) -> Result<()> {
    // Check we have the expected number of levels (typically 11)
    // but we allow flexibility since the structure may vary
    if has.current_buckets.is_empty() {
        return Err(HistoryError::VerificationFailed(
            "HAS has no bucket levels".to_string(),
        ));
    }

    // Check version is supported
    if has.version < 1 || has.version > 2 {
        return Err(HistoryError::VerificationFailed(format!(
            "unsupported HAS version: {}",
            has.version
        )));
    }

    Ok(())
}

/// Verify that the HAS is for the expected checkpoint.
pub fn verify_has_checkpoint(has: &HistoryArchiveState, expected: u32) -> Result<()> {
    if has.current_ledger != expected {
        return Err(HistoryError::VerificationFailed(format!(
            "HAS checkpoint mismatch: expected {}, got {}",
            expected, has.current_ledger
        )));
    }
    Ok(())
}

/// Verify SCP history entries contain quorum sets for all referenced envelopes.
pub fn verify_scp_history_entries(entries: &[ScpHistoryEntry]) -> Result<()> {
    for entry in entries {
        let ScpHistoryEntry::V0(v0) = entry;
        let mut qset_hashes = std::collections::HashSet::new();
        for qset in v0.quorum_sets.iter() {
            qset_hashes.insert(Hash256::hash_xdr(qset)?);
        }

        for envelope in v0.ledger_messages.messages.iter() {
            if let Some(hash) = scp_quorum_set_hash(&envelope.statement) {
                let hash256 = Hash256::from_bytes(hash.0);
                if !qset_hashes.contains(&hash256) {
                    return Err(HistoryError::VerificationFailed(format!(
                        "missing quorum set {} in scp history",
                        hash256.to_hex()
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Verify that transaction result entries within a checkpoint are correctly ordered.
///
/// Validates that:
/// 1. All ledger sequence numbers fall within the checkpoint range
/// 2. Sequence numbers are strictly increasing
///
/// # Arguments
///
/// * `entries` - Transaction result entries to verify
/// * `checkpoint` - The checkpoint ledger sequence number
pub fn verify_tx_result_ordering(
    entries: &[TransactionHistoryResultEntry],
    checkpoint: u32,
) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    let (range_start, range_end) = checkpoint::checkpoint_range(checkpoint);

    let mut prev_seq = None;
    for entry in entries {
        // Check within checkpoint range
        if entry.ledger_seq < range_start || entry.ledger_seq > range_end {
            return Err(HistoryError::VerificationFailed(format!(
                "tx result entry ledger {} outside checkpoint range [{}, {}]",
                entry.ledger_seq, range_start, range_end
            )));
        }

        // Check strictly increasing
        if let Some(prev) = prev_seq {
            if entry.ledger_seq <= prev {
                return Err(HistoryError::VerificationFailed(format!(
                    "tx result entries not strictly increasing: {} followed by {}",
                    prev, entry.ledger_seq
                )));
            }
        }

        prev_seq = Some(entry.ledger_seq);
    }

    Ok(())
}

fn scp_quorum_set_hash(statement: &ScpStatement) -> Option<stellar_xdr::curr::Hash> {
    match &statement.pledges {
        stellar_xdr::curr::ScpStatementPledges::Nominate(nom) => Some(nom.quorum_set_hash.clone()),
        stellar_xdr::curr::ScpStatementPledges::Prepare(prep) => Some(prep.quorum_set_hash.clone()),
        stellar_xdr::curr::ScpStatementPledges::Confirm(conf) => Some(conf.quorum_set_hash.clone()),
        stellar_xdr::curr::ScpStatementPledges::Externalize(ext) => {
            Some(ext.commit_quorum_set_hash.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{Hash, StellarValue, TimePoint, VecM};

    fn make_test_header(seq: u32, prev_hash: Hash256) -> LedgerHeader {
        LedgerHeader {
            ledger_version: 20,
            previous_ledger_hash: prev_hash.into(),
            scp_value: StellarValue {
                tx_set_hash: Hash([0u8; 32]),
                close_time: TimePoint(0),
                upgrades: VecM::default(),
                ext: stellar_xdr::curr::StellarValueExt::Basic,
            },
            tx_set_result_hash: Hash([0u8; 32]),
            bucket_list_hash: Hash([0u8; 32]),
            ledger_seq: seq,
            total_coins: 0,
            fee_pool: 0,
            inflation_seq: 0,
            id_pool: 0,
            base_fee: 100,
            base_reserve: 5000000,
            max_tx_set_size: 100,
            skip_list: std::array::from_fn(|_| Hash([0u8; 32])),
            ext: stellar_xdr::curr::LedgerHeaderExt::V0,
        }
    }

    #[test]
    fn test_verify_header_chain_valid() {
        let header1 = make_test_header(1, Hash256::ZERO);
        let hash1 = compute_header_hash(&header1).unwrap();
        let header2 = make_test_header(2, hash1);
        let hash2 = compute_header_hash(&header2).unwrap();
        let header3 = make_test_header(3, hash2);

        let headers = vec![header1, header2, header3];
        assert!(verify_header_chain(&headers).is_ok());
    }

    #[test]
    fn test_verify_header_chain_broken() {
        let header1 = make_test_header(1, Hash256::ZERO);
        let header2 = make_test_header(2, Hash256::ZERO); // Wrong prev hash
        let headers = vec![header1, header2];

        assert!(verify_header_chain(&headers).is_err());
    }

    #[test]
    fn test_verify_header_chain_non_consecutive() {
        let header1 = make_test_header(1, Hash256::ZERO);
        let hash1 = compute_header_hash(&header1).unwrap();
        let header3 = make_test_header(3, hash1); // Skipped sequence 2

        let headers = vec![header1, header3];
        assert!(verify_header_chain(&headers).is_err());
    }

    #[test]
    fn test_verify_bucket_hash() {
        let data = b"test bucket data";
        let correct_hash = Hash256::hash(data);
        let wrong_hash = Hash256::hash(b"different data");

        assert!(verify_bucket_hash(data, &correct_hash).is_ok());
        assert!(verify_bucket_hash(data, &wrong_hash).is_err());
    }

    #[test]
    fn test_verify_header_chain_empty() {
        let headers: Vec<LedgerHeader> = vec![];
        assert!(verify_header_chain(&headers).is_ok());
    }

    #[test]
    fn test_verify_header_chain_single() {
        let header = make_test_header(1, Hash256::ZERO);
        let headers = vec![header];
        assert!(verify_header_chain(&headers).is_ok());
    }

    // Item 1: Genesis ledger exception tests
    #[test]
    fn test_verify_tx_result_set_genesis_empty() {
        let header = make_test_header(GENESIS_LEDGER_SEQ, Hash256::ZERO);
        // Empty result set at genesis should pass without hash check
        assert!(verify_tx_result_set(&header, &[]).is_ok());
    }

    #[test]
    fn test_verify_tx_result_set_genesis_nonempty() {
        let header = make_test_header(GENESIS_LEDGER_SEQ, Hash256::ZERO);
        // Non-empty result set at genesis should still verify hash
        let result = verify_tx_result_set(&header, &[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_tx_result_set_non_genesis_empty() {
        let header = make_test_header(2, Hash256::ZERO);
        // Empty result at non-genesis should still verify hash
        let result = verify_tx_result_set(&header, &[]);
        // This will fail unless the hash happens to match (it won't for zero header)
        // The hash of empty bytes won't match the zero tx_set_result_hash
        let empty_hash = Hash256::hash(&[]);
        let expected_hash = Hash256::from(header.tx_set_result_hash.clone());
        if empty_hash != expected_hash {
            assert!(result.is_err());
        }
    }

    // Item 4: Transaction result ordering tests
    #[test]
    fn test_verify_tx_result_ordering_valid() {
        use stellar_xdr::curr::{
            TransactionHistoryResultEntry, TransactionHistoryResultEntryExt,
            TransactionResultSet, VecM,
        };

        let entries = vec![
            TransactionHistoryResultEntry {
                ledger_seq: 64,
                tx_result_set: TransactionResultSet {
                    results: VecM::default(),
                },
                ext: TransactionHistoryResultEntryExt::V0,
            },
            TransactionHistoryResultEntry {
                ledger_seq: 65,
                tx_result_set: TransactionResultSet {
                    results: VecM::default(),
                },
                ext: TransactionHistoryResultEntryExt::V0,
            },
            TransactionHistoryResultEntry {
                ledger_seq: 127,
                tx_result_set: TransactionResultSet {
                    results: VecM::default(),
                },
                ext: TransactionHistoryResultEntryExt::V0,
            },
        ];
        assert!(verify_tx_result_ordering(&entries, 127).is_ok());
    }

    #[test]
    fn test_verify_tx_result_ordering_out_of_range() {
        use stellar_xdr::curr::{
            TransactionHistoryResultEntry, TransactionHistoryResultEntryExt,
            TransactionResultSet, VecM,
        };

        let entries = vec![TransactionHistoryResultEntry {
            ledger_seq: 200, // Outside checkpoint 127 (range 64-127)
            tx_result_set: TransactionResultSet {
                results: VecM::default(),
            },
            ext: TransactionHistoryResultEntryExt::V0,
        }];
        assert!(verify_tx_result_ordering(&entries, 127).is_err());
    }

    #[test]
    fn test_verify_tx_result_ordering_not_increasing() {
        use stellar_xdr::curr::{
            TransactionHistoryResultEntry, TransactionHistoryResultEntryExt,
            TransactionResultSet, VecM,
        };

        let entries = vec![
            TransactionHistoryResultEntry {
                ledger_seq: 65,
                tx_result_set: TransactionResultSet {
                    results: VecM::default(),
                },
                ext: TransactionHistoryResultEntryExt::V0,
            },
            TransactionHistoryResultEntry {
                ledger_seq: 65, // Duplicate, not strictly increasing
                tx_result_set: TransactionResultSet {
                    results: VecM::default(),
                },
                ext: TransactionHistoryResultEntryExt::V0,
            },
        ];
        assert!(verify_tx_result_ordering(&entries, 127).is_err());
    }

    #[test]
    fn test_verify_tx_result_ordering_empty() {
        let entries: Vec<TransactionHistoryResultEntry> = vec![];
        assert!(verify_tx_result_ordering(&entries, 127).is_ok());
    }

    #[test]
    fn test_verify_tx_result_ordering_descending() {
        use stellar_xdr::curr::{
            TransactionHistoryResultEntry, TransactionHistoryResultEntryExt,
            TransactionResultSet, VecM,
        };

        let entries = vec![
            TransactionHistoryResultEntry {
                ledger_seq: 100,
                tx_result_set: TransactionResultSet {
                    results: VecM::default(),
                },
                ext: TransactionHistoryResultEntryExt::V0,
            },
            TransactionHistoryResultEntry {
                ledger_seq: 80, // Descending, not strictly increasing
                tx_result_set: TransactionResultSet {
                    results: VecM::default(),
                },
                ext: TransactionHistoryResultEntryExt::V0,
            },
        ];
        assert!(verify_tx_result_ordering(&entries, 127).is_err());
    }

    #[test]
    fn test_verify_tx_result_ordering_single_entry() {
        use stellar_xdr::curr::{
            TransactionHistoryResultEntry, TransactionHistoryResultEntryExt,
            TransactionResultSet, VecM,
        };

        let entries = vec![TransactionHistoryResultEntry {
            ledger_seq: 100,
            tx_result_set: TransactionResultSet {
                results: VecM::default(),
            },
            ext: TransactionHistoryResultEntryExt::V0,
        }];
        assert!(verify_tx_result_ordering(&entries, 127).is_ok());
    }

    #[test]
    fn test_verify_tx_result_ordering_first_checkpoint() {
        use stellar_xdr::curr::{
            TransactionHistoryResultEntry, TransactionHistoryResultEntryExt,
            TransactionResultSet, VecM,
        };

        // Checkpoint 63: range is 0-63
        let entries = vec![
            TransactionHistoryResultEntry {
                ledger_seq: 1,
                tx_result_set: TransactionResultSet {
                    results: VecM::default(),
                },
                ext: TransactionHistoryResultEntryExt::V0,
            },
            TransactionHistoryResultEntry {
                ledger_seq: 63,
                tx_result_set: TransactionResultSet {
                    results: VecM::default(),
                },
                ext: TransactionHistoryResultEntryExt::V0,
            },
        ];
        assert!(verify_tx_result_ordering(&entries, 63).is_ok());
    }
}
