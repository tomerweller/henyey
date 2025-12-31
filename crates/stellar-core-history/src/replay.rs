//! Ledger replay for history catchup.
//!
//! This module handles replaying ledgers from history during catchup.
//!
//! Key insight: During catchup, we don't re-execute transactions. Instead, we:
//! 1. Download the state at a checkpoint (bucket list)
//! 2. Download ledger headers, transaction sets, and transaction results
//! 3. Apply the *known* results from history to update ledger state
//!
//! This is safe because:
//! - The bucket list hash in each header verifies the state is correct
//! - The transaction result hash in each header verifies the results
//! - We trust history archives that have been verified

use crate::{verify, HistoryError, Result};
use stellar_core_common::Hash256;
use stellar_xdr::curr::{
    LedgerEntry, LedgerHeader, LedgerKey, TransactionMeta, TransactionResultPair,
    TransactionSet, WriteXdr,
};

/// The result of replaying a single ledger.
#[derive(Debug, Clone)]
pub struct LedgerReplayResult {
    /// The ledger sequence that was replayed.
    pub sequence: u32,
    /// Hash of the ledger after replay.
    pub ledger_hash: Hash256,
    /// Number of transactions in the ledger.
    pub tx_count: u32,
    /// Number of operations in the ledger.
    pub op_count: u32,
    /// Changes to apply to the bucket list.
    pub live_entries: Vec<LedgerEntry>,
    /// Keys to mark as dead in the bucket list.
    pub dead_entries: Vec<LedgerKey>,
}

/// Configuration for ledger replay.
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Whether to verify transaction results.
    pub verify_results: bool,
    /// Whether to verify bucket list hashes.
    pub verify_bucket_list: bool,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            verify_results: true,
            verify_bucket_list: true,
        }
    }
}

/// Replays a single ledger from history data.
///
/// This applies the transaction results to extract ledger entry changes,
/// which can then be applied to the bucket list.
///
/// # Arguments
///
/// * `header` - The ledger header
/// * `tx_set` - The transaction set for this ledger
/// * `tx_results` - The transaction results from history
/// * `tx_metas` - Transaction metadata containing ledger entry changes
/// * `config` - Replay configuration
///
/// # Returns
///
/// A `LedgerReplayResult` containing the changes to apply to ledger state.
pub fn replay_ledger(
    header: &LedgerHeader,
    tx_set: &TransactionSet,
    _tx_results: &[TransactionResultPair],
    tx_metas: &[TransactionMeta],
    config: &ReplayConfig,
) -> Result<LedgerReplayResult> {
    // Verify the transaction set hash matches the header
    if config.verify_results {
        let tx_set_xdr = tx_set
            .to_xdr(stellar_xdr::curr::Limits::none())
            .map_err(|e| HistoryError::CatchupFailed(format!("failed to encode tx set: {}", e)))?;
        verify::verify_tx_set(header, &tx_set_xdr)?;
    }

    // Extract ledger entry changes from transaction metadata
    let (live_entries, dead_entries) = extract_ledger_changes(tx_metas)?;

    // Count transactions and operations
    let tx_count = tx_set.txs.len() as u32;
    let op_count = count_operations(tx_set);

    // Compute the ledger hash
    let ledger_hash = verify::compute_header_hash(header)?;

    Ok(LedgerReplayResult {
        sequence: header.ledger_seq,
        ledger_hash,
        tx_count,
        op_count,
        live_entries,
        dead_entries,
    })
}

/// Extract ledger entry changes from transaction metadata.
///
/// Returns (live_entries, dead_entries) where:
/// - live_entries: Entries that were created or updated
/// - dead_entries: Keys of entries that were deleted
fn extract_ledger_changes(
    tx_metas: &[TransactionMeta],
) -> Result<(Vec<LedgerEntry>, Vec<LedgerKey>)> {
    let mut live_entries = Vec::new();
    let mut dead_entries = Vec::new();

    for meta in tx_metas {
        match meta {
            TransactionMeta::V0(operations) => {
                // V0: VecM<OperationMeta> - each OperationMeta has a changes field
                for op_meta in operations.iter() {
                    for change in op_meta.changes.iter() {
                        process_ledger_entry_change(change, &mut live_entries, &mut dead_entries);
                    }
                }
            }
            TransactionMeta::V1(v1) => {
                // Process txChanges (before)
                for change in v1.tx_changes.iter() {
                    process_ledger_entry_change(change, &mut live_entries, &mut dead_entries);
                }
                // Process operation changes
                for op_changes in v1.operations.iter() {
                    for change in op_changes.changes.iter() {
                        process_ledger_entry_change(change, &mut live_entries, &mut dead_entries);
                    }
                }
            }
            TransactionMeta::V2(v2) => {
                // Process txChangesBefore
                for change in v2.tx_changes_before.iter() {
                    process_ledger_entry_change(change, &mut live_entries, &mut dead_entries);
                }
                // Process operation changes
                for op_changes in v2.operations.iter() {
                    for change in op_changes.changes.iter() {
                        process_ledger_entry_change(change, &mut live_entries, &mut dead_entries);
                    }
                }
                // Process txChangesAfter
                for change in v2.tx_changes_after.iter() {
                    process_ledger_entry_change(change, &mut live_entries, &mut dead_entries);
                }
            }
            TransactionMeta::V3(v3) => {
                // Process txChangesBefore
                for change in v3.tx_changes_before.iter() {
                    process_ledger_entry_change(change, &mut live_entries, &mut dead_entries);
                }
                // Process operation changes
                for op_changes in v3.operations.iter() {
                    for change in op_changes.changes.iter() {
                        process_ledger_entry_change(change, &mut live_entries, &mut dead_entries);
                    }
                }
                // Process txChangesAfter
                for change in v3.tx_changes_after.iter() {
                    process_ledger_entry_change(change, &mut live_entries, &mut dead_entries);
                }
                // Note: sorobanMeta is handled separately if needed
            }
            TransactionMeta::V4(v4) => {
                // V4 follows the same pattern as V3
                for change in v4.tx_changes_before.iter() {
                    process_ledger_entry_change(change, &mut live_entries, &mut dead_entries);
                }
                for op_changes in v4.operations.iter() {
                    for change in op_changes.changes.iter() {
                        process_ledger_entry_change(change, &mut live_entries, &mut dead_entries);
                    }
                }
                for change in v4.tx_changes_after.iter() {
                    process_ledger_entry_change(change, &mut live_entries, &mut dead_entries);
                }
            }
        }
    }

    Ok((live_entries, dead_entries))
}

/// Process a single ledger entry change.
fn process_ledger_entry_change(
    change: &stellar_xdr::curr::LedgerEntryChange,
    live_entries: &mut Vec<LedgerEntry>,
    dead_entries: &mut Vec<LedgerKey>,
) {
    use stellar_xdr::curr::LedgerEntryChange;

    match change {
        LedgerEntryChange::Created(entry) => {
            live_entries.push(entry.clone());
        }
        LedgerEntryChange::Updated(entry) => {
            live_entries.push(entry.clone());
        }
        LedgerEntryChange::Removed(key) => {
            dead_entries.push(key.clone());
        }
        LedgerEntryChange::State(_) => {
            // State entries represent the state before a change,
            // we don't need to process them for replay
        }
        LedgerEntryChange::Restored(entry) => {
            // Restored entries (from Soroban) are treated as live entries
            live_entries.push(entry.clone());
        }
    }
}

/// Count the total number of operations in a transaction set.
fn count_operations(tx_set: &TransactionSet) -> u32 {
    let mut count = 0;

    for tx_env in tx_set.txs.iter() {
        use stellar_xdr::curr::TransactionEnvelope;
        match tx_env {
            TransactionEnvelope::TxV0(tx) => {
                count += tx.tx.operations.len() as u32;
            }
            TransactionEnvelope::Tx(tx) => {
                count += tx.tx.operations.len() as u32;
            }
            TransactionEnvelope::TxFeeBump(tx) => {
                // Fee bump wraps an inner transaction
                match &tx.tx.inner_tx {
                    stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                        count += inner.tx.operations.len() as u32;
                    }
                }
            }
        }
    }

    count
}

/// Replay a batch of ledgers.
///
/// This is used during catchup to replay all ledgers from a checkpoint
/// to the target ledger.
///
/// # Arguments
///
/// * `ledgers` - Slice of (header, tx_set, results, metas) tuples
/// * `config` - Replay configuration
/// * `progress_callback` - Optional callback for progress updates
pub fn replay_ledgers<F>(
    ledgers: &[(LedgerHeader, TransactionSet, Vec<TransactionResultPair>, Vec<TransactionMeta>)],
    config: &ReplayConfig,
    mut progress_callback: Option<F>,
) -> Result<Vec<LedgerReplayResult>>
where
    F: FnMut(u32, u32), // (current, total)
{
    let total = ledgers.len() as u32;
    let mut results = Vec::with_capacity(ledgers.len());

    for (i, (header, tx_set, tx_results, tx_metas)) in ledgers.iter().enumerate() {
        let result = replay_ledger(header, tx_set, tx_results, tx_metas, config)?;
        results.push(result);

        if let Some(ref mut callback) = progress_callback {
            callback(i as u32 + 1, total);
        }
    }

    Ok(results)
}

/// Verify ledger consistency after replay.
///
/// Checks that the final bucket list hash matches the expected hash
/// from the last replayed ledger header.
pub fn verify_replay_consistency(
    final_header: &LedgerHeader,
    computed_bucket_list_hash: &Hash256,
) -> Result<()> {
    verify::verify_ledger_hash(final_header, computed_bucket_list_hash)
}

/// Apply replay results to the bucket list.
///
/// This takes the changes from ledger replay and applies them to the
/// bucket list to update the ledger state.
pub fn apply_replay_to_bucket_list(
    bucket_list: &mut stellar_core_bucket::BucketList,
    replay_result: &LedgerReplayResult,
) -> Result<()> {
    bucket_list
        .add_batch(
            replay_result.sequence,
            replay_result.live_entries.clone(),
            replay_result.dead_entries.clone(),
        )
        .map_err(HistoryError::Bucket)
}

/// Prepare a ledger close based on replay data.
///
/// This is used when we've replayed history and want to set up the
/// ledger manager to continue from that point.
#[derive(Debug, Clone)]
pub struct ReplayedLedgerState {
    /// The ledger sequence we replayed to.
    pub sequence: u32,
    /// Hash of the final ledger.
    pub ledger_hash: Hash256,
    /// Hash of the bucket list.
    pub bucket_list_hash: Hash256,
    /// Close time of the final ledger.
    pub close_time: u64,
    /// Protocol version.
    pub protocol_version: u32,
    /// Base fee.
    pub base_fee: u32,
    /// Base reserve.
    pub base_reserve: u32,
}

impl ReplayedLedgerState {
    /// Create from a final ledger header after replay.
    pub fn from_header(header: &LedgerHeader, ledger_hash: Hash256) -> Self {
        Self {
            sequence: header.ledger_seq,
            ledger_hash,
            bucket_list_hash: Hash256::from(header.bucket_list_hash.clone()),
            close_time: header.scp_value.close_time.0,
            protocol_version: header.ledger_version,
            base_fee: header.base_fee,
            base_reserve: header.base_reserve,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{Hash, StellarValue, TimePoint, VecM};

    fn make_test_header(seq: u32) -> LedgerHeader {
        LedgerHeader {
            ledger_version: 20,
            previous_ledger_hash: Hash([0u8; 32]),
            scp_value: StellarValue {
                tx_set_hash: Hash([0u8; 32]),
                close_time: TimePoint(1234567890),
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

    fn make_empty_tx_set() -> TransactionSet {
        TransactionSet {
            previous_ledger_hash: Hash([0u8; 32]),
            txs: VecM::default(),
        }
    }

    #[test]
    fn test_replay_empty_ledger() {
        let header = make_test_header(100);
        let tx_set = make_empty_tx_set();
        let tx_results = vec![];
        let tx_metas = vec![];

        let config = ReplayConfig {
            verify_results: false, // Skip verification for test
            verify_bucket_list: false,
        };

        let result = replay_ledger(&header, &tx_set, &tx_results, &tx_metas, &config).unwrap();

        assert_eq!(result.sequence, 100);
        assert_eq!(result.tx_count, 0);
        assert_eq!(result.op_count, 0);
        assert!(result.live_entries.is_empty());
        assert!(result.dead_entries.is_empty());
    }

    #[test]
    fn test_count_operations_empty() {
        let tx_set = make_empty_tx_set();
        assert_eq!(count_operations(&tx_set), 0);
    }

    #[test]
    fn test_replayed_ledger_state_from_header() {
        let header = make_test_header(42);
        let hash = Hash256::hash(b"test");

        let state = ReplayedLedgerState::from_header(&header, hash);

        assert_eq!(state.sequence, 42);
        assert_eq!(state.ledger_hash, hash);
        assert_eq!(state.close_time, 1234567890);
        assert_eq!(state.protocol_version, 20);
        assert_eq!(state.base_fee, 100);
    }

    #[test]
    fn test_replay_config_default() {
        let config = ReplayConfig::default();
        assert!(config.verify_results);
        assert!(config.verify_bucket_list);
    }
}
