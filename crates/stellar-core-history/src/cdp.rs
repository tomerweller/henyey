//! CDP Data Lake client for fetching LedgerCloseMeta.
//!
//! This module implements SEP-0054 for reading ledger metadata from
//! Stellar's Composable Data Platform (CDP) data lakes stored in S3.
//!
//! Reference: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0054.md

use crate::{HistoryError, Result};
use stellar_xdr::curr::{LedgerCloseMeta, Limits, ReadXdr, WriteXdr};
use std::io::Read;

/// CDP data lake client for fetching LedgerCloseMeta from S3-compatible storage.
#[derive(Debug, Clone)]
pub struct CdpDataLake {
    /// Base URL for the data lake (e.g., "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/v1.1/stellar/ledgers/testnet")
    base_url: String,
    /// HTTP client
    client: reqwest::Client,
    /// Date partition to use (e.g., "2025-12-18")
    date_partition: String,
}

/// Configuration for the CDP data lake.
#[derive(Debug, Clone, Default)]
pub struct CdpConfig {
    /// Number of ledgers per batch file (default: 1)
    pub ledgers_per_batch: u32,
    /// Number of batches per partition directory (default: 64000)
    pub batches_per_partition: u32,
}

impl CdpDataLake {
    /// Create a new CDP data lake client.
    ///
    /// # Arguments
    /// * `base_url` - Base URL for the data lake (e.g., "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/v1.1/stellar/ledgers/testnet")
    /// * `date_partition` - Date partition to use (e.g., "2025-12-18")
    pub fn new(base_url: &str, date_partition: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            date_partition: date_partition.to_string(),
        }
    }

    /// Calculate the partition directory name for a ledger sequence.
    ///
    /// Partitions are 64000 ledgers each (configurable).
    /// Format: `{inverted_start}--{start}-{end}/`
    fn partition_for_ledger(&self, ledger_seq: u32) -> String {
        let partition_size: u32 = 64000;
        let partition_start = (ledger_seq / partition_size) * partition_size;
        let partition_end = partition_start + partition_size - 1;
        let inverted = u32::MAX - partition_start;
        format!("{:08X}--{}-{}", inverted, partition_start, partition_end)
    }

    /// Calculate the batch file name for a ledger sequence.
    ///
    /// For single-ledger batches: `{inverted}--{ledger}.xdr.zst`
    fn batch_filename(&self, ledger_seq: u32) -> String {
        let inverted = u32::MAX - ledger_seq;
        format!("{:08X}--{}.xdr.zst", inverted, ledger_seq)
    }

    /// Build the full URL for a ledger's metadata file.
    fn url_for_ledger(&self, ledger_seq: u32) -> String {
        let partition = self.partition_for_ledger(ledger_seq);
        let filename = self.batch_filename(ledger_seq);
        format!(
            "{}/{}/{}/{}",
            self.base_url, self.date_partition, partition, filename
        )
    }

    /// Fetch LedgerCloseMeta for a single ledger.
    pub async fn get_ledger_close_meta(&self, ledger_seq: u32) -> Result<LedgerCloseMeta> {
        let url = self.url_for_ledger(ledger_seq);
        tracing::debug!(ledger_seq = ledger_seq, url = %url, "Fetching LedgerCloseMeta from CDP");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| HistoryError::DownloadFailed(format!("CDP fetch failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(HistoryError::HttpStatus {
                url: url.clone(),
                status: response.status().as_u16(),
            });
        }

        let compressed_data: bytes::Bytes = response
            .bytes()
            .await
            .map_err(|e| HistoryError::DownloadFailed(format!("CDP read failed: {}", e)))?;

        // Decompress zstd
        let decompressed = self.decompress_zstd(&compressed_data)?;

        // Parse the LedgerCloseMetaBatch XDR
        // The batch format is: startSequence (u32) + endSequence (u32) + LedgerCloseMeta[]
        self.parse_ledger_close_meta_batch(&decompressed, ledger_seq)
    }

    /// Fetch LedgerCloseMeta for a range of ledgers.
    pub async fn get_ledger_close_metas(
        &self,
        start_seq: u32,
        end_seq: u32,
    ) -> Result<Vec<LedgerCloseMeta>> {
        let mut metas = Vec::with_capacity((end_seq - start_seq + 1) as usize);

        for seq in start_seq..=end_seq {
            let meta = self.get_ledger_close_meta(seq).await?;
            metas.push(meta);
        }

        Ok(metas)
    }

    /// Decompress zstd-compressed data.
    fn decompress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = zstd::Decoder::new(data)
            .map_err(|e| HistoryError::XdrParsing(format!("zstd init failed: {}", e)))?;

        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| HistoryError::XdrParsing(format!("zstd decompress failed: {}", e)))?;

        Ok(decompressed)
    }

    /// Parse LedgerCloseMetaBatch XDR and extract the LedgerCloseMeta for the requested ledger.
    ///
    /// The batch format according to SEP-0054:
    /// ```xdr
    /// struct LedgerCloseMetaBatch {
    ///     uint32 startSequence;
    ///     uint32 endSequence;
    ///     LedgerCloseMeta ledgerCloseMetas<>;
    /// }
    /// ```
    fn parse_ledger_close_meta_batch(
        &self,
        data: &[u8],
        requested_ledger: u32,
    ) -> Result<LedgerCloseMeta> {
        if data.len() < 8 {
            return Err(HistoryError::XdrParsing(
                "LedgerCloseMetaBatch too short".to_string(),
            ));
        }

        // Read startSequence and endSequence (big-endian u32)
        let start_seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let end_seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        tracing::debug!(
            start_seq = start_seq,
            end_seq = end_seq,
            requested = requested_ledger,
            "Parsing LedgerCloseMetaBatch"
        );

        if requested_ledger < start_seq || requested_ledger > end_seq {
            return Err(HistoryError::XdrParsing(format!(
                "Ledger {} not in batch range [{}, {}]",
                requested_ledger, start_seq, end_seq
            )));
        }

        // Read the count of LedgerCloseMetas (XDR array length)
        if data.len() < 12 {
            return Err(HistoryError::XdrParsing(
                "LedgerCloseMetaBatch missing array length".to_string(),
            ));
        }
        let count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        // For single-ledger batches, just parse the one LedgerCloseMeta
        if count == 1 && start_seq == end_seq {
            let meta = LedgerCloseMeta::from_xdr(&data[12..], Limits::none())
                .map_err(|e| HistoryError::XdrParsing(format!("XDR parse failed: {}", e)))?;
            return Ok(meta);
        }

        // For multi-ledger batches, we need to iterate to find the right one
        // This is less common since the testnet uses 1 ledger per batch
        let mut offset = 12;
        for i in 0..count {
            let current_ledger = start_seq + i;

            // Parse this LedgerCloseMeta
            let meta = LedgerCloseMeta::from_xdr(&data[offset..], Limits::none())
                .map_err(|e| HistoryError::XdrParsing(format!("XDR parse failed: {}", e)))?;

            if current_ledger == requested_ledger {
                return Ok(meta);
            }

            // Skip to next entry (need to calculate XDR size)
            // A proper implementation would calculate the exact size
            offset += meta
                .to_xdr(Limits::none())
                .map_err(|e| HistoryError::XdrParsing(format!("XDR size calc failed: {}", e)))?
                .len();
        }

        Err(HistoryError::XdrParsing(format!(
            "Ledger {} not found in batch",
            requested_ledger
        )))
    }
}

/// Extract TransactionMeta from LedgerCloseMeta for replay.
pub fn extract_transaction_metas(
    meta: &LedgerCloseMeta,
) -> Vec<stellar_xdr::curr::TransactionMeta> {
    match meta {
        LedgerCloseMeta::V0(v0) => v0
            .tx_processing
            .iter()
            .map(|tp| tp.tx_apply_processing.clone())
            .collect(),
        LedgerCloseMeta::V1(v1) => v1
            .tx_processing
            .iter()
            .map(|tp| tp.tx_apply_processing.clone())
            .collect(),
        LedgerCloseMeta::V2(v2) => v2
            .tx_processing
            .iter()
            .map(|tp| tp.tx_apply_processing.clone())
            .collect(),
    }
}

/// Transaction processing info - combines envelope, result, and meta in apply order.
#[derive(Debug, Clone)]
pub struct TransactionProcessingInfo {
    /// The transaction envelope
    pub envelope: stellar_xdr::curr::TransactionEnvelope,
    /// The transaction result
    pub result: stellar_xdr::curr::TransactionResultPair,
    /// The transaction metadata (ledger entry changes)
    pub meta: stellar_xdr::curr::TransactionMeta,
    /// Fee changes meta
    pub fee_meta: stellar_xdr::curr::LedgerEntryChanges,
}

/// Extract all transaction processing info in apply order from LedgerCloseMeta.
/// This ensures envelope, result, and meta are all aligned.
/// The network_id is needed to compute the correct transaction hash for matching.
pub fn extract_transaction_processing(
    meta: &LedgerCloseMeta,
    network_id: &[u8; 32],
) -> Vec<TransactionProcessingInfo> {
    match meta {
        LedgerCloseMeta::V0(v0) => {
            // V0 has a simpler structure - tx_set.txs and tx_processing should align
            let txs = &v0.tx_set.txs;
            let processing_count = v0.tx_processing.len();
            let result: Vec<_> = v0.tx_processing
                .iter()
                .enumerate()
                .filter_map(|(i, tp)| {
                    txs.get(i).map(|env| TransactionProcessingInfo {
                        envelope: env.clone(),
                        result: tp.result.clone(),
                        meta: tp.tx_apply_processing.clone(),
                        fee_meta: tp.fee_processing.clone(),
                    })
                })
                .collect();
            if result.len() != processing_count {
                tracing::warn!(
                    processing_count = processing_count,
                    result_count = result.len(),
                    "Some transactions were not matched in V0 LedgerCloseMeta"
                );
            }
            result
        }
        LedgerCloseMeta::V1(v1) => {
            // V1/V2: tx_processing contains the transactions in apply order
            // We need to get the envelopes from tx_set but match them to processing
            // The transaction_hash uses network-aware hashing
            let txs = extract_txs_from_generalized_set(&v1.tx_set);
            let tx_map = build_tx_hash_map_with_network(&txs, network_id);
            let processing_count = v1.tx_processing.len();

            let result: Vec<_> = v1.tx_processing
                .iter()
                .filter_map(|tp| {
                    let tx_hash = tp.result.transaction_hash.0;
                    tx_map.get(&tx_hash).map(|env| TransactionProcessingInfo {
                        envelope: env.clone(),
                        result: tp.result.clone(),
                        meta: tp.tx_apply_processing.clone(),
                        fee_meta: tp.fee_processing.clone(),
                    })
                })
                .collect();
            if result.len() != processing_count {
                tracing::warn!(
                    processing_count = processing_count,
                    result_count = result.len(),
                    txs_in_set = txs.len(),
                    "Some transactions were not matched in V1 LedgerCloseMeta"
                );
            }
            result
        }
        LedgerCloseMeta::V2(v2) => {
            let txs = extract_txs_from_generalized_set(&v2.tx_set);
            let tx_map = build_tx_hash_map_with_network(&txs, network_id);
            let processing_count = v2.tx_processing.len();

            let result: Vec<_> = v2.tx_processing
                .iter()
                .filter_map(|tp| {
                    let tx_hash = tp.result.transaction_hash.0;
                    tx_map.get(&tx_hash).map(|env| TransactionProcessingInfo {
                        envelope: env.clone(),
                        result: tp.result.clone(),
                        meta: tp.tx_apply_processing.clone(),
                        fee_meta: tp.fee_processing.clone(),
                    })
                })
                .collect();
            if result.len() != processing_count {
                tracing::warn!(
                    processing_count = processing_count,
                    result_count = result.len(),
                    txs_in_set = txs.len(),
                    "Some transactions were not matched in V2 LedgerCloseMeta"
                );
            }
            result
        }
    }
}

/// Build a map from transaction hash to envelope for matching.
/// This version uses the network-aware hash (network_id || ENVELOPE_TYPE || tx).
pub fn build_tx_hash_map_with_network(
    txs: &[stellar_xdr::curr::TransactionEnvelope],
    network_id: &[u8; 32],
) -> std::collections::HashMap<[u8; 32], stellar_xdr::curr::TransactionEnvelope> {
    use sha2::{Digest, Sha256};
    use stellar_xdr::curr::{EnvelopeType, Limits, WriteXdr};

    txs.iter()
        .filter_map(|env| {
            // Hash format: SHA256(network_id || envelope_type || transaction)
            let mut hasher = Sha256::new();
            hasher.update(network_id);

            // Add envelope type discriminant
            let envelope_type = match env {
                stellar_xdr::curr::TransactionEnvelope::TxV0(_) => EnvelopeType::TxV0,
                stellar_xdr::curr::TransactionEnvelope::Tx(_) => EnvelopeType::Tx,
                stellar_xdr::curr::TransactionEnvelope::TxFeeBump(_) => EnvelopeType::TxFeeBump,
            };
            hasher.update(&(envelope_type as i32).to_be_bytes());

            // Add the transaction body (not the full envelope)
            match env {
                stellar_xdr::curr::TransactionEnvelope::TxV0(tx_v0) => {
                    let tx_xdr = tx_v0.tx.to_xdr(Limits::none()).ok()?;
                    hasher.update(&tx_xdr);
                }
                stellar_xdr::curr::TransactionEnvelope::Tx(tx_v1) => {
                    let tx_xdr = tx_v1.tx.to_xdr(Limits::none()).ok()?;
                    hasher.update(&tx_xdr);
                }
                stellar_xdr::curr::TransactionEnvelope::TxFeeBump(fee_bump) => {
                    let tx_xdr = fee_bump.tx.to_xdr(Limits::none()).ok()?;
                    hasher.update(&tx_xdr);
                }
            }

            let hash: [u8; 32] = hasher.finalize().into();
            Some((hash, env.clone()))
        })
        .collect()
}

/// Extract ledger header from LedgerCloseMeta.
pub fn extract_ledger_header(meta: &LedgerCloseMeta) -> stellar_xdr::curr::LedgerHeader {
    match meta {
        LedgerCloseMeta::V0(v0) => v0.ledger_header.header.clone(),
        LedgerCloseMeta::V1(v1) => v1.ledger_header.header.clone(),
        LedgerCloseMeta::V2(v2) => v2.ledger_header.header.clone(),
    }
}

/// Extract transaction envelopes from LedgerCloseMeta.
pub fn extract_transaction_envelopes(
    meta: &LedgerCloseMeta,
) -> Vec<stellar_xdr::curr::TransactionEnvelope> {
    match meta {
        LedgerCloseMeta::V0(v0) => v0.tx_set.txs.to_vec(),
        LedgerCloseMeta::V1(v1) => extract_txs_from_generalized_set(&v1.tx_set),
        LedgerCloseMeta::V2(v2) => extract_txs_from_generalized_set(&v2.tx_set),
    }
}

/// Helper to extract transactions from a GeneralizedTransactionSet.
fn extract_txs_from_generalized_set(
    tx_set: &stellar_xdr::curr::GeneralizedTransactionSet,
) -> Vec<stellar_xdr::curr::TransactionEnvelope> {
    match tx_set {
        stellar_xdr::curr::GeneralizedTransactionSet::V1(v1) => {
            v1.phases
                .iter()
                .flat_map(|phase| match phase {
                    stellar_xdr::curr::TransactionPhase::V0(components) => {
                        components
                            .iter()
                            .flat_map(|c| match c {
                                stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(
                                    comp,
                                ) => comp.txs.iter().cloned().collect::<Vec<_>>(),
                            })
                            .collect::<Vec<_>>()
                    }
                    stellar_xdr::curr::TransactionPhase::V1(parallel) => {
                        // V1 phase contains parallel/Soroban transactions in execution_stages
                        let mut txs = Vec::new();
                        for stage in parallel.execution_stages.iter() {
                            for cluster in stage.iter() {
                                txs.extend(cluster.0.iter().cloned());
                            }
                        }
                        txs
                    }
                })
                .collect()
        }
    }
}

/// Extract transaction result pairs from LedgerCloseMeta.
pub fn extract_transaction_results(
    meta: &LedgerCloseMeta,
) -> Vec<stellar_xdr::curr::TransactionResultPair> {
    match meta {
        LedgerCloseMeta::V0(v0) => v0
            .tx_processing
            .iter()
            .map(|tp| tp.result.clone())
            .collect(),
        LedgerCloseMeta::V1(v1) => v1
            .tx_processing
            .iter()
            .map(|tp| tp.result.clone())
            .collect(),
        LedgerCloseMeta::V2(v2) => v2
            .tx_processing
            .iter()
            .map(|tp| tp.result.clone())
            .collect(),
    }
}

/// Extract evicted ledger keys from LedgerCloseMeta (V2 only).
/// These are entries that were evicted from the live bucket list.
pub fn extract_evicted_keys(
    meta: &LedgerCloseMeta,
) -> Vec<stellar_xdr::curr::LedgerKey> {
    match meta {
        LedgerCloseMeta::V0(_) | LedgerCloseMeta::V1(_) => Vec::new(),
        LedgerCloseMeta::V2(v2) => v2.evicted_keys.to_vec(),
    }
}

/// Extract upgrade changes from LedgerCloseMeta.
/// These are ledger entry changes from protocol upgrades (not from transactions).
pub fn extract_upgrade_metas(
    meta: &LedgerCloseMeta,
) -> Vec<stellar_xdr::curr::UpgradeEntryMeta> {
    match meta {
        LedgerCloseMeta::V0(v0) => v0.upgrades_processing.to_vec(),
        LedgerCloseMeta::V1(v1) => v1.upgrades_processing.to_vec(),
        LedgerCloseMeta::V2(v2) => v2.upgrades_processing.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_calculation() {
        let cdp = CdpDataLake::new(
            "https://example.com/stellar/ledgers/testnet",
            "2025-12-18",
        );

        // Ledger 310079 should be in partition 256000-319999
        assert_eq!(cdp.partition_for_ledger(310079), "FFFC17FF--256000-319999");

        // Ledger 0 should be in partition 0-63999
        assert_eq!(cdp.partition_for_ledger(0), "FFFFFFFF--0-63999");

        // Ledger 64000 should be in partition 64000-127999
        assert_eq!(cdp.partition_for_ledger(64000), "FFFF05FF--64000-127999");
    }

    #[test]
    fn test_batch_filename() {
        let cdp = CdpDataLake::new(
            "https://example.com/stellar/ledgers/testnet",
            "2025-12-18",
        );

        // Ledger 310079 -> inverted = 0xFFFB44C0
        assert_eq!(cdp.batch_filename(310079), "FFFB44C0--310079.xdr.zst");

        // Ledger 0 -> inverted = 0xFFFFFFFF
        assert_eq!(cdp.batch_filename(0), "FFFFFFFF--0.xdr.zst");
    }

    #[test]
    fn test_url_construction() {
        let cdp = CdpDataLake::new(
            "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/v1.1/stellar/ledgers/testnet",
            "2025-12-18",
        );

        let url = cdp.url_for_ledger(310079);
        assert_eq!(
            url,
            "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/v1.1/stellar/ledgers/testnet/2025-12-18/FFFC17FF--256000-319999/FFFB44C0--310079.xdr.zst"
        );
    }
}
