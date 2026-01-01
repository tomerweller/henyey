//! LedgerCloseData - All data needed to close a ledger.
//!
//! This module contains the structures representing all the data
//! needed to close a ledger, including the transaction set, results,
//! and any protocol upgrades.

use stellar_core_common::Hash256;
use stellar_xdr::curr::{
    GeneralizedTransactionSet, Hash, LedgerCloseMeta, LedgerHeader, LedgerUpgrade,
    TransactionEnvelope, TransactionResult, TransactionResultPair, TransactionResultSet,
    TransactionSet, UpgradeType,
};

/// Data needed to close a ledger.
///
/// This is the complete set of data required to apply a ledger close,
/// typically externalized by SCP consensus.
#[derive(Debug, Clone)]
pub struct LedgerCloseData {
    /// The ledger sequence being closed.
    pub ledger_seq: u32,

    /// The transaction set to apply.
    pub tx_set: TransactionSetVariant,

    /// The close time for this ledger.
    pub close_time: u64,

    /// Protocol upgrades to apply (if any).
    pub upgrades: Vec<LedgerUpgrade>,

    /// Hash of the previous ledger.
    pub prev_ledger_hash: Hash256,
}

impl LedgerCloseData {
    /// Create new ledger close data.
    pub fn new(
        ledger_seq: u32,
        tx_set: TransactionSetVariant,
        close_time: u64,
        prev_ledger_hash: Hash256,
    ) -> Self {
        Self {
            ledger_seq,
            tx_set,
            close_time,
            upgrades: Vec::new(),
            prev_ledger_hash,
        }
    }

    /// Add a protocol upgrade.
    pub fn with_upgrade(mut self, upgrade: LedgerUpgrade) -> Self {
        self.upgrades.push(upgrade);
        self
    }

    /// Add multiple protocol upgrades.
    pub fn with_upgrades(mut self, upgrades: Vec<LedgerUpgrade>) -> Self {
        self.upgrades = upgrades;
        self
    }

    /// Get the number of transactions.
    pub fn num_transactions(&self) -> usize {
        self.tx_set.num_transactions()
    }

    /// Get the transaction set hash.
    pub fn tx_set_hash(&self) -> Hash256 {
        self.tx_set.hash()
    }

    /// Check if there are any upgrades.
    pub fn has_upgrades(&self) -> bool {
        !self.upgrades.is_empty()
    }
}

/// Variant of transaction set (pre-protocol 20 or generalized).
#[derive(Debug, Clone)]
pub enum TransactionSetVariant {
    /// Classic transaction set (pre-protocol 20).
    Classic(TransactionSet),
    /// Generalized transaction set (protocol 20+).
    Generalized(GeneralizedTransactionSet),
}

impl TransactionSetVariant {
    /// Get the number of transactions in the set.
    pub fn num_transactions(&self) -> usize {
        match self {
            TransactionSetVariant::Classic(set) => set.txs.len(),
            TransactionSetVariant::Generalized(set) => {
                let stellar_xdr::curr::GeneralizedTransactionSet::V1(set_v1) = set;
                let mut count = 0;
                for phase in set_v1.phases.iter() {
                    match phase {
                        stellar_xdr::curr::TransactionPhase::V0(components) => {
                            for comp in components.iter() {
                                match comp {
                                    stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) => {
                                        count += c.txs.len();
                                    }
                                }
                            }
                        }
                        stellar_xdr::curr::TransactionPhase::V1(parallel) => {
                            for stage in parallel.execution_stages.iter() {
                                for cluster in stage.iter() {
                                    count += cluster.0.len();
                                }
                            }
                        }
                    }
                }
                count
            }
        }
    }

    /// Get the hash of the transaction set.
    pub fn hash(&self) -> Hash256 {
        match self {
            TransactionSetVariant::Classic(set) => {
                Hash256::hash_xdr(set).unwrap_or(Hash256::ZERO)
            }
            TransactionSetVariant::Generalized(set) => {
                Hash256::hash_xdr(set).unwrap_or(Hash256::ZERO)
            }
        }
    }

    /// Get the previous ledger hash.
    pub fn previous_ledger_hash(&self) -> Hash256 {
        match self {
            TransactionSetVariant::Classic(set) => Hash256::from(set.previous_ledger_hash.0),
            TransactionSetVariant::Generalized(set) => {
                let stellar_xdr::curr::GeneralizedTransactionSet::V1(set_v1) = set;
                Hash256::from(set_v1.previous_ledger_hash.0)
            }
        }
    }

    /// Iterate over transactions (borrowed).
    pub fn transactions(&self) -> Vec<&TransactionEnvelope> {
        match self {
            TransactionSetVariant::Classic(set) => set.txs.iter().collect(),
            TransactionSetVariant::Generalized(set) => {
                let stellar_xdr::curr::GeneralizedTransactionSet::V1(set_v1) = set;
                let mut txs = Vec::new();
                for phase in set_v1.phases.iter() {
                    match phase {
                        stellar_xdr::curr::TransactionPhase::V0(components) => {
                            for comp in components.iter() {
                                match comp {
                                    stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) => {
                                        txs.extend(c.txs.iter());
                                    }
                                }
                            }
                        }
                        stellar_xdr::curr::TransactionPhase::V1(parallel) => {
                            for stage in parallel.execution_stages.iter() {
                                for cluster in stage.iter() {
                                    txs.extend(cluster.0.iter());
                                }
                            }
                        }
                    }
                }
                txs
            }
        }
    }

    /// Get owned copies of all transactions.
    pub fn transactions_owned(&self) -> Vec<TransactionEnvelope> {
        self.transactions().into_iter().cloned().collect()
    }

    /// Get owned transactions with optional per-component base fee overrides.
    pub fn transactions_with_base_fee(&self) -> Vec<(TransactionEnvelope, Option<u32>)> {
        match self {
            TransactionSetVariant::Classic(set) => {
                set.txs.iter().cloned().map(|tx| (tx, None)).collect()
            }
            TransactionSetVariant::Generalized(set) => {
                let stellar_xdr::curr::GeneralizedTransactionSet::V1(set_v1) = set;
                let mut txs = Vec::new();
                for phase in set_v1.phases.iter() {
                    match phase {
                        stellar_xdr::curr::TransactionPhase::V0(components) => {
                            for comp in components.iter() {
                                match comp {
                                    stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) => {
                                        let base_fee = c.base_fee.and_then(|fee| u32::try_from(fee).ok());
                                        txs.extend(c.txs.iter().cloned().map(|tx| (tx, base_fee)));
                                    }
                                }
                            }
                        }
                        stellar_xdr::curr::TransactionPhase::V1(parallel) => {
                            let base_fee =
                                parallel.base_fee.and_then(|fee| u32::try_from(fee).ok());
                            for stage in parallel.execution_stages.iter() {
                                for cluster in stage.iter() {
                                    txs.extend(
                                        cluster
                                            .0
                                            .iter()
                                            .cloned()
                                            .map(|tx| (tx, base_fee)),
                                    );
                                }
                            }
                        }
                    }
                }
                txs
            }
        }
    }
}

/// Result of processing a ledger close.
#[derive(Debug, Clone)]
pub struct LedgerCloseResult {
    /// The new ledger header.
    pub header: LedgerHeader,

    /// Hash of the new header.
    pub header_hash: Hash256,

    /// Transaction results.
    pub tx_results: Vec<TransactionResultPair>,

    /// Ledger close metadata (for history).
    pub meta: Option<LedgerCloseMeta>,
}

impl LedgerCloseResult {
    /// Create a new close result.
    pub fn new(header: LedgerHeader, header_hash: Hash256) -> Self {
        Self {
            header,
            header_hash,
            tx_results: Vec::new(),
            meta: None,
        }
    }

    /// Add transaction results.
    pub fn with_tx_results(mut self, results: Vec<TransactionResultPair>) -> Self {
        self.tx_results = results;
        self
    }

    /// Add ledger close metadata.
    pub fn with_meta(mut self, meta: LedgerCloseMeta) -> Self {
        self.meta = Some(meta);
        self
    }

    /// Get the ledger sequence.
    pub fn ledger_seq(&self) -> u32 {
        self.header.ledger_seq
    }

    /// Get the transaction result set.
    pub fn tx_result_set(&self) -> TransactionResultSet {
        TransactionResultSet {
            results: self.tx_results.clone().try_into().unwrap_or_default(),
        }
    }

    /// Compute the hash of transaction results.
    pub fn tx_result_hash(&self) -> Hash256 {
        let result_set = self.tx_result_set();
        Hash256::hash_xdr(&result_set).unwrap_or(Hash256::ZERO)
    }
}

/// Context for applying upgrades during ledger close.
#[derive(Debug, Clone)]
pub struct UpgradeContext {
    /// The upgrades to apply.
    pub upgrades: Vec<LedgerUpgrade>,

    /// Current protocol version before upgrades.
    pub current_version: u32,
}

impl UpgradeContext {
    /// Create a new upgrade context.
    pub fn new(current_version: u32) -> Self {
        Self {
            upgrades: Vec::new(),
            current_version,
        }
    }

    /// Add an upgrade.
    pub fn add_upgrade(&mut self, upgrade: LedgerUpgrade) {
        self.upgrades.push(upgrade);
    }

    /// Check if there's a version upgrade.
    pub fn version_upgrade(&self) -> Option<u32> {
        for upgrade in &self.upgrades {
            if let LedgerUpgrade::Version(v) = upgrade {
                return Some(*v);
            }
        }
        None
    }

    /// Check if there's a base fee upgrade.
    pub fn base_fee_upgrade(&self) -> Option<u32> {
        for upgrade in &self.upgrades {
            if let LedgerUpgrade::BaseFee(fee) = upgrade {
                return Some(*fee);
            }
        }
        None
    }

    /// Check if there's a max tx set size upgrade.
    pub fn max_tx_set_size_upgrade(&self) -> Option<u32> {
        for upgrade in &self.upgrades {
            if let LedgerUpgrade::MaxTxSetSize(size) = upgrade {
                return Some(*size);
            }
        }
        None
    }

    /// Check if there's a base reserve upgrade.
    pub fn base_reserve_upgrade(&self) -> Option<u32> {
        for upgrade in &self.upgrades {
            if let LedgerUpgrade::BaseReserve(reserve) = upgrade {
                return Some(*reserve);
            }
        }
        None
    }

    /// Apply upgrades to a header, returning the modified values.
    pub fn apply_to_header(&self, header: &mut LedgerHeader) {
        for upgrade in &self.upgrades {
            match upgrade {
                LedgerUpgrade::Version(v) => {
                    header.ledger_version = *v;
                }
                LedgerUpgrade::BaseFee(fee) => {
                    header.base_fee = *fee;
                }
                LedgerUpgrade::MaxTxSetSize(size) => {
                    header.max_tx_set_size = *size;
                }
                LedgerUpgrade::BaseReserve(reserve) => {
                    header.base_reserve = *reserve;
                }
                LedgerUpgrade::Flags(flags) => {
                    // Flags are typically network-wide settings
                    // handled in header extension
                    let _ = flags;
                }
                LedgerUpgrade::Config(_) => {
                    // Config upgrades are handled separately
                }
                LedgerUpgrade::MaxSorobanTxSetSize(size) => {
                    // Handled in header extension for Soroban
                    let _ = size;
                }
            }
        }
    }
}

/// Statistics about a ledger close.
#[derive(Debug, Clone, Default)]
pub struct LedgerCloseStats {
    /// Number of transactions processed.
    pub tx_count: usize,

    /// Number of operations executed.
    pub op_count: usize,

    /// Number of successful transactions.
    pub tx_success_count: usize,

    /// Number of failed transactions.
    pub tx_failed_count: usize,

    /// Total fees charged.
    pub total_fees: i64,

    /// Number of entries created.
    pub entries_created: usize,

    /// Number of entries updated.
    pub entries_updated: usize,

    /// Number of entries deleted.
    pub entries_deleted: usize,

    /// Time taken to close the ledger (in milliseconds).
    pub close_time_ms: u64,
}

impl LedgerCloseStats {
    /// Create new empty stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful transaction.
    pub fn record_success(&mut self, ops: usize, fee: i64) {
        self.tx_count += 1;
        self.op_count += ops;
        self.tx_success_count += 1;
        self.total_fees += fee;
    }

    /// Record a failed transaction.
    pub fn record_failure(&mut self, fee: i64) {
        self.tx_count += 1;
        self.tx_failed_count += 1;
        self.total_fees += fee;
    }

    /// Record entry changes.
    pub fn record_entry_changes(&mut self, created: usize, updated: usize, deleted: usize) {
        self.entries_created += created;
        self.entries_updated += updated;
        self.entries_deleted += deleted;
    }

    /// Set the close time.
    pub fn set_close_time(&mut self, ms: u64) {
        self.close_time_ms = ms;
    }

    /// Record transaction batch results.
    pub fn record_transactions(&mut self, total: usize, success: usize, ops: usize) {
        self.tx_count += total;
        self.tx_success_count += success;
        self.tx_failed_count += total - success;
        self.op_count += ops;
    }

    /// Record fees collected.
    pub fn record_fees(&mut self, fees: i64) {
        self.total_fees += fees;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ledger_close_data() {
        let prev_hash = Hash256::hash(b"prev");
        let close_data = LedgerCloseData::new(
            100,
            TransactionSetVariant::Classic(TransactionSet {
                previous_ledger_hash: prev_hash.into(),
                txs: vec![].try_into().unwrap(),
            }),
            1234567890,
            prev_hash,
        );

        assert_eq!(close_data.ledger_seq, 100);
        assert_eq!(close_data.close_time, 1234567890);
        assert_eq!(close_data.num_transactions(), 0);
        assert!(!close_data.has_upgrades());
    }

    #[test]
    fn test_upgrade_context() {
        let mut ctx = UpgradeContext::new(20);
        ctx.add_upgrade(LedgerUpgrade::Version(21));
        ctx.add_upgrade(LedgerUpgrade::BaseFee(200));

        assert_eq!(ctx.version_upgrade(), Some(21));
        assert_eq!(ctx.base_fee_upgrade(), Some(200));
        assert_eq!(ctx.max_tx_set_size_upgrade(), None);
    }

    #[test]
    fn test_ledger_close_stats() {
        let mut stats = LedgerCloseStats::new();

        stats.record_success(3, 300);
        stats.record_success(2, 200);
        stats.record_failure(100);

        assert_eq!(stats.tx_count, 3);
        assert_eq!(stats.tx_success_count, 2);
        assert_eq!(stats.tx_failed_count, 1);
        assert_eq!(stats.op_count, 5);
        assert_eq!(stats.total_fees, 600);
    }
}
