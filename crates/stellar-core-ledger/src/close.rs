//! Ledger close data structures and transaction set handling.
//!
//! This module provides the data structures needed for ledger close operations:
//!
//! - [`LedgerCloseData`]: Input data for closing a ledger (from SCP)
//! - [`LedgerCloseResult`]: Output data from a successful ledger close
//! - [`TransactionSetVariant`]: Classic or generalized transaction sets
//! - [`UpgradeContext`]: Protocol upgrade handling
//! - [`LedgerCloseStats`]: Statistics from ledger processing
//!
//! # Transaction Set Types
//!
//! Stellar supports two transaction set formats:
//!
//! - **Classic** (pre-Protocol 20): Simple list of transactions
//! - **Generalized** (Protocol 20+): Phased execution with Soroban support
//!
//! The generalized format supports parallel execution stages for Soroban
//! transactions and per-component fee overrides.

use std::cmp::Ordering;
use std::collections::HashMap;
use stellar_core_common::Hash256;
use stellar_core_crypto::Sha256Hasher;
use stellar_xdr::curr::{
    ConfigUpgradeSetKey, GeneralizedTransactionSet, LedgerCloseMeta, LedgerHeader, LedgerUpgrade,
    Limits, ScpHistoryEntry, StellarValueExt, TransactionEnvelope, TransactionResultPair,
    TransactionResultSet, TransactionSet, WriteXdr,
};

use crate::config_upgrade::{ConfigUpgradeSetFrame, ConfigUpgradeValidity};
use crate::delta::LedgerDelta;
use crate::error::LedgerError;
use crate::snapshot::SnapshotHandle;

/// Complete input data for closing a ledger.
///
/// This struct contains all the data needed to process a ledger close,
/// typically received from SCP consensus after externalization. It includes
/// the transaction set to apply, the agreed-upon close time, and any
/// protocol upgrades that validators have voted to apply.
///
/// # Creation
///
/// Use [`LedgerCloseData::new`] to create an instance, then chain builder
/// methods to add optional data:
///
/// ```ignore
/// let close_data = LedgerCloseData::new(seq, tx_set, close_time, prev_hash)
///     .with_upgrades(upgrades)
///     .with_stellar_value_ext(ext)
///     .with_scp_history(scp_entries);
/// ```
///
/// # SCP History
///
/// The optional `scp_history` field can be populated with SCP messages
/// for inclusion in [`LedgerCloseMeta`]. This is useful for debugging
/// consensus behavior and for history archive completeness.
#[derive(Debug, Clone)]
pub struct LedgerCloseData {
    /// The sequence number of the ledger being closed.
    pub ledger_seq: u32,

    /// The transaction set to apply during this ledger close.
    pub tx_set: TransactionSetVariant,

    /// The agreed-upon close time (Unix timestamp in seconds).
    ///
    /// This must be greater than or equal to the previous ledger's close time.
    pub close_time: u64,

    /// Protocol upgrades to apply at this ledger boundary.
    ///
    /// Upgrades take effect immediately and apply to this ledger's processing.
    pub upgrades: Vec<LedgerUpgrade>,

    /// SCP history entries for this ledger close (optional).
    ///
    /// When populated, these are included in the `LedgerCloseMeta` for
    /// historical analysis of consensus behavior.
    pub scp_history: Vec<ScpHistoryEntry>,

    /// Hash of the previous ledger header.
    ///
    /// Used to verify chain continuity and prevent forks.
    pub prev_ledger_hash: Hash256,

    /// StellarValue extension (Basic or Signed).
    ///
    /// This must match what the network used in consensus to produce the
    /// correct ledger header hash. Validators sign their consensus values,
    /// so this is typically `Signed` for live network operation.
    pub stellar_value_ext: StellarValueExt,
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
            scp_history: Vec::new(),
            prev_ledger_hash,
            stellar_value_ext: StellarValueExt::Basic,
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

    /// Attach SCP history entries for this ledger close.
    pub fn with_scp_history(mut self, scp_history: Vec<ScpHistoryEntry>) -> Self {
        self.scp_history = scp_history;
        self
    }

    /// Set the StellarValue extension (Basic or Signed).
    ///
    /// This must match what the network used in consensus to produce the
    /// correct ledger header hash.
    pub fn with_stellar_value_ext(mut self, ext: StellarValueExt) -> Self {
        self.stellar_value_ext = ext;
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

/// Transaction set format variant.
///
/// Stellar uses two different transaction set formats depending on the
/// protocol version:
///
/// # Classic (Pre-Protocol 20)
///
/// A simple list of transactions with no special structure. All transactions
/// are executed sequentially in a deterministic order based on their hash.
///
/// # Generalized (Protocol 20+)
///
/// A structured format that supports:
///
/// - **Phases**: Separate classic and Soroban transaction phases
/// - **Parallel stages**: Soroban transactions grouped for parallel execution
/// - **Per-component fees**: Optional fee overrides for different components
///
/// The generalized format enables parallel execution of non-conflicting
/// Soroban transactions while maintaining deterministic ordering.
#[derive(Debug, Clone)]
pub enum TransactionSetVariant {
    /// Classic transaction set (pre-Protocol 20).
    ///
    /// A simple list of transactions executed sequentially.
    Classic(TransactionSet),
    /// Generalized transaction set (Protocol 20+).
    ///
    /// Supports phased execution and parallel Soroban processing.
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
                let mut hasher = Sha256Hasher::new();
                hasher.update(&set.previous_ledger_hash.0);
                for tx in set.txs.iter() {
                    let bytes = match tx.to_xdr(Limits::none()) {
                        Ok(bytes) => bytes,
                        Err(_) => return Hash256::ZERO,
                    };
                    hasher.update(&bytes);
                }
                hasher.finalize()
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

    /// Create an empty generalized transaction set for a given ledger header.
    pub fn empty_generalized(header: &LedgerHeader) -> Self {
        TransactionSetVariant::Generalized(GeneralizedTransactionSet::V1(
            stellar_xdr::curr::TransactionSetV1 {
                previous_ledger_hash: header.previous_ledger_hash.clone(),
                phases: stellar_xdr::curr::VecM::default(),
            },
        ))
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
        let set_hash = self.hash();
        match self {
            TransactionSetVariant::Classic(set) => {
                let txs: Vec<(TransactionEnvelope, Option<u32>)> =
                    set.txs.iter().cloned().map(|tx| (tx, None)).collect();
                sorted_for_apply_sequential(txs, set_hash)
            }
            TransactionSetVariant::Generalized(set) => {
                let stellar_xdr::curr::GeneralizedTransactionSet::V1(set_v1) = set;
                let mut txs = Vec::new();
                for phase in set_v1.phases.iter() {
                    match phase {
                        stellar_xdr::curr::TransactionPhase::V0(components) => {
                            let mut phase_txs = Vec::new();
                            for comp in components.iter() {
                                match comp {
                                    stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) => {
                                        let base_fee = c.base_fee.and_then(|fee| u32::try_from(fee).ok());
                                        phase_txs.extend(c.txs.iter().cloned().map(|tx| (tx, base_fee)));
                                    }
                                }
                            }
                            txs.extend(sorted_for_apply_sequential(phase_txs, set_hash));
                        }
                        stellar_xdr::curr::TransactionPhase::V1(parallel) => {
                            let base_fee =
                                parallel.base_fee.and_then(|fee| u32::try_from(fee).ok());
                            txs.extend(sorted_for_apply_parallel(
                                parallel.execution_stages.as_slice(),
                                set_hash,
                                base_fee,
                            ));
                        }
                    }
                }
                txs
            }
        }
    }
}

fn tx_hash(tx: &TransactionEnvelope) -> Hash256 {
    Hash256::hash_xdr(tx).unwrap_or(Hash256::ZERO)
}

fn less_than_xored(left: &Hash256, right: &Hash256, x: &Hash256) -> bool {
    for i in 0..left.0.len() {
        let v1 = x.0[i] ^ left.0[i];
        let v2 = x.0[i] ^ right.0[i];
        if v1 != v2 {
            return v1 < v2;
        }
    }
    false
}

fn apply_sort_cmp(
    a: &TransactionEnvelope,
    b: &TransactionEnvelope,
    set_hash: &Hash256,
) -> Ordering {
    let left = tx_hash(a);
    let right = tx_hash(b);
    if left == right {
        return Ordering::Equal;
    }
    if less_than_xored(&left, &right, set_hash) {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

fn tx_source_id(tx: &TransactionEnvelope) -> stellar_xdr::curr::AccountId {
    match tx {
        TransactionEnvelope::TxV0(env) => stellar_core_tx::muxed_to_account_id(
            &stellar_xdr::curr::MuxedAccount::Ed25519(env.tx.source_account_ed25519.clone()),
        ),
        TransactionEnvelope::Tx(env) => {
            stellar_core_tx::muxed_to_account_id(&env.tx.source_account)
        }
        TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
            stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                stellar_core_tx::muxed_to_account_id(&inner.tx.source_account)
            }
        },
    }
}

fn tx_sequence_number(tx: &TransactionEnvelope) -> i64 {
    match tx {
        TransactionEnvelope::TxV0(env) => env.tx.seq_num.0,
        TransactionEnvelope::Tx(env) => env.tx.seq_num.0,
        TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
            stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.seq_num.0,
        },
    }
}

fn sorted_for_apply_sequential(
    txs: Vec<(TransactionEnvelope, Option<u32>)>,
    set_hash: Hash256,
) -> Vec<(TransactionEnvelope, Option<u32>)> {
    if txs.len() <= 1 {
        return txs;
    }

    let mut by_account: HashMap<[u8; 32], Vec<(TransactionEnvelope, Option<u32>)>> = HashMap::new();
    for (tx, base_fee) in txs {
        let account_id = tx_source_id(&tx);
        let key = stellar_core_tx::account_id_to_key(&account_id);
        by_account.entry(key).or_default().push((tx, base_fee));
    }

    let mut queues: Vec<std::collections::VecDeque<(TransactionEnvelope, Option<u32>)>> =
        by_account
            .into_values()
            .map(|mut txs| {
                txs.sort_by(|a, b| tx_sequence_number(&a.0).cmp(&tx_sequence_number(&b.0)));
                txs.into_iter().collect()
            })
            .collect();

    let mut result = Vec::new();
    while queues.iter().any(|q| !q.is_empty()) {
        let mut batch = Vec::new();
        for queue in queues.iter_mut() {
            if let Some(item) = queue.pop_front() {
                batch.push(item);
            }
        }
        batch.sort_by(|a, b| apply_sort_cmp(&a.0, &b.0, &set_hash));
        result.extend(batch);
    }
    result
}

fn sorted_for_apply_parallel(
    stages: &[stellar_xdr::curr::ParallelTxExecutionStage],
    set_hash: Hash256,
    base_fee: Option<u32>,
) -> Vec<(TransactionEnvelope, Option<u32>)> {
    let mut stage_vec: Vec<Vec<Vec<TransactionEnvelope>>> = stages
        .iter()
        .map(|stage| stage.0.iter().map(|cluster| cluster.0.to_vec()).collect())
        .collect();

    for stage in stage_vec.iter_mut() {
        for cluster in stage.iter_mut() {
            cluster.sort_by(|a, b| apply_sort_cmp(a, b, &set_hash));
        }
        // C++ does NOT sort clusters within a stage. Clusters are independent,
        // so their execution order doesn't matter, and the original XDR order
        // is preserved. Sorting clusters would change the transaction result
        // ordering and produce a different result hash.
    }

    stage_vec.sort_by(|a, b| {
        if a.is_empty() || b.is_empty() {
            return a.len().cmp(&b.len());
        }
        if a[0].is_empty() || b[0].is_empty() {
            return a[0].len().cmp(&b[0].len());
        }
        apply_sort_cmp(&a[0][0], &b[0][0], &set_hash)
    });

    let mut result = Vec::new();
    for stage in stage_vec {
        for cluster in stage {
            for tx in cluster {
                result.push((tx, base_fee));
            }
        }
    }
    result
}

/// Result of successfully closing a ledger.
///
/// This struct contains all the output data from a ledger close operation,
/// including the new ledger header, transaction results, and metadata for
/// history archival.
///
/// # Header Hash
///
/// The `header_hash` is the SHA-256 hash of the XDR-encoded header. This
/// hash becomes the `previous_ledger_hash` for the next ledger and is used
/// to verify chain integrity.
///
/// # Transaction Results
///
/// The `tx_results` vector contains one entry per transaction in the same
/// order as the input transaction set. Each entry includes the transaction
/// hash and its result code.
#[derive(Debug, Clone)]
pub struct LedgerCloseResult {
    /// The newly created ledger header.
    pub header: LedgerHeader,

    /// SHA-256 hash of the XDR-encoded header.
    pub header_hash: Hash256,

    /// Results for each transaction in the set.
    ///
    /// Order matches the transaction set order.
    pub tx_results: Vec<TransactionResultPair>,

    /// Full ledger close metadata for history archival.
    ///
    /// Contains transaction processing details, SCP history, and other
    /// data needed for complete history archive reconstruction.
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

/// Context for applying protocol upgrades during ledger close.
///
/// Protocol upgrades allow the network to evolve without hard forks.
/// Validators vote on upgrades, and when consensus is reached, the
/// upgrade is applied at the ledger boundary.
///
/// # Supported Upgrades
///
/// - **Version**: Protocol version bump (enables new features)
/// - **BaseFee**: Network-wide base fee per operation
/// - **BaseReserve**: Minimum balance per entry
/// - **MaxTxSetSize**: Maximum transactions per ledger
/// - **Config**: Soroban configuration settings (Protocol 20+)
///
/// # Application Order
///
/// Upgrades are applied to the header in the order they appear in the list.
/// Multiple upgrades of the same type will result in the last one winning.
#[derive(Debug, Clone)]
pub struct UpgradeContext {
    /// List of upgrades to apply.
    pub upgrades: Vec<LedgerUpgrade>,

    /// Protocol version before any upgrades are applied.
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

    /// Get all config upgrade keys, if any.
    ///
    /// Multiple config upgrades can be included, all will be returned
    /// in the order they appear.
    pub fn config_upgrade_keys(&self) -> Vec<ConfigUpgradeSetKey> {
        self.upgrades
            .iter()
            .filter_map(|u| {
                if let LedgerUpgrade::Config(key) = u {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Check if there are any config upgrades.
    pub fn has_config_upgrades(&self) -> bool {
        self.upgrades
            .iter()
            .any(|u| matches!(u, LedgerUpgrade::Config(_)))
    }

    /// Apply all config upgrades to the ledger.
    ///
    /// Loads and validates each config upgrade, then applies the configuration
    /// changes to the ledger delta.
    ///
    /// Returns a tuple of:
    /// - `state_archival_changed`: Whether any StateArchival settings were modified
    /// - `memory_limit_changed`: Whether any memory limit settings were modified
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A config upgrade cannot be loaded from the ledger
    /// - A config upgrade fails validation
    /// - The delta update fails
    pub fn apply_config_upgrades(
        &self,
        snapshot: &SnapshotHandle,
        delta: &mut LedgerDelta,
    ) -> Result<(bool, bool), LedgerError> {
        let mut state_archival_changed = false;
        let mut memory_limit_changed = false;

        for key in self.config_upgrade_keys() {
            // Load the upgrade set from the ledger
            let frame = match ConfigUpgradeSetFrame::make_from_key(snapshot, &key) {
                Some(f) => f,
                None => {
                    tracing::warn!(
                        contract_id = ?key.contract_id,
                        "Config upgrade set not found or expired"
                    );
                    continue;
                }
            };

            // Validate the upgrade
            match frame.is_valid_for_apply() {
                ConfigUpgradeValidity::Valid => {}
                ConfigUpgradeValidity::XdrInvalid => {
                    tracing::warn!(
                        contract_id = ?key.contract_id,
                        "Config upgrade set has invalid XDR"
                    );
                    continue;
                }
                ConfigUpgradeValidity::Invalid => {
                    tracing::warn!(
                        contract_id = ?key.contract_id,
                        "Config upgrade set is invalid"
                    );
                    continue;
                }
            }

            // Apply the upgrade
            let (archival, memory) = frame.apply_to(snapshot, delta)?;
            state_archival_changed |= archival;
            memory_limit_changed |= memory;

            tracing::info!(
                contract_id = ?key.contract_id,
                "Applied config upgrade"
            );
        }

        Ok((state_archival_changed, memory_limit_changed))
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

/// Statistics collected during ledger close processing.
///
/// These statistics are useful for monitoring ledger close performance,
/// tracking transaction success rates, and understanding state changes.
///
/// # Usage
///
/// Statistics are accumulated during transaction processing and returned
/// as part of [`LedgerCloseResult`].
///
/// ```ignore
/// let result = manager.close_ledger(close_data)?;
/// println!("Closed ledger {}", result.ledger_seq());
/// ```
#[derive(Debug, Clone, Default)]
pub struct LedgerCloseStats {
    /// Total number of transactions processed (success + failure).
    pub tx_count: usize,

    /// Total number of operations executed across all transactions.
    pub op_count: usize,

    /// Number of transactions that completed successfully.
    pub tx_success_count: usize,

    /// Number of transactions that failed.
    pub tx_failed_count: usize,

    /// Total fees collected from all transactions (in stroops).
    ///
    /// Fees are charged even for failed transactions.
    pub total_fees: i64,

    /// Number of new ledger entries created.
    pub entries_created: usize,

    /// Number of existing entries modified.
    pub entries_updated: usize,

    /// Number of entries deleted.
    pub entries_deleted: usize,

    /// Wall-clock time to close the ledger (milliseconds).
    ///
    /// Measured from begin_close to commit completion.
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
    use std::collections::HashMap;
    use stellar_core_crypto::Sha256Hasher;
    use stellar_xdr::curr::{
        DependentTxCluster, FeeBumpTransaction, FeeBumpTransactionEnvelope,
        FeeBumpTransactionInnerTx, GeneralizedTransactionSet, Hash, Limits, Memo, MuxedAccount,
        ParallelTxExecutionStage, ParallelTxsComponent, Preconditions, Transaction,
        TransactionEnvelope, TransactionExt, TransactionPhase, TransactionSetV1,
        TransactionV1Envelope, TxSetComponent, TxSetComponentTxsMaybeDiscountedFee, Uint256, VecM,
        WriteXdr,
    };

    fn make_tx(seed: u8, seq: i64) -> TransactionEnvelope {
        let source = MuxedAccount::Ed25519(Uint256([seed; 32]));
        let tx = Transaction {
            source_account: source,
            fee: 100,
            seq_num: stellar_xdr::curr::SequenceNumber(seq),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: VecM::default(),
            ext: TransactionExt::V0,
        };
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        })
    }

    fn make_fee_bump(fee_seed: u8, inner_seed: u8, seq: i64) -> TransactionEnvelope {
        let inner = match make_tx(inner_seed, seq) {
            TransactionEnvelope::Tx(inner) => inner,
            _ => unreachable!("inner must be v1"),
        };
        let fee_source = MuxedAccount::Ed25519(Uint256([fee_seed; 32]));
        let fee_bump = FeeBumpTransaction {
            fee_source,
            fee: 200,
            inner_tx: FeeBumpTransactionInnerTx::Tx(inner),
            ext: stellar_xdr::curr::FeeBumpTransactionExt::V0,
        };
        TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: fee_bump,
            signatures: VecM::default(),
        })
    }

    fn tx_hash(tx: &TransactionEnvelope) -> Hash256 {
        Hash256::hash_xdr(tx).unwrap_or(Hash256::ZERO)
    }

    #[test]
    fn classic_tx_set_hash_uses_contents_hash() {
        let tx_a = make_tx(1, 1);
        let tx_b = make_tx(2, 2);
        let txs: VecM<TransactionEnvelope> = vec![tx_a, tx_b].try_into().expect("tx vec");
        let set = TransactionSet {
            previous_ledger_hash: Hash([3u8; 32]),
            txs,
        };
        let mut hasher = Sha256Hasher::new();
        hasher.update(&set.previous_ledger_hash.0);
        for tx in set.txs.iter() {
            let bytes = tx.to_xdr(Limits::none()).expect("tx xdr");
            hasher.update(&bytes);
        }
        let expected = hasher.finalize();
        let variant = TransactionSetVariant::Classic(set);
        assert_eq!(variant.hash(), expected);
    }

    fn less_than_xored(left: &Hash256, right: &Hash256, x: &Hash256) -> bool {
        for i in 0..left.0.len() {
            let v1 = x.0[i] ^ left.0[i];
            let v2 = x.0[i] ^ right.0[i];
            if v1 != v2 {
                return v1 < v2;
            }
        }
        false
    }

    fn apply_sort_cmp(
        a: &TransactionEnvelope,
        b: &TransactionEnvelope,
        set_hash: &Hash256,
    ) -> Ordering {
        let left = tx_hash(a);
        let right = tx_hash(b);
        if left == right {
            return Ordering::Equal;
        }
        if less_than_xored(&left, &right, set_hash) {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }

    fn fee_source_id(tx: &TransactionEnvelope) -> stellar_xdr::curr::AccountId {
        match tx {
            TransactionEnvelope::TxV0(env) => stellar_core_tx::muxed_to_account_id(
                &MuxedAccount::Ed25519(env.tx.source_account_ed25519.clone()),
            ),
            TransactionEnvelope::Tx(env) => {
                stellar_core_tx::muxed_to_account_id(&env.tx.source_account)
            }
            TransactionEnvelope::TxFeeBump(env) => {
                stellar_core_tx::muxed_to_account_id(&env.tx.fee_source)
            }
        }
    }

    fn inner_source_id(tx: &TransactionEnvelope) -> stellar_xdr::curr::AccountId {
        match tx {
            TransactionEnvelope::TxV0(env) => stellar_core_tx::muxed_to_account_id(
                &MuxedAccount::Ed25519(env.tx.source_account_ed25519.clone()),
            ),
            TransactionEnvelope::Tx(env) => {
                stellar_core_tx::muxed_to_account_id(&env.tx.source_account)
            }
            TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => {
                    stellar_core_tx::muxed_to_account_id(&inner.tx.source_account)
                }
            },
        }
    }

    fn seq_num(tx: &TransactionEnvelope) -> i64 {
        match tx {
            TransactionEnvelope::TxV0(env) => env.tx.seq_num.0,
            TransactionEnvelope::Tx(env) => env.tx.seq_num.0,
            TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.seq_num.0,
            },
        }
    }

    fn expected_apply_order(
        txs: Vec<TransactionEnvelope>,
        set_hash: Hash256,
        use_fee_source: bool,
    ) -> Vec<Hash256> {
        let mut by_account: HashMap<[u8; 32], Vec<TransactionEnvelope>> = HashMap::new();
        for tx in txs {
            let account_id = if use_fee_source {
                fee_source_id(&tx)
            } else {
                inner_source_id(&tx)
            };
            let key = stellar_core_tx::account_id_to_key(&account_id);
            by_account.entry(key).or_default().push(tx);
        }

        let mut queues: Vec<std::collections::VecDeque<TransactionEnvelope>> = by_account
            .into_values()
            .map(|mut txs| {
                txs.sort_by(|a, b| seq_num(a).cmp(&seq_num(b)));
                txs.into_iter().collect()
            })
            .collect();

        let mut result = Vec::new();
        while queues.iter().any(|q| !q.is_empty()) {
            let mut batch = Vec::new();
            for queue in queues.iter_mut() {
                if let Some(item) = queue.pop_front() {
                    batch.push(item);
                }
            }
            batch.sort_by(|a, b| apply_sort_cmp(a, b, &set_hash));
            result.extend(batch.into_iter().map(|tx| tx_hash(&tx)));
        }
        result
    }

    fn expected_parallel_order(
        stages: Vec<Vec<Vec<TransactionEnvelope>>>,
        set_hash: Hash256,
    ) -> Vec<Hash256> {
        let mut stage_vec = stages;
        for stage in stage_vec.iter_mut() {
            for cluster in stage.iter_mut() {
                cluster.sort_by(|a, b| apply_sort_cmp(a, b, &set_hash));
            }
            // C++ does NOT sort clusters within a stage - preserve XDR order.
        }
        stage_vec.sort_by(|a, b| {
            if a.is_empty() || b.is_empty() {
                return a.len().cmp(&b.len());
            }
            if a[0].is_empty() || b[0].is_empty() {
                return a[0].len().cmp(&b[0].len());
            }
            apply_sort_cmp(&a[0][0], &b[0][0], &set_hash)
        });

        let mut result = Vec::new();
        for stage in stage_vec {
            for cluster in stage {
                for tx in cluster {
                    result.push(tx_hash(&tx));
                }
            }
        }
        result
    }

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

    #[test]
    fn fee_bump_apply_order_uses_inner_source() {
        let mut chosen = None;
        'search: for inner_a in 1u8..=8 {
            for inner_b in 9u8..=16 {
                for classic_seed in 17u8..=24 {
                    let fee_bump_a = make_fee_bump(9, inner_a, 1);
                    let fee_bump_b = make_fee_bump(9, inner_b, 1);
                    let classic = make_tx(classic_seed, 1);
                    let txs = vec![fee_bump_a.clone(), classic.clone(), fee_bump_b.clone()];
                    let set = stellar_xdr::curr::TransactionSet {
                        previous_ledger_hash: Hash::from(Hash256::ZERO),
                        txs: txs.clone().try_into().unwrap(),
                    };
                    let set_hash = TransactionSetVariant::Classic(set.clone()).hash();
                    let expected = expected_apply_order(txs.clone(), set_hash, false);
                    let wrong = expected_apply_order(txs, set_hash, true);
                    if expected != wrong {
                        chosen = Some((set, expected, wrong));
                        break 'search;
                    }
                }
            }
        }

        let (set, expected, wrong) = chosen.expect("distinct apply order case");
        assert_ne!(
            expected, wrong,
            "test should distinguish inner vs fee source"
        );

        let variant = TransactionSetVariant::Classic(set);
        let actual: Vec<Hash256> = variant
            .transactions_with_base_fee()
            .into_iter()
            .map(|(tx, _)| tx_hash(&tx))
            .collect();

        assert_eq!(actual, expected);
    }

    #[test]
    fn generalized_tx_set_apply_order_uses_xor_sort() {
        let classic_a = make_tx(10, 1);
        let classic_b = make_tx(11, 1);
        let soroban_a = make_tx(20, 1);
        let soroban_b = make_tx(21, 1);
        let soroban_c = make_tx(22, 1);
        let soroban_d = make_tx(23, 1);

        let classic_component =
            TxSetComponent::TxsetCompTxsMaybeDiscountedFee(TxSetComponentTxsMaybeDiscountedFee {
                base_fee: None,
                txs: vec![classic_b.clone(), classic_a.clone()]
                    .try_into()
                    .unwrap(),
            });
        let classic_phase = TransactionPhase::V0(vec![classic_component].try_into().unwrap());

        let cluster_a = DependentTxCluster(
            vec![soroban_b.clone(), soroban_a.clone()]
                .try_into()
                .unwrap(),
        );
        let cluster_b = DependentTxCluster(vec![soroban_c.clone()].try_into().unwrap());
        let cluster_c = DependentTxCluster(vec![soroban_d.clone()].try_into().unwrap());
        let stage_one = ParallelTxExecutionStage(vec![cluster_b, cluster_a].try_into().unwrap());
        let stage_two = ParallelTxExecutionStage(vec![cluster_c].try_into().unwrap());
        let soroban_phase = TransactionPhase::V1(ParallelTxsComponent {
            base_fee: None,
            execution_stages: vec![stage_two, stage_one].try_into().unwrap(),
        });

        let gen_set = GeneralizedTransactionSet::V1(TransactionSetV1 {
            previous_ledger_hash: Hash::from(Hash256::ZERO),
            phases: vec![classic_phase, soroban_phase].try_into().unwrap(),
        });

        let set_hash = Hash256::hash_xdr(&gen_set).unwrap_or(Hash256::ZERO);
        let classic_expected = expected_apply_order(vec![classic_a, classic_b], set_hash, false);
        // Must match XDR cluster order: stage_one = [cluster_b(soroban_c),
        // cluster_a(soroban_b, soroban_a)], stage_two = [cluster_c(soroban_d)],
        // execution_stages = [stage_two, stage_one].
        let soroban_expected = expected_parallel_order(
            vec![
                vec![vec![soroban_d]],
                vec![vec![soroban_c], vec![soroban_a, soroban_b]],
            ],
            set_hash,
        );
        let expected: Vec<Hash256> = classic_expected
            .into_iter()
            .chain(soroban_expected.into_iter())
            .collect();

        let variant = TransactionSetVariant::Generalized(gen_set);
        let actual: Vec<Hash256> = variant
            .transactions_with_base_fee()
            .into_iter()
            .map(|(tx, _)| tx_hash(&tx))
            .collect();

        assert_eq!(actual, expected);
    }

    /// Regression test: clusters within a parallel stage must preserve their
    /// original XDR order. C++ does NOT sort clusters within a stage because
    /// clusters are independent and their execution order doesn't affect
    /// correctness. Sorting clusters would change the transaction result
    /// ordering and produce a different result hash than C++.
    #[test]
    fn parallel_clusters_preserve_xdr_order_within_stage() {
        // Find seeds where sorting clusters would produce a different order
        // than the original XDR order. We need cluster_first's first tx to
        // sort AFTER cluster_second's first tx, so that if clusters were
        // sorted, the order would reverse.
        let mut found = None;
        'search: for seed_a in 1u8..=50 {
            for seed_b in 51u8..=100 {
                let tx_a = make_tx(seed_a, 1);
                let tx_b = make_tx(seed_b, 1);

                let cluster_first =
                    DependentTxCluster(vec![tx_a.clone()].try_into().unwrap());
                let cluster_second =
                    DependentTxCluster(vec![tx_b.clone()].try_into().unwrap());

                let stage = ParallelTxExecutionStage(
                    vec![cluster_first, cluster_second].try_into().unwrap(),
                );
                let parallel = ParallelTxsComponent {
                    base_fee: None,
                    execution_stages: vec![stage].try_into().unwrap(),
                };
                let gen_set = GeneralizedTransactionSet::V1(TransactionSetV1 {
                    previous_ledger_hash: Hash::from(Hash256::ZERO),
                    phases: vec![
                        TransactionPhase::V0(vec![].try_into().unwrap()),
                        TransactionPhase::V1(parallel),
                    ]
                    .try_into()
                    .unwrap(),
                });
                let set_hash = Hash256::hash_xdr(&gen_set).unwrap_or(Hash256::ZERO);

                // Check if sorting would reverse the cluster order
                let cmp = apply_sort_cmp(&tx_a, &tx_b, &set_hash);
                if cmp == std::cmp::Ordering::Greater {
                    // tx_a sorts after tx_b, so if clusters were sorted,
                    // cluster_second would come first (reversing XDR order)
                    found = Some((gen_set, set_hash, tx_a, tx_b));
                    break 'search;
                }
            }
        }

        let (gen_set, set_hash, tx_a, tx_b) =
            found.expect("should find seeds where cluster sorting differs from XDR order");

        let variant = TransactionSetVariant::Generalized(gen_set);
        let actual: Vec<Hash256> = variant
            .transactions_with_base_fee()
            .into_iter()
            .map(|(tx, _)| tx_hash(&tx))
            .collect();

        // Clusters must preserve XDR order: tx_a first, tx_b second
        assert_eq!(actual.len(), 2);
        assert_eq!(
            actual[0],
            tx_hash(&tx_a),
            "First cluster's tx should appear first (XDR order preserved)"
        );
        assert_eq!(
            actual[1],
            tx_hash(&tx_b),
            "Second cluster's tx should appear second (XDR order preserved)"
        );

        // Verify that sorting WOULD have reversed the order (test is meaningful)
        let wrong_order = apply_sort_cmp(&tx_a, &tx_b, &set_hash);
        assert_eq!(
            wrong_order,
            std::cmp::Ordering::Greater,
            "Test requires that sorting would reverse cluster order"
        );
    }
}
