//! Transaction queue management.
//!
//! The transaction queue holds pending transactions waiting to be included
//! in a ledger. Transactions are ordered by fee (highest first) to maximize
//! miner extractable value and network efficiency.

use parking_lot::RwLock;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use stellar_core_common::{
    any_greater, Hash256, NetworkId, Resource, ResourceType, NUM_SOROBAN_TX_RESOURCES,
};
use stellar_xdr::curr::{
    AccountId, DecoratedSignature, FeeBumpTransactionInnerTx, GeneralizedTransactionSet, Limits,
    Preconditions, SignerKey, TransactionEnvelope,
};
use stellar_xdr::curr::WriteXdr;

use crate::error::HerderError;
use crate::surge_pricing::{
    DexLimitingLaneConfig, OpsOnlyLaneConfig, SorobanGenericLaneConfig,
    SurgePricingPriorityQueue, GENERIC_LANE,
};
use crate::Result;
use rand::Rng;

/// Result of attempting to add a transaction to the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxQueueResult {
    /// Transaction was added successfully.
    Added,
    /// Transaction is a duplicate.
    Duplicate,
    /// Queue is full.
    QueueFull,
    /// Transaction fee is too low.
    FeeTooLow,
    /// Transaction is invalid.
    Invalid,
}

const MAX_TX_SET_ALLOWANCE_BYTES: u32 = 10 * 1024 * 1024;
const MAX_CLASSIC_BYTE_ALLOWANCE: u32 = MAX_TX_SET_ALLOWANCE_BYTES / 2;
const MAX_SOROBAN_BYTE_ALLOWANCE: u32 = MAX_TX_SET_ALLOWANCE_BYTES / 2;


/// Configuration for the transaction queue.
#[derive(Debug, Clone)]
pub struct TxQueueConfig {
    /// Maximum number of transactions in the queue.
    pub max_size: usize,
    /// Maximum age of a transaction before it's evicted (in seconds).
    pub max_age_secs: u64,
    /// Minimum fee per operation in stroops.
    pub min_fee_per_op: u32,
    /// Whether to validate signatures before queueing.
    pub validate_signatures: bool,
    /// Whether to validate time bounds before queueing.
    pub validate_time_bounds: bool,
    /// Network ID for signature validation.
    pub network_id: NetworkId,
    /// Optional limit for DEX operation counts within a tx set.
    pub max_dex_ops: Option<u32>,
    /// Optional classic tx byte allowance for tx set selection.
    pub max_classic_bytes: Option<u32>,
    /// Optional byte allowance for DEX lane tx set selection.
    pub max_dex_bytes: Option<u32>,
    /// Optional Soroban resource limit for tx set selection.
    pub max_soroban_resources: Option<Resource>,
    /// Optional Soroban tx byte allowance for tx set selection.
    pub max_soroban_bytes: Option<u32>,
    /// Optional limit for DEX operation counts within the queue.
    pub max_queue_dex_ops: Option<u32>,
    /// Optional Soroban resource limit for queue admission.
    pub max_queue_soroban_resources: Option<Resource>,
    /// Optional total op limit for queue admission.
    pub max_queue_ops: Option<u32>,
    /// Optional classic tx byte allowance for queue admission.
    pub max_queue_classic_bytes: Option<u32>,
}

impl Default for TxQueueConfig {
    fn default() -> Self {
        Self {
            max_size: 1000,
            max_age_secs: 300, // 5 minutes
            min_fee_per_op: 100,
            validate_signatures: true,
            validate_time_bounds: true,
            network_id: NetworkId::testnet(),
            max_dex_ops: None,
            max_classic_bytes: Some(MAX_CLASSIC_BYTE_ALLOWANCE),
            max_dex_bytes: None,
            max_soroban_resources: None,
            max_soroban_bytes: Some(MAX_SOROBAN_BYTE_ALLOWANCE),
            max_queue_dex_ops: None,
            max_queue_soroban_resources: None,
            max_queue_ops: None,
            max_queue_classic_bytes: None,
        }
    }
}

/// Validation context for transaction queue.
#[derive(Debug, Clone)]
pub struct ValidationContext {
    /// Current ledger sequence.
    pub ledger_seq: u32,
    /// Current close time (Unix timestamp).
    pub close_time: u64,
    /// Protocol version.
    pub protocol_version: u32,
}

impl Default for ValidationContext {
    fn default() -> Self {
        Self {
            ledger_seq: 0,
            close_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            protocol_version: 21,
        }
    }
}

/// A transaction in the queue with metadata.
#[derive(Debug, Clone)]
pub struct QueuedTransaction {
    /// The transaction envelope.
    pub envelope: TransactionEnvelope,
    /// Hash of the transaction.
    pub hash: Hash256,
    /// When this transaction was received.
    pub received_at: Instant,
    /// Fee per operation for ordering.
    pub fee_per_op: u64,
    /// Number of operations in the transaction.
    pub op_count: u32,
    /// Total fee.
    pub total_fee: u64,
}

impl QueuedTransaction {
    /// Create a new queued transaction.
    pub fn new(envelope: TransactionEnvelope) -> Result<Self> {
        let hash = Hash256::hash_xdr(&envelope)
            .map_err(|e| HerderError::Internal(format!("Failed to hash transaction: {}", e)))?;

        let (fee, op_count) = Self::extract_fee_and_ops(&envelope)?;
        let fee_per_op = if op_count > 0 {
            fee / op_count as u64
        } else {
            0
        };

        Ok(Self {
            envelope,
            hash,
            received_at: Instant::now(),
            fee_per_op,
            op_count,
            total_fee: fee,
        })
    }

    /// Extract fee and operation count from the envelope.
    fn extract_fee_and_ops(envelope: &TransactionEnvelope) -> Result<(u64, u32)> {
        match envelope {
            TransactionEnvelope::TxV0(tx) => {
                Ok((tx.tx.fee as u64, tx.tx.operations.len() as u32))
            }
            TransactionEnvelope::Tx(tx) => {
                Ok((tx.tx.fee as u64, tx.tx.operations.len() as u32))
            }
            TransactionEnvelope::TxFeeBump(tx) => {
                // For fee bump, use the outer fee
                let inner_ops = match &tx.tx.inner_tx {
                    stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                        inner.tx.operations.len() as u32
                    }
                };
                Ok((tx.tx.fee as u64, inner_ops))
            }
        }
    }

    fn sequence_number(&self) -> i64 {
        match &self.envelope {
            TransactionEnvelope::TxV0(env) => env.tx.seq_num.0,
            TransactionEnvelope::Tx(env) => env.tx.seq_num.0,
            TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
                stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.seq_num.0,
            },
        }
    }

    pub(crate) fn account_key(&self) -> Vec<u8> {
        account_key(&self.envelope)
    }

    /// Check if this transaction has expired.
    pub fn is_expired(&self, max_age_secs: u64) -> bool {
        self.received_at.elapsed().as_secs() > max_age_secs
    }

    fn is_better_than(&self, other: &QueuedTransaction) -> bool {
        better_fee_ratio(self, other)
    }
}

fn envelope_fee_per_op(envelope: &TransactionEnvelope) -> Option<(u64, u64, u32)> {
    QueuedTransaction::extract_fee_and_ops(envelope)
        .ok()
        .map(|(fee, op_count)| {
            let per_op = if op_count > 0 {
                fee / op_count as u64
            } else {
                0
            };
            (per_op, fee, op_count)
        })
}

pub(crate) fn fee_rate_cmp(a_fee: u64, a_ops: u32, b_fee: u64, b_ops: u32) -> Ordering {
    let left = (a_fee as u128).saturating_mul(b_ops as u128);
    let right = (b_fee as u128).saturating_mul(a_ops as u128);
    left.cmp(&right)
}

fn tx_size_bytes(envelope: &TransactionEnvelope) -> u32 {
    envelope
        .to_xdr(Limits::none())
        .map(|bytes| bytes.len() as u32)
        .unwrap_or(0)
}

fn better_fee_ratio(new_tx: &QueuedTransaction, old_tx: &QueuedTransaction) -> bool {
    match fee_rate_cmp(new_tx.total_fee, new_tx.op_count, old_tx.total_fee, old_tx.op_count) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => new_tx.hash.0 < old_tx.hash.0,
    }
}

#[derive(Debug, Clone)]
struct SelectedTxs {
    transactions: Vec<TransactionEnvelope>,
    soroban_limited: bool,
    dex_limited: bool,
    classic_limited: bool,
}

fn sort_txs_by_hash(txs: &mut Vec<TransactionEnvelope>) {
    txs.sort_by(|a, b| {
        let hash_a = Hash256::hash_xdr(a).unwrap_or_default();
        let hash_b = Hash256::hash_xdr(b).unwrap_or_default();
        hash_a.0.cmp(&hash_b.0)
    });
}

fn account_key(envelope: &TransactionEnvelope) -> Vec<u8> {
    let source = match envelope {
        TransactionEnvelope::TxV0(env) => {
            stellar_xdr::curr::MuxedAccount::Ed25519(env.tx.source_account_ed25519.clone())
        }
        TransactionEnvelope::Tx(env) => env.tx.source_account.clone(),
        TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
            stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.source_account.clone(),
        },
    };
    let account_id = stellar_core_tx::muxed_to_account_id(&source);
    account_id
        .to_xdr(stellar_xdr::curr::Limits::none())
        .unwrap_or_default()
}

pub(crate) fn account_key_from_account_id(account_id: &AccountId) -> Vec<u8> {
    account_id
        .to_xdr(stellar_xdr::curr::Limits::none())
        .unwrap_or_default()
}

fn account_id_from_envelope(envelope: &TransactionEnvelope) -> AccountId {
    let source = match envelope {
        TransactionEnvelope::TxV0(env) => {
            stellar_xdr::curr::MuxedAccount::Ed25519(env.tx.source_account_ed25519.clone())
        }
        TransactionEnvelope::Tx(env) => env.tx.source_account.clone(),
        TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
            stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.source_account.clone(),
        },
    };
    stellar_core_tx::muxed_to_account_id(&source)
}

/// A set of transactions for a ledger.
#[derive(Debug, Clone)]
pub struct TransactionSet {
    /// Hash of this transaction set.
    pub hash: Hash256,
    /// Previous ledger hash.
    pub previous_ledger_hash: Hash256,
    /// Transactions in the set.
    pub transactions: Vec<TransactionEnvelope>,
    /// Generalized transaction set (protocol 20+), if available.
    pub generalized_tx_set: Option<GeneralizedTransactionSet>,
}

impl TransactionSet {
    /// Create a new transaction set with computed hash (for legacy TransactionSet).
    pub fn new(previous_ledger_hash: Hash256, transactions: Vec<TransactionEnvelope>) -> Self {
        // Compute set hash for legacy format: hash of prev_hash + txs
        let mut data = previous_ledger_hash.0.to_vec();
        for tx in &transactions {
            if let Ok(bytes) = tx.to_xdr(stellar_xdr::curr::Limits::none()) {
                data.extend_from_slice(&bytes);
            }
        }
        let hash = Hash256::hash(&data);

        Self {
            hash,
            previous_ledger_hash,
            transactions,
            generalized_tx_set: None,
        }
    }

    /// Create a transaction set with a pre-computed hash (for GeneralizedTransactionSet).
    /// The hash should be SHA-256 of the XDR-encoded GeneralizedTransactionSet.
    pub fn with_hash(
        previous_ledger_hash: Hash256,
        hash: Hash256,
        transactions: Vec<TransactionEnvelope>,
    ) -> Self {
        Self {
            hash,
            previous_ledger_hash,
            transactions,
            generalized_tx_set: None,
        }
    }

    pub fn with_generalized(
        previous_ledger_hash: Hash256,
        hash: Hash256,
        transactions: Vec<TransactionEnvelope>,
        generalized_tx_set: GeneralizedTransactionSet,
    ) -> Self {
        Self {
            hash,
            previous_ledger_hash,
            transactions,
            generalized_tx_set: Some(generalized_tx_set),
        }
    }

    /// Get the number of transactions.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

/// Queue of pending transactions.
///
/// Maintains transactions waiting to be included in a ledger, ordered by fee.
pub struct TransactionQueue {
    /// Configuration.
    config: TxQueueConfig,
    /// Transactions indexed by hash.
    by_hash: RwLock<HashMap<Hash256, QueuedTransaction>>,
    /// Seen transaction hashes (includes recently applied).
    seen: RwLock<HashSet<Hash256>>,
    /// Validation context (ledger state info for validation).
    validation_context: RwLock<ValidationContext>,
}

impl TransactionQueue {
    /// Create a new transaction queue.
    pub fn new(config: TxQueueConfig) -> Self {
        Self {
            config,
            by_hash: RwLock::new(HashMap::new()),
            seen: RwLock::new(HashSet::new()),
            validation_context: RwLock::new(ValidationContext::default()),
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(TxQueueConfig::default())
    }

    /// Create with a maximum size.
    pub fn with_max_size(max_size: usize) -> Self {
        Self::new(TxQueueConfig {
            max_size,
            ..Default::default()
        })
    }

    /// Update the validation context (should be called when ledger closes).
    pub fn update_validation_context(&self, ledger_seq: u32, close_time: u64, protocol_version: u32) {
        let mut ctx = self.validation_context.write();
        ctx.ledger_seq = ledger_seq;
        ctx.close_time = close_time;
        ctx.protocol_version = protocol_version;
    }

    /// Validate a transaction before queueing.
    fn validate_transaction(&self, envelope: &TransactionEnvelope) -> std::result::Result<(), &'static str> {
        use stellar_core_tx::{
            validate_ledger_bounds, validate_signatures, validate_time_bounds, LedgerContext,
            TransactionFrame,
        };

        let frame = TransactionFrame::with_network(envelope.clone(), self.config.network_id);
        let ctx = self.validation_context.read();

        // Validate basic structure
        if !frame.is_valid_structure() {
            return Err("invalid transaction structure");
        }

        // Validate time bounds if enabled
        if self.config.validate_time_bounds {
            let ledger_ctx = LedgerContext::new(
                ctx.ledger_seq,
                ctx.close_time,
                self.config.min_fee_per_op,
                5_000_000, // base reserve
                ctx.protocol_version,
                self.config.network_id.clone(),
            );

            if validate_time_bounds(&frame, &ledger_ctx).is_err() {
                return Err("time bounds validation failed");
            }

            if validate_ledger_bounds(&frame, &ledger_ctx).is_err() {
                return Err("ledger bounds validation failed");
            }
        }

        // Validate signatures if enabled
        if self.config.validate_signatures {
            let ledger_ctx = LedgerContext::new(
                ctx.ledger_seq,
                ctx.close_time,
                self.config.min_fee_per_op,
                5_000_000, // base reserve
                ctx.protocol_version,
                self.config.network_id.clone(),
            );

            if validate_signatures(&frame, &ledger_ctx).is_err() {
                return Err("signature validation failed");
            }
        }

        // Validate preconditions (extra signers / min seq age+gap)
        if let Preconditions::V2(cond) = frame.preconditions() {
            if !cond.extra_signers.is_empty() {
                if !extra_signers_satisfied(envelope, &self.config.network_id, &cond.extra_signers)? {
                    return Err("extra signer validation failed");
                }
            }
        }

        Ok(())
    }

    fn collect_evictions_for_lane_config<F>(
        &self,
        by_hash: &HashMap<Hash256, QueuedTransaction>,
        queued: &QueuedTransaction,
        lane_config: Box<dyn crate::surge_pricing::SurgePricingLaneConfig>,
        ledger_version: u32,
        exclude: &HashSet<Hash256>,
        filter: F,
        seed: u64,
    ) -> Option<Vec<Hash256>>
    where
        F: Fn(&QueuedTransaction) -> bool,
    {
        let mut queue = SurgePricingPriorityQueue::new(lane_config, seed);
        for tx in by_hash.values() {
            if exclude.contains(&tx.hash) {
                continue;
            }
            if filter(tx) {
                queue.add(tx.clone(), &self.config.network_id, ledger_version);
            }
        }
        queue
            .can_fit_with_eviction(queued, None, &self.config.network_id, ledger_version)
            .map(|evictions| evictions.into_iter().map(|(tx, _)| tx.hash).collect())
    }

    /// Try to add a transaction to the queue.
    pub fn try_add(&self, envelope: TransactionEnvelope) -> TxQueueResult {
        // Validate transaction before queueing
        if let Err(_) = self.validate_transaction(&envelope) {
            return TxQueueResult::Invalid;
        }

        // Create queued transaction
        let queued = match QueuedTransaction::new(envelope) {
            Ok(q) => q,
            Err(_) => return TxQueueResult::Invalid,
        };

        // Check if already seen
        if self.seen.read().contains(&queued.hash) {
            return TxQueueResult::Duplicate;
        }

        // Check fee
        if queued.fee_per_op < self.config.min_fee_per_op as u64 {
            return TxQueueResult::FeeTooLow;
        }

        let mut by_hash = self.by_hash.write();
        let ledger_version = self.validation_context.read().protocol_version;
        let queued_frame = stellar_core_tx::TransactionFrame::with_network(
            queued.envelope.clone(),
            self.config.network_id,
        );
        let queued_is_soroban = queued_frame.is_soroban();
        // Check for duplicate in queue
        if by_hash.contains_key(&queued.hash) {
            return TxQueueResult::Duplicate;
        }

        let mut pending_evictions: HashSet<Hash256> = HashSet::new();
        let seed = if cfg!(test) { 0 } else { rand::thread_rng().gen() };

        if !queued_is_soroban
            && (self.config.max_queue_classic_bytes.is_some()
                || self.config.max_queue_dex_ops.is_some())
        {
            let use_bytes = self.config.max_queue_classic_bytes.is_some();
            let ops_limit = i64::MAX;
            let generic_limit = if use_bytes {
                let bytes_limit = self.config.max_queue_classic_bytes.unwrap_or(u32::MAX) as i64;
                Resource::new(vec![ops_limit, bytes_limit])
            } else {
                Resource::new(vec![ops_limit])
            };
            let dex_limit = self.config.max_queue_dex_ops.map(|dex_ops| {
                if use_bytes {
                    // Upstream uses MAX_CLASSIC_BYTE_ALLOWANCE for the DEX lane byte limit.
                    Resource::new(vec![dex_ops as i64, MAX_CLASSIC_BYTE_ALLOWANCE as i64])
                } else {
                    Resource::new(vec![dex_ops as i64])
                }
            });
            let lane_config = DexLimitingLaneConfig::new(generic_limit, dex_limit);
            let filter = |tx: &QueuedTransaction| {
                let frame = stellar_core_tx::TransactionFrame::with_network(
                    tx.envelope.clone(),
                    self.config.network_id,
                );
                !frame.is_soroban()
            };
            let Some(evictions) = self.collect_evictions_for_lane_config(
                &by_hash,
                &queued,
                Box::new(lane_config),
                ledger_version,
                &pending_evictions,
                filter,
                seed,
            ) else {
                return TxQueueResult::QueueFull;
            };
            pending_evictions.extend(evictions);
        }

        if queued_is_soroban {
            if let Some(limit) = &self.config.max_queue_soroban_resources {
                let lane_config = SorobanGenericLaneConfig::new(limit.clone());
                let filter = |tx: &QueuedTransaction| {
                    let frame = stellar_core_tx::TransactionFrame::with_network(
                        tx.envelope.clone(),
                        self.config.network_id,
                    );
                    frame.is_soroban()
                };
                let Some(evictions) = self.collect_evictions_for_lane_config(
                    &by_hash,
                    &queued,
                    Box::new(lane_config),
                    ledger_version,
                    &pending_evictions,
                    filter,
                    seed,
                ) else {
                    return TxQueueResult::QueueFull;
                };
                pending_evictions.extend(evictions);
            }
        }

        if let Some(limit) = self.config.max_queue_ops {
            let lane_config = OpsOnlyLaneConfig::new(Resource::new(vec![limit as i64]));
            let filter = |_tx: &QueuedTransaction| true;
            let Some(evictions) = self.collect_evictions_for_lane_config(
                &by_hash,
                &queued,
                Box::new(lane_config),
                ledger_version,
                &pending_evictions,
                filter,
                seed,
            ) else {
                return TxQueueResult::QueueFull;
            };
            pending_evictions.extend(evictions);
        }

        for hash in pending_evictions {
            by_hash.remove(&hash);
        }

        // Check queue size
        if by_hash.len() >= self.config.max_size {
            // Try to evict expired transactions
            let expired: Vec<Hash256> = by_hash
                .iter()
                .filter(|(_, tx)| tx.is_expired(self.config.max_age_secs))
                .map(|(h, _)| *h)
                .collect();

            for hash in expired {
                by_hash.remove(&hash);
            }

            if by_hash.len() >= self.config.max_size {
                if let Some((evict_hash, evict_tx)) = by_hash
                    .iter()
                    .min_by(|a, b| {
                        let a_tx = a.1;
                        let b_tx = b.1;
                        fee_rate_cmp(a_tx.total_fee, a_tx.op_count, b_tx.total_fee, b_tx.op_count)
                            .then_with(|| b_tx.hash.0.cmp(&a_tx.hash.0))
                    })
                    .map(|(h, tx)| (*h, tx.clone()))
                {
                    if queued.is_better_than(&evict_tx) {
                        by_hash.remove(&evict_hash);
                    } else {
                        return TxQueueResult::QueueFull;
                    }
                } else {
                    return TxQueueResult::QueueFull;
                }
            }
        }

        // Add to queue
        let hash = queued.hash;
        by_hash.insert(hash, queued);
        self.seen.write().insert(hash);

        TxQueueResult::Added
    }

    /// Get a transaction set for the next ledger.
    ///
    /// Returns the highest-fee transactions up to the specified limit.
    pub fn get_transaction_set(&self, previous_ledger_hash: Hash256, max_ops: usize) -> TransactionSet {
        let SelectedTxs { transactions, .. } =
            self.select_transactions_with_starting_seq(max_ops, None);
        TransactionSet::new(previous_ledger_hash, transactions)
    }

    pub fn get_transaction_set_with_starting_seq(
        &self,
        previous_ledger_hash: Hash256,
        max_ops: usize,
        starting_seq: Option<&HashMap<Vec<u8>, i64>>,
    ) -> TransactionSet {
        let SelectedTxs { transactions, .. } =
            self.select_transactions_with_starting_seq(max_ops, starting_seq);
        TransactionSet::new(previous_ledger_hash, transactions)
    }

    /// Build a GeneralizedTransactionSet (protocol 20+) and return it with the correct hash.
    ///
    /// The hash is SHA-256 of the XDR-encoded GeneralizedTransactionSet.
    pub fn build_generalized_tx_set(&self, previous_ledger_hash: Hash256, max_ops: usize) -> (TransactionSet, stellar_xdr::curr::GeneralizedTransactionSet) {
        self.build_generalized_tx_set_with_starting_seq(previous_ledger_hash, max_ops, None)
    }

    pub fn build_generalized_tx_set_with_starting_seq(
        &self,
        previous_ledger_hash: Hash256,
        max_ops: usize,
        starting_seq: Option<&HashMap<Vec<u8>, i64>>,
    ) -> (TransactionSet, stellar_xdr::curr::GeneralizedTransactionSet) {
        use stellar_xdr::curr::{
            DependentTxCluster, GeneralizedTransactionSet, ParallelTxExecutionStage,
            ParallelTxsComponent, TransactionPhase, TxSetComponent,
            TxSetComponentTxsMaybeDiscountedFee, VecM, WriteXdr,
        };

        let SelectedTxs {
            transactions,
            soroban_limited,
            dex_limited,
            classic_limited,
        } = self.select_transactions_with_starting_seq(max_ops, starting_seq);
        let mut classic_txs = Vec::new();
        let mut soroban_txs = Vec::new();
        for tx in &transactions {
            let frame = stellar_core_tx::TransactionFrame::with_network(
                tx.clone(),
                self.config.network_id,
            );
            if frame.is_soroban() {
                soroban_txs.push(tx.clone());
            } else {
                classic_txs.push(tx.clone());
            }
        }

        soroban_txs.sort_by(|a, b| {
            let hash_a = Hash256::hash_xdr(a).unwrap_or_default();
            let hash_b = Hash256::hash_xdr(b).unwrap_or_default();
            hash_a.0.cmp(&hash_b.0)
        });

        let classic_base_fee = if classic_limited {
            classic_txs
                .iter()
                .filter_map(|tx| envelope_fee_per_op(tx).map(|(per_op, _, _)| per_op as i64))
                .min()
        } else {
            None
        };
        let dex_base_fee = if dex_limited {
            classic_txs
                .iter()
                .filter(|tx| {
                    let frame = stellar_core_tx::TransactionFrame::with_network(
                        (*tx).clone(),
                        self.config.network_id,
                    );
                    frame.has_dex_operations()
                })
                .filter_map(|tx| envelope_fee_per_op(tx).map(|(per_op, _, _)| per_op as i64))
                .min()
        } else {
            None
        };

        let mut classic_components: Vec<TxSetComponent> = Vec::new();
        if !classic_txs.is_empty() {
            let mut grouped: BTreeMap<Option<i64>, Vec<TransactionEnvelope>> = BTreeMap::new();
            for tx in classic_txs {
                let frame = stellar_core_tx::TransactionFrame::with_network(
                    tx.clone(),
                    self.config.network_id,
                );
                let fee = if frame.has_dex_operations() {
                    dex_base_fee.or(classic_base_fee)
                } else {
                    classic_base_fee
                };
                grouped.entry(fee).or_default().push(tx);
            }
            for (fee, mut txs) in grouped {
                sort_txs_by_hash(&mut txs);
                classic_components.push(
                    TxSetComponent::TxsetCompTxsMaybeDiscountedFee(
                        TxSetComponentTxsMaybeDiscountedFee {
                            base_fee: fee,
                            txs: txs.try_into().unwrap_or_default(),
                        },
                    ),
                );
            }
        }
        let classic_phase = TransactionPhase::V0(
            classic_components.try_into().unwrap_or_default(),
        );

        let soroban_base_fee = if soroban_limited {
            soroban_txs
                .iter()
                .filter_map(|tx| envelope_fee_per_op(tx).map(|(per_op, _, _)| per_op as i64))
                .min()
        } else {
            None
        };

        let soroban_phase = if soroban_txs.is_empty() {
            TransactionPhase::V1(ParallelTxsComponent {
                base_fee: soroban_base_fee,
                execution_stages: VecM::default(),
            })
        } else {
            let cluster = DependentTxCluster(
                soroban_txs.try_into().unwrap_or_default()
            );
            let stage = ParallelTxExecutionStage(
                vec![cluster].try_into().unwrap_or_default()
            );
            TransactionPhase::V1(ParallelTxsComponent {
                base_fee: soroban_base_fee,
                execution_stages: vec![stage].try_into().unwrap_or_default(),
            })
        };

        let gen_tx_set = GeneralizedTransactionSet::V1(
            stellar_xdr::curr::TransactionSetV1 {
                previous_ledger_hash: stellar_xdr::curr::Hash(previous_ledger_hash.0),
                phases: vec![classic_phase, soroban_phase]
                    .try_into()
                    .unwrap_or_default(),
            }
        );

        // Compute hash as SHA-256 of XDR-encoded GeneralizedTransactionSet
        let hash = if let Ok(xdr_bytes) = gen_tx_set.to_xdr(stellar_xdr::curr::Limits::none()) {
            Hash256::hash(&xdr_bytes)
        } else {
            Hash256::ZERO
        };

        let tx_set = TransactionSet::with_generalized(
            previous_ledger_hash,
            hash,
            transactions,
            gen_tx_set.clone(),
        );
        (tx_set, gen_tx_set)
    }

    fn select_transactions(&self, max_ops: usize) -> SelectedTxs {
        self.select_transactions_with_starting_seq(max_ops, None)
    }

    fn select_transactions_with_starting_seq(
        &self,
        max_ops: usize,
        starting_seq: Option<&HashMap<Vec<u8>, i64>>,
    ) -> SelectedTxs {
        let seed = if cfg!(test) {
            0
        } else {
            rand::thread_rng().gen()
        };
        let by_hash = self.by_hash.read();
        let mut per_account: HashMap<Vec<u8>, Vec<QueuedTransaction>> = HashMap::new();

        for tx in by_hash.values() {
            if tx.is_expired(self.config.max_age_secs) {
                continue;
            }
            let key = account_key(&tx.envelope);
            per_account.entry(key).or_default().push(tx.clone());
        }

        let mut layered: HashMap<Vec<u8>, Vec<QueuedTransaction>> = HashMap::new();
        for (account, mut txs) in per_account {
            txs.sort_by(|a, b| {
                a.sequence_number()
                    .cmp(&b.sequence_number())
                    .then_with(|| {
                        fee_rate_cmp(b.total_fee, b.op_count, a.total_fee, a.op_count)
                    })
                    .then_with(|| a.hash.0.cmp(&b.hash.0))
            });

            let mut deduped: HashMap<i64, QueuedTransaction> = HashMap::new();
            for tx in txs {
                let seq = tx.sequence_number();
                match deduped.get(&seq) {
                    None => {
                        deduped.insert(seq, tx);
                    }
                    Some(existing) => {
                        let replace = better_fee_ratio(&tx, existing);
                        if replace {
                            deduped.insert(seq, tx);
                        }
                    }
                }
            }

            let mut seqs: Vec<_> = deduped.keys().copied().collect();
            seqs.sort();
            let mut contiguous = Vec::new();
            let mut expected = starting_seq
                .and_then(|map| map.get(&account).copied())
                .map(|seq| seq.saturating_add(1));
            for seq in seqs {
                if let Some(exp) = expected {
                    if seq < exp {
                        continue;
                    }
                    if seq != exp {
                        break;
                    }
                }
                let Some(tx) = deduped.remove(&seq) else {
                    break;
                };
                contiguous.push(tx);
                expected = Some(seq.saturating_add(1));
            }

            if !contiguous.is_empty() {
                layered.insert(account, contiguous);
            }
        }

        let max_ops = u32::try_from(max_ops).unwrap_or(u32::MAX);
        let use_classic_bytes = self.config.max_classic_bytes.is_some()
            || self.config.max_dex_bytes.is_some();
        let ledger_version = self.validation_context.read().protocol_version;

        let mut classic_accounts: HashMap<Vec<u8>, Vec<QueuedTransaction>> = HashMap::new();
        let mut soroban_accounts: HashMap<Vec<u8>, Vec<QueuedTransaction>> = HashMap::new();
        let mut accounts: Vec<_> = layered.keys().cloned().collect();
        accounts.sort();
        for account in accounts {
            if let Some(txs) = layered.get(&account) {
                for tx in txs {
                    let frame = stellar_core_tx::TransactionFrame::with_network(
                        tx.envelope.clone(),
                        self.config.network_id,
                    );
                    if frame.is_soroban() {
                        soroban_accounts
                            .entry(account.clone())
                            .or_default()
                            .push(tx.clone());
                    } else {
                        classic_accounts
                            .entry(account.clone())
                            .or_default()
                            .push(tx.clone());
                    }
                }
            }
        }

        let classic_bytes = self
            .config
            .max_classic_bytes
            .unwrap_or(MAX_CLASSIC_BYTE_ALLOWANCE) as i64;
        let classic_limit = if use_classic_bytes {
            Resource::new(vec![max_ops as i64, classic_bytes])
        } else {
            Resource::new(vec![max_ops as i64])
        };
        let dex_limit = self.config.max_dex_ops.map(|dex_ops| {
            if use_classic_bytes {
                // Upstream uses MAX_CLASSIC_BYTE_ALLOWANCE for the DEX lane byte limit.
                Resource::new(vec![dex_ops as i64, MAX_CLASSIC_BYTE_ALLOWANCE as i64])
            } else {
                Resource::new(vec![dex_ops as i64])
            }
        });

        let classic_lane_config = DexLimitingLaneConfig::new(classic_limit, dex_limit);
        let mut classic_had_not_fitting = Vec::new();
        let mut classic_queue = SurgePricingPriorityQueue::new(Box::new(classic_lane_config), seed);
        let mut classic_positions: HashMap<Vec<u8>, usize> = HashMap::new();
        for (account, txs) in classic_accounts.iter() {
            if let Some(first) = txs.first() {
                classic_queue.add(first.clone(), &self.config.network_id, ledger_version);
                classic_positions.insert(account.clone(), 0);
            }
        }

        let mut classic_selected = Vec::new();
        let lane_count = classic_queue.get_num_lanes();
        let mut classic_lane_left: Vec<Resource> = (0..lane_count)
            .map(|lane| classic_queue.lane_limits(lane))
            .collect();
        classic_had_not_fitting.resize(lane_count, false);
        while let Some((lane, entry)) = classic_queue.peek_top() {
            let frame = stellar_core_tx::TransactionFrame::with_network(
                entry.tx.envelope.clone(),
                self.config.network_id,
            );
            let resources = classic_queue.tx_resources(&frame, ledger_version);
            let exceeds_lane = any_greater(&resources, &classic_lane_left[lane]);
            let exceeds_generic = any_greater(&resources, &classic_lane_left[GENERIC_LANE]);
            if exceeds_lane || exceeds_generic {
                if exceeds_lane {
                    classic_had_not_fitting[lane] = true;
                } else {
                    classic_had_not_fitting[GENERIC_LANE] = true;
                }
                classic_queue.remove_entry(
                    lane,
                    &entry,
                    ledger_version,
                    &self.config.network_id,
                );
                continue;
            }

            classic_selected.push(entry.tx.clone());
            classic_lane_left[GENERIC_LANE] -= resources.clone();
            if lane != GENERIC_LANE {
                classic_lane_left[lane] -= resources;
            }

            classic_queue.remove_entry(
                lane,
                &entry,
                ledger_version,
                &self.config.network_id,
            );
            let account = account_key(&entry.tx.envelope);
            if let Some(txs) = classic_accounts.get(&account) {
                let next_index = classic_positions
                    .get(&account)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(1);
                if next_index < txs.len() {
                    classic_positions.insert(account.clone(), next_index);
                    classic_queue.add(txs[next_index].clone(), &self.config.network_id, ledger_version);
                }
            }
        }
        let classic_limited = classic_had_not_fitting
            .get(GENERIC_LANE)
            .copied()
            .unwrap_or(false);
        let dex_limited = classic_had_not_fitting
            .get(crate::surge_pricing::DEX_LANE)
            .copied()
            .unwrap_or(false);

        let mut soroban_limit = self.config.max_soroban_resources.clone();
        if soroban_limit.is_none() {
            if let Some(byte_limit) = self.config.max_soroban_bytes {
                let mut values = vec![i64::MAX; NUM_SOROBAN_TX_RESOURCES];
                values[ResourceType::TxByteSize as usize] = byte_limit as i64;
                soroban_limit = Some(Resource::new(values));
            }
        }
        if let (Some(limit), Some(byte_limit)) =
            (soroban_limit.as_mut(), self.config.max_soroban_bytes)
        {
            let current = limit.get_val(ResourceType::TxByteSize);
            let clamped = (byte_limit as i64).min(current);
            limit.set_val(ResourceType::TxByteSize, clamped);
        }
        let (soroban_selected, soroban_limited) = if let Some(limit) = soroban_limit {
            let mut had_not_fitting = vec![false];
            let lane_config = SorobanGenericLaneConfig::new(limit);
            let mut queue = SurgePricingPriorityQueue::new(Box::new(lane_config), seed);
            let mut positions: HashMap<Vec<u8>, usize> = HashMap::new();
            for (account, txs) in soroban_accounts.iter() {
                if let Some(first) = txs.first() {
                    queue.add(first.clone(), &self.config.network_id, ledger_version);
                    positions.insert(account.clone(), 0);
                }
            }

            let mut selected = Vec::new();
            let mut lane_left = vec![queue.lane_limits(GENERIC_LANE)];
            while let Some((lane, entry)) = queue.peek_top() {
                let frame = stellar_core_tx::TransactionFrame::with_network(
                    entry.tx.envelope.clone(),
                    self.config.network_id,
                );
                let resources = queue.tx_resources(&frame, ledger_version);
                let exceeds = any_greater(&resources, &lane_left[GENERIC_LANE]);
                if exceeds {
                    had_not_fitting[GENERIC_LANE] = true;
                    queue.remove_entry(
                        lane,
                        &entry,
                        ledger_version,
                        &self.config.network_id,
                    );
                    continue;
                }
                selected.push(entry.tx.clone());
                lane_left[GENERIC_LANE] -= resources;
                queue.remove_entry(
                    lane,
                    &entry,
                    ledger_version,
                    &self.config.network_id,
                );
                let account = account_key(&entry.tx.envelope);
                if let Some(txs) = soroban_accounts.get(&account) {
                    let next_index = positions
                        .get(&account)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(1);
                    if next_index < txs.len() {
                        positions.insert(account.clone(), next_index);
                        queue.add(txs[next_index].clone(), &self.config.network_id, ledger_version);
                    }
                }
            }
            let limited = had_not_fitting.get(GENERIC_LANE).copied().unwrap_or(false);
            (selected, limited)
        } else {
            let mut selected = Vec::new();
            let mut accounts: Vec<_> = soroban_accounts.keys().cloned().collect();
            accounts.sort();
            for account in accounts {
                if let Some(txs) = soroban_accounts.get(&account) {
                    selected.extend(txs.iter().cloned());
                }
            }
            (selected, false)
        };

        let mut transactions = Vec::new();
        transactions.extend(classic_selected.into_iter().map(|tx| tx.envelope.clone()));
        transactions.extend(soroban_selected.into_iter().map(|tx| tx.envelope.clone()));

        SelectedTxs {
            transactions,
            soroban_limited,
            dex_limited,
            classic_limited,
        }
    }

    /// Remove transactions that were applied in a ledger.
    pub fn remove_applied(&self, tx_hashes: &[Hash256]) {
        let mut by_hash = self.by_hash.write();
        for hash in tx_hashes {
            by_hash.remove(hash);
        }
        // Keep in seen to prevent re-adding
    }

    /// Get a transaction by hash.
    pub fn get(&self, hash: &Hash256) -> Option<QueuedTransaction> {
        self.by_hash.read().get(hash).cloned()
    }

    /// Check if a transaction is in the queue.
    pub fn contains(&self, hash: &Hash256) -> bool {
        self.by_hash.read().contains_key(hash)
    }

    /// Get the number of pending transactions.
    pub fn len(&self) -> usize {
        self.by_hash.read().len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.by_hash.read().is_empty()
    }

    /// Clear expired transactions.
    pub fn evict_expired(&self) {
        let mut by_hash = self.by_hash.write();
        let max_age = self.config.max_age_secs;
        by_hash.retain(|_, tx| !tx.is_expired(max_age));
    }

    /// Clear all transactions.
    pub fn clear(&self) {
        self.by_hash.write().clear();
        // Don't clear seen - prevents replay
    }

    /// Clear the seen set (for testing or reset).
    pub fn clear_seen(&self) {
        self.seen.write().clear();
    }

    pub fn pending_accounts(&self) -> Vec<AccountId> {
        let by_hash = self.by_hash.read();
        let mut accounts: HashSet<Vec<u8>> = HashSet::new();
        let mut out = Vec::new();
        for tx in by_hash.values() {
            let account_id = account_id_from_envelope(&tx.envelope);
            let key = account_key_from_account_id(&account_id);
            if accounts.insert(key) {
                out.push(account_id);
            }
        }
        out
    }

    /// Return transaction hashes ordered by fee per op (desc) then received time (asc).
    pub fn ordered_hashes_by_fee(&self, limit: usize) -> Vec<Hash256> {
        let by_hash = self.by_hash.read();
        let mut entries: Vec<_> = by_hash
            .values()
            .map(|tx| (tx.fee_per_op, tx.received_at, tx.hash))
            .collect();
        entries.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.2.to_hex().cmp(&b.2.to_hex()))
        });
        entries
            .into_iter()
            .take(limit)
            .map(|entry| entry.2)
            .collect()
    }
}

fn extra_signers_satisfied(
    envelope: &TransactionEnvelope,
    network_id: &NetworkId,
    extra_signers: &[SignerKey],
) -> std::result::Result<bool, &'static str> {
    let (tx_hash, signatures) = precondition_hash_and_signatures(envelope, network_id)?;

    Ok(extra_signers.iter().all(|signer| match signer {
        SignerKey::Ed25519(key) => {
            if let Ok(pk) = stellar_core_crypto::PublicKey::from_bytes(&key.0) {
                has_ed25519_signature(&tx_hash, signatures, &pk)
            } else {
                false
            }
        }
        SignerKey::PreAuthTx(key) => key.0 == tx_hash.0,
        SignerKey::HashX(key) => has_hashx_signature(signatures, key),
        SignerKey::Ed25519SignedPayload(payload) => {
            has_signed_payload_signature(&tx_hash, signatures, payload)
        }
    }))
}

fn precondition_hash_and_signatures<'a>(
    envelope: &'a TransactionEnvelope,
    network_id: &NetworkId,
) -> std::result::Result<(Hash256, &'a [DecoratedSignature]), &'static str> {
    match envelope {
        TransactionEnvelope::TxV0(env) => {
            let frame = stellar_core_tx::TransactionFrame::with_network(envelope.clone(), *network_id);
            let hash = frame.hash(network_id).map_err(|_| "tx hash error")?;
            Ok((hash, env.signatures.as_slice()))
        }
        TransactionEnvelope::Tx(env) => {
            let frame = stellar_core_tx::TransactionFrame::with_network(envelope.clone(), *network_id);
            let hash = frame.hash(network_id).map_err(|_| "tx hash error")?;
            Ok((hash, env.signatures.as_slice()))
        }
        TransactionEnvelope::TxFeeBump(env) => {
            let inner_env = match &env.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => inner.clone(),
            };
            let inner_frame = stellar_core_tx::TransactionFrame::with_network(
                TransactionEnvelope::Tx(inner_env),
                *network_id,
            );
            let hash = inner_frame.hash(network_id).map_err(|_| "inner tx hash error")?;
            let signatures = match &env.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => inner.signatures.as_slice(),
            };
            Ok((hash, signatures))
        }
    }
}

fn has_ed25519_signature(
    tx_hash: &Hash256,
    signatures: &[DecoratedSignature],
    pk: &stellar_core_crypto::PublicKey,
) -> bool {
    signatures
        .iter()
        .any(|sig| stellar_core_tx::validation::verify_signature_with_key(tx_hash, sig, pk))
}

fn has_hashx_signature(
    signatures: &[DecoratedSignature],
    key: &stellar_xdr::curr::Uint256,
) -> bool {
    signatures.iter().any(|sig| {
        if sig.signature.0.len() != 32 {
            return false;
        }
        let expected_hint = [key.0[28], key.0[29], key.0[30], key.0[31]];
        if sig.hint.0 != expected_hint {
            return false;
        }
        let hash = Hash256::hash(&sig.signature.0);
        hash.0 == key.0
    })
}

fn has_signed_payload_signature(
    tx_hash: &Hash256,
    signatures: &[DecoratedSignature],
    payload: &stellar_xdr::curr::SignerKeyEd25519SignedPayload,
) -> bool {
    let pk = match stellar_core_crypto::PublicKey::from_bytes(&payload.ed25519.0) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let mut data = Vec::with_capacity(32 + payload.payload.len());
    data.extend_from_slice(&tx_hash.0);
    data.extend_from_slice(&payload.payload);
    let payload_hash = Hash256::hash(&data);

    signatures
        .iter()
        .any(|sig| stellar_core_tx::validation::verify_signature_with_key(&payload_hash, sig, &pk))
}

impl Default for TransactionQueue {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_core_common::NetworkId;
    use stellar_core_crypto::{sign_hash, SecretKey};
    use stellar_core_common::{Resource, ResourceType, NUM_SOROBAN_TX_RESOURCES};
    use stellar_xdr::curr::{
        AccountId, AlphaNum4, Asset, AssetCode4, CreateAccountOp, DecoratedSignature, Duration,
        HostFunction, InvokeContractArgs, InvokeHostFunctionOp, LedgerFootprint, ManageSellOfferOp,
        Memo, MuxedAccount, Operation, OperationBody, Preconditions, PreconditionsV2, Price,
        PublicKey, ScAddress, ScSymbol, ScVal, SequenceNumber, Signature as XdrSignature,
        SignatureHint, SignerKey, SorobanResources, SorobanTransactionData, SorobanTransactionDataExt,
        StringM, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256,
        VecM,
    };

    fn make_test_envelope(fee: u32, ops: usize) -> TransactionEnvelope {
        let source = MuxedAccount::Ed25519(Uint256([0u8; 32]));

        let operations: Vec<Operation> = (0..ops)
            .map(|_| Operation {
                source_account: None,
                body: OperationBody::CreateAccount(CreateAccountOp {
                    destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1u8; 32]))),
                    starting_balance: 1000000000,
                }),
            })
            .collect();

        let tx = Transaction {
            source_account: source,
            fee,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: operations.try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![DecoratedSignature {
                hint: SignatureHint([0u8; 4]),
                signature: XdrSignature(vec![0u8; 64].try_into().unwrap()),
            }].try_into().unwrap(),
        })
    }

    fn make_soroban_envelope(fee: u32) -> TransactionEnvelope {
        let source = MuxedAccount::Ed25519(Uint256([9u8; 32]));
        let function_name = ScSymbol(
            StringM::<32>::try_from("test".to_string()).expect("symbol")
        );
        let host_function = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: ScAddress::default(),
            function_name,
            args: VecM::<ScVal>::default(),
        });
        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function,
                auth: VecM::default(),
            }),
        };

        let tx = Transaction {
            source_account: source,
            fee,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![DecoratedSignature {
                hint: SignatureHint([0u8; 4]),
                signature: XdrSignature(vec![0u8; 64].try_into().unwrap()),
            }]
            .try_into()
            .unwrap(),
        })
    }

    fn make_soroban_envelope_with_resources(fee: u32, instructions: u32) -> TransactionEnvelope {
        let mut envelope = make_soroban_envelope(fee);
        if let TransactionEnvelope::Tx(env) = &mut envelope {
            let resources = SorobanResources {
                footprint: LedgerFootprint {
                    read_only: VecM::default(),
                    read_write: VecM::default(),
                },
                instructions,
                disk_read_bytes: 0,
                write_bytes: 0,
            };
            env.tx.ext = TransactionExt::V1(SorobanTransactionData {
                ext: SorobanTransactionDataExt::V0,
                resources,
                resource_fee: 0,
            });
        }
        envelope
    }

    fn make_dex_envelope(fee: u32) -> TransactionEnvelope {
        let source = MuxedAccount::Ed25519(Uint256([10u8; 32]));
        let selling = Asset::Native;
        let buying = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USDC"),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([11u8; 32]))),
        });
        let op = Operation {
            source_account: None,
            body: OperationBody::ManageSellOffer(ManageSellOfferOp {
                selling,
                buying,
                amount: 1,
                price: Price { n: 1, d: 1 },
                offer_id: 0,
            }),
        };

        let tx = Transaction {
            source_account: source,
            fee,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![DecoratedSignature {
                hint: SignatureHint([0u8; 4]),
                signature: XdrSignature(vec![0u8; 64].try_into().unwrap()),
            }]
            .try_into()
            .unwrap(),
        })
    }

    fn sign_envelope(
        envelope: &TransactionEnvelope,
        secret: &SecretKey,
        network_id: &NetworkId,
    ) -> DecoratedSignature {
        let frame = stellar_core_tx::TransactionFrame::with_network(envelope.clone(), *network_id);
        let hash = frame.hash(network_id).expect("tx hash");
        let signature = sign_hash(secret, &hash);

        let public_key = secret.public_key();
        let pk_bytes = public_key.as_bytes();
        let hint = SignatureHint([pk_bytes[28], pk_bytes[29], pk_bytes[30], pk_bytes[31]]);

        DecoratedSignature {
            hint,
            signature: XdrSignature(signature.0.to_vec().try_into().unwrap()),
        }
    }

    fn envelope_fee(envelope: &TransactionEnvelope) -> u64 {
        match envelope {
            TransactionEnvelope::TxV0(tx) => tx.tx.fee as u64,
            TransactionEnvelope::Tx(tx) => tx.tx.fee as u64,
            TransactionEnvelope::TxFeeBump(tx) => tx.tx.fee as u64,
        }
    }

    fn envelope_seq(envelope: &TransactionEnvelope) -> i64 {
        match envelope {
            TransactionEnvelope::TxV0(tx) => tx.tx.seq_num.0,
            TransactionEnvelope::Tx(tx) => tx.tx.seq_num.0,
            TransactionEnvelope::TxFeeBump(tx) => match &tx.tx.inner_tx {
                stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.seq_num.0,
            },
        }
    }

    fn envelope_size(envelope: &TransactionEnvelope) -> usize {
        envelope
            .to_xdr(stellar_xdr::curr::Limits::none())
            .map(|bytes| bytes.len())
            .unwrap_or(0)
    }

    fn set_source(envelope: &mut TransactionEnvelope, seed: u8) {
        let source = MuxedAccount::Ed25519(Uint256([seed; 32]));
        match envelope {
            TransactionEnvelope::TxV0(env) => {
                env.tx.source_account_ed25519 = Uint256([seed; 32]);
            }
            TransactionEnvelope::Tx(env) => {
                env.tx.source_account = source;
            }
            TransactionEnvelope::TxFeeBump(env) => match &mut env.tx.inner_tx {
                stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                    inner.tx.source_account = source;
                }
            },
        }
    }

    #[test]
    fn test_add_transaction() {
        let queue = TransactionQueue::with_defaults();

        let tx = make_test_envelope(200, 1);
        let result = queue.try_add(tx);
        assert_eq!(result, TxQueueResult::Added);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_duplicate_detection() {
        let queue = TransactionQueue::with_defaults();

        let tx = make_test_envelope(200, 1);
        queue.try_add(tx.clone());
        let result = queue.try_add(tx);
        assert_eq!(result, TxQueueResult::Duplicate);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_fee_ordering() {
        let queue = TransactionQueue::with_defaults();

        // Add transactions with different fees
        let mut tx_low = make_test_envelope(100, 1);
        let mut tx_high = make_test_envelope(300, 1);
        let mut tx_mid = make_test_envelope(200, 1);
        set_source(&mut tx_low, 1);
        set_source(&mut tx_high, 2);
        set_source(&mut tx_mid, 3);
        assert_eq!(queue.try_add(tx_low), TxQueueResult::Added);
        assert_eq!(queue.try_add(tx_high), TxQueueResult::Added);
        assert_eq!(queue.len(), 2);
        queue.try_add(tx_mid);

        let set = queue.get_transaction_set(Hash256::ZERO, 10);
        assert_eq!(set.len(), 3);

        let fees: Vec<u64> = set
            .transactions
            .iter()
            .map(envelope_fee)
            .collect();
        assert_eq!(fees, vec![300, 200, 100]);
    }

    #[test]
    fn test_tie_breaker_is_deterministic() {
        let queue = TransactionQueue::with_defaults();

        let mut tx_a = make_test_envelope(200, 1);
        let mut tx_b = make_test_envelope(200, 1);
        set_source(&mut tx_a, 4);
        set_source(&mut tx_b, 5);
        let hash_a = Hash256::hash_xdr(&tx_a).expect("hash tx_a");
        let hash_b = Hash256::hash_xdr(&tx_b).expect("hash tx_b");

        queue.try_add(tx_a);
        queue.try_add(tx_b);

        let set = queue.get_transaction_set(Hash256::ZERO, 10);
        assert_eq!(set.len(), 2);

        let expected = if hash_a.0 <= hash_b.0 {
            vec![hash_a, hash_b]
        } else {
            vec![hash_b, hash_a]
        };
        let got: Vec<Hash256> = set
            .transactions
            .iter()
            .map(|tx| Hash256::hash_xdr(tx).expect("hash tx"))
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn test_sequence_gap_stops_layer() {
        let queue = TransactionQueue::with_defaults();

        let mut tx_a = make_test_envelope(200, 1);
        let mut tx_b = make_test_envelope(200, 1);
        if let TransactionEnvelope::Tx(env) = &mut tx_a {
            env.tx.seq_num = SequenceNumber(1);
        }
        if let TransactionEnvelope::Tx(env) = &mut tx_b {
            env.tx.seq_num = SequenceNumber(3);
        }

        queue.try_add(tx_a);
        queue.try_add(tx_b);

        let set = queue.get_transaction_set(Hash256::ZERO, 10);
        assert_eq!(set.len(), 1);
        assert_eq!(envelope_seq(&set.transactions[0]), 1);
    }

    #[test]
    fn test_sequence_order_preserved() {
        let queue = TransactionQueue::with_defaults();

        let mut tx_a = make_test_envelope(200, 1);
        let mut tx_b = make_test_envelope(200, 1);
        if let TransactionEnvelope::Tx(env) = &mut tx_a {
            env.tx.seq_num = SequenceNumber(1);
        }
        if let TransactionEnvelope::Tx(env) = &mut tx_b {
            env.tx.seq_num = SequenceNumber(2);
        }

        queue.try_add(tx_a);
        queue.try_add(tx_b);

        let set = queue.get_transaction_set(Hash256::ZERO, 10);
        let seqs: Vec<i64> = set.transactions.iter().map(envelope_seq).collect();
        assert_eq!(seqs, vec![1, 2]);
    }

    #[test]
    fn test_sequence_respects_starting_seq() {
        let queue = TransactionQueue::with_defaults();

        let mut tx_a = make_test_envelope(200, 1);
        let mut tx_b = make_test_envelope(200, 1);
        if let TransactionEnvelope::Tx(env) = &mut tx_a {
            env.tx.seq_num = SequenceNumber(5);
        }
        if let TransactionEnvelope::Tx(env) = &mut tx_b {
            env.tx.seq_num = SequenceNumber(6);
        }

        queue.try_add(tx_a);
        queue.try_add(tx_b);

        let account_id = account_id_from_envelope(&make_test_envelope(200, 1));
        let mut starting = std::collections::HashMap::new();
        starting.insert(account_key_from_account_id(&account_id), 5);

        let set = queue.get_transaction_set_with_starting_seq(Hash256::ZERO, 10, Some(&starting));
        let seqs: Vec<i64> = set.transactions.iter().map(envelope_seq).collect();
        assert_eq!(seqs, vec![6]);
    }

    #[test]
    fn test_generalized_tx_set_phase_split() {
        let queue = TransactionQueue::with_defaults();

        let classic = make_test_envelope(200, 1);
        let soroban = make_soroban_envelope(200);
        queue.try_add(classic.clone());
        queue.try_add(soroban.clone());

        let (_set, gen) = queue.build_generalized_tx_set(Hash256::ZERO, 100);
        let stellar_xdr::curr::GeneralizedTransactionSet::V1(v1) = gen;
        assert_eq!(v1.phases.len(), 2);

        match &v1.phases[0] {
            stellar_xdr::curr::TransactionPhase::V0(components) => {
                let txs: Vec<_> = components
                    .iter()
                    .flat_map(|component| match component {
                        stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) => {
                            comp.txs.to_vec()
                        }
                    })
                    .collect();
                assert_eq!(txs.len(), 1);
                assert!(!stellar_core_tx::TransactionFrame::with_network(
                    txs[0].clone(),
                    NetworkId::testnet()
                )
                .is_soroban());
            }
            _ => panic!("expected classic phase"),
        }

        match &v1.phases[1] {
            stellar_xdr::curr::TransactionPhase::V1(parallel) => {
                let mut txs = Vec::new();
                for stage in parallel.execution_stages.iter() {
                    for cluster in stage.iter() {
                        txs.extend(cluster.0.iter().cloned());
                    }
                }
                assert_eq!(txs.len(), 1);
                assert!(stellar_core_tx::TransactionFrame::with_network(
                    txs[0].clone(),
                    NetworkId::testnet()
                )
                .is_soroban());
            }
            _ => panic!("expected soroban phase"),
        }
    }

    #[test]
    fn test_classic_base_fee_surge() {
        let queue = TransactionQueue::with_defaults();

        let mut tx_low = make_test_envelope(8000, 80);
        let mut tx_high = make_test_envelope(12000, 80);
        set_source(&mut tx_low, 8);
        set_source(&mut tx_high, 9);
        assert_eq!(queue.try_add(tx_low), TxQueueResult::Added);
        assert_eq!(queue.try_add(tx_high), TxQueueResult::Added);
        assert_eq!(queue.len(), 2);

        let SelectedTxs {
            classic_limited,
            transactions,
            ..
        } = queue.select_transactions(100);
        assert!(classic_limited);
        assert_eq!(transactions.len(), 1);

        let (_set, gen) = queue.build_generalized_tx_set(Hash256::ZERO, 100);
        let stellar_xdr::curr::GeneralizedTransactionSet::V1(v1) = gen;
        let base_fee = match &v1.phases[0] {
            stellar_xdr::curr::TransactionPhase::V0(components) => {
                match &components[0] {
                    stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) => {
                        comp.base_fee
                    }
                }
            }
            _ => None,
        };

        assert_eq!(base_fee, Some(150));
    }

    #[test]
    fn test_classic_byte_limit() {
        let mut tx_high = make_test_envelope(400, 1);
        let mut tx_low = make_test_envelope(200, 1);
        set_source(&mut tx_high, 60);
        set_source(&mut tx_low, 61);

        let byte_limit = envelope_size(&tx_high) as u32;
        let config = TxQueueConfig {
            max_classic_bytes: Some(byte_limit),
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        queue.try_add(tx_high);
        queue.try_add(tx_low);

        let SelectedTxs {
            classic_limited,
            transactions,
            ..
        } = queue.select_transactions(1000);
        assert!(classic_limited);
        assert_eq!(transactions.len(), 1);
        assert_eq!(envelope_fee(&transactions[0]), 400);
    }

    #[test]
    fn test_dex_ops_limit() {
        let config = TxQueueConfig {
            max_dex_ops: Some(1),
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut dex_a = make_dex_envelope(400);
        let mut dex_b = make_dex_envelope(300);
        let mut classic = make_test_envelope(200, 1);
        set_source(&mut dex_a, 12);
        set_source(&mut dex_b, 13);
        set_source(&mut classic, 14);

        queue.try_add(dex_a);
        queue.try_add(dex_b);
        queue.try_add(classic);

        let set = queue.get_transaction_set(Hash256::ZERO, 10);
        assert_eq!(set.len(), 2);

        let mut dex_count = 0;
        for tx in &set.transactions {
            let frame = stellar_core_tx::TransactionFrame::with_network(
                tx.clone(),
                NetworkId::testnet(),
            );
            if frame.has_dex_operations() {
                dex_count += 1;
            }
        }
        assert_eq!(dex_count, 1);
    }

    #[test]
    fn test_dex_queue_limit_eviction() {
        let config = TxQueueConfig {
            max_queue_dex_ops: Some(1),
            max_size: 10,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut dex_low = make_dex_envelope(200);
        let mut dex_high = make_dex_envelope(400);
        set_source(&mut dex_low, 21);
        set_source(&mut dex_high, 22);

        assert_eq!(queue.try_add(dex_low.clone()), TxQueueResult::Added);
        assert_eq!(queue.try_add(dex_high.clone()), TxQueueResult::Added);

        let low_hash = Hash256::hash_xdr(&dex_low).unwrap();
        let high_hash = Hash256::hash_xdr(&dex_high).unwrap();
        assert!(!queue.contains(&low_hash));
        assert!(queue.contains(&high_hash));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_queue_ops_limit_eviction() {
        let config = TxQueueConfig {
            max_queue_ops: Some(2),
            max_size: 10,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut tx_low = make_test_envelope(100, 1);
        let mut tx_mid = make_test_envelope(200, 1);
        let mut tx_high = make_test_envelope(400, 1);
        set_source(&mut tx_low, 31);
        set_source(&mut tx_mid, 32);
        set_source(&mut tx_high, 33);

        assert_eq!(queue.try_add(tx_low.clone()), TxQueueResult::Added);
        assert_eq!(queue.try_add(tx_mid.clone()), TxQueueResult::Added);
        assert_eq!(queue.try_add(tx_high.clone()), TxQueueResult::Added);

        let low_hash = Hash256::hash_xdr(&tx_low).unwrap();
        let mid_hash = Hash256::hash_xdr(&tx_mid).unwrap();
        let high_hash = Hash256::hash_xdr(&tx_high).unwrap();
        assert!(!queue.contains(&low_hash));
        assert!(queue.contains(&mid_hash));
        assert!(queue.contains(&high_hash));
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_queue_ops_limit_rejects_same_account_eviction() {
        let config = TxQueueConfig {
            max_queue_ops: Some(1),
            max_size: 10,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut tx_low = make_test_envelope(100, 1);
        let mut tx_high = make_test_envelope(400, 1);
        set_source(&mut tx_low, 91);
        set_source(&mut tx_high, 91);
        if let TransactionEnvelope::Tx(env) = &mut tx_low {
            env.tx.seq_num = SequenceNumber(1);
        }
        if let TransactionEnvelope::Tx(env) = &mut tx_high {
            env.tx.seq_num = SequenceNumber(2);
        }

        assert_eq!(queue.try_add(tx_low), TxQueueResult::Added);
        assert_eq!(queue.try_add(tx_high), TxQueueResult::QueueFull);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_dex_base_fee_override() {
        let config = TxQueueConfig {
            max_dex_ops: Some(1),
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut dex_high = make_dex_envelope(500);
        let mut dex_low = make_dex_envelope(300);
        let mut classic = make_test_envelope(200, 1);
        set_source(&mut dex_high, 51);
        set_source(&mut dex_low, 52);
        set_source(&mut classic, 53);

        queue.try_add(dex_high);
        queue.try_add(dex_low);
        queue.try_add(classic);

        let (_set, gen) = queue.build_generalized_tx_set(Hash256::ZERO, 200);
        let stellar_xdr::curr::GeneralizedTransactionSet::V1(v1) = gen;
        let components = match &v1.phases[0] {
            stellar_xdr::curr::TransactionPhase::V0(comps) => comps,
            _ => panic!("expected classic phase"),
        };

        let mut has_dex_fee = false;
        let mut has_none_fee = false;
        for comp in components.iter() {
            let stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) = comp;
            match comp.base_fee {
                Some(500) => has_dex_fee = true,
                None => has_none_fee = true,
                _ => {}
            }
        }
        assert!(has_dex_fee);
        assert!(has_none_fee);
    }

    #[test]
    fn test_soroban_queue_limit_eviction() {
        let mut limit = Resource::new(vec![i64::MAX; NUM_SOROBAN_TX_RESOURCES]);
        limit.set_val(ResourceType::Instructions, 100);
        let config = TxQueueConfig {
            max_queue_soroban_resources: Some(limit),
            max_size: 10,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut low_fee = make_soroban_envelope_with_resources(4000, 80);
        let mut high_fee = make_soroban_envelope_with_resources(8000, 80);
        set_source(&mut low_fee, 71);
        set_source(&mut high_fee, 72);

        assert_eq!(queue.try_add(low_fee.clone()), TxQueueResult::Added);
        assert_eq!(queue.try_add(high_fee.clone()), TxQueueResult::Added);

        let low_hash = Hash256::hash_xdr(&low_fee).unwrap();
        let high_hash = Hash256::hash_xdr(&high_fee).unwrap();
        assert!(!queue.contains(&low_hash));
        assert!(queue.contains(&high_hash));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_soroban_resource_limit() {
        let mut limit = Resource::new(vec![i64::MAX; NUM_SOROBAN_TX_RESOURCES]);
        limit.set_val(ResourceType::Instructions, 100);
        let config = TxQueueConfig {
            max_soroban_resources: Some(limit),
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut tx_a = make_soroban_envelope_with_resources(400, 80);
        let mut tx_b = make_soroban_envelope_with_resources(300, 80);
        set_source(&mut tx_a, 31);
        set_source(&mut tx_b, 32);
        queue.try_add(tx_a);
        queue.try_add(tx_b);

        let set = queue.get_transaction_set(Hash256::ZERO, 10);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_soroban_base_fee_on_limit() {
        let mut limit = Resource::new(vec![i64::MAX; NUM_SOROBAN_TX_RESOURCES]);
        limit.set_val(ResourceType::Instructions, 100);
        let config = TxQueueConfig {
            max_soroban_resources: Some(limit),
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut high_fee = make_soroban_envelope_with_resources(8000, 80);
        let mut low_fee = make_soroban_envelope_with_resources(4000, 80);
        set_source(&mut high_fee, 41);
        set_source(&mut low_fee, 42);
        queue.try_add(high_fee);
        queue.try_add(low_fee);

        let (_set, gen) = queue.build_generalized_tx_set(Hash256::ZERO, 10);
        let stellar_xdr::curr::GeneralizedTransactionSet::V1(v1) = gen;
        let base_fee = match &v1.phases[1] {
            stellar_xdr::curr::TransactionPhase::V1(parallel) => parallel.base_fee,
            _ => None,
        };
        assert_eq!(base_fee, Some(8000));
    }

    #[test]
    fn test_soroban_byte_limit() {
        let mut limit = Resource::new(vec![i64::MAX; NUM_SOROBAN_TX_RESOURCES]);
        limit.set_val(ResourceType::TxByteSize, i64::MAX);
        let mut tx_high = make_soroban_envelope(12000);
        let mut tx_low = make_soroban_envelope(8000);
        set_source(&mut tx_high, 71);
        set_source(&mut tx_low, 72);
        let tx_size = envelope_size(&tx_high) as u32;
        let config = TxQueueConfig {
            max_soroban_resources: Some(limit),
            max_soroban_bytes: Some(tx_size),
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        queue.try_add(tx_high);
        queue.try_add(tx_low);

        let SelectedTxs {
            soroban_limited,
            transactions,
            ..
        } = queue.select_transactions(1000);
        assert!(soroban_limited);
        assert_eq!(transactions.len(), 1);
        assert_eq!(envelope_fee(&transactions[0]), 12000);
    }

    #[test]
    fn test_soroban_byte_limit_without_resource_limit() {
        let mut tx_high = make_soroban_envelope(12000);
        let mut tx_low = make_soroban_envelope(8000);
        set_source(&mut tx_high, 81);
        set_source(&mut tx_low, 82);
        let tx_size = envelope_size(&tx_high) as u32;
        let config = TxQueueConfig {
            max_soroban_bytes: Some(tx_size),
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        queue.try_add(tx_high);
        queue.try_add(tx_low);

        let SelectedTxs {
            soroban_limited,
            transactions,
            ..
        } = queue.select_transactions(1000);
        assert!(soroban_limited);
        assert_eq!(transactions.len(), 1);
        assert_eq!(envelope_fee(&transactions[0]), 12000);
    }

    #[test]
    fn test_soroban_no_limit_order_is_deterministic() {
        let config = TxQueueConfig {
            max_soroban_resources: None,
            max_soroban_bytes: None,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut tx_a = make_soroban_envelope(5000);
        let mut tx_b = make_soroban_envelope(4000);
        set_source(&mut tx_a, 1);
        set_source(&mut tx_b, 2);
        queue.try_add(tx_b);
        queue.try_add(tx_a);

        let SelectedTxs { transactions, .. } = queue.select_transactions(1000);
        assert_eq!(transactions.len(), 2);
        let key_a = account_key(&transactions[0]);
        let key_b = account_key(&transactions[1]);
        assert!(key_a < key_b);
    }

    #[test]
    fn test_queue_full() {
        let config = TxQueueConfig {
            max_size: 2,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        queue.try_add(make_test_envelope(100, 1));
        queue.try_add(make_test_envelope(200, 1));
        let result = queue.try_add(make_test_envelope(300, 1));
        assert_eq!(result, TxQueueResult::Added);
    }

    #[test]
    fn test_queue_eviction_for_higher_fee() {
        let config = TxQueueConfig {
            max_size: 1,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut low = make_test_envelope(200, 1);
        let mut high = make_test_envelope(400, 1);
        set_source(&mut low, 21);
        set_source(&mut high, 22);

        let low_hash = Hash256::hash_xdr(&low).unwrap();
        let high_hash = Hash256::hash_xdr(&high).unwrap();

        assert_eq!(queue.try_add(low), TxQueueResult::Added);
        assert_eq!(queue.try_add(high), TxQueueResult::Added);
        assert!(!queue.contains(&low_hash));
        assert!(queue.contains(&high_hash));
    }

    #[test]
    fn test_remove_applied() {
        let queue = TransactionQueue::with_defaults();

        let tx = make_test_envelope(200, 1);
        queue.try_add(tx.clone());

        let hash = Hash256::hash_xdr(&tx).unwrap();
        assert!(queue.contains(&hash));

        queue.remove_applied(&[hash]);
        assert!(!queue.contains(&hash));
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_extra_signer_required_missing() {
        let queue = TransactionQueue::with_defaults();
        let network_id = NetworkId::testnet();

        let source = MuxedAccount::Ed25519(Uint256([1u8; 32]));
        let extra_secret = SecretKey::from_seed(&[9u8; 32]);
        let extra_signer = SignerKey::Ed25519(Uint256(*extra_secret.public_key().as_bytes()));

        let preconditions = Preconditions::V2(PreconditionsV2 {
            time_bounds: None,
            ledger_bounds: None,
            min_seq_num: None,
            min_seq_age: Duration(0),
            min_seq_ledger_gap: 0,
            extra_signers: vec![extra_signer].try_into().unwrap(),
        });

        let operations: Vec<Operation> = vec![Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32]))),
                starting_balance: 1000000000,
            }),
        }];

        let tx = Transaction {
            source_account: source,
            fee: 200,
            seq_num: SequenceNumber(1),
            cond: preconditions,
            memo: Memo::None,
            operations: operations.try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });

        let wrong_secret = SecretKey::from_seed(&[8u8; 32]);
        let sig = sign_envelope(&envelope, &wrong_secret, &network_id);
        if let TransactionEnvelope::Tx(ref mut env) = envelope {
            env.signatures = vec![sig].try_into().unwrap();
        }

        assert_eq!(queue.try_add(envelope), TxQueueResult::Invalid);
    }

    #[test]
    fn test_extra_signer_required_satisfied() {
        let queue = TransactionQueue::with_defaults();
        let network_id = NetworkId::testnet();

        let source = MuxedAccount::Ed25519(Uint256([1u8; 32]));
        let extra_secret = SecretKey::from_seed(&[9u8; 32]);
        let extra_signer = SignerKey::Ed25519(Uint256(*extra_secret.public_key().as_bytes()));

        let preconditions = Preconditions::V2(PreconditionsV2 {
            time_bounds: None,
            ledger_bounds: None,
            min_seq_num: None,
            min_seq_age: Duration(0),
            min_seq_ledger_gap: 0,
            extra_signers: vec![extra_signer].try_into().unwrap(),
        });

        let operations: Vec<Operation> = vec![Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32]))),
                starting_balance: 1000000000,
            }),
        }];

        let tx = Transaction {
            source_account: source,
            fee: 200,
            seq_num: SequenceNumber(1),
            cond: preconditions,
            memo: Memo::None,
            operations: operations.try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });

        let sig = sign_envelope(&envelope, &extra_secret, &network_id);
        if let TransactionEnvelope::Tx(ref mut env) = envelope {
            env.signatures = vec![sig].try_into().unwrap();
        }

        assert_eq!(queue.try_add(envelope), TxQueueResult::Added);
    }

    #[test]
    fn test_min_seq_age_allowed() {
        let queue = TransactionQueue::with_defaults();
        let network_id = NetworkId::testnet();
        let source_secret = SecretKey::from_seed(&[5u8; 32]);
        let source = MuxedAccount::Ed25519(Uint256(*source_secret.public_key().as_bytes()));
        let preconditions = Preconditions::V2(PreconditionsV2 {
            time_bounds: None,
            ledger_bounds: None,
            min_seq_num: None,
            min_seq_age: Duration(1),
            min_seq_ledger_gap: 0,
            extra_signers: VecM::default(),
        });

        let operation = Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32]))),
                starting_balance: 1000000000,
            }),
        };

        let tx = Transaction {
            source_account: source,
            fee: 200,
            seq_num: SequenceNumber(1),
            cond: preconditions,
            memo: Memo::None,
            operations: vec![operation].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });

        let mut signed = envelope;
        let sig = sign_envelope(&signed, &source_secret, &network_id);
        if let TransactionEnvelope::Tx(ref mut env) = signed {
            env.signatures = vec![sig].try_into().unwrap();
        }

        assert_eq!(queue.try_add(signed), TxQueueResult::Added);
    }
}
