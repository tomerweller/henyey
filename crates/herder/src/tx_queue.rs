//! Transaction queue management.
//!
//! The transaction queue holds pending transactions waiting to be included
//! in a ledger. Transactions are ordered by fee (highest first) to maximize
//! network efficiency and incentivize appropriate fee bidding.
//!
//! # Overview
//!
//! The [`TransactionQueue`] is the central component for transaction mempool
//! management. It handles:
//!
//! - **Transaction validation**: Structural, time bounds, and signature checks
//! - **Fee-based ordering**: Higher-fee transactions are prioritized
//! - **Sequence number handling**: Maintains contiguous sequences per account
//! - **Lane-based limits**: Separate limits for classic, DEX, and Soroban transactions
//! - **Eviction**: Lower-fee transactions are evicted when limits are exceeded
//! - **Per-account limits**: One transaction per account (sequence-number-source)
//! - **Fee balance validation**: Validates fee-source has sufficient balance
//!
//! # Transaction Set Building
//!
//! When building a transaction set for consensus, the queue:
//!
//! 1. Groups transactions by source account
//! 2. Ensures contiguous sequence numbers (gaps break the chain)
//! 3. Separates classic and Soroban transactions into different phases
//! 4. Applies surge pricing when demand exceeds capacity
//! 5. Produces a [`GeneralizedTransactionSet`] (protocol 20+) or legacy format
//!
//! # Sequence Number Rules
//!
//! For a given account, only transactions with contiguous sequence numbers
//! can be included in the same ledger. Additionally, once a Soroban transaction
//! appears in the sequence, subsequent classic transactions are excluded
//! (Soroban and classic transactions execute in different phases).
//!
//! # Per-Account Limits
//!
//! The queue enforces a one-transaction-per-account limit (based on the
//! sequence-number-source). Fee-bump transactions can replace an existing
//! transaction with the same sequence number if the new fee is at least
//! 10x the existing fee rate. Transactions that are not included in a ledger
//! for too many consecutive ledgers (pending_depth) are automatically banned.

use parking_lot::RwLock;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use henyey_common::{
    any_greater, Hash256, NetworkId, Resource, ResourceType, NUM_SOROBAN_TX_RESOURCES,
};
use henyey_crypto::Sha256Hasher;
use stellar_xdr::curr::WriteXdr;
use stellar_xdr::curr::{
    AccountId, DecoratedSignature, FeeBumpTransactionInnerTx, GeneralizedTransactionSet, Limits,
    OperationType, Preconditions, SignerKey, TransactionEnvelope, TransactionPhase, TxSetComponent,
};

use crate::error::HerderError;
use crate::surge_pricing::{
    DexLimitingLaneConfig, OpsOnlyLaneConfig, SorobanGenericLaneConfig, SurgePricingLaneConfig,
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
    /// Transaction is banned.
    Banned,
    /// Transaction contains a filtered operation type.
    Filtered,
    /// Account already has a pending transaction. Try again later or use fee-bump.
    TryAgainLater,
}

/// Result of the shift() operation after ledger close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShiftResult {
    /// Number of transactions that were unbanned (reached end of ban period).
    pub unbanned_count: usize,
    /// Number of transactions that were auto-banned due to age (pending too long).
    pub evicted_due_to_age: usize,
}

const MAX_TX_SET_ALLOWANCE_BYTES: u32 = 10 * 1024 * 1024;
const MAX_CLASSIC_BYTE_ALLOWANCE: u32 = MAX_TX_SET_ALLOWANCE_BYTES / 2;
const MAX_SOROBAN_BYTE_ALLOWANCE: u32 = MAX_TX_SET_ALLOWANCE_BYTES / 2;

/// Trait for providing ledger account balance information.
///
/// This trait is used for fee balance validation during transaction queue
/// operations. Implementations should provide the available balance for
/// an account that can be used to pay transaction fees.
pub trait FeeBalanceProvider: Send + Sync {
    /// Get the available balance for an account that can be used for fees.
    ///
    /// Returns the native asset balance minus any reserves or holds,
    /// or None if the account doesn't exist.
    fn get_available_balance(&self, account_id: &AccountId) -> Option<i64>;
}

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
    /// Operation types to filter out (transactions containing these will be rejected).
    ///
    /// This allows nodes to exclude transactions with specific operation types
    /// from their mempool. This is configured via
    /// `EXCLUDE_TRANSACTIONS_CONTAINING_OPERATION_TYPE` in stellar-core.
    pub filtered_operation_types: HashSet<OperationType>,
    /// Maximum ledger-wide Soroban instructions (from ContractComputeV0).
    /// Used for parallel phase building. Default 0 disables parallel building.
    pub ledger_max_instructions: i64,
    /// Maximum dependent TX clusters per stage (from ContractParallelComputeV0).
    /// Used for parallel phase building. Default 0 disables parallel building.
    pub ledger_max_dependent_tx_clusters: u32,
    /// Minimum number of stages to try when building the parallel Soroban phase.
    pub soroban_phase_min_stage_count: u32,
    /// Maximum number of stages to try when building the parallel Soroban phase.
    pub soroban_phase_max_stage_count: u32,
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
            filtered_operation_types: HashSet::new(),
            ledger_max_instructions: 0,
            ledger_max_dependent_tx_clusters: 0,
            soroban_phase_min_stage_count: 1,
            soroban_phase_max_stage_count: 4,
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
    /// Current ledger base fee (stroops per op).
    pub base_fee: u32,
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
            base_fee: 100,
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
            TransactionEnvelope::TxV0(tx) => Ok((tx.tx.fee as u64, tx.tx.operations.len() as u32)),
            TransactionEnvelope::Tx(tx) => Ok((tx.tx.fee as u64, tx.tx.operations.len() as u32)),
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

/// A transaction wrapper for per-account tracking.
#[derive(Debug, Clone)]
pub struct TimestampedTx {
    /// The queued transaction.
    pub tx: QueuedTransaction,
}

/// Per-account state in the transaction queue.
///
/// Parity: An AccountID is tracked in mAccountStates if and only if:
/// - total_fees > 0 (account is fee-source for at least one tx), OR
/// - transaction.is_some() (account is seq-number-source for a queued tx)
///
/// The fee-source and sequence-number-source can be different accounts
/// (e.g., in fee-bump transactions where another account pays the fee).
#[derive(Debug, Clone, Default)]
pub struct AccountState {
    /// Sum of full fees for all transactions where this account is the fee-source.
    /// This tracks the total fees this account is liable for across all queued
    /// transactions, which may include transactions where the sequence-number-source
    /// is a different account.
    pub total_fees: i64,
    /// Number of ledgers that have closed since the last ledger in which a transaction
    /// from this sequence-number-source was included. Always 0 if transaction is None.
    /// Used for auto-ban: when age reaches pending_depth, the transaction is banned.
    pub age: u32,
    /// The single pending transaction for which this account is the sequence-number-source.
    /// stellar-core enforces one transaction per account (non-fee-bump) in the queue.
    pub transaction: Option<TimestampedTx>,
}

impl AccountState {
    /// Check if this account state can be removed (no transaction and no fees tracked).
    pub fn is_empty(&self) -> bool {
        self.transaction.is_none() && self.total_fees == 0
    }
}

/// Fee multiplier required for replace-by-fee with fee-bump transactions.
/// A fee-bump must have a fee at least FEE_MULTIPLIER times the existing fee rate.
const FEE_MULTIPLIER: u64 = 10;

/// Default pending depth (number of ledgers before auto-ban).
const DEFAULT_PENDING_DEPTH: u32 = 10;

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

fn better_fee_ratio(new_tx: &QueuedTransaction, old_tx: &QueuedTransaction) -> bool {
    match fee_rate_cmp(
        new_tx.total_fee,
        new_tx.op_count,
        old_tx.total_fee,
        old_tx.op_count,
    ) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => new_tx.hash.0 < old_tx.hash.0,
    }
}

fn compute_better_fee(evicted_fee: u64, evicted_ops: u32, tx_ops: u32) -> u64 {
    if evicted_ops == 0 {
        return 0;
    }
    let numerator = (evicted_fee as u128).saturating_mul(tx_ops as u128);
    let denominator = evicted_ops as u128;
    let base = numerator / denominator;
    let candidate = base.saturating_add(1);
    u64::try_from(candidate).unwrap_or(u64::MAX)
}

fn min_inclusion_fee_to_beat(evicted: (u64, u32), tx: &QueuedTransaction) -> u64 {
    if evicted.1 == 0 {
        return 0;
    }
    if fee_rate_cmp(evicted.0, evicted.1, tx.total_fee, tx.op_count) != Ordering::Less {
        compute_better_fee(evicted.0, evicted.1, tx.op_count)
    } else {
        0
    }
}

/// Check if a fee-bump transaction can replace an existing transaction.
/// For replace-by-fee to work, the new fee must be at least FEE_MULTIPLIER times the old fee rate.
/// Returns Ok(()) if replacement is allowed, or Err(min_fee) if the fee is insufficient.
fn can_replace_by_fee(
    new_fee: u64,
    new_ops: u32,
    old_fee: u64,
    old_ops: u32,
) -> std::result::Result<(), u64> {
    // newFee / newOps >= FEE_MULTIPLIER * oldFee / oldOps
    // Cross-multiply to avoid division:
    // newFee * oldOps >= FEE_MULTIPLIER * oldFee * newOps
    let left = (new_fee as u128).saturating_mul(old_ops as u128);
    let right = (FEE_MULTIPLIER as u128)
        .saturating_mul(old_fee as u128)
        .saturating_mul(new_ops as u128);

    if left < right {
        // Calculate minimum fee required:
        // minFee * oldOps >= FEE_MULTIPLIER * oldFee * newOps
        // minFee >= (FEE_MULTIPLIER * oldFee * newOps) / oldOps + 1 (round up)
        let min_fee = if old_ops > 0 {
            let numerator = right;
            let denominator = old_ops as u128;
            let quotient = numerator / denominator;
            let remainder = numerator % denominator;
            let rounded = if remainder > 0 {
                quotient + 1
            } else {
                quotient
            };
            u64::try_from(rounded).unwrap_or(u64::MAX)
        } else {
            0
        };
        Err(min_fee)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct SelectedTxs {
    transactions: Vec<TransactionEnvelope>,
    soroban_limited: bool,
    dex_limited: bool,
    classic_limited: bool,
}

fn sort_txs_by_hash(txs: &mut [TransactionEnvelope]) {
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
            stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                inner.tx.source_account.clone()
            }
        },
    };
    let account_id = henyey_tx::muxed_to_account_id(&source);
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
            stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                inner.tx.source_account.clone()
            }
        },
    };
    henyey_tx::muxed_to_account_id(&source)
}

/// Get the fee-source account key (for fee bump, this is the outer source; otherwise same as inner).
fn fee_source_key(envelope: &TransactionEnvelope) -> Vec<u8> {
    let fee_source = match envelope {
        TransactionEnvelope::TxV0(env) => {
            stellar_xdr::curr::MuxedAccount::Ed25519(env.tx.source_account_ed25519.clone())
        }
        TransactionEnvelope::Tx(env) => env.tx.source_account.clone(),
        TransactionEnvelope::TxFeeBump(env) => env.tx.fee_source.clone(),
    };
    let account_id = henyey_tx::muxed_to_account_id(&fee_source);
    account_id
        .to_xdr(stellar_xdr::curr::Limits::none())
        .unwrap_or_default()
}

/// Get sequence number from a TransactionEnvelope.
fn envelope_seq_num(envelope: &TransactionEnvelope) -> i64 {
    match envelope {
        TransactionEnvelope::TxV0(env) => env.tx.seq_num.0,
        TransactionEnvelope::Tx(env) => env.tx.seq_num.0,
        TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
            stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.seq_num.0,
        },
    }
}

/// Check if envelope is a fee-bump transaction.
fn is_fee_bump_envelope(envelope: &TransactionEnvelope) -> bool {
    matches!(envelope, TransactionEnvelope::TxFeeBump(_))
}

/// Convert an XDR-encoded account key back to AccountId.
fn account_id_from_fee_source_key(key: &[u8]) -> AccountId {
    use stellar_xdr::curr::ReadXdr;
    AccountId::from_xdr(key, Limits::none()).unwrap_or({
        // Fallback to a zero account ID if decoding fails
        AccountId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::curr::Uint256([0; 32]),
        ))
    })
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
    /// Compute the legacy TransactionSet contents hash (non-generalized).
    pub fn compute_non_generalized_hash(
        previous_ledger_hash: Hash256,
        transactions: &[TransactionEnvelope],
    ) -> Option<Hash256> {
        let mut hasher = Sha256Hasher::new();
        hasher.update(&previous_ledger_hash.0);
        for tx in transactions {
            let bytes = tx.to_xdr(Limits::none()).ok()?;
            hasher.update(&bytes);
        }
        Some(hasher.finalize())
    }

    /// Create a new transaction set with computed hash (for legacy TransactionSet).
    pub fn new(previous_ledger_hash: Hash256, transactions: Vec<TransactionEnvelope>) -> Self {
        let mut transactions = transactions;
        sort_txs_by_hash(&mut transactions);
        let hash = Self::compute_non_generalized_hash(previous_ledger_hash, &transactions)
            .unwrap_or_default();

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

    /// Recompute the transaction set hash from its contents.
    pub fn recompute_hash(&self) -> Option<Hash256> {
        if let Some(gen) = &self.generalized_tx_set {
            let bytes = gen.to_xdr(stellar_xdr::curr::Limits::none()).ok()?;
            return Some(Hash256::hash(&bytes));
        }
        Self::compute_non_generalized_hash(self.previous_ledger_hash, &self.transactions)
    }

    /// Summarize the transaction set for logging/debugging.
    pub fn summary(&self) -> String {
        if self.transactions.is_empty() {
            return "empty tx set".to_string();
        }

        if let Some(gen) = &self.generalized_tx_set {
            return summary_generalized_tx_set(gen);
        }

        let tx_count = self.transactions.len();
        let op_count: i64 = self.transactions.iter().map(tx_operation_count).sum();
        let base_fee = self
            .transactions
            .iter()
            .map(tx_inclusion_fee)
            .zip(self.transactions.iter().map(tx_operation_count))
            .filter(|(_, ops)| *ops > 0)
            .map(|(fee, ops)| fee / ops)
            .min()
            .unwrap_or(0);

        format!("txs:{}, ops:{}, base_fee:{}", tx_count, op_count, base_fee)
    }

    /// Convert to StoredTransactionSet XDR for persistence.
    ///
    /// Uses the generalized format (v1) if available, otherwise falls back to legacy (v0).
    pub fn to_xdr_stored_set(&self) -> stellar_xdr::curr::StoredTransactionSet {
        use stellar_xdr::curr::StoredTransactionSet;

        if let Some(ref gen) = self.generalized_tx_set {
            StoredTransactionSet::V1(gen.clone())
        } else {
            // Build legacy TransactionSet
            let legacy = stellar_xdr::curr::TransactionSet {
                previous_ledger_hash: stellar_xdr::curr::Hash(self.previous_ledger_hash.0),
                txs: self.transactions.clone().try_into().unwrap_or_default(),
            };
            StoredTransactionSet::V0(legacy)
        }
    }

    /// Create from StoredTransactionSet XDR.
    ///
    /// # Errors
    ///
    /// Returns an error description if the transaction set cannot be decoded.
    pub fn from_xdr_stored_set(
        stored: &stellar_xdr::curr::StoredTransactionSet,
    ) -> std::result::Result<Self, String> {
        use stellar_xdr::curr::StoredTransactionSet;

        match stored {
            StoredTransactionSet::V0(legacy) => {
                let previous_ledger_hash = Hash256::from_bytes(legacy.previous_ledger_hash.0);
                let transactions: Vec<TransactionEnvelope> = legacy.txs.to_vec();

                // Compute hash
                let hash = Self::compute_non_generalized_hash(previous_ledger_hash, &transactions)
                    .ok_or_else(|| "Failed to compute tx set hash".to_string())?;

                Ok(Self {
                    hash,
                    previous_ledger_hash,
                    transactions,
                    generalized_tx_set: None,
                })
            }
            StoredTransactionSet::V1(gen) => {
                let previous_ledger_hash = match gen {
                    GeneralizedTransactionSet::V1(v1) => {
                        Hash256::from_bytes(v1.previous_ledger_hash.0)
                    }
                };

                // Extract transactions from phases
                let transactions = extract_transactions_from_generalized(gen);

                // Compute hash from generalized format
                let hash = gen
                    .to_xdr(Limits::none())
                    .map(|bytes| Hash256::hash(&bytes))
                    .map_err(|e| format!("Failed to encode generalized tx set: {}", e))?;

                Ok(Self {
                    hash,
                    previous_ledger_hash,
                    transactions,
                    generalized_tx_set: Some(gen.clone()),
                })
            }
        }
    }
}

/// Extract all transactions from a GeneralizedTransactionSet.
fn extract_transactions_from_generalized(
    gen: &GeneralizedTransactionSet,
) -> Vec<TransactionEnvelope> {
    let GeneralizedTransactionSet::V1(v1) = gen;
    let mut transactions = Vec::new();

    for phase in v1.phases.iter() {
        match phase {
            stellar_xdr::curr::TransactionPhase::V0(components) => {
                for component in components.iter() {
                    match component {
                        stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) => {
                            transactions.extend(comp.txs.iter().cloned());
                        }
                    }
                }
            }
            stellar_xdr::curr::TransactionPhase::V1(parallel) => {
                // V1 phase has execution_stages, which contains parallel stages
                for stage in parallel.execution_stages.iter() {
                    for cluster in stage.iter() {
                        transactions.extend(cluster.iter().cloned());
                    }
                }
            }
        }
    }

    transactions
}

fn tx_operation_count(envelope: &TransactionEnvelope) -> i64 {
    match envelope {
        TransactionEnvelope::TxV0(env) => env.tx.operations.len() as i64,
        TransactionEnvelope::Tx(env) => env.tx.operations.len() as i64,
        TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
            stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                inner.tx.operations.len() as i64
            }
        },
    }
}

fn tx_inclusion_fee(envelope: &TransactionEnvelope) -> i64 {
    match envelope {
        TransactionEnvelope::TxV0(env) => env.tx.fee as i64,
        TransactionEnvelope::Tx(env) => env.tx.fee as i64,
        TransactionEnvelope::TxFeeBump(env) => env.tx.fee,
    }
}

fn summary_generalized_tx_set(gen: &GeneralizedTransactionSet) -> String {
    use std::collections::BTreeMap;

    let GeneralizedTransactionSet::V1(tx_set) = gen;
    if tx_set.phases.is_empty() {
        return "empty tx set".to_string();
    }

    let mut parts = Vec::new();
    for (phase_idx, phase) in tx_set.phases.iter().enumerate() {
        let mut component_stats: BTreeMap<Option<i64>, (i64, i64)> = BTreeMap::new();
        match phase {
            TransactionPhase::V0(components) => {
                for component in components.iter() {
                    let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) = component;
                    let base_fee = comp.base_fee;
                    for tx in comp.txs.iter() {
                        let entry = component_stats.entry(base_fee).or_insert((0, 0));
                        entry.0 += 1;
                        entry.1 += tx_operation_count(tx);
                    }
                }
            }
            TransactionPhase::V1(parallel) => {
                let base_fee = parallel.base_fee;
                for stage in parallel.execution_stages.iter() {
                    for cluster in stage.iter() {
                        for tx in cluster.0.iter() {
                            let entry = component_stats.entry(base_fee).or_insert((0, 0));
                            entry.0 += 1;
                            entry.1 += tx_operation_count(tx);
                        }
                    }
                }
            }
        }

        let mut component_parts = Vec::new();
        for (fee, stats) in component_stats.iter() {
            if let Some(base_fee) = fee {
                component_parts.push(format!(
                    "{{discounted txs:{}, ops:{}, base_fee:{}}}",
                    stats.0, stats.1, base_fee
                ));
            } else {
                component_parts.push(format!(
                    "{{non-discounted txs:{}, ops:{}}}",
                    stats.0, stats.1
                ));
            }
        }
        let phase_name = match phase_idx {
            0 => "classic",
            1 => "soroban",
            _ => "unknown",
        };
        parts.push(format!(
            "{} phase: {} component(s): [{}]",
            phase_name,
            component_stats.len(),
            component_parts.join(", ")
        ));
    }

    parts.join(", ")
}

/// Queue of pending transactions.
///
/// Maintains transactions waiting to be included in a ledger, ordered by fee.
///
/// # Per-Account Limits
///
/// Parity: The queue enforces one transaction per account (sequence-number-source).
/// This prevents spam and ensures predictable transaction ordering. Accounts can
/// replace their pending transaction with a fee-bump (10x fee multiplier required).
///
/// # Transaction Aging
///
/// Transactions that sit in the queue for too long (pending_depth ledgers) are
/// automatically banned. This prevents stale transactions from occupying queue space.
pub struct TransactionQueue {
    /// Configuration.
    config: TxQueueConfig,
    /// Transactions indexed by hash.
    by_hash: RwLock<HashMap<Hash256, QueuedTransaction>>,
    /// Seen transaction hashes (includes recently applied).
    seen: RwLock<HashSet<Hash256>>,
    /// Validation context (ledger state info for validation).
    validation_context: RwLock<ValidationContext>,
    /// Lane eviction thresholds for classic queue admission.
    classic_lane_evicted_inclusion_fee: RwLock<Vec<(u64, u32)>>,
    /// Lane eviction thresholds for Soroban queue admission.
    soroban_lane_evicted_inclusion_fee: RwLock<Vec<(u64, u32)>>,
    /// Eviction threshold for global queue limits.
    global_evicted_inclusion_fee: RwLock<(u64, u32)>,
    /// Banned transaction hashes, organized as a deque of sets.
    /// Each set represents one ledger's worth of banned transactions.
    /// The front is the oldest, the back is the newest.
    banned_transactions: RwLock<std::collections::VecDeque<HashSet<Hash256>>>,
    /// Depth of the ban deque (number of ledgers transactions stay banned).
    _ban_depth: u32,
    /// Per-account state tracking for one-tx-per-account limit.
    /// Key is the XDR-encoded AccountId bytes.
    account_states: RwLock<HashMap<Vec<u8>, AccountState>>,
    /// Number of ledgers before auto-banning stale transactions.
    pending_depth: u32,
    /// Optional fee balance provider for validating fee-source balances.
    /// When set, transactions are validated to ensure the fee-source has
    /// sufficient balance to cover all pending fees plus the new transaction fee.
    fee_balance_provider: RwLock<Option<Arc<dyn FeeBalanceProvider>>>,
}

/// Default ban depth (number of ledgers transactions stay banned).
const DEFAULT_BAN_DEPTH: u32 = 10;

impl TransactionQueue {
    /// Create a new transaction queue.
    pub fn new(config: TxQueueConfig) -> Self {
        Self::with_depths(config, DEFAULT_BAN_DEPTH, DEFAULT_PENDING_DEPTH)
    }

    /// Create a new transaction queue with custom ban depth.
    pub fn with_ban_depth(config: TxQueueConfig, ban_depth: u32) -> Self {
        Self::with_depths(config, ban_depth, DEFAULT_PENDING_DEPTH)
    }

    /// Create a new transaction queue with custom ban and pending depths.
    ///
    /// # Arguments
    ///
    /// * `config` - Queue configuration
    /// * `ban_depth` - Number of ledgers transactions stay banned
    /// * `pending_depth` - Number of ledgers before stale transactions are auto-banned
    pub fn with_depths(config: TxQueueConfig, ban_depth: u32, pending_depth: u32) -> Self {
        let ctx = ValidationContext {
            base_fee: config.min_fee_per_op,
            ..Default::default()
        };

        // Initialize the banned transactions deque with ban_depth empty sets
        let mut banned = std::collections::VecDeque::with_capacity(ban_depth as usize);
        for _ in 0..ban_depth {
            banned.push_back(HashSet::new());
        }

        Self {
            config,
            by_hash: RwLock::new(HashMap::new()),
            seen: RwLock::new(HashSet::new()),
            validation_context: RwLock::new(ctx),
            classic_lane_evicted_inclusion_fee: RwLock::new(Vec::new()),
            soroban_lane_evicted_inclusion_fee: RwLock::new(Vec::new()),
            global_evicted_inclusion_fee: RwLock::new((0, 0)),
            banned_transactions: RwLock::new(banned),
            _ban_depth: ban_depth,
            account_states: RwLock::new(HashMap::new()),
            pending_depth,
            fee_balance_provider: RwLock::new(None),
        }
    }

    /// Set the fee balance provider for validating fee-source balances.
    ///
    /// When set, transactions are validated to ensure the fee-source account
    /// has sufficient balance to cover all pending fees plus the new transaction fee.
    pub fn set_fee_balance_provider(&self, provider: Arc<dyn FeeBalanceProvider>) {
        *self.fee_balance_provider.write() = Some(provider);
    }

    /// Clear the fee balance provider.
    pub fn clear_fee_balance_provider(&self) {
        *self.fee_balance_provider.write() = None;
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
    pub fn update_validation_context(
        &self,
        ledger_seq: u32,
        close_time: u64,
        protocol_version: u32,
        base_fee: u32,
    ) {
        let mut ctx = self.validation_context.write();
        ctx.ledger_seq = ledger_seq;
        ctx.close_time = close_time;
        ctx.protocol_version = protocol_version;
        ctx.base_fee = base_fee;
    }

    /// Validate a transaction before queueing.
    fn validate_transaction(
        &self,
        envelope: &TransactionEnvelope,
    ) -> std::result::Result<(), &'static str> {
        use henyey_tx::{
            validate_ledger_bounds, validate_signatures, validate_time_bounds, LedgerContext,
            TransactionFrame,
        };

        let frame = TransactionFrame::with_network(envelope.clone(), self.config.network_id);
        let ctx = self.validation_context.read();
        let base_fee = ctx.base_fee.max(self.config.min_fee_per_op);

        // Validate basic structure
        if !frame.is_valid_structure() {
            return Err("invalid transaction structure");
        }

        // Validate time bounds if enabled
        if self.config.validate_time_bounds {
            let ledger_ctx = LedgerContext::new(
                ctx.ledger_seq,
                ctx.close_time,
                base_fee,
                5_000_000, // base reserve
                ctx.protocol_version,
                self.config.network_id,
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
                base_fee,
                5_000_000, // base reserve
                ctx.protocol_version,
                self.config.network_id,
            );

            if validate_signatures(&frame, &ledger_ctx).is_err() {
                return Err("signature validation failed");
            }
        }

        // Validate preconditions (extra signers / min seq age+gap)
        if let Preconditions::V2(cond) = frame.preconditions() {
            if !cond.extra_signers.is_empty()
                && !extra_signers_satisfied(envelope, &self.config.network_id, &cond.extra_signers)?
            {
                return Err("extra signer validation failed");
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_evictions_for_lane_config<F>(
        &self,
        by_hash: &HashMap<Hash256, QueuedTransaction>,
        queued: &QueuedTransaction,
        lane_config: Box<dyn crate::surge_pricing::SurgePricingLaneConfig>,
        ledger_version: u32,
        exclude: &HashSet<Hash256>,
        filter: F,
        seed: u64,
    ) -> Option<Vec<(QueuedTransaction, bool)>>
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
            .map(|evictions| evictions.into_iter().collect())
    }

    /// Try to add a transaction to the queue.
    pub fn try_add(&self, envelope: TransactionEnvelope) -> TxQueueResult {
        // Validate transaction before queueing
        if self.validate_transaction(&envelope).is_err() {
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

        // Check if banned
        if self.is_banned(&queued.hash) {
            return TxQueueResult::Banned;
        }

        // Check if filtered by operation type
        if self.is_filtered(&queued.envelope) {
            return TxQueueResult::Filtered;
        }

        // Check fee
        let min_fee_per_op = {
            let ctx = self.validation_context.read();
            ctx.base_fee.max(self.config.min_fee_per_op) as u64
        };
        if queued.fee_per_op < min_fee_per_op {
            return TxQueueResult::FeeTooLow;
        }

        let mut by_hash = self.by_hash.write();
        let ledger_version = self.validation_context.read().protocol_version;
        let queued_frame = henyey_tx::TransactionFrame::with_network(
            queued.envelope.clone(),
            self.config.network_id,
        );
        let queued_is_soroban = queued_frame.is_soroban();
        // Check for duplicate in queue
        if by_hash.contains_key(&queued.hash) {
            return TxQueueResult::Duplicate;
        }

        // Per-account limit check: one transaction per account (sequence-number-source)
        let seq_source_key = account_key(&queued.envelope);
        let new_seq = envelope_seq_num(&queued.envelope);
        let is_fee_bump = is_fee_bump_envelope(&queued.envelope);
        let new_fee_source_key = fee_source_key(&queued.envelope);

        // Track the transaction being replaced (for fee-bump replace-by-fee)
        let mut replaced_tx: Option<QueuedTransaction> = None;

        {
            let account_states = self.account_states.read();
            if let Some(state) = account_states.get(&seq_source_key) {
                if let Some(ref timestamped) = state.transaction {
                    let current_tx = &timestamped.tx;

                    // Check if it's a duplicate (same hash)
                    if current_tx.hash == queued.hash {
                        return TxQueueResult::Duplicate;
                    }

                    // Any transaction older than the current one is invalid
                    let current_seq = envelope_seq_num(&current_tx.envelope);
                    if new_seq < current_seq {
                        return TxQueueResult::Invalid;
                    }

                    // If not a fee-bump, reject (only one tx per account allowed)
                    if !is_fee_bump {
                        return TxQueueResult::TryAgainLater;
                    }

                    // Fee-bump must have the same sequence number to replace
                    if new_seq != current_seq {
                        return TxQueueResult::TryAgainLater;
                    }

                    // Check if fee-bump meets the 10x fee multiplier requirement
                    if let Err(_min_fee) = can_replace_by_fee(
                        queued.total_fee,
                        queued.op_count,
                        current_tx.total_fee,
                        current_tx.op_count,
                    ) {
                        // Fee is insufficient for replace-by-fee
                        return TxQueueResult::FeeTooLow;
                    }

                    // Fee-bump replacement is valid - mark the current tx for replacement
                    replaced_tx = Some(current_tx.clone());
                }
            }
        }

        let mut pending_evictions: HashSet<Hash256> = HashSet::new();
        let mut pending_eviction_list: Vec<QueuedTransaction> = Vec::new();
        let seed = if cfg!(test) {
            0
        } else {
            rand::thread_rng().gen()
        };

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
                    // stellar-core uses MAX_CLASSIC_BYTE_ALLOWANCE for the DEX lane byte limit.
                    Resource::new(vec![dex_ops as i64, MAX_CLASSIC_BYTE_ALLOWANCE as i64])
                } else {
                    Resource::new(vec![dex_ops as i64])
                }
            });
            let lane_config = DexLimitingLaneConfig::new(generic_limit.clone(), dex_limit.clone());
            let lane = lane_config.get_lane(&queued_frame);
            {
                let mut lane_fees = self.classic_lane_evicted_inclusion_fee.write();
                if lane_fees.len() != lane_config.lane_limits().len() {
                    lane_fees.resize(lane_config.lane_limits().len(), (0, 0));
                }
                let global_fee = *self.global_evicted_inclusion_fee.read();
                let mut min_fee = min_inclusion_fee_to_beat(lane_fees[lane], &queued);
                min_fee = min_fee.max(min_inclusion_fee_to_beat(lane_fees[GENERIC_LANE], &queued));
                if self.config.max_queue_ops.is_some() {
                    min_fee = min_fee.max(min_inclusion_fee_to_beat(global_fee, &queued));
                }
                if min_fee > 0 {
                    return TxQueueResult::FeeTooLow;
                }
            }
        }

        if queued_is_soroban {
            if let Some(limit) = &self.config.max_queue_soroban_resources {
                let lane_config = SorobanGenericLaneConfig::new(limit.clone());
                let lane = lane_config.get_lane(&queued_frame);
                {
                    let mut lane_fees = self.soroban_lane_evicted_inclusion_fee.write();
                    if lane_fees.len() != lane_config.lane_limits().len() {
                        lane_fees.resize(lane_config.lane_limits().len(), (0, 0));
                    }
                    let global_fee = *self.global_evicted_inclusion_fee.read();
                    let mut min_fee = min_inclusion_fee_to_beat(lane_fees[lane], &queued);
                    min_fee =
                        min_fee.max(min_inclusion_fee_to_beat(lane_fees[GENERIC_LANE], &queued));
                    if self.config.max_queue_ops.is_some() {
                        min_fee = min_fee.max(min_inclusion_fee_to_beat(global_fee, &queued));
                    }
                    if min_fee > 0 {
                        return TxQueueResult::FeeTooLow;
                    }
                }
            }
        }

        if self.config.max_queue_ops.is_some() {
            let global_fee = *self.global_evicted_inclusion_fee.read();
            if min_inclusion_fee_to_beat(global_fee, &queued) > 0 {
                return TxQueueResult::FeeTooLow;
            }
        }

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
                    // stellar-core uses MAX_CLASSIC_BYTE_ALLOWANCE for the DEX lane byte limit.
                    Resource::new(vec![dex_ops as i64, MAX_CLASSIC_BYTE_ALLOWANCE as i64])
                } else {
                    Resource::new(vec![dex_ops as i64])
                }
            });
            let lane_config = DexLimitingLaneConfig::new(generic_limit.clone(), dex_limit.clone());
            let filter = |tx: &QueuedTransaction| {
                let frame = henyey_tx::TransactionFrame::with_network(
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
            let lane_config = DexLimitingLaneConfig::new(generic_limit, dex_limit);
            for (evicted, evicted_due_to_lane_limit) in evictions {
                if !pending_evictions.insert(evicted.hash) {
                    continue;
                }
                pending_eviction_list.push(evicted.clone());
                let frame = henyey_tx::TransactionFrame::with_network(
                    evicted.envelope.clone(),
                    self.config.network_id,
                );
                let lane = lane_config.get_lane(&frame);
                let mut lane_fees = self.classic_lane_evicted_inclusion_fee.write();
                if lane_fees.len() != lane_config.lane_limits().len() {
                    lane_fees.resize(lane_config.lane_limits().len(), (0, 0));
                }
                if evicted_due_to_lane_limit {
                    lane_fees[lane] = (evicted.total_fee, evicted.op_count);
                } else {
                    lane_fees[GENERIC_LANE] = (evicted.total_fee, evicted.op_count);
                }
            }
        }

        if queued_is_soroban {
            if let Some(limit) = &self.config.max_queue_soroban_resources {
                let lane_config = SorobanGenericLaneConfig::new(limit.clone());
                let filter = |tx: &QueuedTransaction| {
                    let frame = henyey_tx::TransactionFrame::with_network(
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
                let lane_config = SorobanGenericLaneConfig::new(limit.clone());
                for (evicted, evicted_due_to_lane_limit) in evictions {
                    if !pending_evictions.insert(evicted.hash) {
                        continue;
                    }
                    pending_eviction_list.push(evicted.clone());
                    let frame = henyey_tx::TransactionFrame::with_network(
                        evicted.envelope.clone(),
                        self.config.network_id,
                    );
                    let lane = lane_config.get_lane(&frame);
                    let mut lane_fees = self.soroban_lane_evicted_inclusion_fee.write();
                    if lane_fees.len() != lane_config.lane_limits().len() {
                        lane_fees.resize(lane_config.lane_limits().len(), (0, 0));
                    }
                    if evicted_due_to_lane_limit {
                        lane_fees[lane] = (evicted.total_fee, evicted.op_count);
                    } else {
                        lane_fees[GENERIC_LANE] = (evicted.total_fee, evicted.op_count);
                    }
                }
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
            for (evicted, _evicted_due_to_lane_limit) in evictions {
                if !pending_evictions.insert(evicted.hash) {
                    continue;
                }
                pending_eviction_list.push(evicted.clone());
                let mut global_fee = self.global_evicted_inclusion_fee.write();
                *global_fee = (evicted.total_fee, evicted.op_count);
            }
        }

        for evicted in pending_eviction_list {
            by_hash.remove(&evicted.hash);
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

        // Fee balance validation (if provider is set)
        // Check that fee-source has sufficient balance for total fees + new fee
        if let Some(ref provider) = *self.fee_balance_provider.read() {
            let fee_source_id = account_id_from_fee_source_key(&new_fee_source_key);

            // Calculate the net new fee being added
            let net_new_fee = if let Some(ref old_tx) = replaced_tx {
                let old_fee_source_key = fee_source_key(&old_tx.envelope);
                if old_fee_source_key == new_fee_source_key {
                    // Same fee source - only the difference is new
                    (queued.total_fee as i64).saturating_sub(old_tx.total_fee as i64)
                } else {
                    // Different fee source - full new fee
                    queued.total_fee as i64
                }
            } else {
                queued.total_fee as i64
            };

            // Get current total fees for this fee-source
            let current_total_fees = {
                let account_states = self.account_states.read();
                account_states
                    .get(&new_fee_source_key)
                    .map(|s| s.total_fees)
                    .unwrap_or(0)
            };

            // Check if fee-source has sufficient balance
            if let Some(available) = provider.get_available_balance(&fee_source_id) {
                // available - net_new_fee < current_total_fees means insufficient
                if available.saturating_sub(net_new_fee) < current_total_fees {
                    return TxQueueResult::Invalid; // txINSUFFICIENT_BALANCE
                }
            } else {
                // Account doesn't exist
                return TxQueueResult::Invalid;
            }
        }

        // Handle fee-bump replacement if applicable
        if let Some(ref old_tx) = replaced_tx {
            // Remove the old transaction from by_hash
            by_hash.remove(&old_tx.hash);

            // If the old tx has a different fee-source, release the fee from that account
            let old_fee_source_key = fee_source_key(&old_tx.envelope);
            if old_fee_source_key != new_fee_source_key {
                let mut account_states = self.account_states.write();
                if let Some(old_fee_state) = account_states.get_mut(&old_fee_source_key) {
                    old_fee_state.total_fees = old_fee_state
                        .total_fees
                        .saturating_sub(old_tx.total_fee as i64);
                    // Remove the account state if it's empty
                    if old_fee_state.is_empty() {
                        account_states.remove(&old_fee_source_key);
                    }
                }
            }
        }

        // Add to queue
        let hash = queued.hash;
        let new_fee = queued.total_fee;

        // Update account_states
        {
            let mut account_states = self.account_states.write();

            // Update the sequence-source account state (stores the pending transaction)
            let seq_state = account_states.entry(seq_source_key.clone()).or_default();

            // If replacing, and same fee source as old tx, adjust the fee delta
            let fee_to_add = if let Some(ref old_tx) = replaced_tx {
                let old_fee_source_key = fee_source_key(&old_tx.envelope);
                if old_fee_source_key == new_fee_source_key {
                    // Same fee source - only add the difference
                    (new_fee as i64).saturating_sub(old_tx.total_fee as i64)
                } else {
                    // Different fee source - add full new fee
                    new_fee as i64
                }
            } else {
                // New transaction - add full fee
                new_fee as i64
            };

            seq_state.transaction = Some(TimestampedTx { tx: queued.clone() });

            // Update the fee-source account state (tracks total_fees)
            // Note: seq_source and fee_source may be the same account
            if seq_source_key == new_fee_source_key {
                // Same account - already have the entry
                seq_state.total_fees = seq_state.total_fees.saturating_add(fee_to_add);
            } else {
                // Different accounts - update fee-source separately
                let fee_state = account_states.entry(new_fee_source_key).or_default();
                fee_state.total_fees = fee_state.total_fees.saturating_add(fee_to_add);
            }
        }

        by_hash.insert(hash, queued);
        self.seen.write().insert(hash);

        TxQueueResult::Added
    }

    /// Get a transaction set for the next ledger.
    ///
    /// Returns the highest-fee transactions up to the specified limit.
    pub fn get_transaction_set(
        &self,
        previous_ledger_hash: Hash256,
        max_ops: usize,
    ) -> TransactionSet {
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
    pub fn build_generalized_tx_set(
        &self,
        previous_ledger_hash: Hash256,
        max_ops: usize,
    ) -> (TransactionSet, stellar_xdr::curr::GeneralizedTransactionSet) {
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
        let base_fee = self.validation_context.read().base_fee as i64;
        let mut classic_txs = Vec::new();
        let mut soroban_txs = Vec::new();
        for tx in &transactions {
            let frame =
                henyey_tx::TransactionFrame::with_network(tx.clone(), self.config.network_id);
            if frame.is_soroban() {
                soroban_txs.push(tx.clone());
            } else {
                classic_txs.push(tx.clone());
            }
        }

        sort_txs_by_hash(&mut soroban_txs);

        let mut classic_components: Vec<TxSetComponent> = Vec::new();
        if !classic_txs.is_empty() {
            let has_dex_lane = self.config.max_dex_ops.is_some();
            let lane_count = if has_dex_lane { 2 } else { 1 };
            let mut lowest_lane_fee = vec![i64::MAX; lane_count];
            let mut lane_for_tx = Vec::with_capacity(classic_txs.len());

            for tx in &classic_txs {
                let frame = henyey_tx::TransactionFrame::with_network(
                    tx.clone(),
                    self.config.network_id,
                );
                let lane = if has_dex_lane && frame.has_dex_operations() {
                    crate::surge_pricing::DEX_LANE
                } else {
                    GENERIC_LANE
                };
                if let Some((per_op, _, _)) = envelope_fee_per_op(tx) {
                    let lane_fee = &mut lowest_lane_fee[lane];
                    let fee = per_op as i64;
                    if fee < *lane_fee {
                        *lane_fee = fee;
                    }
                }
                lane_for_tx.push(lane);
            }

            let min_lane_fee = lowest_lane_fee
                .iter()
                .copied()
                .filter(|fee| *fee != i64::MAX)
                .min()
                .unwrap_or(base_fee);
            let mut lane_base_fee = vec![base_fee; lane_count];
            if classic_limited {
                lane_base_fee.fill(min_lane_fee);
            }
            if has_dex_lane && dex_limited {
                let dex_fee = lowest_lane_fee[crate::surge_pricing::DEX_LANE];
                if dex_fee != i64::MAX {
                    lane_base_fee[crate::surge_pricing::DEX_LANE] = dex_fee;
                }
            }

            let mut components_by_fee: BTreeMap<i64, Vec<TransactionEnvelope>> = BTreeMap::new();
            for (tx, lane) in classic_txs.into_iter().zip(lane_for_tx.into_iter()) {
                let fee = lane_base_fee[lane];
                components_by_fee.entry(fee).or_default().push(tx);
            }

            for (fee, mut txs) in components_by_fee {
                sort_txs_by_hash(&mut txs);
                classic_components.push(TxSetComponent::TxsetCompTxsMaybeDiscountedFee(
                    TxSetComponentTxsMaybeDiscountedFee {
                        base_fee: Some(fee),
                        txs: txs.try_into().unwrap_or_default(),
                    },
                ));
            }
        }
        let classic_phase = TransactionPhase::V0(classic_components.try_into().unwrap_or_default());

        let soroban_base_fee = if soroban_limited {
            soroban_txs
                .iter()
                .filter_map(|tx| envelope_fee_per_op(tx).map(|(per_op, _, _)| per_op as i64))
                .min()
                .or(Some(base_fee))
        } else if soroban_txs.is_empty() {
            None
        } else {
            Some(base_fee)
        };

        let use_parallel_builder = !soroban_txs.is_empty()
            && self.config.ledger_max_instructions > 0
            && self.config.ledger_max_dependent_tx_clusters > 0
            && self.config.soroban_phase_max_stage_count > 0;

        let soroban_phase = if soroban_txs.is_empty() {
            TransactionPhase::V1(ParallelTxsComponent {
                base_fee: soroban_base_fee,
                execution_stages: VecM::default(),
            })
        } else if use_parallel_builder {
            let stages = crate::parallel_tx_set_builder::build_parallel_soroban_phase(
                &soroban_txs,
                self.config.network_id,
                self.config.ledger_max_instructions,
                self.config.ledger_max_dependent_tx_clusters,
                self.config.soroban_phase_min_stage_count,
                self.config.soroban_phase_max_stage_count,
            );
            crate::parallel_tx_set_builder::stages_to_xdr_phase(stages, soroban_base_fee)
        } else {
            let cluster = DependentTxCluster(soroban_txs.try_into().unwrap_or_default());
            let stage = ParallelTxExecutionStage(vec![cluster].try_into().unwrap_or_default());
            TransactionPhase::V1(ParallelTxsComponent {
                base_fee: soroban_base_fee,
                execution_stages: vec![stage].try_into().unwrap_or_default(),
            })
        };

        let gen_tx_set = GeneralizedTransactionSet::V1(stellar_xdr::curr::TransactionSetV1 {
            previous_ledger_hash: stellar_xdr::curr::Hash(previous_ledger_hash.0),
            phases: vec![classic_phase, soroban_phase]
                .try_into()
                .unwrap_or_default(),
        });

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

    #[cfg(test)]
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
                    .then_with(|| fee_rate_cmp(b.total_fee, b.op_count, a.total_fee, a.op_count))
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
        let use_classic_bytes =
            self.config.max_classic_bytes.is_some() || self.config.max_dex_bytes.is_some();
        let ledger_version = self.validation_context.read().protocol_version;

        let mut classic_accounts: HashMap<Vec<u8>, Vec<QueuedTransaction>> = HashMap::new();
        let mut soroban_accounts: HashMap<Vec<u8>, Vec<QueuedTransaction>> = HashMap::new();
        let mut accounts: Vec<_> = layered.keys().cloned().collect();
        accounts.sort();
        for account in accounts {
            if let Some(txs) = layered.get(&account) {
                let mut seen_soroban = false;
                for tx in txs {
                    let frame = henyey_tx::TransactionFrame::with_network(
                        tx.envelope.clone(),
                        self.config.network_id,
                    );
                    let is_soroban = frame.is_soroban();
                    if !seen_soroban {
                        if is_soroban {
                            seen_soroban = true;
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
                    } else {
                        if !is_soroban {
                            break;
                        }
                        soroban_accounts
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
                // stellar-core uses MAX_CLASSIC_BYTE_ALLOWANCE for the DEX lane byte limit.
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
            let frame = henyey_tx::TransactionFrame::with_network(
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
                classic_queue.remove_entry(lane, &entry, ledger_version, &self.config.network_id);
                continue;
            }

            classic_selected.push(entry.tx.clone());
            classic_lane_left[GENERIC_LANE] -= resources.clone();
            if lane != GENERIC_LANE {
                classic_lane_left[lane] -= resources;
            }

            classic_queue.remove_entry(lane, &entry, ledger_version, &self.config.network_id);
            let account = account_key(&entry.tx.envelope);
            if let Some(txs) = classic_accounts.get(&account) {
                let next_index = classic_positions
                    .get(&account)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(1);
                if next_index < txs.len() {
                    classic_positions.insert(account.clone(), next_index);
                    classic_queue.add(
                        txs[next_index].clone(),
                        &self.config.network_id,
                        ledger_version,
                    );
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
            let mut had_not_fitting = [false];
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
            let mut lane_left = [queue.lane_limits(GENERIC_LANE)];
            while let Some((lane, entry)) = queue.peek_top() {
                let frame = henyey_tx::TransactionFrame::with_network(
                    entry.tx.envelope.clone(),
                    self.config.network_id,
                );
                let resources = queue.tx_resources(&frame, ledger_version);
                let exceeds = any_greater(&resources, &lane_left[GENERIC_LANE]);
                if exceeds {
                    had_not_fitting[GENERIC_LANE] = true;
                    queue.remove_entry(lane, &entry, ledger_version, &self.config.network_id);
                    continue;
                }
                selected.push(entry.tx.clone());
                lane_left[GENERIC_LANE] -= resources;
                queue.remove_entry(lane, &entry, ledger_version, &self.config.network_id);
                let account = account_key(&entry.tx.envelope);
                if let Some(txs) = soroban_accounts.get(&account) {
                    let next_index = positions
                        .get(&account)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(1);
                    if next_index < txs.len() {
                        positions.insert(account.clone(), next_index);
                        queue.add(
                            txs[next_index].clone(),
                            &self.config.network_id,
                            ledger_version,
                        );
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

    /// Remove transactions that were applied in a ledger (simple version).
    ///
    /// This is a simplified version that only removes by hash.
    /// For full per-account tracking, use `remove_applied_with_seq()`.
    pub fn remove_applied_by_hash(&self, tx_hashes: &[Hash256]) {
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

        // Mirror stellar-core: clear eviction thresholds after aging to avoid
        // carrying stale min-fee requirements.
        self.classic_lane_evicted_inclusion_fee.write().clear();
        self.soroban_lane_evicted_inclusion_fee.write().clear();
        *self.global_evicted_inclusion_fee.write() = (0, 0);
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

    /// Ban a list of transactions by hash.
    ///
    /// Banned transactions cannot be added to the queue again for `ban_depth`
    /// ledgers. This should be called when transactions become invalid or
    /// are evicted due to age.
    ///
    /// # Arguments
    ///
    /// * `tx_hashes` - Hashes of transactions to ban
    pub fn ban(&self, tx_hashes: &[Hash256]) {
        if tx_hashes.is_empty() {
            return;
        }

        let mut banned = self.banned_transactions.write();
        // Add to the newest (back) set
        if let Some(newest) = banned.back_mut() {
            for hash in tx_hashes {
                newest.insert(*hash);
            }
        }

        // Also remove from the queue if present
        let mut by_hash = self.by_hash.write();
        for hash in tx_hashes {
            by_hash.remove(hash);
        }
    }

    /// Check if a transaction is banned.
    ///
    /// # Arguments
    ///
    /// * `hash` - Hash of the transaction to check
    ///
    /// # Returns
    ///
    /// `true` if the transaction is currently banned.
    pub fn is_banned(&self, hash: &Hash256) -> bool {
        let banned = self.banned_transactions.read();
        banned.iter().any(|set| set.contains(hash))
    }

    /// Check if a transaction contains any filtered operation types.
    ///
    /// Returns `true` if the transaction contains at least one operation
    /// whose type is in the `filtered_operation_types` set.
    ///
    /// # Arguments
    ///
    /// * `envelope` - The transaction envelope to check
    ///
    /// # Returns
    ///
    /// `true` if the transaction should be filtered out.
    pub fn is_filtered(&self, envelope: &TransactionEnvelope) -> bool {
        // Skip check if no types are filtered
        if self.config.filtered_operation_types.is_empty() {
            return false;
        }

        let ops = match envelope {
            TransactionEnvelope::TxV0(env) => &env.tx.operations,
            TransactionEnvelope::Tx(env) => &env.tx.operations,
            TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => &inner.tx.operations,
            },
        };

        ops.iter().any(|op| {
            let op_type = op.body.discriminant();
            self.config.filtered_operation_types.contains(&op_type)
        })
    }

    /// Remove applied transactions from the queue and reset their source account ages.
    ///
    /// This should be called after transactions are applied in a ledger, before `shift()`.
    ///
    /// For each applied transaction:
    /// 1. Find the account state by sequence-number-source
    /// 2. If a queued tx exists with seq_num <= applied seq_num, drop it
    /// 3. Reset the account's age to 0
    /// 4. Release the fee from the fee-source account's total_fees
    /// 5. Ban the applied transaction hash (prevents re-submission)
    ///
    /// # Arguments
    ///
    /// * `applied_txs` - List of (envelope, sequence_number) pairs for applied transactions
    pub fn remove_applied(&self, applied_txs: &[(TransactionEnvelope, i64)]) {
        if applied_txs.is_empty() {
            return;
        }

        let mut account_states = self.account_states.write();
        let mut by_hash = self.by_hash.write();
        let mut banned = self.banned_transactions.write();

        // Collect fee releases to apply after processing all transactions
        let mut fee_releases: Vec<(Vec<u8>, i64)> = Vec::new();
        let mut accounts_to_cleanup: Vec<Vec<u8>> = Vec::new();

        for (envelope, applied_seq) in applied_txs {
            let frame = henyey_tx::TransactionFrame::with_network(
                envelope.clone(),
                self.config.network_id,
            );

            // Get sequence-number-source (inner source for fee-bump)
            let seq_source_id = henyey_tx::muxed_to_account_id(&frame.inner_source_account());
            let seq_source_key = account_key_from_account_id(&seq_source_id);

            // Get fee-source
            let fee_source_id = henyey_tx::muxed_to_account_id(&frame.fee_source_account());
            let fee_source_key = account_key_from_account_id(&fee_source_id);

            // Process sequence-source account
            if let Some(state) = account_states.get_mut(&seq_source_key) {
                if let Some(ref timestamped) = state.transaction {
                    // Drop if queued tx has seq <= applied seq
                    if timestamped.tx.sequence_number() <= *applied_seq {
                        // Remove from by_hash
                        by_hash.remove(&timestamped.tx.hash);

                        // Collect fee release info
                        let tx_fee = timestamped.tx.total_fee as i64;
                        let tx_fee_source_id = henyey_tx::muxed_to_account_id(
                            &henyey_tx::TransactionFrame::with_network(
                                timestamped.tx.envelope.clone(),
                                self.config.network_id,
                            )
                            .fee_source_account(),
                        );
                        let tx_fee_source_key = account_key_from_account_id(&tx_fee_source_id);
                        fee_releases.push((tx_fee_source_key, tx_fee));

                        state.transaction = None;
                        state.age = 0;
                    }
                }
            }

            // Ban the applied tx hash
            let applied_hash = Hash256::hash_xdr(envelope).unwrap_or_default();
            if let Some(newest) = banned.back_mut() {
                newest.insert(applied_hash);
            }

            // Track accounts for cleanup
            accounts_to_cleanup.push(seq_source_key);
            if fee_source_key != accounts_to_cleanup.last().cloned().unwrap_or_default() {
                accounts_to_cleanup.push(fee_source_key);
            }
        }

        // Apply fee releases
        for (fee_source_key, tx_fee) in fee_releases {
            if let Some(fee_state) = account_states.get_mut(&fee_source_key) {
                fee_state.total_fees = fee_state.total_fees.saturating_sub(tx_fee);
            }
        }

        // Clean up empty account states
        for account_key in accounts_to_cleanup {
            if let Some(state) = account_states.get(&account_key) {
                if state.is_empty() {
                    account_states.remove(&account_key);
                }
            }
        }
    }

    /// Shift the queue after a ledger close.
    ///
    /// This should be called after `remove_applied()`. It:
    /// 1. Rotates the ban deque (unbans old transactions, makes room for new bans)
    /// 2. Increments age for all accounts with pending transactions
    /// 3. Auto-bans transactions that reach pending_depth age
    /// 4. Resets eviction thresholds for the new ledger
    ///
    /// # Returns
    ///
    /// A `ShiftResult` with details about unbanned and auto-banned transactions.
    pub fn shift(&self) -> ShiftResult {
        let mut banned = self.banned_transactions.write();
        let mut account_states = self.account_states.write();
        let mut by_hash = self.by_hash.write();

        // Remove the oldest set (front) to unban those transactions
        let unbanned_count = banned.pop_front().map(|s| s.len()).unwrap_or(0);

        // Add a new empty set at the back for the next ledger
        banned.push_back(HashSet::new());

        let mut evicted_due_to_age = 0;
        let mut accounts_to_remove = Vec::new();
        // Collect fee releases to apply after iteration (to avoid borrow conflicts)
        let mut fee_releases: Vec<(Vec<u8>, u64)> = Vec::new();

        // Process account states: increment age, auto-ban stale transactions
        for (account_key, state) in account_states.iter_mut() {
            // Only increment age if there's a pending transaction
            if state.transaction.is_some() {
                state.age += 1;

                // Auto-ban at pending_depth
                if state.age >= self.pending_depth {
                    if let Some(ref timestamped) = state.transaction {
                        // Add to banned set
                        if let Some(newest) = banned.back_mut() {
                            newest.insert(timestamped.tx.hash);
                        }
                        // Remove from by_hash
                        by_hash.remove(&timestamped.tx.hash);

                        // Track fee release for the fee-source account
                        let tx_fee_source_key = fee_source_key(&timestamped.tx.envelope);
                        fee_releases.push((tx_fee_source_key, timestamped.tx.total_fee));

                        evicted_due_to_age += 1;
                    }
                    state.transaction = None;

                    // Mark for removal if no fees tracked (will check again after fee release)
                    if state.total_fees == 0 {
                        accounts_to_remove.push(account_key.clone());
                    } else {
                        state.age = 0;
                    }
                }
            }
        }

        // Apply fee releases
        for (fee_source_key, tx_fee) in fee_releases {
            if let Some(fee_state) = account_states.get_mut(&fee_source_key) {
                fee_state.total_fees = fee_state.total_fees.saturating_sub(tx_fee as i64);
                // Mark for removal if now empty
                if fee_state.is_empty() && !accounts_to_remove.contains(&fee_source_key) {
                    accounts_to_remove.push(fee_source_key);
                }
            }
        }

        // Remove empty account states
        for account_key in accounts_to_remove {
            account_states.remove(&account_key);
        }

        // Reset eviction thresholds for the new ledger
        self.classic_lane_evicted_inclusion_fee.write().clear();
        self.soroban_lane_evicted_inclusion_fee.write().clear();
        *self.global_evicted_inclusion_fee.write() = (0, 0);

        ShiftResult {
            unbanned_count,
            evicted_due_to_age,
        }
    }

    /// Get the total number of currently banned transactions.
    pub fn banned_count(&self) -> usize {
        let banned = self.banned_transactions.read();
        banned.iter().map(|s| s.len()).sum()
    }

    /// Get the number of banned transactions at each depth level.
    ///
    /// Index 0 is the oldest (about to be unbanned), index ban_depth-1 is newest.
    #[cfg(test)]
    pub fn banned_count_by_depth(&self) -> Vec<usize> {
        let banned = self.banned_transactions.read();
        banned.iter().map(|s| s.len()).collect()
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

    /// Get statistics about the transaction queue.
    pub fn stats(&self) -> TxQueueStats {
        let by_hash = self.by_hash.read();
        let seen = self.seen.read();

        // Count accounts with pending transactions
        let mut accounts: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for tx in by_hash.values() {
            let account_id = account_id_from_envelope(&tx.envelope);
            accounts.insert(account_key_from_account_id(&account_id));
        }

        TxQueueStats {
            pending_count: by_hash.len(),
            account_count: accounts.len(),
            banned_count: self.banned_count(),
            seen_count: seen.len(),
        }
    }
}

/// Statistics about the transaction queue.
#[derive(Debug, Clone, Default)]
pub struct TxQueueStats {
    /// Number of pending transactions.
    pub pending_count: usize,
    /// Number of accounts with pending transactions.
    pub account_count: usize,
    /// Number of currently banned transactions.
    pub banned_count: usize,
    /// Number of seen (deduplicated) transaction hashes.
    pub seen_count: usize,
}

fn extra_signers_satisfied(
    envelope: &TransactionEnvelope,
    network_id: &NetworkId,
    extra_signers: &[SignerKey],
) -> std::result::Result<bool, &'static str> {
    let (tx_hash, signatures) = precondition_hash_and_signatures(envelope, network_id)?;

    Ok(extra_signers.iter().all(|signer| match signer {
        SignerKey::Ed25519(key) => {
            if let Ok(pk) = henyey_crypto::PublicKey::from_bytes(&key.0) {
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
            let frame =
                henyey_tx::TransactionFrame::with_network(envelope.clone(), *network_id);
            let hash = frame.hash(network_id).map_err(|_| "tx hash error")?;
            Ok((hash, env.signatures.as_slice()))
        }
        TransactionEnvelope::Tx(env) => {
            let frame =
                henyey_tx::TransactionFrame::with_network(envelope.clone(), *network_id);
            let hash = frame.hash(network_id).map_err(|_| "tx hash error")?;
            Ok((hash, env.signatures.as_slice()))
        }
        TransactionEnvelope::TxFeeBump(env) => {
            let inner_env = match &env.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => inner.clone(),
            };
            let inner_frame = henyey_tx::TransactionFrame::with_network(
                TransactionEnvelope::Tx(inner_env),
                *network_id,
            );
            let hash = inner_frame
                .hash(network_id)
                .map_err(|_| "inner tx hash error")?;
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
    pk: &henyey_crypto::PublicKey,
) -> bool {
    signatures
        .iter()
        .any(|sig| henyey_tx::validation::verify_signature_with_key(tx_hash, sig, pk))
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
    let pk = match henyey_crypto::PublicKey::from_bytes(&payload.ed25519.0) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let mut data = Vec::with_capacity(32 + payload.payload.len());
    data.extend_from_slice(&tx_hash.0);
    data.extend_from_slice(&payload.payload);
    let payload_hash = Hash256::hash(&data);

    signatures
        .iter()
        .any(|sig| henyey_tx::validation::verify_signature_with_key(&payload_hash, sig, &pk))
}

impl Default for TransactionQueue {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use henyey_common::NetworkId;
    use henyey_common::{Resource, ResourceType, NUM_SOROBAN_TX_RESOURCES};
    use henyey_crypto::{sign_hash, SecretKey};
    use stellar_xdr::curr::{
        AccountId, AlphaNum4, Asset, AssetCode4, CreateAccountOp, DecoratedSignature, Duration,
        HostFunction, InvokeContractArgs, InvokeHostFunctionOp, LedgerFootprint, ManageSellOfferOp,
        Memo, MuxedAccount, Operation, OperationBody, Preconditions, PreconditionsV2, Price,
        PublicKey, ScAddress, ScSymbol, ScVal, SequenceNumber, Signature as XdrSignature,
        SignatureHint, SignerKey, SorobanResources, SorobanTransactionData,
        SorobanTransactionDataExt, StringM, Transaction, TransactionEnvelope, TransactionExt,
        TransactionV1Envelope, Uint256, VecM,
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
            }]
            .try_into()
            .unwrap(),
        })
    }

    fn make_soroban_envelope(fee: u32) -> TransactionEnvelope {
        let source = MuxedAccount::Ed25519(Uint256([9u8; 32]));
        let function_name = ScSymbol(StringM::<32>::try_from("test".to_string()).expect("symbol"));
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
        make_dex_envelope_with_ops(fee, 1)
    }

    fn make_dex_envelope_with_ops(fee: u32, ops: usize) -> TransactionEnvelope {
        let source = MuxedAccount::Ed25519(Uint256([10u8; 32]));
        let selling = Asset::Native;
        let buying = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USDC"),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([11u8; 32]))),
        });
        let operations: Vec<Operation> = (0..ops)
            .map(|_| Operation {
                source_account: None,
                body: OperationBody::ManageSellOffer(ManageSellOfferOp {
                    selling: selling.clone(),
                    buying: buying.clone(),
                    amount: 1,
                    price: Price { n: 1, d: 1 },
                    offer_id: 0,
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
        let frame = henyey_tx::TransactionFrame::with_network(envelope.clone(), *network_id);
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

    fn full_hash(envelope: &TransactionEnvelope) -> Hash256 {
        Hash256::hash_xdr(envelope).expect("hash tx")
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
    fn test_ban_mechanism() {
        let queue = TransactionQueue::with_ban_depth(TxQueueConfig::default(), 3);

        // Create two transactions
        let tx1 = make_test_envelope(200, 1);
        let hash1 = Hash256::hash_xdr(&tx1).unwrap();
        let mut tx2 = make_test_envelope(200, 1);
        set_source(&mut tx2, 2);
        let hash2 = Hash256::hash_xdr(&tx2).unwrap();

        // Add tx1 to the queue
        assert_eq!(queue.try_add(tx1.clone()), TxQueueResult::Added);
        assert_eq!(queue.len(), 1);

        // Ban tx1 (which is in queue) and tx2 (which is not)
        queue.ban(&[hash1, hash2]);
        assert!(queue.is_banned(&hash1));
        assert!(queue.is_banned(&hash2));
        assert_eq!(queue.len(), 0); // tx1 should be removed from queue
        assert_eq!(queue.banned_count(), 2);

        // Try to add tx2 - should fail as banned (not in seen set)
        assert_eq!(queue.try_add(tx2.clone()), TxQueueResult::Banned);

        // tx1 would return Duplicate because it was seen (added before ban)
        // This is correct behavior - seen takes precedence
        assert_eq!(queue.try_add(tx1.clone()), TxQueueResult::Duplicate);

        // Verify ban depth tracking
        let counts = queue.banned_count_by_depth();
        assert_eq!(counts.len(), 3);
        assert_eq!(counts[2], 2); // Newest set has both bans
        assert_eq!(counts[0], 0);
        assert_eq!(counts[1], 0);
    }

    #[test]
    fn test_ban_shift_unban() {
        let queue = TransactionQueue::with_ban_depth(TxQueueConfig::default(), 3);

        let tx = make_test_envelope(200, 1);
        let hash = Hash256::hash_xdr(&tx).unwrap();
        queue.ban(&[hash]);
        assert!(queue.is_banned(&hash));

        // After 3 shifts, the ban should be removed
        queue.shift(); // ledger 1
        assert!(queue.is_banned(&hash));
        queue.shift(); // ledger 2
        assert!(queue.is_banned(&hash));
        let shift_result = queue.shift(); // ledger 3 - oldest set removed
        assert_eq!(shift_result.unbanned_count, 1);
        assert!(!queue.is_banned(&hash)); // Now unbanned

        // Should be able to add again
        assert_eq!(queue.try_add(tx), TxQueueResult::Added);
    }

    #[test]
    fn test_multiple_bans_across_ledgers() {
        let queue = TransactionQueue::with_ban_depth(TxQueueConfig::default(), 3);

        // Ban tx1 in ledger 1
        let mut tx1 = make_test_envelope(200, 1);
        set_source(&mut tx1, 1);
        let hash1 = Hash256::hash_xdr(&tx1).unwrap();
        queue.ban(&[hash1]);

        queue.shift(); // ledger 2

        // Ban tx2 in ledger 2
        let mut tx2 = make_test_envelope(200, 1);
        set_source(&mut tx2, 2);
        let hash2 = Hash256::hash_xdr(&tx2).unwrap();
        queue.ban(&[hash2]);

        queue.shift(); // ledger 3

        // Ban tx3 in ledger 3
        let mut tx3 = make_test_envelope(200, 1);
        set_source(&mut tx3, 3);
        let hash3 = Hash256::hash_xdr(&tx3).unwrap();
        queue.ban(&[hash3]);

        // All should be banned
        assert!(queue.is_banned(&hash1));
        assert!(queue.is_banned(&hash2));
        assert!(queue.is_banned(&hash3));

        // After shift, tx1 should be unbanned
        queue.shift(); // ledger 4
        assert!(!queue.is_banned(&hash1));
        assert!(queue.is_banned(&hash2));
        assert!(queue.is_banned(&hash3));

        // After another shift, tx2 should be unbanned
        queue.shift(); // ledger 5
        assert!(!queue.is_banned(&hash2));
        assert!(queue.is_banned(&hash3));
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

        let mut fees: Vec<u64> = set.transactions.iter().map(envelope_fee).collect();
        fees.sort_by(|a, b| b.cmp(a));
        assert_eq!(fees, vec![300, 200, 100]);
    }

    #[test]
    fn test_tie_breaker_is_deterministic() {
        let queue = TransactionQueue::with_defaults();
        let network_id = NetworkId::testnet();

        let mut tx_a = make_test_envelope(200, 1);
        let mut tx_b = make_test_envelope(200, 1);
        set_source(&mut tx_a, 4);
        set_source(&mut tx_b, 5);
        let hash_a = henyey_tx::TransactionFrame::with_network(tx_a.clone(), network_id)
            .hash(&network_id)
            .expect("hash tx_a");
        let hash_b = henyey_tx::TransactionFrame::with_network(tx_b.clone(), network_id)
            .hash(&network_id)
            .expect("hash tx_b");

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
            .map(|tx| {
                henyey_tx::TransactionFrame::with_network(tx.clone(), network_id)
                    .hash(&network_id)
                    .expect("hash tx")
            })
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
        // With one-tx-per-account limit, each transaction needs a different source account
        let queue = TransactionQueue::with_defaults();

        let mut tx_a = make_test_envelope(200, 1);
        let mut tx_b = make_test_envelope(200, 1);
        set_source(&mut tx_a, 1);
        set_source(&mut tx_b, 2); // Different account
        if let TransactionEnvelope::Tx(env) = &mut tx_a {
            env.tx.seq_num = SequenceNumber(1);
        }
        if let TransactionEnvelope::Tx(env) = &mut tx_b {
            env.tx.seq_num = SequenceNumber(2);
        }

        queue.try_add(tx_a);
        queue.try_add(tx_b);

        let set = queue.get_transaction_set(Hash256::ZERO, 10);
        let mut seqs: Vec<i64> = set.transactions.iter().map(envelope_seq).collect();
        seqs.sort();
        assert_eq!(seqs, vec![1, 2]);
    }

    #[test]
    fn test_sequence_blocks_classic_after_soroban() {
        // With one-tx-per-account limit, only one tx per account can be added.
        // Use different accounts to test that both classic and soroban can coexist.
        let queue = TransactionQueue::with_defaults();

        let mut classic = make_test_envelope(250, 1);
        let mut soroban = make_soroban_envelope(200);
        set_source(&mut classic, 7);
        set_source(&mut soroban, 8); // Different account
        if let TransactionEnvelope::Tx(env) = &mut classic {
            env.tx.seq_num = SequenceNumber(1);
        }
        if let TransactionEnvelope::Tx(env) = &mut soroban {
            env.tx.seq_num = SequenceNumber(2);
        }

        assert_eq!(queue.try_add(classic), TxQueueResult::Added);
        assert_eq!(queue.try_add(soroban), TxQueueResult::Added);

        let set = queue.get_transaction_set(Hash256::ZERO, 10);
        let mut seqs: Vec<i64> = set.transactions.iter().map(envelope_seq).collect();
        seqs.sort();
        assert_eq!(seqs, vec![1, 2]);
    }

    #[test]
    fn test_sequence_allows_soroban_suffix() {
        // With one-tx-per-account limit, use different accounts for each transaction
        let queue = TransactionQueue::with_defaults();

        let mut classic = make_test_envelope(200, 1);
        let mut soroban_a = make_soroban_envelope(200);
        let mut soroban_b = make_soroban_envelope(200);
        set_source(&mut classic, 7);
        set_source(&mut soroban_a, 8); // Different account
        set_source(&mut soroban_b, 9); // Different account
        if let TransactionEnvelope::Tx(env) = &mut classic {
            env.tx.seq_num = SequenceNumber(1);
        }
        if let TransactionEnvelope::Tx(env) = &mut soroban_a {
            env.tx.seq_num = SequenceNumber(2);
        }
        if let TransactionEnvelope::Tx(env) = &mut soroban_b {
            env.tx.seq_num = SequenceNumber(3);
        }

        assert_eq!(queue.try_add(classic), TxQueueResult::Added);
        assert_eq!(queue.try_add(soroban_a), TxQueueResult::Added);
        assert_eq!(queue.try_add(soroban_b), TxQueueResult::Added);

        let set = queue.get_transaction_set(Hash256::ZERO, 10);
        let mut seqs: Vec<i64> = set.transactions.iter().map(envelope_seq).collect();
        seqs.sort();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[test]
    fn test_sequence_respects_starting_seq() {
        // With one-tx-per-account limit, use different accounts
        let queue = TransactionQueue::with_defaults();

        let mut tx_a = make_test_envelope(200, 1);
        let mut tx_b = make_test_envelope(200, 1);
        set_source(&mut tx_a, 1);
        set_source(&mut tx_b, 2); // Different account
        if let TransactionEnvelope::Tx(env) = &mut tx_a {
            env.tx.seq_num = SequenceNumber(5);
        }
        if let TransactionEnvelope::Tx(env) = &mut tx_b {
            env.tx.seq_num = SequenceNumber(6);
        }

        queue.try_add(tx_a.clone());
        queue.try_add(tx_b);

        // Set starting sequence for account 1 to 5, so tx_a (seq 5) should be filtered out
        let account_id = account_id_from_envelope(&tx_a);
        let mut starting = std::collections::HashMap::new();
        starting.insert(account_key_from_account_id(&account_id), 5);

        let set = queue.get_transaction_set_with_starting_seq(Hash256::ZERO, 10, Some(&starting));
        let mut seqs: Vec<i64> = set.transactions.iter().map(envelope_seq).collect();
        seqs.sort();
        // tx_a with seq 5 is filtered (starting_seq >= 5), only tx_b with seq 6 remains
        assert_eq!(seqs, vec![6]);
    }

    #[test]
    fn test_starting_sequence_boundary() {
        // With one-tx-per-account limit, use different accounts
        let queue = TransactionQueue::with_defaults();

        let starting_seq = (4_i64) << 32;
        let mut tx_starting = make_test_envelope(200, 1);
        let mut tx_next = make_test_envelope(200, 1);
        set_source(&mut tx_starting, 1);
        set_source(&mut tx_next, 2); // Different account
        if let TransactionEnvelope::Tx(env) = &mut tx_starting {
            env.tx.seq_num = SequenceNumber(starting_seq);
        }
        if let TransactionEnvelope::Tx(env) = &mut tx_next {
            env.tx.seq_num = SequenceNumber(starting_seq + 1);
        }

        queue.try_add(tx_starting.clone());
        queue.try_add(tx_next);

        // Set starting sequence for account 1, so tx_starting should be filtered out
        let account_id = account_id_from_envelope(&tx_starting);
        let mut starting = std::collections::HashMap::new();
        starting.insert(account_key_from_account_id(&account_id), starting_seq);

        let set = queue.get_transaction_set_with_starting_seq(Hash256::ZERO, 10, Some(&starting));
        let mut seqs: Vec<i64> = set.transactions.iter().map(envelope_seq).collect();
        seqs.sort();
        // tx_starting is filtered (starting_seq >= starting_seq), only tx_next remains
        assert_eq!(seqs, vec![starting_seq + 1]);
    }

    #[test]
    fn test_transaction_set_hash_matches_recompute() {
        let mut tx_a = make_test_envelope(200, 1);
        let mut tx_b = make_test_envelope(300, 1);
        set_source(&mut tx_a, 40);
        set_source(&mut tx_b, 41);
        if let TransactionEnvelope::Tx(env) = &mut tx_a {
            env.tx.seq_num = SequenceNumber(1);
        }
        if let TransactionEnvelope::Tx(env) = &mut tx_b {
            env.tx.seq_num = SequenceNumber(2);
        }

        let tx_set = TransactionSet::new(Hash256::ZERO, vec![tx_a, tx_b]);
        let recomputed = tx_set.recompute_hash().expect("recompute hash");
        assert_eq!(tx_set.hash, recomputed);
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
                assert!(!henyey_tx::TransactionFrame::with_network(
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
                assert!(henyey_tx::TransactionFrame::with_network(
                    txs[0].clone(),
                    NetworkId::testnet()
                )
                .is_soroban());
            }
            _ => panic!("expected soroban phase"),
        }
    }

    #[test]
    fn test_generalized_tx_set_hash_matches_recompute() {
        let queue = TransactionQueue::with_defaults();

        let classic = make_test_envelope(200, 1);
        let soroban = make_soroban_envelope(200);
        queue.try_add(classic);
        queue.try_add(soroban);

        let (tx_set, gen) = queue.build_generalized_tx_set(Hash256::ZERO, 100);
        let recomputed = tx_set.recompute_hash().expect("recompute hash");
        assert_eq!(tx_set.hash, recomputed);

        let gen_hash = Hash256::hash_xdr(&gen).expect("hash generalized");
        assert_eq!(tx_set.hash, gen_hash);
    }

    #[test]
    fn test_classic_base_fee_defaults_to_min_fee() {
        let queue = TransactionQueue::with_defaults();
        let expected_base_fee = queue.validation_context.read().base_fee as i64;

        queue.try_add(make_test_envelope(200, 1));
        queue.try_add(make_test_envelope(300, 1));

        let (_set, gen) = queue.build_generalized_tx_set(Hash256::ZERO, 10);
        let stellar_xdr::curr::GeneralizedTransactionSet::V1(v1) = gen;
        let base_fee = match &v1.phases[0] {
            stellar_xdr::curr::TransactionPhase::V0(components) => {
                let stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) =
                    &components[0];
                comp.base_fee
            }
            _ => None,
        };

        assert_eq!(base_fee, Some(expected_base_fee));
    }

    #[test]
    fn test_soroban_base_fee_defaults_to_min_fee() {
        let queue = TransactionQueue::with_defaults();
        let expected_base_fee = queue.validation_context.read().base_fee as i64;

        queue.try_add(make_soroban_envelope(200));
        queue.try_add(make_soroban_envelope(300));

        let (_set, gen) = queue.build_generalized_tx_set(Hash256::ZERO, 10);
        let stellar_xdr::curr::GeneralizedTransactionSet::V1(v1) = gen;
        let base_fee = match &v1.phases[1] {
            stellar_xdr::curr::TransactionPhase::V1(parallel) => parallel.base_fee,
            _ => None,
        };

        assert_eq!(base_fee, Some(expected_base_fee));
    }

    #[test]
    fn test_classic_component_orders_by_hash() {
        let queue = TransactionQueue::with_defaults();

        let mut tx_a = make_test_envelope(200, 1);
        let mut tx_b = make_test_envelope(200, 1);
        set_source(&mut tx_a, 11);
        set_source(&mut tx_b, 12);

        queue.try_add(tx_b.clone());
        queue.try_add(tx_a.clone());

        let (_set, gen) = queue.build_generalized_tx_set(Hash256::ZERO, 10);
        let stellar_xdr::curr::GeneralizedTransactionSet::V1(v1) = gen;

        let txs = match &v1.phases[0] {
            stellar_xdr::curr::TransactionPhase::V0(components) => {
                let stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) =
                    &components[0];
                comp.txs.to_vec()
            }
            _ => panic!("expected classic phase"),
        };

        assert_eq!(txs.len(), 2);
        let hashes: Vec<_> = txs.iter().map(full_hash).collect();
        assert!(hashes[0].0 <= hashes[1].0);
    }

    #[test]
    fn test_soroban_component_orders_by_hash() {
        let queue = TransactionQueue::with_defaults();

        let mut tx_a = make_soroban_envelope(200);
        let mut tx_b = make_soroban_envelope(200);
        set_source(&mut tx_a, 21);
        set_source(&mut tx_b, 22);

        queue.try_add(tx_b.clone());
        queue.try_add(tx_a.clone());

        let (_set, gen) = queue.build_generalized_tx_set(Hash256::ZERO, 10);
        let stellar_xdr::curr::GeneralizedTransactionSet::V1(v1) = gen;

        let mut txs = Vec::new();
        match &v1.phases[1] {
            stellar_xdr::curr::TransactionPhase::V1(parallel) => {
                for stage in parallel.execution_stages.iter() {
                    for cluster in stage.iter() {
                        txs.extend(cluster.0.iter().cloned());
                    }
                }
            }
            _ => panic!("expected soroban phase"),
        }

        assert_eq!(txs.len(), 2);
        let hashes: Vec<_> = txs.iter().map(full_hash).collect();
        assert!(hashes[0].0 <= hashes[1].0);
    }

    #[test]
    fn test_queue_rejects_below_current_base_fee() {
        let queue = TransactionQueue::with_defaults();

        queue.update_validation_context(1, 0, 25, 500);

        let low_fee = make_test_envelope(200, 1);
        let high_fee = make_test_envelope(600, 1);

        assert_eq!(queue.try_add(low_fee), TxQueueResult::FeeTooLow);
        assert_eq!(queue.try_add(high_fee), TxQueueResult::Added);
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
            stellar_xdr::curr::TransactionPhase::V0(components) => match &components[0] {
                stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) => {
                    comp.base_fee
                }
            },
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
    fn test_queue_classic_byte_limit_eviction() {
        let mut tx_low = make_test_envelope(200, 1);
        let mut tx_high = make_test_envelope(400, 1);
        set_source(&mut tx_low, 62);
        set_source(&mut tx_high, 63);

        let byte_limit = envelope_size(&tx_high) as u32;
        let config = TxQueueConfig {
            max_queue_classic_bytes: Some(byte_limit),
            max_size: 10,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        assert_eq!(queue.try_add(tx_low.clone()), TxQueueResult::Added);
        assert_eq!(queue.try_add(tx_high.clone()), TxQueueResult::Added);

        let low_hash = full_hash(&tx_low);
        let high_hash = full_hash(&tx_high);
        assert!(!queue.contains(&low_hash));
        assert!(queue.contains(&high_hash));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_queue_classic_byte_limit_sets_min_fee_after_eviction() {
        let mut tx_low = make_test_envelope(200, 1);
        let mut tx_high = make_test_envelope(400, 1);
        let mut tx_lower = make_test_envelope(100, 1);
        set_source(&mut tx_low, 64);
        set_source(&mut tx_high, 65);
        set_source(&mut tx_lower, 66);

        let byte_limit = envelope_size(&tx_high) as u32;
        let config = TxQueueConfig {
            max_queue_classic_bytes: Some(byte_limit),
            max_size: 10,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        assert_eq!(queue.try_add(tx_low), TxQueueResult::Added);
        assert_eq!(queue.try_add(tx_high), TxQueueResult::Added);
        assert_eq!(queue.try_add(tx_lower), TxQueueResult::FeeTooLow);
        assert_eq!(queue.len(), 1);
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
            let frame =
                henyey_tx::TransactionFrame::with_network(tx.clone(), NetworkId::testnet());
            if frame.has_dex_operations() {
                dex_count += 1;
            }
        }
        assert_eq!(dex_count, 1);
    }

    #[test]
    fn test_dex_lane_limit_deterministic_selection() {
        let config = TxQueueConfig {
            max_dex_ops: Some(1),
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut dex_a = make_dex_envelope(200);
        let mut dex_b = make_dex_envelope(200);
        let mut classic = make_test_envelope(200, 1);
        set_source(&mut dex_a, 201);
        set_source(&mut dex_b, 202);
        set_source(&mut classic, 203);

        queue.try_add(dex_a.clone());
        queue.try_add(dex_b.clone());
        queue.try_add(classic.clone());

        let set = queue.get_transaction_set(Hash256::ZERO, 10);
        assert_eq!(set.len(), 2);

        let hash_dex_a = full_hash(&dex_a);
        let hash_dex_b = full_hash(&dex_b);
        let hash_classic = full_hash(&classic);
        let included_dex = if hash_dex_a.0 <= hash_dex_b.0 {
            hash_dex_a
        } else {
            hash_dex_b
        };

        let mut expected = vec![hash_classic, included_dex];
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        let hashes: Vec<_> = set.transactions.iter().map(full_hash).collect();
        assert_eq!(hashes, expected);
    }

    #[test]
    fn test_dex_limit_sets_only_dex_limited_flag() {
        let config = TxQueueConfig {
            max_dex_ops: Some(1),
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut dex_a = make_dex_envelope(400);
        let mut dex_b = make_dex_envelope(300);
        let mut classic = make_test_envelope(200, 1);
        set_source(&mut dex_a, 16);
        set_source(&mut dex_b, 17);
        set_source(&mut classic, 18);

        queue.try_add(dex_a);
        queue.try_add(dex_b);
        queue.try_add(classic);

        let SelectedTxs {
            dex_limited,
            classic_limited,
            transactions,
            ..
        } = queue.select_transactions(10);

        assert!(dex_limited);
        assert!(!classic_limited);
        assert_eq!(transactions.len(), 2);
    }

    #[test]
    fn test_dex_evicts_non_dex_when_lane_insufficient() {
        let config = TxQueueConfig {
            max_queue_ops: Some(9),
            max_queue_dex_ops: Some(3),
            max_size: 10,
            min_fee_per_op: 0,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut non_dex = make_test_envelope(100 * 8, 8);
        let mut dex_low = make_dex_envelope(200);
        let mut dex_high = make_dex_envelope_with_ops(10000 * 3, 3);
        set_source(&mut non_dex, 100);
        set_source(&mut dex_low, 101);
        set_source(&mut dex_high, 102);

        let non_dex_hash = full_hash(&non_dex);
        let dex_low_hash = full_hash(&dex_low);
        let dex_high_hash = full_hash(&dex_high);

        assert_eq!(queue.try_add(non_dex), TxQueueResult::Added);
        assert_eq!(queue.try_add(dex_low), TxQueueResult::Added);
        assert_eq!(queue.try_add(dex_high), TxQueueResult::Added);

        assert!(!queue.contains(&non_dex_hash));
        assert!(!queue.contains(&dex_low_hash));
        assert!(queue.contains(&dex_high_hash));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_dex_eviction_with_global_limit_only() {
        let config = TxQueueConfig {
            max_queue_ops: Some(9),
            max_queue_dex_ops: Some(3),
            max_size: 10,
            min_fee_per_op: 0,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut dex = make_dex_envelope_with_ops(200, 1);
        let mut non_dex_high = make_test_envelope(400 * 6, 6);
        let mut non_dex_low = make_test_envelope(100, 1);
        let mut non_dex_mid = make_test_envelope(300, 1);
        let mut dex_new = make_dex_envelope_with_ops(301 * 3, 3);
        set_source(&mut dex, 110);
        set_source(&mut non_dex_high, 111);
        set_source(&mut non_dex_low, 112);
        set_source(&mut non_dex_mid, 113);
        set_source(&mut dex_new, 114);

        let dex_hash = full_hash(&dex);
        let non_dex_high_hash = full_hash(&non_dex_high);
        let non_dex_low_hash = full_hash(&non_dex_low);
        let non_dex_mid_hash = full_hash(&non_dex_mid);
        let dex_new_hash = full_hash(&dex_new);

        assert_eq!(queue.try_add(dex), TxQueueResult::Added);
        assert_eq!(queue.try_add(non_dex_high), TxQueueResult::Added);
        assert_eq!(queue.try_add(non_dex_low), TxQueueResult::Added);
        assert_eq!(queue.try_add(non_dex_mid), TxQueueResult::Added);
        assert_eq!(queue.try_add(dex_new), TxQueueResult::Added);

        assert!(!queue.contains(&dex_hash));
        assert!(queue.contains(&non_dex_high_hash));
        assert!(!queue.contains(&non_dex_low_hash));
        assert!(!queue.contains(&non_dex_mid_hash));
        assert!(queue.contains(&dex_new_hash));
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_dex_eviction_with_global_and_dex_limits() {
        let config = TxQueueConfig {
            max_queue_ops: Some(9),
            max_queue_dex_ops: Some(3),
            max_size: 10,
            min_fee_per_op: 0,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut dex = make_dex_envelope_with_ops(200 * 2, 2);
        let mut non_dex_high = make_test_envelope(400 * 5, 5);
        let mut non_dex_low = make_test_envelope(100, 1);
        let mut non_dex_mid = make_test_envelope(150, 1);
        let mut dex_new = make_dex_envelope_with_ops(201 * 3, 3);
        set_source(&mut dex, 120);
        set_source(&mut non_dex_high, 121);
        set_source(&mut non_dex_low, 122);
        set_source(&mut non_dex_mid, 123);
        set_source(&mut dex_new, 124);

        let dex_hash = full_hash(&dex);
        let non_dex_high_hash = full_hash(&non_dex_high);
        let non_dex_low_hash = full_hash(&non_dex_low);
        let non_dex_mid_hash = full_hash(&non_dex_mid);
        let dex_new_hash = full_hash(&dex_new);

        assert_eq!(queue.try_add(dex), TxQueueResult::Added);
        assert_eq!(queue.try_add(non_dex_high), TxQueueResult::Added);
        assert_eq!(queue.try_add(non_dex_low), TxQueueResult::Added);
        assert_eq!(queue.try_add(non_dex_mid), TxQueueResult::Added);
        assert_eq!(queue.try_add(dex_new), TxQueueResult::Added);

        assert!(!queue.contains(&dex_hash));
        assert!(queue.contains(&non_dex_high_hash));
        assert!(!queue.contains(&non_dex_low_hash));
        assert!(queue.contains(&non_dex_mid_hash));
        assert!(queue.contains(&dex_new_hash));
        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn test_dex_only_min_fee_threshold_after_eviction() {
        let config = TxQueueConfig {
            max_queue_ops: Some(9),
            max_queue_dex_ops: Some(3),
            max_size: 10,
            min_fee_per_op: 0,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut dex_low_a = make_dex_envelope_with_ops(100, 1);
        let mut dex_mid = make_dex_envelope_with_ops(150 * 2, 2);
        let mut dex_evicted = make_dex_envelope_with_ops(200 * 2, 2);
        let mut dex_low = make_dex_envelope_with_ops(100, 1);
        let mut dex_high = make_dex_envelope_with_ops(201 * 3, 3);
        set_source(&mut dex_low_a, 140);
        set_source(&mut dex_mid, 141);
        set_source(&mut dex_evicted, 142);
        set_source(&mut dex_low, 143);
        set_source(&mut dex_high, 144);

        assert_eq!(queue.try_add(dex_low_a), TxQueueResult::Added);
        assert_eq!(queue.try_add(dex_mid), TxQueueResult::Added);
        assert_eq!(queue.try_add(dex_evicted), TxQueueResult::Added);
        assert_eq!(queue.try_add(dex_low), TxQueueResult::FeeTooLow);
        assert_eq!(queue.try_add(dex_high), TxQueueResult::Added);
    }

    #[test]
    fn test_non_dex_only_min_fee_threshold_after_eviction() {
        let config = TxQueueConfig {
            max_queue_ops: Some(6),
            max_queue_dex_ops: Some(3),
            max_size: 10,
            min_fee_per_op: 0,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut non_dex_a = make_test_envelope(100, 1);
        let mut non_dex_b = make_test_envelope(150 * 5, 5);
        let mut non_dex_evict = make_test_envelope(200 * 5, 5);
        let mut non_dex_low = make_test_envelope(100, 1);
        let mut non_dex_high = make_test_envelope(201 * 2, 2);
        set_source(&mut non_dex_a, 150);
        set_source(&mut non_dex_b, 151);
        set_source(&mut non_dex_evict, 152);
        set_source(&mut non_dex_low, 153);
        set_source(&mut non_dex_high, 154);

        assert_eq!(queue.try_add(non_dex_a), TxQueueResult::Added);
        assert_eq!(queue.try_add(non_dex_b), TxQueueResult::Added);
        assert_eq!(queue.try_add(non_dex_evict), TxQueueResult::Added);
        assert_eq!(queue.try_add(non_dex_low), TxQueueResult::FeeTooLow);
        assert_eq!(queue.try_add(non_dex_high), TxQueueResult::Added);
    }

    #[test]
    fn test_classic_components_group_by_discounted_base_fee() {
        let mut dex_a = make_dex_envelope(300);
        let mut dex_b = make_dex_envelope(200);
        let mut classic_high = make_test_envelope(250, 1);
        let mut classic_low = make_test_envelope(100, 1);
        set_source(&mut dex_a, 160);
        set_source(&mut dex_b, 161);
        set_source(&mut classic_high, 162);
        set_source(&mut classic_low, 163);

        let byte_limit = (envelope_size(&dex_a) + envelope_size(&classic_high)) as u32;
        let config = TxQueueConfig {
            max_dex_ops: Some(1),
            max_classic_bytes: Some(byte_limit),
            max_size: 10,
            min_fee_per_op: 0,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        queue.try_add(dex_a.clone());
        queue.try_add(dex_b.clone());
        queue.try_add(classic_high.clone());
        queue.try_add(classic_low.clone());

        let (_set, gen) = queue.build_generalized_tx_set(Hash256::ZERO, 10);
        let stellar_xdr::curr::GeneralizedTransactionSet::V1(tx_set) = gen;
        let phases = &tx_set.phases;
        let components = match &phases[0] {
            stellar_xdr::curr::TransactionPhase::V0(components) => components,
            _ => panic!("expected classic phase"),
        };
        assert_eq!(components.len(), 2);

        let mut base_fees = Vec::new();
        let mut tx_counts = Vec::new();
        for comp in components.iter() {
            let stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) = comp;
            base_fees.push(comp.base_fee);
            tx_counts.push(comp.txs.len());
        }
        base_fees.sort();
        tx_counts.sort();
        assert_eq!(base_fees, vec![Some(250), Some(300)]);
        assert_eq!(tx_counts, vec![1, 1]);
    }

    #[test]
    fn test_dex_and_non_dex_min_fee_thresholds_after_evictions() {
        let config = TxQueueConfig {
            max_queue_ops: Some(9),
            max_queue_dex_ops: Some(3),
            max_size: 10,
            min_fee_per_op: 0,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut dex_a = make_dex_envelope_with_ops(200 * 2, 2);
        let mut non_dex_a = make_test_envelope(100 * 3, 3);
        let mut dex_b = make_dex_envelope_with_ops(300 * 2, 2);
        let mut non_dex_b = make_test_envelope(250 * 5, 5);
        set_source(&mut dex_a, 130);
        set_source(&mut non_dex_a, 131);
        set_source(&mut dex_b, 132);
        set_source(&mut non_dex_b, 133);

        let dex_a_hash = full_hash(&dex_a);
        let non_dex_a_hash = full_hash(&non_dex_a);
        let dex_b_hash = full_hash(&dex_b);
        let non_dex_b_hash = full_hash(&non_dex_b);

        assert_eq!(queue.try_add(dex_a), TxQueueResult::Added);
        assert_eq!(queue.try_add(non_dex_a), TxQueueResult::Added);
        assert_eq!(queue.try_add(dex_b), TxQueueResult::Added);
        assert_eq!(queue.try_add(non_dex_b), TxQueueResult::Added);

        assert!(!queue.contains(&dex_a_hash));
        assert!(!queue.contains(&non_dex_a_hash));
        assert!(queue.contains(&dex_b_hash));
        assert!(queue.contains(&non_dex_b_hash));

        let mut dex_low = make_dex_envelope_with_ops(200, 1);
        let mut non_dex_low = make_test_envelope(100, 1);
        let mut dex_high = make_dex_envelope_with_ops(201, 1);
        let mut non_dex_high = make_test_envelope(101, 1);
        set_source(&mut dex_low, 134);
        set_source(&mut non_dex_low, 135);
        set_source(&mut dex_high, 136);
        set_source(&mut non_dex_high, 137);

        assert_eq!(queue.try_add(dex_low), TxQueueResult::FeeTooLow);
        assert_eq!(queue.try_add(non_dex_low), TxQueueResult::FeeTooLow);
        assert_eq!(queue.try_add(dex_high), TxQueueResult::Added);
        assert_eq!(queue.try_add(non_dex_high), TxQueueResult::Added);
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

        let low_hash = full_hash(&dex_low);
        let high_hash = full_hash(&dex_high);
        assert!(!queue.contains(&low_hash));
        assert!(queue.contains(&high_hash));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_dex_queue_limit_sets_min_fee_after_eviction() {
        let config = TxQueueConfig {
            max_queue_dex_ops: Some(1),
            max_size: 10,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut dex_low = make_dex_envelope(200);
        let mut dex_high = make_dex_envelope(400);
        let mut dex_lower = make_dex_envelope(150);
        set_source(&mut dex_low, 31);
        set_source(&mut dex_high, 32);
        set_source(&mut dex_lower, 33);

        assert_eq!(queue.try_add(dex_low), TxQueueResult::Added);
        assert_eq!(queue.try_add(dex_high), TxQueueResult::Added);
        assert_eq!(queue.try_add(dex_lower), TxQueueResult::FeeTooLow);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_dex_lane_min_fee_blocks_classic() {
        let config = TxQueueConfig {
            max_queue_dex_ops: Some(1),
            max_size: 10,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut dex_low = make_dex_envelope(200);
        let mut dex_high = make_dex_envelope(400);
        let mut classic_low = make_test_envelope(100, 1);
        set_source(&mut dex_low, 34);
        set_source(&mut dex_high, 35);
        set_source(&mut classic_low, 36);

        assert_eq!(queue.try_add(dex_low), TxQueueResult::Added);
        assert_eq!(queue.try_add(dex_high), TxQueueResult::Added);
        assert_eq!(queue.try_add(classic_low), TxQueueResult::FeeTooLow);
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

        let low_hash = full_hash(&tx_low);
        let mid_hash = full_hash(&tx_mid);
        let high_hash = full_hash(&tx_high);
        assert!(!queue.contains(&low_hash));
        assert!(queue.contains(&mid_hash));
        assert!(queue.contains(&high_hash));
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_queue_ops_limit_sets_min_fee_after_eviction() {
        let config = TxQueueConfig {
            max_queue_ops: Some(2),
            max_size: 10,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut tx_low = make_test_envelope(100, 1);
        let mut tx_high = make_test_envelope(400, 1);
        let mut tx_lower = make_test_envelope(80, 1);
        set_source(&mut tx_low, 41);
        set_source(&mut tx_high, 42);
        set_source(&mut tx_lower, 43);

        assert_eq!(queue.try_add(tx_low), TxQueueResult::Added);
        assert_eq!(queue.try_add(tx_high), TxQueueResult::Added);
        assert_eq!(queue.try_add(tx_lower), TxQueueResult::FeeTooLow);
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_queue_ops_limit_accepts_higher_fee_after_eviction() {
        let config = TxQueueConfig {
            max_queue_ops: Some(2),
            max_size: 10,
            min_fee_per_op: 0,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut tx_low = make_test_envelope(100, 1);
        let mut tx_high = make_test_envelope(400, 1);
        let mut tx_mid = make_test_envelope(150, 1);
        set_source(&mut tx_low, 52);
        set_source(&mut tx_high, 53);
        set_source(&mut tx_mid, 54);

        let low_hash = full_hash(&tx_low);
        let high_hash = full_hash(&tx_high);
        let mid_hash = full_hash(&tx_mid);

        assert_eq!(queue.try_add(tx_low), TxQueueResult::Added);
        assert_eq!(queue.try_add(tx_high), TxQueueResult::Added);
        assert_eq!(queue.try_add(tx_mid), TxQueueResult::Added);

        assert!(!queue.contains(&low_hash));
        assert!(queue.contains(&high_hash));
        assert!(queue.contains(&mid_hash));
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_eviction_thresholds_reset_after_age_eviction() {
        let config = TxQueueConfig {
            max_queue_ops: Some(1),
            max_size: 10,
            max_age_secs: 1,
            min_fee_per_op: 0,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut tx_low = make_test_envelope(100, 1);
        let mut tx_high = make_test_envelope(200, 1);
        let mut tx_lower = make_test_envelope(80, 1);
        let mut tx_new = make_test_envelope(80, 1);
        set_source(&mut tx_low, 90);
        set_source(&mut tx_high, 91);
        set_source(&mut tx_lower, 92);
        set_source(&mut tx_new, 93);

        assert_eq!(queue.try_add(tx_low), TxQueueResult::Added);
        assert_eq!(queue.try_add(tx_high), TxQueueResult::Added);
        assert_eq!(queue.try_add(tx_lower), TxQueueResult::FeeTooLow);
        assert_eq!(queue.len(), 1);

        {
            let mut by_hash = queue.by_hash.write();
            for tx in by_hash.values_mut() {
                tx.received_at = tx
                    .received_at
                    .checked_sub(std::time::Duration::from_secs(10))
                    .unwrap_or_else(|| Instant::now() - std::time::Duration::from_secs(10));
            }
        }
        queue.evict_expired();
        assert!(queue.is_empty());

        assert_eq!(queue.try_add(tx_new), TxQueueResult::Added);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_queue_ops_limit_rejects_same_account_eviction() {
        // With one-tx-per-account limit, the second transaction is rejected with TryAgainLater
        // (not QueueFull) because the account already has a pending transaction.
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
        // With one-tx-per-account, second tx from same account is rejected as TryAgainLater
        assert_eq!(queue.try_add(tx_high), TxQueueResult::TryAgainLater);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_dex_base_fee_override() {
        let config = TxQueueConfig {
            max_dex_ops: Some(1),
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);
        let base_fee = queue.validation_context.read().base_fee as i64;

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
        let mut has_classic_fee = false;
        for comp in components.iter() {
            let stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) = comp;
            match comp.base_fee {
                Some(500) => has_dex_fee = true,
                Some(fee) if fee == base_fee => has_classic_fee = true,
                _ => {}
            }
        }
        assert!(has_dex_fee);
        assert!(has_classic_fee);
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

        let low_hash = full_hash(&low_fee);
        let high_hash = full_hash(&high_fee);
        assert!(!queue.contains(&low_hash));
        assert!(queue.contains(&high_hash));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_soroban_queue_limit_sets_min_fee_after_eviction() {
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
        let mut lower_fee = make_soroban_envelope_with_resources(2000, 80);
        set_source(&mut low_fee, 81);
        set_source(&mut high_fee, 82);
        set_source(&mut lower_fee, 83);

        assert_eq!(queue.try_add(low_fee), TxQueueResult::Added);
        assert_eq!(queue.try_add(high_fee), TxQueueResult::Added);
        assert_eq!(queue.try_add(lower_fee), TxQueueResult::FeeTooLow);
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
        // With one-tx-per-account limit, use different accounts for each transaction
        let config = TxQueueConfig {
            max_size: 2,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        let mut tx1 = make_test_envelope(100, 1);
        let mut tx2 = make_test_envelope(200, 1);
        let mut tx3 = make_test_envelope(300, 1);
        set_source(&mut tx1, 1);
        set_source(&mut tx2, 2);
        set_source(&mut tx3, 3);

        queue.try_add(tx1);
        queue.try_add(tx2);
        // Third transaction should evict the lowest-fee one
        let result = queue.try_add(tx3);
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

        let low_hash = full_hash(&low);
        let high_hash = full_hash(&high);

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

        let hash = full_hash(&tx);
        assert!(queue.contains(&hash));

        queue.remove_applied_by_hash(&[hash]);
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

    #[test]
    fn test_is_filtered_empty_config() {
        let config = TxQueueConfig {
            validate_signatures: false,
            validate_time_bounds: false,
            filtered_operation_types: HashSet::new(), // No filters
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        // Create a transaction with CreateAccount operation
        let envelope = make_test_envelope(1000, 1);

        // Should NOT be filtered when no types are configured
        assert!(!queue.is_filtered(&envelope));
    }

    #[test]
    fn test_is_filtered_matching_type() {
        let mut filtered = HashSet::new();
        filtered.insert(OperationType::CreateAccount);

        let config = TxQueueConfig {
            validate_signatures: false,
            validate_time_bounds: false,
            filtered_operation_types: filtered,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        // Create a transaction with CreateAccount operation
        let envelope = make_test_envelope(1000, 1);

        // Should be filtered
        assert!(queue.is_filtered(&envelope));
    }

    #[test]
    fn test_is_filtered_non_matching_type() {
        let mut filtered = HashSet::new();
        filtered.insert(OperationType::Payment); // Filter payments, not CreateAccount

        let config = TxQueueConfig {
            validate_signatures: false,
            validate_time_bounds: false,
            filtered_operation_types: filtered,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        // Create a transaction with CreateAccount operation
        let envelope = make_test_envelope(1000, 1);

        // Should NOT be filtered (we filter Payment, not CreateAccount)
        assert!(!queue.is_filtered(&envelope));
    }

    #[test]
    fn test_try_add_filtered_transaction() {
        let mut filtered = HashSet::new();
        filtered.insert(OperationType::CreateAccount);

        let config = TxQueueConfig {
            validate_signatures: false,
            validate_time_bounds: false,
            filtered_operation_types: filtered,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        // Create a transaction with CreateAccount operation
        let envelope = make_test_envelope(1000, 1);

        // Should return Filtered result
        assert_eq!(queue.try_add(envelope), TxQueueResult::Filtered);
    }

    #[test]
    fn test_is_filtered_soroban_type() {
        let mut filtered = HashSet::new();
        filtered.insert(OperationType::InvokeHostFunction);

        let config = TxQueueConfig {
            validate_signatures: false,
            validate_time_bounds: false,
            filtered_operation_types: filtered,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        // Create a Soroban transaction
        let envelope = make_soroban_envelope(1000);

        // Should be filtered
        assert!(queue.is_filtered(&envelope));
    }

    #[test]
    fn test_is_filtered_multiple_ops_one_filtered() {
        let mut filtered = HashSet::new();
        // Filter ManageSellOffer operations
        filtered.insert(OperationType::ManageSellOffer);

        let config = TxQueueConfig {
            validate_signatures: false,
            validate_time_bounds: false,
            filtered_operation_types: filtered,
            ..Default::default()
        };
        let queue = TransactionQueue::new(config);

        // Create a transaction with multiple operations - CreateAccount and ManageSellOffer
        let source = MuxedAccount::Ed25519(Uint256([0u8; 32]));
        let operations = vec![
            Operation {
                source_account: None,
                body: OperationBody::CreateAccount(CreateAccountOp {
                    destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1u8; 32]))),
                    starting_balance: 1000000000,
                }),
            },
            Operation {
                source_account: None,
                body: OperationBody::ManageSellOffer(ManageSellOfferOp {
                    selling: Asset::Native,
                    buying: Asset::CreditAlphanum4(AlphaNum4 {
                        asset_code: AssetCode4([b'U', b'S', b'D', 0]),
                        issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32]))),
                    }),
                    amount: 1000,
                    price: Price { n: 1, d: 1 },
                    offer_id: 0,
                }),
            },
        ];

        let tx = Transaction {
            source_account: source,
            fee: 1000,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: operations.try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![DecoratedSignature {
                hint: SignatureHint([0u8; 4]),
                signature: XdrSignature(vec![0u8; 64].try_into().unwrap()),
            }]
            .try_into()
            .unwrap(),
        });

        // Should be filtered because one operation is ManageSellOffer
        assert!(queue.is_filtered(&envelope));
    }
}
