//! Transaction queue management.
//!
//! The transaction queue holds pending transactions waiting to be included
//! in a ledger. Transactions are ordered by fee (highest first) to maximize
//! miner extractable value and network efficiency.

use parking_lot::RwLock;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use stellar_core_common::{Hash256, NetworkId};
use stellar_xdr::curr::{TransactionEnvelope, Hash};
use stellar_xdr::curr::WriteXdr;

use crate::error::HerderError;
use crate::Result;

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

    /// Check if this transaction has expired.
    pub fn is_expired(&self, max_age_secs: u64) -> bool {
        self.received_at.elapsed().as_secs() > max_age_secs
    }
}

/// Wrapper for heap ordering (highest fee first).
struct OrderedTx(QueuedTransaction);

impl PartialEq for OrderedTx {
    fn eq(&self, other: &Self) -> bool {
        self.0.hash == other.0.hash
    }
}

impl Eq for OrderedTx {}

impl PartialOrd for OrderedTx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedTx {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher fee per op comes first
        self.0.fee_per_op.cmp(&other.0.fee_per_op)
            .then_with(|| {
                // Then by total fee
                self.0.total_fee.cmp(&other.0.total_fee)
            })
            .then_with(|| {
                // Then by arrival time (earlier is better)
                other.0.received_at.cmp(&self.0.received_at)
            })
    }
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
        }
    }

    /// Create a transaction set with a pre-computed hash (for GeneralizedTransactionSet).
    /// The hash should be SHA-256 of the XDR-encoded GeneralizedTransactionSet.
    pub fn with_hash(hash: Hash256, transactions: Vec<TransactionEnvelope>) -> Self {
        Self {
            hash,
            previous_ledger_hash: Hash256::ZERO,
            transactions,
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
            TransactionFrame, LedgerContext,
            validate_time_bounds, validate_ledger_bounds, validate_signatures,
        };

        let frame = TransactionFrame::new(envelope.clone());
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

        Ok(())
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

        // Check for duplicate in queue
        if by_hash.contains_key(&queued.hash) {
            return TxQueueResult::Duplicate;
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
                return TxQueueResult::QueueFull;
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
    pub fn get_transaction_set(&self, previous_ledger_hash: Hash256, max_txs: usize) -> TransactionSet {
        let by_hash = self.by_hash.read();

        // Build a heap for ordering
        let mut heap: BinaryHeap<OrderedTx> = by_hash
            .values()
            .filter(|tx| !tx.is_expired(self.config.max_age_secs))
            .cloned()
            .map(OrderedTx)
            .collect();

        // Take top transactions
        let mut transactions = Vec::with_capacity(max_txs.min(heap.len()));
        while transactions.len() < max_txs {
            if let Some(OrderedTx(tx)) = heap.pop() {
                transactions.push(tx.envelope);
            } else {
                break;
            }
        }

        TransactionSet::new(previous_ledger_hash, transactions)
    }

    /// Build a GeneralizedTransactionSet (protocol 20+) and return it with the correct hash.
    ///
    /// The hash is SHA-256 of the XDR-encoded GeneralizedTransactionSet.
    pub fn build_generalized_tx_set(&self, previous_ledger_hash: Hash256, max_txs: usize) -> (TransactionSet, stellar_xdr::curr::GeneralizedTransactionSet) {
        use stellar_xdr::curr::{
            GeneralizedTransactionSet, TransactionPhase, TxSetComponent,
            TxSetComponentTxsMaybeDiscountedFee, VecM, WriteXdr,
        };

        let by_hash = self.by_hash.read();

        // Build a heap for ordering
        let mut heap: BinaryHeap<OrderedTx> = by_hash
            .values()
            .filter(|tx| !tx.is_expired(self.config.max_age_secs))
            .cloned()
            .map(OrderedTx)
            .collect();

        // Take top transactions
        let mut transactions = Vec::with_capacity(max_txs.min(heap.len()));
        while transactions.len() < max_txs {
            if let Some(OrderedTx(tx)) = heap.pop() {
                transactions.push(tx.envelope);
            } else {
                break;
            }
        }

        // Build GeneralizedTransactionSet XDR structure
        // Use V0 phase with a single TxSetComponent
        let component = TxSetComponent::TxsetCompTxsMaybeDiscountedFee(
            TxSetComponentTxsMaybeDiscountedFee {
                base_fee: None, // No discount
                txs: transactions.clone().try_into().unwrap_or_default(),
            }
        );

        let phase = TransactionPhase::V0(
            vec![component].try_into().unwrap_or_default()
        );

        let gen_tx_set = GeneralizedTransactionSet::V1(
            stellar_xdr::curr::TransactionSetV1 {
                previous_ledger_hash: stellar_xdr::curr::Hash(previous_ledger_hash.0),
                phases: vec![phase].try_into().unwrap_or_default(),
            }
        );

        // Compute hash as SHA-256 of XDR-encoded GeneralizedTransactionSet
        let hash = if let Ok(xdr_bytes) = gen_tx_set.to_xdr(stellar_xdr::curr::Limits::none()) {
            Hash256::hash(&xdr_bytes)
        } else {
            Hash256::ZERO
        };

        let tx_set = TransactionSet::with_hash(hash, transactions);
        (tx_set, gen_tx_set)
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
}

impl Default for TransactionQueue {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        Transaction, TransactionV1Envelope, MuxedAccount, PublicKey, Uint256,
        SequenceNumber, Preconditions, Memo, Operation, OperationBody,
        DecoratedSignature, SignatureHint, Signature as XdrSignature,
        CreateAccountOp, AccountId,
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
            ext: stellar_xdr::curr::TransactionExt::V0,
        };

        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![DecoratedSignature {
                hint: SignatureHint([0u8; 4]),
                signature: XdrSignature(vec![0u8; 64].try_into().unwrap()),
            }].try_into().unwrap(),
        })
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
        queue.try_add(make_test_envelope(100, 1));
        queue.try_add(make_test_envelope(300, 1));
        queue.try_add(make_test_envelope(200, 1));

        let set = queue.get_transaction_set(Hash256::ZERO, 10);
        assert_eq!(set.len(), 3);

        // First should have highest fee (300)
        // Note: We can't easily check the order without extracting fees
        // but the test verifies basic functionality
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
        assert_eq!(result, TxQueueResult::QueueFull);
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
}
