//! Transaction frame - wrapper around TransactionEnvelope.

use stellar_core_common::{Hash256, NetworkId};
use stellar_core_crypto::sha256;
use stellar_xdr::curr::{
    AccountId, DecoratedSignature, EnvelopeType, FeeBumpTransactionInnerTx, Hash,
    InvokeHostFunctionOp, Memo, MuxedAccount, Operation, OperationBody, Preconditions,
    SorobanTransactionData, Transaction, TransactionEnvelope, TransactionExt,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    TransactionV1Envelope, Uint256, WriteXdr,
};
use stellar_xdr::curr::Limits;

use crate::{Result, TxError};

/// A wrapper around a TransactionEnvelope that provides convenient access
/// to transaction properties and operations.
#[derive(Debug, Clone)]
pub struct TransactionFrame {
    /// The underlying transaction envelope.
    envelope: TransactionEnvelope,
    /// Cached transaction hash (computed on demand).
    hash: Option<Hash256>,
    /// Network ID used for hash computation.
    network_id: Option<NetworkId>,
}

impl TransactionFrame {
    /// Create a new TransactionFrame from an envelope.
    pub fn new(envelope: TransactionEnvelope) -> Self {
        Self {
            envelope,
            hash: None,
            network_id: None,
        }
    }

    /// Create a new TransactionFrame with a known network ID.
    pub fn with_network(envelope: TransactionEnvelope, network_id: NetworkId) -> Self {
        Self {
            envelope,
            hash: None,
            network_id: Some(network_id),
        }
    }

    /// Get the underlying envelope.
    pub fn envelope(&self) -> &TransactionEnvelope {
        &self.envelope
    }

    /// Consume the frame and return the envelope.
    pub fn into_envelope(self) -> TransactionEnvelope {
        self.envelope
    }

    /// Compute the transaction hash for a given network.
    pub fn hash(&self, network_id: &NetworkId) -> Result<Hash256> {
        // Create the signature payload
        let payload = self.signature_payload(network_id)?;

        // Serialize and hash
        let bytes = payload
            .to_xdr(Limits::none())
            .map_err(|e| TxError::Internal(format!("XDR serialization failed: {}", e)))?;

        Ok(sha256(&bytes))
    }

    /// Get the cached hash or compute it if network ID is available.
    pub fn cached_hash(&self) -> Option<Hash256> {
        self.hash
    }

    /// Compute and cache the hash.
    pub fn compute_hash(&mut self, network_id: &NetworkId) -> Result<Hash256> {
        let hash = self.hash(network_id)?;
        self.hash = Some(hash);
        self.network_id = Some(*network_id);
        Ok(hash)
    }

    /// Create the signature payload for signing/verification.
    fn signature_payload(&self, network_id: &NetworkId) -> Result<TransactionSignaturePayload> {
        let tagged_tx = match &self.envelope {
            TransactionEnvelope::TxV0(env) => {
                // Convert V0 to V1 for signature payload
                let tx = self.v0_to_v1_transaction(&env.tx)?;
                TransactionSignaturePayloadTaggedTransaction::Tx(tx)
            }
            TransactionEnvelope::Tx(env) => {
                TransactionSignaturePayloadTaggedTransaction::Tx(env.tx.clone())
            }
            TransactionEnvelope::TxFeeBump(env) => {
                TransactionSignaturePayloadTaggedTransaction::TxFeeBump(env.tx.clone())
            }
        };

        Ok(TransactionSignaturePayload {
            network_id: Hash(network_id.0 .0),
            tagged_transaction: tagged_tx,
        })
    }

    /// Convert a V0 transaction to V1 (needed for signature payload).
    fn v0_to_v1_transaction(
        &self,
        v0: &stellar_xdr::curr::TransactionV0,
    ) -> Result<Transaction> {
        // V0 stores raw public key bytes, V1 uses MuxedAccount
        let source_account = MuxedAccount::Ed25519(v0.source_account_ed25519.clone());

        Ok(Transaction {
            source_account,
            fee: v0.fee,
            seq_num: v0.seq_num.clone(),
            cond: Preconditions::None,
            memo: v0.memo.clone(),
            operations: v0.operations.clone(),
            ext: TransactionExt::V0,
        })
    }

    /// Get the source account.
    pub fn source_account(&self) -> MuxedAccount {
        match &self.envelope {
            TransactionEnvelope::TxV0(env) => {
                MuxedAccount::Ed25519(env.tx.source_account_ed25519.clone())
            }
            TransactionEnvelope::Tx(env) => env.tx.source_account.clone(),
            TransactionEnvelope::TxFeeBump(env) => env.tx.fee_source.clone(),
        }
    }

    /// Get the source account ID (unwrapped from MuxedAccount).
    pub fn source_account_id(&self) -> AccountId {
        muxed_to_account_id(&self.source_account())
    }

    /// Get the fee-paying account (for fee bump, this is the outer source).
    pub fn fee_source_account(&self) -> MuxedAccount {
        match &self.envelope {
            TransactionEnvelope::TxV0(env) => {
                MuxedAccount::Ed25519(env.tx.source_account_ed25519.clone())
            }
            TransactionEnvelope::Tx(env) => env.tx.source_account.clone(),
            TransactionEnvelope::TxFeeBump(env) => env.tx.fee_source.clone(),
        }
    }

    /// Get the inner transaction source (for fee bump, this is the inner tx source).
    pub fn inner_source_account(&self) -> MuxedAccount {
        match &self.envelope {
            TransactionEnvelope::TxV0(env) => {
                MuxedAccount::Ed25519(env.tx.source_account_ed25519.clone())
            }
            TransactionEnvelope::Tx(env) => env.tx.source_account.clone(),
            TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.source_account.clone(),
            },
        }
    }

    /// Get the sequence number.
    pub fn sequence_number(&self) -> i64 {
        match &self.envelope {
            TransactionEnvelope::TxV0(env) => env.tx.seq_num.0,
            TransactionEnvelope::Tx(env) => env.tx.seq_num.0,
            TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.seq_num.0,
            },
        }
    }

    /// Get the fee.
    pub fn fee(&self) -> u32 {
        match &self.envelope {
            TransactionEnvelope::TxV0(env) => env.tx.fee,
            TransactionEnvelope::Tx(env) => env.tx.fee,
            TransactionEnvelope::TxFeeBump(env) => {
                // For fee bump, the outer fee is the total fee
                // Convert i64 to u32 safely
                env.tx.fee.min(u32::MAX as i64) as u32
            }
        }
    }

    /// Get the total fee (for fee bump, this is the outer fee).
    pub fn total_fee(&self) -> i64 {
        match &self.envelope {
            TransactionEnvelope::TxV0(env) => env.tx.fee as i64,
            TransactionEnvelope::Tx(env) => env.tx.fee as i64,
            TransactionEnvelope::TxFeeBump(env) => env.tx.fee,
        }
    }

    /// Get the inner transaction's original fee (for fee bump).
    pub fn inner_fee(&self) -> u32 {
        match &self.envelope {
            TransactionEnvelope::TxV0(env) => env.tx.fee,
            TransactionEnvelope::Tx(env) => env.tx.fee,
            TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.fee,
            },
        }
    }

    /// Get the operations.
    pub fn operations(&self) -> &[Operation] {
        match &self.envelope {
            TransactionEnvelope::TxV0(env) => env.tx.operations.as_slice(),
            TransactionEnvelope::Tx(env) => env.tx.operations.as_slice(),
            TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.operations.as_slice(),
            },
        }
    }

    /// Get the number of operations.
    pub fn operation_count(&self) -> usize {
        self.operations().len()
    }

    /// Get the memo.
    pub fn memo(&self) -> &Memo {
        match &self.envelope {
            TransactionEnvelope::TxV0(env) => &env.tx.memo,
            TransactionEnvelope::Tx(env) => &env.tx.memo,
            TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => &inner.tx.memo,
            },
        }
    }

    /// Get the preconditions (time bounds, ledger bounds, etc.).
    pub fn preconditions(&self) -> Preconditions {
        match &self.envelope {
            TransactionEnvelope::TxV0(env) => {
                // V0 only has time bounds
                if let Some(tb) = &env.tx.time_bounds {
                    Preconditions::Time(tb.clone())
                } else {
                    Preconditions::None
                }
            }
            TransactionEnvelope::Tx(env) => env.tx.cond.clone(),
            TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.cond.clone(),
            },
        }
    }

    /// Get the signatures.
    pub fn signatures(&self) -> &[DecoratedSignature] {
        match &self.envelope {
            TransactionEnvelope::TxV0(env) => env.signatures.as_slice(),
            TransactionEnvelope::Tx(env) => env.signatures.as_slice(),
            TransactionEnvelope::TxFeeBump(env) => env.signatures.as_slice(),
        }
    }

    /// Get the inner transaction signatures (for fee bump).
    pub fn inner_signatures(&self) -> &[DecoratedSignature] {
        match &self.envelope {
            TransactionEnvelope::TxV0(env) => env.signatures.as_slice(),
            TransactionEnvelope::Tx(env) => env.signatures.as_slice(),
            TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => inner.signatures.as_slice(),
            },
        }
    }

    /// Check if this is a fee bump transaction.
    pub fn is_fee_bump(&self) -> bool {
        matches!(&self.envelope, TransactionEnvelope::TxFeeBump(_))
    }

    /// Check if this is a Soroban transaction.
    pub fn is_soroban(&self) -> bool {
        self.operations().iter().any(|op| {
            matches!(
                op.body,
                OperationBody::InvokeHostFunction(_)
                    | OperationBody::ExtendFootprintTtl(_)
                    | OperationBody::RestoreFootprint(_)
            )
        })
    }

    /// Get the Soroban transaction data (if present).
    pub fn soroban_data(&self) -> Option<&SorobanTransactionData> {
        match &self.envelope {
            TransactionEnvelope::TxV0(_) => None,
            TransactionEnvelope::Tx(env) => match &env.tx.ext {
                TransactionExt::V0 => None,
                TransactionExt::V1(data) => Some(data),
            },
            TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => match &inner.tx.ext {
                    TransactionExt::V0 => None,
                    TransactionExt::V1(data) => Some(data),
                },
            },
        }
    }

    /// Get the InvokeHostFunction operations (if this is a Soroban transaction).
    pub fn invoke_host_function_ops(&self) -> Vec<&InvokeHostFunctionOp> {
        self.operations()
            .iter()
            .filter_map(|op| match &op.body {
                OperationBody::InvokeHostFunction(ihf) => Some(ihf),
                _ => None,
            })
            .collect()
    }

    /// Get the envelope type.
    pub fn envelope_type(&self) -> EnvelopeType {
        match &self.envelope {
            TransactionEnvelope::TxV0(_) => EnvelopeType::TxV0,
            TransactionEnvelope::Tx(_) => EnvelopeType::Tx,
            TransactionEnvelope::TxFeeBump(_) => EnvelopeType::TxFeeBump,
        }
    }

    /// Check if this transaction has valid structure (basic syntactic checks).
    pub fn is_valid_structure(&self) -> bool {
        // Must have at least one operation
        if self.operations().is_empty() {
            return false;
        }

        // Must have at most 100 operations
        if self.operations().len() > 100 {
            return false;
        }

        // Fee must be positive
        if self.fee() == 0 {
            return false;
        }

        // If Soroban, must have exactly one operation
        if self.is_soroban() && self.operations().len() != 1 {
            return false;
        }

        true
    }
}

/// Convert a MuxedAccount to AccountId.
pub fn muxed_to_account_id(muxed: &MuxedAccount) -> AccountId {
    match muxed {
        MuxedAccount::Ed25519(key) => {
            AccountId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key.clone()))
        }
        MuxedAccount::MuxedEd25519(m) => {
            AccountId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                m.ed25519.clone(),
            ))
        }
    }
}

/// Extract the Ed25519 public key bytes from a MuxedAccount.
pub fn muxed_to_ed25519(muxed: &MuxedAccount) -> &Uint256 {
    match muxed {
        MuxedAccount::Ed25519(key) => key,
        MuxedAccount::MuxedEd25519(m) => &m.ed25519,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_transaction() -> TransactionEnvelope {
        // Create a minimal valid transaction
        let source = MuxedAccount::Ed25519(Uint256([0u8; 32]));
        let dest = MuxedAccount::Ed25519(Uint256([1u8; 32]));

        let payment_op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: dest,
                asset: Asset::Native,
                amount: 1000,
            }),
        };

        let tx = Transaction {
            source_account: source,
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![payment_op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        })
    }

    #[test]
    fn test_frame_creation() {
        let envelope = create_test_transaction();
        let frame = TransactionFrame::new(envelope.clone());

        assert_eq!(frame.operation_count(), 1);
        assert_eq!(frame.fee(), 100);
        assert_eq!(frame.sequence_number(), 1);
        assert!(!frame.is_fee_bump());
        assert!(!frame.is_soroban());
    }

    #[test]
    fn test_hash_computation() {
        let envelope = create_test_transaction();
        let frame = TransactionFrame::new(envelope);

        let network_id = NetworkId::testnet();
        let hash = frame.hash(&network_id).unwrap();

        // Hash should be deterministic
        let hash2 = frame.hash(&network_id).unwrap();
        assert_eq!(hash, hash2);

        // Different network should produce different hash
        let mainnet_id = NetworkId::mainnet();
        let hash3 = frame.hash(&mainnet_id).unwrap();
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_structure_validation() {
        let envelope = create_test_transaction();
        let frame = TransactionFrame::new(envelope);
        assert!(frame.is_valid_structure());
    }
}
