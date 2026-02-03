//! Transaction frame - wrapper around TransactionEnvelope.
//!
//! This module provides the [`TransactionFrame`] type, which wraps XDR transaction
//! envelopes and provides convenient accessors for transaction properties.
//!
//! # Key Features
//!
//! - Unified API for all transaction envelope types (V0, V1, FeeBump)
//! - Transaction hash computation with network ID
//! - Resource extraction for surge pricing and limits
//! - Soroban transaction detection and data access
//!
//! # Example
//!
//! ```ignore
//! use stellar_core_tx::TransactionFrame;
//! use stellar_core_common::NetworkId;
//!
//! let frame = TransactionFrame::new(envelope);
//!
//! // Access transaction properties
//! println!("Fee: {}", frame.fee());
//! println!("Sequence: {}", frame.sequence_number());
//! println!("Operations: {}", frame.operation_count());
//!
//! // Compute transaction hash
//! let hash = frame.hash(&NetworkId::testnet())?;
//! ```

use soroban_env_host_p25::fees::TransactionResources;
use stellar_core_common::{Hash256, NetworkId, Resource};
use stellar_core_crypto::sha256;
use stellar_xdr::curr::Limits;
use stellar_xdr::curr::{
    AccountId, DecoratedSignature, EnvelopeType, FeeBumpTransactionInnerTx, Hash,
    InvokeHostFunctionOp, LedgerKey, Memo, MuxedAccount, Operation, OperationBody, Preconditions,
    SorobanTransactionData, SorobanTransactionDataExt, Transaction, TransactionEnvelope,
    TransactionExt, TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    Uint256, VecM, WriteXdr,
};

use crate::{Result, TxError};

/// Wrapper around a TransactionEnvelope providing unified access to transaction data.
///
/// `TransactionFrame` abstracts over the different transaction envelope versions
/// (V0, V1, and FeeBump) to provide a consistent API. It handles:
///
/// - Extracting common properties (source, fee, sequence, operations)
/// - Computing transaction hashes with network ID binding
/// - Detecting Soroban vs. classic transactions
/// - Extracting resource requirements for fee calculation
///
/// # Transaction Types
///
/// - **V0 Transactions**: Legacy format with raw Ed25519 public key as source
/// - **V1 Transactions**: Modern format with MuxedAccount support
/// - **FeeBump Transactions**: Wraps an inner transaction with a higher fee
///
/// # Hash Computation
///
/// The transaction hash is computed by hashing the `TransactionSignaturePayload`,
/// which includes the network ID. This ensures signatures are network-specific.
///
/// ```ignore
/// let hash = frame.hash(&NetworkId::mainnet())?;
/// ```
#[derive(Debug, Clone)]
pub struct TransactionFrame {
    /// The underlying XDR transaction envelope.
    envelope: TransactionEnvelope,
    /// Cached transaction hash (lazily computed).
    hash: Option<Hash256>,
    /// Network ID used when computing the cached hash.
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
    fn v0_to_v1_transaction(&self, v0: &stellar_xdr::curr::TransactionV0) -> Result<Transaction> {
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

    /// Get the fee-paying account ID (unwrapped from MuxedAccount).
    /// For fee bump transactions, this is the outer source. For regular transactions,
    /// this is the same as the inner source.
    pub fn fee_source_account_id(&self) -> AccountId {
        muxed_to_account_id(&self.fee_source_account())
    }

    /// Get the inner source account ID (unwrapped from MuxedAccount).
    /// For fee bump transactions, this is the inner tx source (sequence-number-source).
    /// For regular transactions, this is the same as the fee source.
    pub fn inner_source_account_id(&self) -> AccountId {
        muxed_to_account_id(&self.inner_source_account())
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

    /// Get the declared Soroban resource fee (0 for non-Soroban).
    pub fn declared_soroban_resource_fee(&self) -> i64 {
        if !self.is_soroban() {
            return 0;
        }
        self.soroban_data()
            .map(|data| data.resource_fee)
            .unwrap_or(0)
    }

    /// Get the inclusion fee (total fee minus Soroban resource fee).
    pub fn inclusion_fee(&self) -> i64 {
        if self.is_soroban() {
            let resource_fee = self.declared_soroban_resource_fee();
            if resource_fee < 0 {
                panic!("TransactionFrame::inclusion_fee: negative resource fee");
            }
            return self.total_fee() - resource_fee;
        }

        self.total_fee()
    }

    /// Get the refundable fee for Soroban transactions.
    ///
    /// The refundable fee is the portion of the Soroban resource fee that can be
    /// refunded if not fully consumed during execution. For non-Soroban transactions,
    /// returns `None`.
    ///
    /// # C++ Parity
    ///
    /// Matches `TransactionFrame::getRefundableFee()` in C++ stellar-core.
    pub fn refundable_fee(&self) -> Option<i64> {
        if !self.is_soroban() {
            return None;
        }

        // The refundable fee is the Soroban resource fee.
        // The inclusion fee is non-refundable; the resource fee covers compute,
        // storage, and other costs that may be partially refunded.
        let resource_fee = self.declared_soroban_resource_fee();
        if resource_fee > 0 {
            Some(resource_fee)
        } else {
            None
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

    /// Check if this transaction includes DEX-related operations.
    pub fn has_dex_operations(&self) -> bool {
        self.operations().iter().any(|op| {
            matches!(
                op.body,
                OperationBody::ManageSellOffer(_)
                    | OperationBody::ManageBuyOffer(_)
                    | OperationBody::CreatePassiveSellOffer(_)
                    | OperationBody::PathPaymentStrictSend(_)
                    | OperationBody::PathPaymentStrictReceive(_)
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

    fn is_restore_footprint_tx(&self) -> bool {
        self.operations()
            .iter()
            .any(|op| matches!(op.body, OperationBody::RestoreFootprint(_)))
    }

    /// Return the resource footprint used for surge pricing and limits.
    pub fn resources(&self, use_byte_limit_in_classic: bool, ledger_version: u32) -> Resource {
        let tx_size = self.tx_size_bytes() as i64;

        if self.is_soroban() {
            let data = self.soroban_data();
            let fallback_resources = stellar_xdr::curr::SorobanResources {
                footprint: stellar_xdr::curr::LedgerFootprint {
                    read_only: VecM::default(),
                    read_write: VecM::default(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            };
            let resources = data.map(|d| &d.resources).unwrap_or(&fallback_resources);

            let op_count = 1i64;
            let disk_read_entries = soroban_disk_read_entries(
                resources,
                data.map(|d| &d.ext),
                self.is_restore_footprint_tx(),
                ledger_version,
            );
            let write_entries = resources.footprint.read_write.len() as i64;

            return Resource::new(vec![
                op_count,
                resources.instructions as i64,
                tx_size,
                resources.disk_read_bytes as i64,
                resources.write_bytes as i64,
                disk_read_entries,
                write_entries,
            ]);
        }

        if use_byte_limit_in_classic {
            Resource::new(vec![self.operation_count() as i64, tx_size])
        } else {
            Resource::new(vec![self.operation_count() as i64])
        }
    }

    /// Return the transaction size in bytes (XDR encoding).
    pub fn tx_size_bytes(&self) -> u32 {
        self.envelope
            .to_xdr(Limits::none())
            .map(|bytes| bytes.len() as u32)
            .unwrap_or(0)
    }

    /// Return the inner transaction envelope size for fee bump, or full envelope size for regular tx.
    /// This is used for Soroban resource fee computation, matching C++ behavior where
    /// FeeBumpTransactionFrame::getResources() delegates to mInnerTx->getResources().
    pub fn inner_tx_size_bytes(&self) -> u32 {
        match &self.envelope {
            TransactionEnvelope::TxFeeBump(fee_bump) => {
                // Get the inner transaction envelope and compute its size
                let inner_envelope = match &fee_bump.tx.inner_tx {
                    stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                        TransactionEnvelope::Tx(inner.clone())
                    }
                };
                inner_envelope
                    .to_xdr(Limits::none())
                    .map(|bytes| bytes.len() as u32)
                    .unwrap_or(0)
            }
            _ => self.tx_size_bytes(),
        }
    }

    /// Build Soroban transaction resources for fee computation.
    pub fn soroban_transaction_resources(
        &self,
        ledger_version: u32,
        contract_events_size_bytes: u32,
    ) -> Option<TransactionResources> {
        if !self.is_soroban() {
            return None;
        }
        let data = self.soroban_data()?;
        let disk_read_entries = soroban_disk_read_entries(
            &data.resources,
            Some(&data.ext),
            self.is_restore_footprint_tx(),
            ledger_version,
        );
        Some(TransactionResources {
            instructions: data.resources.instructions,
            disk_read_entries: disk_read_entries as u32,
            write_entries: data.resources.footprint.read_write.len() as u32,
            disk_read_bytes: data.resources.disk_read_bytes,
            write_bytes: data.resources.write_bytes,
            contract_events_size_bytes,
            // Use inner_tx_size_bytes to match C++ behavior: FeeBumpTransactionFrame::getResources()
            // delegates to mInnerTx->getResources(), so the tx size is the inner tx envelope size.
            transaction_size_bytes: self.inner_tx_size_bytes(),
        })
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
        MuxedAccount::Ed25519(key) => AccountId(
            stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key.clone()),
        ),
        MuxedAccount::MuxedEd25519(m) => AccountId(
            stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(m.ed25519.clone()),
        ),
    }
}

/// Extract the Ed25519 public key bytes from a MuxedAccount.
pub fn muxed_to_ed25519(muxed: &MuxedAccount) -> &Uint256 {
    match muxed {
        MuxedAccount::Ed25519(key) => key,
        MuxedAccount::MuxedEd25519(m) => &m.ed25519,
    }
}

fn is_soroban_ledger_key(key: &LedgerKey) -> bool {
    matches!(key, LedgerKey::ContractData(_) | LedgerKey::ContractCode(_))
}

fn soroban_disk_read_entries(
    resources: &stellar_xdr::curr::SorobanResources,
    ext: Option<&SorobanTransactionDataExt>,
    is_restore_footprint: bool,
    ledger_version: u32,
) -> i64 {
    if is_restore_footprint {
        return resources.footprint.read_write.len() as i64;
    }

    if ledger_version < 23 {
        return (resources.footprint.read_only.len() + resources.footprint.read_write.len()) as i64;
    }

    let mut count = 0i64;
    for key in resources.footprint.read_only.iter() {
        if !is_soroban_ledger_key(key) {
            count += 1;
        }
    }
    for key in resources.footprint.read_write.iter() {
        if !is_soroban_ledger_key(key) {
            count += 1;
        }
    }

    if ledger_version >= 23 {
        if let Some(SorobanTransactionDataExt::V1(ext)) = ext {
            count += ext.archived_soroban_entries.len() as i64;
        }
    }

    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_core_common::ResourceType;
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

    fn create_soroban_transaction() -> TransactionEnvelope {
        create_soroban_transaction_with_fees(0, 100)
    }

    fn create_soroban_transaction_with_fees(
        resource_fee: i64,
        total_fee: u32,
    ) -> TransactionEnvelope {
        let source = MuxedAccount::Ed25519(Uint256([2u8; 32]));
        let function_name = ScSymbol(StringM::<32>::try_from("test".to_string()).expect("symbol"));
        let host_function = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
                Uint256([3u8; 32]),
            ))),
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

        let read_only = vec![
            LedgerKey::Account(LedgerKeyAccount {
                account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([4u8; 32]))),
            }),
            LedgerKey::ContractData(LedgerKeyContractData {
                contract: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                    [5u8; 32],
                )))),
                key: ScVal::I32(0),
                durability: ContractDataDurability::Persistent,
            }),
        ];
        let read_write = vec![LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: Hash([6u8; 32]),
        })];
        let footprint = LedgerFootprint {
            read_only: read_only.try_into().unwrap(),
            read_write: read_write.try_into().unwrap(),
        };
        let resources = SorobanResources {
            footprint,
            instructions: 100,
            disk_read_bytes: 55,
            write_bytes: 21,
        };
        let ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
            archived_soroban_entries: vec![0u32, 1u32].try_into().unwrap(),
        });

        let tx = Transaction {
            source_account: source,
            fee: total_fee,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V1(SorobanTransactionData {
                ext,
                resources,
                resource_fee,
            }),
        };

        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        })
    }

    fn create_fee_bump_soroban(
        inner_fee: u32,
        resource_fee: i64,
        outer_fee: i64,
    ) -> TransactionEnvelope {
        let inner = create_soroban_transaction_with_fees(resource_fee, inner_fee);
        let inner_env = match inner {
            TransactionEnvelope::Tx(env) => env,
            _ => panic!("expected inner tx"),
        };

        let fee_bump = FeeBumpTransaction {
            fee_source: MuxedAccount::Ed25519(Uint256([3u8; 32])),
            fee: outer_fee,
            inner_tx: FeeBumpTransactionInnerTx::Tx(inner_env),
            ext: FeeBumpTransactionExt::V0,
        };

        TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: fee_bump,
            signatures: VecM::default(),
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
    fn test_resources_classic_ops() {
        let envelope = create_test_transaction();
        let frame = TransactionFrame::new(envelope);
        let resources = frame.resources(false, 25);

        assert_eq!(resources.size(), 1);
        assert_eq!(resources.get_val(ResourceType::Operations), 1);
    }

    #[test]
    fn test_resources_soroban_disk_reads() {
        let envelope = create_soroban_transaction();
        let frame = TransactionFrame::new(envelope);
        let resources = frame.resources(false, 25);

        assert_eq!(resources.size(), 7);
        assert_eq!(resources.get_val(ResourceType::Operations), 1);
        assert_eq!(resources.get_val(ResourceType::Instructions), 100);
        assert_eq!(resources.get_val(ResourceType::DiskReadBytes), 55);
        assert_eq!(resources.get_val(ResourceType::WriteBytes), 21);
        assert_eq!(resources.get_val(ResourceType::ReadLedgerEntries), 3);
        assert_eq!(resources.get_val(ResourceType::WriteLedgerEntries), 1);
    }

    #[test]
    fn test_structure_validation() {
        let envelope = create_test_transaction();
        let frame = TransactionFrame::new(envelope);
        assert!(frame.is_valid_structure());
    }

    #[test]
    fn test_inclusion_fee_classic() {
        let envelope = create_test_transaction();
        let frame = TransactionFrame::new(envelope);
        assert_eq!(frame.declared_soroban_resource_fee(), 0);
        assert_eq!(frame.inclusion_fee(), frame.total_fee());
    }

    #[test]
    fn test_inclusion_fee_soroban() {
        let envelope = create_soroban_transaction_with_fees(200, 1000);
        let frame = TransactionFrame::new(envelope);
        assert_eq!(frame.declared_soroban_resource_fee(), 200);
        assert_eq!(frame.inclusion_fee(), 800);
    }

    #[test]
    fn test_inclusion_fee_fee_bump_soroban() {
        let envelope = create_fee_bump_soroban(600, 150, 900);
        let frame = TransactionFrame::new(envelope);
        assert_eq!(frame.declared_soroban_resource_fee(), 150);
        assert_eq!(frame.inclusion_fee(), 750);
    }

    /// Test TransactionFrame::with_network creates frame with network ID.
    #[test]
    fn test_frame_with_network() {
        let envelope = create_test_transaction();
        let network = NetworkId::testnet();
        let frame = TransactionFrame::with_network(envelope, network.clone());

        // Hash should be computed with the network ID
        let hash_result = frame.hash(&network);
        assert!(hash_result.is_ok());
    }

    /// Test operation_count for classic transactions.
    #[test]
    fn test_operation_count() {
        let envelope = create_test_transaction();
        let frame = TransactionFrame::new(envelope);
        assert_eq!(frame.operation_count(), 1);
    }

    /// Test fee extraction.
    #[test]
    fn test_fee_extraction() {
        let envelope = create_test_transaction();
        let frame = TransactionFrame::new(envelope);
        assert_eq!(frame.fee(), 100);
    }

    /// Test source_account extraction.
    #[test]
    fn test_source_account() {
        let envelope = create_test_transaction();
        let frame = TransactionFrame::new(envelope);
        let source = frame.source_account();
        // Should be MuxedAccount::Ed25519 with all zeros
        match source {
            MuxedAccount::Ed25519(key) => {
                assert_eq!(key.0, [0u8; 32]);
            }
            _ => panic!("Expected MuxedAccount::Ed25519"),
        }
    }

    /// Test memo extraction.
    #[test]
    fn test_memo() {
        let envelope = create_test_transaction();
        let frame = TransactionFrame::new(envelope);
        assert!(matches!(frame.memo(), Memo::None));
    }
}
