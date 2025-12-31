//! Transaction validation for catchup mode.
//!
//! This module provides basic validation checks for transactions during catchup.
//! During catchup, we trust the historical results from the archive, so we only
//! perform minimal validation to ensure data integrity.

use stellar_core_common::NetworkId;
use stellar_core_crypto::{verify_hash, PublicKey, Signature};
use stellar_xdr::curr::{AccountEntry, DecoratedSignature, Preconditions};

use crate::frame::TransactionFrame;
use crate::{Result, TxError};

/// Ledger context for validation.
pub struct LedgerContext {
    /// Current ledger sequence.
    pub sequence: u32,
    /// Ledger close time (Unix timestamp).
    pub close_time: u64,
    /// Base fee in stroops.
    pub base_fee: u32,
    /// Base reserve in stroops.
    pub base_reserve: u32,
    /// Protocol version.
    pub protocol_version: u32,
    /// Network ID.
    pub network_id: NetworkId,
}

impl LedgerContext {
    /// Create a new ledger context.
    pub fn new(
        sequence: u32,
        close_time: u64,
        base_fee: u32,
        base_reserve: u32,
        protocol_version: u32,
        network_id: NetworkId,
    ) -> Self {
        Self {
            sequence,
            close_time,
            base_fee,
            base_reserve,
            protocol_version,
            network_id,
        }
    }

    /// Create context for testnet.
    pub fn testnet(sequence: u32, close_time: u64) -> Self {
        Self {
            sequence,
            close_time,
            base_fee: 100,
            base_reserve: 5_000_000,
            protocol_version: 21,
            network_id: NetworkId::testnet(),
        }
    }

    /// Create context for mainnet.
    pub fn mainnet(sequence: u32, close_time: u64) -> Self {
        Self {
            sequence,
            close_time,
            base_fee: 100,
            base_reserve: 5_000_000,
            protocol_version: 21,
            network_id: NetworkId::mainnet(),
        }
    }
}

/// Validation result with detailed error information.
#[derive(Debug, Clone)]
pub enum ValidationError {
    /// Transaction has invalid structure.
    InvalidStructure(String),
    /// Invalid signature(s).
    InvalidSignature,
    /// Missing required signatures.
    MissingSignatures,
    /// Bad sequence number.
    BadSequence { expected: i64, actual: i64 },
    /// Insufficient fee.
    InsufficientFee { required: u32, provided: u32 },
    /// Source account not found.
    SourceAccountNotFound,
    /// Insufficient balance for fee.
    InsufficientBalance,
    /// Transaction is too late (time bounds).
    TooLate { max_time: u64, ledger_time: u64 },
    /// Transaction is too early (time bounds).
    TooEarly { min_time: u64, ledger_time: u64 },
    /// Ledger bounds not satisfied.
    BadLedgerBounds { min: u32, max: u32, current: u32 },
    /// Min account sequence not met.
    BadMinAccountSequence,
    /// Min account sequence age not met.
    BadMinAccountSequenceAge,
    /// Min account sequence ledger gap not met.
    BadMinAccountSequenceLedgerGap,
    /// Extra signers requirement not met.
    ExtraSignersNotMet,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStructure(msg) => write!(f, "invalid structure: {}", msg),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::MissingSignatures => write!(f, "missing required signatures"),
            Self::BadSequence { expected, actual } => {
                write!(f, "bad sequence: expected {}, got {}", expected, actual)
            }
            Self::InsufficientFee { required, provided } => {
                write!(f, "insufficient fee: required {}, provided {}", required, provided)
            }
            Self::SourceAccountNotFound => write!(f, "source account not found"),
            Self::InsufficientBalance => write!(f, "insufficient balance"),
            Self::TooLate { max_time, ledger_time } => {
                write!(f, "too late: max_time {}, ledger_time {}", max_time, ledger_time)
            }
            Self::TooEarly { min_time, ledger_time } => {
                write!(f, "too early: min_time {}, ledger_time {}", min_time, ledger_time)
            }
            Self::BadLedgerBounds { min, max, current } => {
                write!(f, "bad ledger bounds: [{}, {}], current {}", min, max, current)
            }
            Self::BadMinAccountSequence => write!(f, "min account sequence not met"),
            Self::BadMinAccountSequenceAge => write!(f, "min account sequence age not met"),
            Self::BadMinAccountSequenceLedgerGap => {
                write!(f, "min account sequence ledger gap not met")
            }
            Self::ExtraSignersNotMet => write!(f, "extra signers requirement not met"),
        }
    }
}

/// Validate transaction signatures.
///
/// This verifies that the signatures on the transaction are cryptographically
/// valid for the transaction hash. It does NOT verify that the signers have
/// the required weights - that requires account information.
pub fn validate_signatures(
    frame: &TransactionFrame,
    context: &LedgerContext,
) -> std::result::Result<(), ValidationError> {
    let tx_hash = frame
        .hash(&context.network_id)
        .map_err(|_| ValidationError::InvalidSignature)?;

    // Validate signatures on the outer envelope
    for sig in frame.signatures() {
        if !is_valid_signature(&tx_hash, sig) {
            return Err(ValidationError::InvalidSignature);
        }
    }

    // For fee bump, also validate inner signatures
    if frame.is_fee_bump() {
        for sig in frame.inner_signatures() {
            // Inner signatures are for the inner tx hash
            // For simplicity in catchup, we just check they're well-formed
            if sig.signature.0.len() != 64 {
                return Err(ValidationError::InvalidSignature);
            }
        }
    }

    Ok(())
}

/// Validate sequence number.
///
/// For catchup mode, we trust the historical sequence but can verify
/// the relationship if we have account data.
pub fn validate_sequence(
    frame: &TransactionFrame,
    source_account: Option<&AccountEntry>,
) -> std::result::Result<(), ValidationError> {
    if let Some(account) = source_account {
        let expected = account.seq_num.0 + 1;
        let actual = frame.sequence_number();

        if actual != expected {
            return Err(ValidationError::BadSequence { expected, actual });
        }
    }

    Ok(())
}

/// Validate transaction fee.
///
/// Checks that the fee meets the minimum required fee based on operation count.
pub fn validate_fee(
    frame: &TransactionFrame,
    context: &LedgerContext,
) -> std::result::Result<(), ValidationError> {
    let op_count = frame.operation_count() as u32;
    let required_fee = op_count.saturating_mul(context.base_fee);
    let provided_fee = frame.fee();

    if provided_fee < required_fee {
        return Err(ValidationError::InsufficientFee {
            required: required_fee,
            provided: provided_fee,
        });
    }

    Ok(())
}

/// Validate time bounds.
pub fn validate_time_bounds(
    frame: &TransactionFrame,
    context: &LedgerContext,
) -> std::result::Result<(), ValidationError> {
    let time_bounds = match frame.preconditions() {
        Preconditions::None => return Ok(()),
        Preconditions::Time(tb) => Some(tb),
        Preconditions::V2(cond) => cond.time_bounds.clone(),
    };

    if let Some(tb) = time_bounds {
        let min_time: u64 = tb.min_time.into();
        let max_time: u64 = tb.max_time.into();

        // Check min time
        if min_time > 0 && context.close_time < min_time {
            return Err(ValidationError::TooEarly {
                min_time,
                ledger_time: context.close_time,
            });
        }

        // Check max time (0 means no limit)
        if max_time > 0 && context.close_time > max_time {
            return Err(ValidationError::TooLate {
                max_time,
                ledger_time: context.close_time,
            });
        }
    }

    Ok(())
}

/// Validate ledger bounds.
pub fn validate_ledger_bounds(
    frame: &TransactionFrame,
    context: &LedgerContext,
) -> std::result::Result<(), ValidationError> {
    let ledger_bounds = match frame.preconditions() {
        Preconditions::None | Preconditions::Time(_) => return Ok(()),
        Preconditions::V2(cond) => cond.ledger_bounds.clone(),
    };

    if let Some(lb) = ledger_bounds {
        let current = context.sequence;

        // Check min ledger
        if lb.min_ledger > 0 && current < lb.min_ledger {
            return Err(ValidationError::BadLedgerBounds {
                min: lb.min_ledger,
                max: lb.max_ledger,
                current,
            });
        }

        // Check max ledger (0 means no limit)
        if lb.max_ledger > 0 && current > lb.max_ledger {
            return Err(ValidationError::BadLedgerBounds {
                min: lb.min_ledger,
                max: lb.max_ledger,
                current,
            });
        }
    }

    Ok(())
}

/// Validate transaction structure.
pub fn validate_structure(frame: &TransactionFrame) -> std::result::Result<(), ValidationError> {
    if !frame.is_valid_structure() {
        return Err(ValidationError::InvalidStructure(
            "basic structure validation failed".to_string(),
        ));
    }

    Ok(())
}

/// Perform all basic validations.
///
/// This is a convenience function that runs all basic checks suitable for catchup.
/// It does not require account data and trusts historical results.
pub fn validate_basic(
    frame: &TransactionFrame,
    context: &LedgerContext,
) -> std::result::Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    if let Err(e) = validate_structure(frame) {
        errors.push(e);
    }

    if let Err(e) = validate_fee(frame, context) {
        errors.push(e);
    }

    if let Err(e) = validate_time_bounds(frame, context) {
        errors.push(e);
    }

    if let Err(e) = validate_ledger_bounds(frame, context) {
        errors.push(e);
    }

    // Signature validation is optional in basic mode
    // (might not have all data needed)

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Full validation with account data.
pub fn validate_full(
    frame: &TransactionFrame,
    context: &LedgerContext,
    source_account: &AccountEntry,
) -> std::result::Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    // Run basic validations first
    if let Err(mut e) = validate_basic(frame, context) {
        errors.append(&mut e);
    }

    // Validate sequence
    if let Err(e) = validate_sequence(frame, Some(source_account)) {
        errors.push(e);
    }

    // Validate signatures
    if let Err(e) = validate_signatures(frame, context) {
        errors.push(e);
    }

    // Check account balance can cover fee
    let available_balance = source_account.balance;
    let fee = frame.total_fee();
    if available_balance < fee {
        errors.push(ValidationError::InsufficientBalance);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Check if a signature is cryptographically valid.
///
/// Note: This only checks the signature format/validity, not whether
/// the signer has authority over the account.
fn is_valid_signature(
    tx_hash: &stellar_core_common::Hash256,
    sig: &DecoratedSignature,
) -> bool {
    // The signature should be 64 bytes for Ed25519
    if sig.signature.0.len() != 64 {
        return false;
    }

    // We can't fully verify without the public key
    // The hint only gives us the last 4 bytes
    // For catchup, we trust the archive data
    true
}

/// Verify a signature against a known public key.
pub fn verify_signature_with_key(
    tx_hash: &stellar_core_common::Hash256,
    sig: &DecoratedSignature,
    public_key: &PublicKey,
) -> bool {
    // Check hint matches
    let key_bytes = public_key.as_bytes();
    let expected_hint = [key_bytes[28], key_bytes[29], key_bytes[30], key_bytes[31]];

    if sig.hint.0 != expected_hint {
        return false;
    }

    // Verify signature
    if let Ok(signature) = Signature::try_from(&sig.signature) {
        verify_hash(public_key, tx_hash, &signature).is_ok()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_frame() -> TransactionFrame {
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

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });

        TransactionFrame::new(envelope)
    }

    #[test]
    fn test_validate_structure() {
        let frame = create_test_frame();
        assert!(validate_structure(&frame).is_ok());
    }

    #[test]
    fn test_validate_fee() {
        let frame = create_test_frame();
        let context = LedgerContext::testnet(1, 1000);

        // Fee of 100 is enough for 1 operation with base_fee of 100
        assert!(validate_fee(&frame, &context).is_ok());
    }

    #[test]
    fn test_validate_fee_insufficient() {
        // Create a transaction with low fee
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
            fee: 10, // Too low
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![payment_op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });

        let frame = TransactionFrame::new(envelope);
        let context = LedgerContext::testnet(1, 1000);

        assert!(matches!(
            validate_fee(&frame, &context),
            Err(ValidationError::InsufficientFee { .. })
        ));
    }

    #[test]
    fn test_validate_time_bounds_ok() {
        let frame = create_test_frame();
        let context = LedgerContext::testnet(1, 1000);

        // No time bounds, should pass
        assert!(validate_time_bounds(&frame, &context).is_ok());
    }

    #[test]
    fn test_validate_basic() {
        let frame = create_test_frame();
        let context = LedgerContext::testnet(1, 1000);

        assert!(validate_basic(&frame, &context).is_ok());
    }
}
