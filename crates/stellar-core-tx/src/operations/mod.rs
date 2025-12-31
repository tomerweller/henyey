//! Operation types and validation.
//!
//! This module enumerates all Stellar operation types and provides
//! basic validation for each operation, as well as execution logic.

pub mod execute;

use stellar_xdr::curr::{
    AllowTrustOp, BeginSponsoringFutureReservesOp, BumpSequenceOp, ChangeTrustOp,
    ClaimClaimableBalanceOp, ClawbackClaimableBalanceOp, ClawbackOp, CreateAccountOp,
    CreateClaimableBalanceOp, CreatePassiveSellOfferOp, ExtendFootprintTtlOp,
    InvokeHostFunctionOp, LiquidityPoolDepositOp, LiquidityPoolWithdrawOp, ManageBuyOfferOp,
    ManageDataOp, ManageSellOfferOp, MuxedAccount, Operation, OperationBody,
    PathPaymentStrictReceiveOp, PathPaymentStrictSendOp, PaymentOp, RestoreFootprintOp,
    SetOptionsOp, SetTrustLineFlagsOp,
};

/// Enumeration of all operation types in Stellar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationType {
    // Classic operations
    CreateAccount,
    Payment,
    PathPaymentStrictReceive,
    ManageSellOffer,
    CreatePassiveSellOffer,
    SetOptions,
    ChangeTrust,
    AllowTrust,
    AccountMerge,
    Inflation,
    ManageData,
    BumpSequence,
    ManageBuyOffer,
    PathPaymentStrictSend,
    CreateClaimableBalance,
    ClaimClaimableBalance,
    BeginSponsoringFutureReserves,
    EndSponsoringFutureReserves,
    RevokeSponsorship,
    Clawback,
    ClawbackClaimableBalance,
    SetTrustLineFlags,
    LiquidityPoolDeposit,
    LiquidityPoolWithdraw,

    // Soroban operations
    InvokeHostFunction,
    ExtendFootprintTtl,
    RestoreFootprint,
}

impl OperationType {
    /// Check if this is a Soroban operation.
    pub fn is_soroban(&self) -> bool {
        matches!(
            self,
            OperationType::InvokeHostFunction
                | OperationType::ExtendFootprintTtl
                | OperationType::RestoreFootprint
        )
    }

    /// Check if this is a classic operation.
    pub fn is_classic(&self) -> bool {
        !self.is_soroban()
    }

    /// Get the operation type from an operation body.
    pub fn from_body(body: &OperationBody) -> Self {
        match body {
            OperationBody::CreateAccount(_) => OperationType::CreateAccount,
            OperationBody::Payment(_) => OperationType::Payment,
            OperationBody::PathPaymentStrictReceive(_) => OperationType::PathPaymentStrictReceive,
            OperationBody::ManageSellOffer(_) => OperationType::ManageSellOffer,
            OperationBody::CreatePassiveSellOffer(_) => OperationType::CreatePassiveSellOffer,
            OperationBody::SetOptions(_) => OperationType::SetOptions,
            OperationBody::ChangeTrust(_) => OperationType::ChangeTrust,
            OperationBody::AllowTrust(_) => OperationType::AllowTrust,
            OperationBody::AccountMerge(_) => OperationType::AccountMerge,
            OperationBody::Inflation => OperationType::Inflation,
            OperationBody::ManageData(_) => OperationType::ManageData,
            OperationBody::BumpSequence(_) => OperationType::BumpSequence,
            OperationBody::ManageBuyOffer(_) => OperationType::ManageBuyOffer,
            OperationBody::PathPaymentStrictSend(_) => OperationType::PathPaymentStrictSend,
            OperationBody::CreateClaimableBalance(_) => OperationType::CreateClaimableBalance,
            OperationBody::ClaimClaimableBalance(_) => OperationType::ClaimClaimableBalance,
            OperationBody::BeginSponsoringFutureReserves(_) => {
                OperationType::BeginSponsoringFutureReserves
            }
            OperationBody::EndSponsoringFutureReserves => {
                OperationType::EndSponsoringFutureReserves
            }
            OperationBody::RevokeSponsorship(_) => OperationType::RevokeSponsorship,
            OperationBody::Clawback(_) => OperationType::Clawback,
            OperationBody::ClawbackClaimableBalance(_) => OperationType::ClawbackClaimableBalance,
            OperationBody::SetTrustLineFlags(_) => OperationType::SetTrustLineFlags,
            OperationBody::LiquidityPoolDeposit(_) => OperationType::LiquidityPoolDeposit,
            OperationBody::LiquidityPoolWithdraw(_) => OperationType::LiquidityPoolWithdraw,
            OperationBody::InvokeHostFunction(_) => OperationType::InvokeHostFunction,
            OperationBody::ExtendFootprintTtl(_) => OperationType::ExtendFootprintTtl,
            OperationBody::RestoreFootprint(_) => OperationType::RestoreFootprint,
        }
    }

    /// Get the name of this operation type.
    pub fn name(&self) -> &'static str {
        match self {
            OperationType::CreateAccount => "CreateAccount",
            OperationType::Payment => "Payment",
            OperationType::PathPaymentStrictReceive => "PathPaymentStrictReceive",
            OperationType::ManageSellOffer => "ManageSellOffer",
            OperationType::CreatePassiveSellOffer => "CreatePassiveSellOffer",
            OperationType::SetOptions => "SetOptions",
            OperationType::ChangeTrust => "ChangeTrust",
            OperationType::AllowTrust => "AllowTrust",
            OperationType::AccountMerge => "AccountMerge",
            OperationType::Inflation => "Inflation",
            OperationType::ManageData => "ManageData",
            OperationType::BumpSequence => "BumpSequence",
            OperationType::ManageBuyOffer => "ManageBuyOffer",
            OperationType::PathPaymentStrictSend => "PathPaymentStrictSend",
            OperationType::CreateClaimableBalance => "CreateClaimableBalance",
            OperationType::ClaimClaimableBalance => "ClaimClaimableBalance",
            OperationType::BeginSponsoringFutureReserves => "BeginSponsoringFutureReserves",
            OperationType::EndSponsoringFutureReserves => "EndSponsoringFutureReserves",
            OperationType::RevokeSponsorship => "RevokeSponsorship",
            OperationType::Clawback => "Clawback",
            OperationType::ClawbackClaimableBalance => "ClawbackClaimableBalance",
            OperationType::SetTrustLineFlags => "SetTrustLineFlags",
            OperationType::LiquidityPoolDeposit => "LiquidityPoolDeposit",
            OperationType::LiquidityPoolWithdraw => "LiquidityPoolWithdraw",
            OperationType::InvokeHostFunction => "InvokeHostFunction",
            OperationType::ExtendFootprintTtl => "ExtendFootprintTtl",
            OperationType::RestoreFootprint => "RestoreFootprint",
        }
    }
}

impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Validation error for operations.
#[derive(Debug, Clone)]
pub enum OperationValidationError {
    /// Invalid amount (negative or zero when positive required).
    InvalidAmount(i64),
    /// Invalid destination.
    InvalidDestination,
    /// Invalid asset.
    InvalidAsset(String),
    /// Invalid data value.
    InvalidDataValue(String),
    /// Invalid threshold.
    InvalidThreshold,
    /// Invalid weight.
    InvalidWeight,
    /// Invalid offer ID.
    InvalidOfferId,
    /// Invalid price.
    InvalidPrice,
    /// Invalid claimant.
    InvalidClaimant,
    /// Invalid pool ID.
    InvalidPoolId,
    /// Invalid host function.
    InvalidHostFunction(String),
    /// Invalid Soroban data.
    InvalidSorobanData(String),
    /// Generic validation error.
    Other(String),
}

impl std::fmt::Display for OperationValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAmount(amt) => write!(f, "invalid amount: {}", amt),
            Self::InvalidDestination => write!(f, "invalid destination"),
            Self::InvalidAsset(msg) => write!(f, "invalid asset: {}", msg),
            Self::InvalidDataValue(msg) => write!(f, "invalid data value: {}", msg),
            Self::InvalidThreshold => write!(f, "invalid threshold"),
            Self::InvalidWeight => write!(f, "invalid weight"),
            Self::InvalidOfferId => write!(f, "invalid offer ID"),
            Self::InvalidPrice => write!(f, "invalid price"),
            Self::InvalidClaimant => write!(f, "invalid claimant"),
            Self::InvalidPoolId => write!(f, "invalid pool ID"),
            Self::InvalidHostFunction(msg) => write!(f, "invalid host function: {}", msg),
            Self::InvalidSorobanData(msg) => write!(f, "invalid Soroban data: {}", msg),
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

/// Validate an operation.
pub fn validate_operation(
    op: &Operation,
) -> std::result::Result<(), OperationValidationError> {
    match &op.body {
        OperationBody::CreateAccount(op) => validate_create_account(op),
        OperationBody::Payment(op) => validate_payment(op),
        OperationBody::PathPaymentStrictReceive(op) => validate_path_payment_strict_receive(op),
        OperationBody::PathPaymentStrictSend(op) => validate_path_payment_strict_send(op),
        OperationBody::ManageSellOffer(op) => validate_manage_sell_offer(op),
        OperationBody::ManageBuyOffer(op) => validate_manage_buy_offer(op),
        OperationBody::CreatePassiveSellOffer(op) => validate_create_passive_sell_offer(op),
        OperationBody::SetOptions(op) => validate_set_options(op),
        OperationBody::ChangeTrust(op) => validate_change_trust(op),
        OperationBody::AllowTrust(op) => validate_allow_trust(op),
        OperationBody::AccountMerge(_) => Ok(()), // No specific validation needed
        OperationBody::Inflation => Ok(()),       // No validation needed
        OperationBody::ManageData(op) => validate_manage_data(op),
        OperationBody::BumpSequence(op) => validate_bump_sequence(op),
        OperationBody::CreateClaimableBalance(op) => validate_create_claimable_balance(op),
        OperationBody::ClaimClaimableBalance(op) => validate_claim_claimable_balance(op),
        OperationBody::BeginSponsoringFutureReserves(op) => {
            validate_begin_sponsoring_future_reserves(op)
        }
        OperationBody::EndSponsoringFutureReserves => Ok(()), // No validation needed
        OperationBody::RevokeSponsorship(_) => Ok(()),        // Complex, trust for now
        OperationBody::Clawback(op) => validate_clawback(op),
        OperationBody::ClawbackClaimableBalance(op) => validate_clawback_claimable_balance(op),
        OperationBody::SetTrustLineFlags(op) => validate_set_trust_line_flags(op),
        OperationBody::LiquidityPoolDeposit(op) => validate_liquidity_pool_deposit(op),
        OperationBody::LiquidityPoolWithdraw(op) => validate_liquidity_pool_withdraw(op),
        OperationBody::InvokeHostFunction(op) => validate_invoke_host_function(op),
        OperationBody::ExtendFootprintTtl(op) => validate_extend_footprint_ttl(op),
        OperationBody::RestoreFootprint(op) => validate_restore_footprint(op),
    }
}

/// Validate CreateAccount operation.
fn validate_create_account(
    op: &CreateAccountOp,
) -> std::result::Result<(), OperationValidationError> {
    if op.starting_balance <= 0 {
        return Err(OperationValidationError::InvalidAmount(op.starting_balance));
    }
    Ok(())
}

/// Validate Payment operation.
fn validate_payment(op: &PaymentOp) -> std::result::Result<(), OperationValidationError> {
    if op.amount <= 0 {
        return Err(OperationValidationError::InvalidAmount(op.amount));
    }
    Ok(())
}

/// Validate PathPaymentStrictReceive operation.
fn validate_path_payment_strict_receive(
    op: &PathPaymentStrictReceiveOp,
) -> std::result::Result<(), OperationValidationError> {
    if op.dest_amount <= 0 {
        return Err(OperationValidationError::InvalidAmount(op.dest_amount));
    }
    if op.send_max <= 0 {
        return Err(OperationValidationError::InvalidAmount(op.send_max));
    }
    Ok(())
}

/// Validate PathPaymentStrictSend operation.
fn validate_path_payment_strict_send(
    op: &PathPaymentStrictSendOp,
) -> std::result::Result<(), OperationValidationError> {
    if op.send_amount <= 0 {
        return Err(OperationValidationError::InvalidAmount(op.send_amount));
    }
    if op.dest_min <= 0 {
        return Err(OperationValidationError::InvalidAmount(op.dest_min));
    }
    Ok(())
}

/// Validate ManageSellOffer operation.
fn validate_manage_sell_offer(
    op: &ManageSellOfferOp,
) -> std::result::Result<(), OperationValidationError> {
    // Amount of 0 is valid (deletes offer)
    if op.amount < 0 {
        return Err(OperationValidationError::InvalidAmount(op.amount));
    }
    // Price must be positive
    if op.price.n <= 0 || op.price.d <= 0 {
        return Err(OperationValidationError::InvalidPrice);
    }
    Ok(())
}

/// Validate ManageBuyOffer operation.
fn validate_manage_buy_offer(
    op: &ManageBuyOfferOp,
) -> std::result::Result<(), OperationValidationError> {
    if op.buy_amount < 0 {
        return Err(OperationValidationError::InvalidAmount(op.buy_amount));
    }
    if op.price.n <= 0 || op.price.d <= 0 {
        return Err(OperationValidationError::InvalidPrice);
    }
    Ok(())
}

/// Validate CreatePassiveSellOffer operation.
fn validate_create_passive_sell_offer(
    op: &CreatePassiveSellOfferOp,
) -> std::result::Result<(), OperationValidationError> {
    if op.amount <= 0 {
        return Err(OperationValidationError::InvalidAmount(op.amount));
    }
    if op.price.n <= 0 || op.price.d <= 0 {
        return Err(OperationValidationError::InvalidPrice);
    }
    Ok(())
}

/// Validate SetOptions operation.
fn validate_set_options(op: &SetOptionsOp) -> std::result::Result<(), OperationValidationError> {
    // Check master weight if set
    if let Some(weight) = op.master_weight {
        if weight > 255 {
            return Err(OperationValidationError::InvalidWeight);
        }
    }
    // Check thresholds if set
    if let Some(t) = op.low_threshold {
        if t > 255 {
            return Err(OperationValidationError::InvalidThreshold);
        }
    }
    if let Some(t) = op.med_threshold {
        if t > 255 {
            return Err(OperationValidationError::InvalidThreshold);
        }
    }
    if let Some(t) = op.high_threshold {
        if t > 255 {
            return Err(OperationValidationError::InvalidThreshold);
        }
    }
    Ok(())
}

/// Validate ChangeTrust operation.
fn validate_change_trust(op: &ChangeTrustOp) -> std::result::Result<(), OperationValidationError> {
    // Limit of 0 is valid (removes trustline)
    if op.limit < 0 {
        return Err(OperationValidationError::InvalidAmount(op.limit));
    }
    Ok(())
}

/// Validate AllowTrust operation.
fn validate_allow_trust(_op: &AllowTrustOp) -> std::result::Result<(), OperationValidationError> {
    // Basic structure is validated by XDR
    Ok(())
}

/// Validate ManageData operation.
fn validate_manage_data(op: &ManageDataOp) -> std::result::Result<(), OperationValidationError> {
    // Data name must not be empty
    if op.data_name.is_empty() {
        return Err(OperationValidationError::InvalidDataValue(
            "data name cannot be empty".to_string(),
        ));
    }
    // Data value (if present) must be <= 64 bytes
    if let Some(value) = &op.data_value {
        if value.len() > 64 {
            return Err(OperationValidationError::InvalidDataValue(
                "data value exceeds 64 bytes".to_string(),
            ));
        }
    }
    Ok(())
}

/// Validate BumpSequence operation.
fn validate_bump_sequence(
    op: &BumpSequenceOp,
) -> std::result::Result<(), OperationValidationError> {
    if op.bump_to.0 < 0 {
        return Err(OperationValidationError::InvalidAmount(op.bump_to.0));
    }
    Ok(())
}

/// Validate CreateClaimableBalance operation.
fn validate_create_claimable_balance(
    op: &CreateClaimableBalanceOp,
) -> std::result::Result<(), OperationValidationError> {
    if op.amount <= 0 {
        return Err(OperationValidationError::InvalidAmount(op.amount));
    }
    if op.claimants.is_empty() {
        return Err(OperationValidationError::InvalidClaimant);
    }
    Ok(())
}

/// Validate ClaimClaimableBalance operation.
fn validate_claim_claimable_balance(
    _op: &ClaimClaimableBalanceOp,
) -> std::result::Result<(), OperationValidationError> {
    // Balance ID validation is handled by XDR
    Ok(())
}

/// Validate BeginSponsoringFutureReserves operation.
fn validate_begin_sponsoring_future_reserves(
    _op: &BeginSponsoringFutureReservesOp,
) -> std::result::Result<(), OperationValidationError> {
    // Account ID validation is handled by XDR
    Ok(())
}

/// Validate Clawback operation.
fn validate_clawback(op: &ClawbackOp) -> std::result::Result<(), OperationValidationError> {
    if op.amount <= 0 {
        return Err(OperationValidationError::InvalidAmount(op.amount));
    }
    Ok(())
}

/// Validate ClawbackClaimableBalance operation.
fn validate_clawback_claimable_balance(
    _op: &ClawbackClaimableBalanceOp,
) -> std::result::Result<(), OperationValidationError> {
    // Balance ID validation is handled by XDR
    Ok(())
}

/// Validate SetTrustLineFlags operation.
fn validate_set_trust_line_flags(
    _op: &SetTrustLineFlagsOp,
) -> std::result::Result<(), OperationValidationError> {
    // Flags validation is handled by XDR
    Ok(())
}

/// Validate LiquidityPoolDeposit operation.
fn validate_liquidity_pool_deposit(
    op: &LiquidityPoolDepositOp,
) -> std::result::Result<(), OperationValidationError> {
    if op.max_amount_a <= 0 {
        return Err(OperationValidationError::InvalidAmount(op.max_amount_a));
    }
    if op.max_amount_b <= 0 {
        return Err(OperationValidationError::InvalidAmount(op.max_amount_b));
    }
    Ok(())
}

/// Validate LiquidityPoolWithdraw operation.
fn validate_liquidity_pool_withdraw(
    op: &LiquidityPoolWithdrawOp,
) -> std::result::Result<(), OperationValidationError> {
    if op.amount <= 0 {
        return Err(OperationValidationError::InvalidAmount(op.amount));
    }
    Ok(())
}

/// Validate InvokeHostFunction operation.
fn validate_invoke_host_function(
    _op: &InvokeHostFunctionOp,
) -> std::result::Result<(), OperationValidationError> {
    // Soroban validation is complex, trust XDR for basic structure
    Ok(())
}

/// Validate ExtendFootprintTtl operation.
fn validate_extend_footprint_ttl(
    op: &ExtendFootprintTtlOp,
) -> std::result::Result<(), OperationValidationError> {
    if op.extend_to == 0 {
        return Err(OperationValidationError::InvalidSorobanData(
            "extend_to must be positive".to_string(),
        ));
    }
    Ok(())
}

/// Validate RestoreFootprint operation.
fn validate_restore_footprint(
    _op: &RestoreFootprintOp,
) -> std::result::Result<(), OperationValidationError> {
    // Structure validation is handled by XDR
    Ok(())
}

/// Get the source account for an operation.
///
/// If the operation has an explicit source, use that.
/// Otherwise, the transaction source is used.
pub fn get_operation_source<'a>(
    op: &'a Operation,
    tx_source: &'a MuxedAccount,
) -> &'a MuxedAccount {
    op.source_account.as_ref().unwrap_or(tx_source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;
    use crate::operations::OperationType; // Re-import to shadow XDR's OperationType

    #[test]
    fn test_operation_type_from_body() {
        let payment = OperationBody::Payment(PaymentOp {
            destination: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            asset: Asset::Native,
            amount: 1000,
        });

        let op_type = OperationType::from_body(&payment);
        assert_eq!(op_type, OperationType::Payment);
        assert!(!op_type.is_soroban());
        assert!(op_type.is_classic());
    }

    #[test]
    fn test_soroban_operation_types() {
        assert!(OperationType::InvokeHostFunction.is_soroban());
        assert!(OperationType::ExtendFootprintTtl.is_soroban());
        assert!(OperationType::RestoreFootprint.is_soroban());

        assert!(!OperationType::Payment.is_soroban());
        assert!(!OperationType::CreateAccount.is_soroban());
    }

    #[test]
    fn test_validate_payment() {
        let valid = PaymentOp {
            destination: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            asset: Asset::Native,
            amount: 1000,
        };
        assert!(validate_payment(&valid).is_ok());

        let invalid = PaymentOp {
            destination: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            asset: Asset::Native,
            amount: 0,
        };
        assert!(validate_payment(&invalid).is_err());

        let negative = PaymentOp {
            destination: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            asset: Asset::Native,
            amount: -100,
        };
        assert!(validate_payment(&negative).is_err());
    }

    #[test]
    fn test_validate_create_account() {
        let valid = CreateAccountOp {
            destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32]))),
            starting_balance: 10_000_000,
        };
        assert!(validate_create_account(&valid).is_ok());

        let invalid = CreateAccountOp {
            destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32]))),
            starting_balance: 0,
        };
        assert!(validate_create_account(&invalid).is_err());
    }

    #[test]
    fn test_operation_type_name() {
        assert_eq!(OperationType::Payment.name(), "Payment");
        assert_eq!(
            OperationType::InvokeHostFunction.name(),
            "InvokeHostFunction"
        );
    }
}
