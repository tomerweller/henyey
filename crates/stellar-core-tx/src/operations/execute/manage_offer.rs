//! Manage Offer operation execution.
//!
//! This module implements the execution logic for ManageSellOffer, ManageBuyOffer,
//! and CreatePassiveSellOffer operations for the Stellar DEX.

use stellar_xdr::curr::{
    AccountId, Asset, CreatePassiveSellOfferOp, ManageBuyOfferOp, ManageOfferSuccessResult,
    ManageOfferSuccessResultOffer, ManageSellOfferOp, ManageSellOfferResult,
    ManageSellOfferResultCode, OfferEntry, OfferEntryExt, OperationResult, OperationResultTr,
    Price,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;

/// Execute a ManageSellOffer operation.
///
/// This operation creates, updates, or deletes an offer to sell one asset for another.
pub fn execute_manage_sell_offer(
    op: &ManageSellOfferOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    // Validate the offer parameters
    if let Err(code) = validate_offer(&op.selling, &op.buying, op.amount, &op.price) {
        return Ok(make_sell_offer_result(code, None));
    }

    // Check if this is a delete operation (amount = 0 with existing offer_id)
    if op.amount == 0 {
        if op.offer_id == 0 {
            return Ok(make_sell_offer_result(
                ManageSellOfferResultCode::Malformed,
                None,
            ));
        }
        return delete_offer(source, op.offer_id, state);
    }

    // Check source account exists
    if state.get_account(source).is_none() {
        return Ok(make_sell_offer_result(
            ManageSellOfferResultCode::Underfunded,
            None,
        ));
    }

    // For selling non-native assets, check trustline exists and has balance
    if !matches!(&op.selling, Asset::Native) {
        let trustline = match state.get_trustline(source, &op.selling) {
            Some(tl) => tl,
            None => {
                return Ok(make_sell_offer_result(
                    ManageSellOfferResultCode::SellNoTrust,
                    None,
                ));
            }
        };

        // Check selling balance
        if trustline.balance < op.amount {
            return Ok(make_sell_offer_result(
                ManageSellOfferResultCode::Underfunded,
                None,
            ));
        }
    } else {
        // For native asset, check account balance
        let account = state.get_account(source).unwrap();
        let min_balance = state.minimum_balance(account.num_sub_entries + 1); // +1 for the offer
        let available = account.balance - min_balance;
        if available < op.amount {
            return Ok(make_sell_offer_result(
                ManageSellOfferResultCode::Underfunded,
                None,
            ));
        }
    }

    // For buying non-native assets, check trustline exists
    if !matches!(&op.buying, Asset::Native) {
        if state.get_trustline(source, &op.buying).is_none() {
            return Ok(make_sell_offer_result(
                ManageSellOfferResultCode::BuyNoTrust,
                None,
            ));
        }
    }

    // Create or update the offer
    if op.offer_id == 0 {
        // Create new offer
        create_offer(source, &op.selling, &op.buying, op.amount, &op.price, state, context)
    } else {
        // Update existing offer
        update_offer(source, op.offer_id, &op.selling, &op.buying, op.amount, &op.price, state)
    }
}

/// Execute a ManageBuyOffer operation.
///
/// This operation creates, updates, or deletes an offer to buy one asset with another.
pub fn execute_manage_buy_offer(
    op: &ManageBuyOfferOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    // Convert buy offer to sell offer for processing
    // buy_amount in dest asset, we need to calculate sell amount
    let sell_amount = calculate_sell_amount(op.buy_amount, &op.price);

    let sell_op = ManageSellOfferOp {
        selling: op.selling.clone(),
        buying: op.buying.clone(),
        amount: sell_amount,
        price: op.price.clone(),
        offer_id: op.offer_id,
    };

    // Execute as sell offer and convert result
    let result = execute_manage_sell_offer(&sell_op, source, state, context)?;

    // Convert result type
    match result {
        OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
            Ok(OperationResult::OpInner(OperationResultTr::ManageBuyOffer(
                convert_sell_to_buy_result(r),
            )))
        }
        other => Ok(other),
    }
}

/// Execute a CreatePassiveSellOffer operation.
///
/// This operation creates a passive sell offer that doesn't cross existing offers.
pub fn execute_create_passive_sell_offer(
    op: &CreatePassiveSellOfferOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    // Convert to ManageSellOffer (passive offers are created the same way but with a flag)
    let sell_op = ManageSellOfferOp {
        selling: op.selling.clone(),
        buying: op.buying.clone(),
        amount: op.amount,
        price: op.price.clone(),
        offer_id: 0, // Always create new
    };

    execute_manage_sell_offer(&sell_op, source, state, context)
}

/// Validate offer parameters.
fn validate_offer(
    selling: &Asset,
    buying: &Asset,
    amount: i64,
    price: &Price,
) -> std::result::Result<(), ManageSellOfferResultCode> {
    // Cannot trade an asset for itself
    if selling == buying {
        return Err(ManageSellOfferResultCode::Malformed);
    }

    // Amount must be non-negative (0 is valid for deleting)
    if amount < 0 {
        return Err(ManageSellOfferResultCode::Malformed);
    }

    // Price must be positive
    if price.n <= 0 || price.d <= 0 {
        return Err(ManageSellOfferResultCode::Malformed);
    }

    Ok(())
}

/// Create a new offer.
fn create_offer(
    source: &AccountId,
    selling: &Asset,
    buying: &Asset,
    amount: i64,
    price: &Price,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    // Generate a new offer ID (in production this should be deterministic based on ledger state)
    let offer_id = generate_offer_id(source, context);

    let offer = OfferEntry {
        seller_id: source.clone(),
        offer_id,
        selling: selling.clone(),
        buying: buying.clone(),
        amount,
        price: price.clone(),
        flags: 0,
        ext: OfferEntryExt::V0,
    };

    state.create_offer(offer);

    // Increment the source account's sub-entries
    if let Some(account) = state.get_account_mut(source) {
        account.num_sub_entries += 1;
    }

    let success = ManageOfferSuccessResult {
        offers_claimed: vec![].try_into().unwrap(),
        offer: ManageOfferSuccessResultOffer::Created(create_offer_entry(
            source, offer_id, selling, buying, amount, price,
        )),
    };

    Ok(make_sell_offer_result(
        ManageSellOfferResultCode::Success,
        Some(success),
    ))
}

/// Update an existing offer.
fn update_offer(
    source: &AccountId,
    offer_id: i64,
    selling: &Asset,
    buying: &Asset,
    amount: i64,
    price: &Price,
    state: &mut LedgerStateManager,
) -> Result<OperationResult> {
    // Check offer exists and belongs to source
    if state.get_offer(source, offer_id).is_none() {
        return Ok(make_sell_offer_result(
            ManageSellOfferResultCode::NotFound,
            None,
        ));
    }

    let offer = OfferEntry {
        seller_id: source.clone(),
        offer_id,
        selling: selling.clone(),
        buying: buying.clone(),
        amount,
        price: price.clone(),
        flags: 0,
        ext: OfferEntryExt::V0,
    };

    state.update_offer(offer);

    let success = ManageOfferSuccessResult {
        offers_claimed: vec![].try_into().unwrap(),
        offer: ManageOfferSuccessResultOffer::Updated(create_offer_entry(
            source, offer_id, selling, buying, amount, price,
        )),
    };

    Ok(make_sell_offer_result(
        ManageSellOfferResultCode::Success,
        Some(success),
    ))
}

/// Delete an existing offer.
fn delete_offer(
    source: &AccountId,
    offer_id: i64,
    state: &mut LedgerStateManager,
) -> Result<OperationResult> {
    // Check offer exists and belongs to source
    if state.get_offer(source, offer_id).is_none() {
        return Ok(make_sell_offer_result(
            ManageSellOfferResultCode::NotFound,
            None,
        ));
    }

    state.delete_offer(source, offer_id);

    // Decrement the source account's sub-entries
    if let Some(account) = state.get_account_mut(source) {
        if account.num_sub_entries > 0 {
            account.num_sub_entries -= 1;
        }
    }

    let success = ManageOfferSuccessResult {
        offers_claimed: vec![].try_into().unwrap(),
        offer: ManageOfferSuccessResultOffer::Deleted,
    };

    Ok(make_sell_offer_result(
        ManageSellOfferResultCode::Success,
        Some(success),
    ))
}

/// Generate a new offer ID.
fn generate_offer_id(source: &AccountId, context: &LedgerContext) -> i64 {
    use sha2::{Digest, Sha256};
    use stellar_xdr::curr::WriteXdr;

    let mut hasher = Sha256::new();
    if let Ok(bytes) = source.to_xdr(stellar_xdr::curr::Limits::none()) {
        hasher.update(&bytes);
    }
    hasher.update(&context.sequence.to_le_bytes());
    hasher.update(&context.close_time.to_le_bytes());

    let hash = hasher.finalize();
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&hash[0..8]);
    i64::from_le_bytes(id_bytes).abs() // Ensure positive
}

/// Calculate sell amount from buy amount and price.
fn calculate_sell_amount(buy_amount: i64, price: &Price) -> i64 {
    // sell_amount = buy_amount * price.d / price.n
    ((buy_amount as i128 * price.d as i128) / price.n as i128) as i64
}

/// Create an OfferEntry for result.
fn create_offer_entry(
    source: &AccountId,
    offer_id: i64,
    selling: &Asset,
    buying: &Asset,
    amount: i64,
    price: &Price,
) -> OfferEntry {
    OfferEntry {
        seller_id: source.clone(),
        offer_id,
        selling: selling.clone(),
        buying: buying.clone(),
        amount,
        price: price.clone(),
        flags: 0,
        ext: OfferEntryExt::V0,
    }
}

/// Convert ManageSellOfferResult to ManageBuyOfferResult.
fn convert_sell_to_buy_result(
    result: ManageSellOfferResult,
) -> stellar_xdr::curr::ManageBuyOfferResult {
    use stellar_xdr::curr::{ManageBuyOfferResult, ManageBuyOfferResultCode};

    match result {
        ManageSellOfferResult::Success(s) => ManageBuyOfferResult::Success(s),
        ManageSellOfferResult::Malformed => ManageBuyOfferResult::Malformed,
        ManageSellOfferResult::SellNoTrust => ManageBuyOfferResult::SellNoTrust,
        ManageSellOfferResult::BuyNoTrust => ManageBuyOfferResult::BuyNoTrust,
        ManageSellOfferResult::SellNotAuthorized => ManageBuyOfferResult::SellNotAuthorized,
        ManageSellOfferResult::BuyNotAuthorized => ManageBuyOfferResult::BuyNotAuthorized,
        ManageSellOfferResult::LineFull => ManageBuyOfferResult::LineFull,
        ManageSellOfferResult::Underfunded => ManageBuyOfferResult::Underfunded,
        ManageSellOfferResult::CrossSelf => ManageBuyOfferResult::CrossSelf,
        ManageSellOfferResult::SellNoIssuer => ManageBuyOfferResult::SellNoIssuer,
        ManageSellOfferResult::BuyNoIssuer => ManageBuyOfferResult::BuyNoIssuer,
        ManageSellOfferResult::NotFound => ManageBuyOfferResult::NotFound,
        ManageSellOfferResult::LowReserve => ManageBuyOfferResult::LowReserve,
    }
}

/// Create a ManageSellOffer result.
fn make_sell_offer_result(
    code: ManageSellOfferResultCode,
    success: Option<ManageOfferSuccessResult>,
) -> OperationResult {
    let result = match code {
        ManageSellOfferResultCode::Success => ManageSellOfferResult::Success(success.unwrap()),
        ManageSellOfferResultCode::Malformed => ManageSellOfferResult::Malformed,
        ManageSellOfferResultCode::SellNoTrust => ManageSellOfferResult::SellNoTrust,
        ManageSellOfferResultCode::BuyNoTrust => ManageSellOfferResult::BuyNoTrust,
        ManageSellOfferResultCode::SellNotAuthorized => ManageSellOfferResult::SellNotAuthorized,
        ManageSellOfferResultCode::BuyNotAuthorized => ManageSellOfferResult::BuyNotAuthorized,
        ManageSellOfferResultCode::LineFull => ManageSellOfferResult::LineFull,
        ManageSellOfferResultCode::Underfunded => ManageSellOfferResult::Underfunded,
        ManageSellOfferResultCode::CrossSelf => ManageSellOfferResult::CrossSelf,
        ManageSellOfferResultCode::SellNoIssuer => ManageSellOfferResult::SellNoIssuer,
        ManageSellOfferResultCode::BuyNoIssuer => ManageSellOfferResult::BuyNoIssuer,
        ManageSellOfferResultCode::NotFound => ManageSellOfferResult::NotFound,
        ManageSellOfferResultCode::LowReserve => ManageSellOfferResult::LowReserve,
    };

    OperationResult::OpInner(OperationResultTr::ManageSellOffer(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    fn create_test_account(account_id: AccountId, balance: i64) -> AccountEntry {
        AccountEntry {
            account_id,
            balance,
            seq_num: SequenceNumber(1),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: vec![].try_into().unwrap(),
            ext: AccountEntryExt::V0,
        }
    }

    fn create_test_asset() -> Asset {
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: create_test_account_id(99),
        })
    }

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    #[test]
    fn test_manage_sell_offer_malformed_same_asset() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = ManageSellOfferOp {
            selling: Asset::Native,
            buying: Asset::Native, // Same as selling
            amount: 10_000_000,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_create() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        // Create trustline for the buying asset
        let buying_asset = create_test_asset();
        let trustline = TrustLineEntry {
            account_id: source_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: create_test_account_id(99),
            }),
            balance: 0,
            limit: i64::MAX,
            flags: 0,
            ext: TrustLineEntryExt::V0,
        };
        state.create_trustline(trustline);

        let op = ManageSellOfferOp {
            selling: Asset::Native,
            buying: buying_asset,
            amount: 10_000_000,
            price: Price { n: 1, d: 2 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::Success(_)));
            }
            _ => panic!("Unexpected result type"),
        }
    }
}
