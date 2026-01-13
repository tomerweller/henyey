//! Path Payment operation execution.
//!
//! This module implements the execution logic for PathPaymentStrictReceive
//! and PathPaymentStrictSend operations, which transfer assets through a path.

use sha2::{Digest, Sha256};
use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountEntryExtensionV1, AccountEntryExtensionV1Ext, AccountId,
    Asset, ClaimAtom, ClaimLiquidityAtom, ClaimOfferAtom, Hash, Liabilities,
    LiquidityPoolEntryBody, LiquidityPoolParameters, OperationResult,
    OperationResultTr, PathPaymentStrictReceiveOp, PathPaymentStrictReceiveResult,
    PathPaymentStrictReceiveResultCode, PathPaymentStrictReceiveResultSuccess,
    PathPaymentStrictSendOp, PathPaymentStrictSendResult, PathPaymentStrictSendResultCode,
    PathPaymentStrictSendResultSuccess, PoolId, Price, SimplePaymentResult, TrustLineEntry,
    TrustLineEntryExt, TrustLineEntryV1, TrustLineEntryV1Ext, TrustLineFlags, WriteXdr, Limits,
    LIQUIDITY_POOL_FEE_V18, LedgerKey, LedgerKeyOffer,
};

use crate::frame::muxed_to_account_id;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::{Result, TxError};
use super::offer_exchange::{exchange_v10, exchange_v10_without_price_error_thresholds, ExchangeError, RoundingType};

/// Execute a PathPaymentStrictReceive operation.
///
/// This operation sends at most `send_max` of `send_asset` to receive exactly
/// `dest_amount` of `dest_asset` at the destination.
pub fn execute_path_payment_strict_receive(
    op: &PathPaymentStrictReceiveOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    let dest = muxed_to_account_id(&op.destination);

    // Validate amounts
    if op.send_max <= 0 || op.dest_amount <= 0 {
        return Ok(make_strict_receive_result(
            PathPaymentStrictReceiveResultCode::Malformed,
            None,
        ));
    }

    let bypass_issuer_check =
        should_bypass_issuer_check(op.path.as_slice(), &op.send_asset, &op.dest_asset, &dest);
    if !bypass_issuer_check && state.get_account(&dest).is_none() {
        return Ok(make_strict_receive_result(
            PathPaymentStrictReceiveResultCode::NoDestination,
            None,
        ));
    }

    let mut offers_claimed: Vec<ClaimAtom> = Vec::new();

    if let Err(err) = update_dest_balance(
        &dest,
        &op.dest_asset,
        op.dest_amount,
        bypass_issuer_check,
        state,
    ) {
        return Ok(make_strict_receive_result_with_asset(
            err.code,
            err.no_issuer_asset,
            None,
        ));
    }

    let mut success = PathPaymentStrictReceiveResultSuccess {
        offers: vec![].try_into().unwrap(),
        last: SimplePaymentResult {
            destination: dest.clone(),
            asset: op.dest_asset.clone(),
            amount: op.dest_amount,
        },
    };

    let mut full_path: Vec<Asset> = op.path.iter().cloned().rev().collect();
    full_path.push(op.send_asset.clone());

    let mut recv_asset = op.dest_asset.clone();
    let mut max_amount_recv = op.dest_amount;
    for send_asset in full_path {
        if recv_asset == send_asset {
            continue;
        }

        if !bypass_issuer_check {
            if let Err(err) = check_issuer(&send_asset, state) {
                return Ok(make_strict_receive_result_with_asset(
                    err.code,
                    err.no_issuer_asset,
                    None,
                ));
            }
        }

        let mut amount_send = 0;
        let mut amount_recv = 0;
        let mut offer_trail = Vec::new();
        let convert_res = convert_with_offers_and_pools(
            source,
            &send_asset,
            i64::MAX,
            &mut amount_send,
            &recv_asset,
            max_amount_recv,
            &mut amount_recv,
            RoundingType::PathPaymentStrictReceive,
            &mut offer_trail,
            state,
            context,
        )?;

        if convert_res == ConvertResult::FilterStopCrossSelf {
            return Ok(make_strict_receive_result(
                PathPaymentStrictReceiveResultCode::OfferCrossSelf,
                None,
            ));
        }
        if convert_res != ConvertResult::Ok || amount_recv != max_amount_recv {
            return Ok(make_strict_receive_result(
                PathPaymentStrictReceiveResultCode::TooFewOffers,
                None,
            ));
        }

        max_amount_recv = amount_send;
        recv_asset = send_asset;

        offers_claimed.splice(0..0, offer_trail);
    }

    if max_amount_recv > op.send_max {
        return Ok(make_strict_receive_result(
            PathPaymentStrictReceiveResultCode::OverSendmax,
            None,
        ));
    }

    if let Err(err) = update_source_balance(
        source,
        &op.send_asset,
        max_amount_recv,
        bypass_issuer_check,
        state,
        context,
    ) {
        return Ok(make_strict_receive_result_with_asset(
            err.code,
            err.no_issuer_asset,
            None,
        ));
    }

    success.offers = offers_claimed.try_into().unwrap();
    Ok(make_strict_receive_result(
        PathPaymentStrictReceiveResultCode::Success,
        Some(success),
    ))
}

/// Execute a PathPaymentStrictSend operation.
///
/// This operation sends exactly `send_amount` of `send_asset` to receive at least
/// `dest_min` of `dest_asset` at the destination.
pub fn execute_path_payment_strict_send(
    op: &PathPaymentStrictSendOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    let dest = muxed_to_account_id(&op.destination);

    // Validate amounts
    if op.send_amount <= 0 || op.dest_min <= 0 {
        return Ok(make_strict_send_result(
            PathPaymentStrictSendResultCode::Malformed,
            None,
        ));
    }

    let bypass_issuer_check =
        should_bypass_issuer_check(op.path.as_slice(), &op.send_asset, &op.dest_asset, &dest);
    if !bypass_issuer_check && state.get_account(&dest).is_none() {
        return Ok(make_strict_send_result(
            PathPaymentStrictSendResultCode::NoDestination,
            None,
        ));
    }

    if let Err(err) = update_source_balance(
        source,
        &op.send_asset,
        op.send_amount,
        bypass_issuer_check,
        state,
        context,
    ) {
        return Ok(make_strict_send_result_with_asset(
            convert_receive_to_send_code(err.code),
            err.no_issuer_asset,
            None,
        ));
    }

    let mut offers_claimed: Vec<ClaimAtom> = Vec::new();
    let mut full_path: Vec<Asset> = op.path.iter().cloned().collect();
    full_path.push(op.dest_asset.clone());

    let mut send_asset = op.send_asset.clone();
    let mut max_amount_send = op.send_amount;
    for recv_asset in full_path {
        if recv_asset == send_asset {
            continue;
        }

        if !bypass_issuer_check {
            if let Err(err) = check_issuer(&recv_asset, state) {
                return Ok(make_strict_send_result_with_asset(
                    convert_receive_to_send_code(err.code),
                    err.no_issuer_asset,
                    None,
                ));
            }
        }

        let mut amount_send = 0;
        let mut amount_recv = 0;
        let mut offer_trail = Vec::new();
        let convert_res = convert_with_offers_and_pools(
            source,
            &send_asset,
            max_amount_send,
            &mut amount_send,
            &recv_asset,
            i64::MAX,
            &mut amount_recv,
            RoundingType::PathPaymentStrictSend,
            &mut offer_trail,
            state,
            context,
        )?;

        if convert_res == ConvertResult::FilterStopCrossSelf {
            return Ok(make_strict_send_result(
                PathPaymentStrictSendResultCode::OfferCrossSelf,
                None,
            ));
        }
        if convert_res != ConvertResult::Ok || amount_send != max_amount_send {
            return Ok(make_strict_send_result(
                PathPaymentStrictSendResultCode::TooFewOffers,
                None,
            ));
        }

        max_amount_send = amount_recv;
        send_asset = recv_asset;

        offers_claimed.extend(offer_trail);
    }

    if max_amount_send < op.dest_min {
        return Ok(make_strict_send_result(
            PathPaymentStrictSendResultCode::UnderDestmin,
            None,
        ));
    }

    if let Err(err) = update_dest_balance(
        &dest,
        &op.dest_asset,
        max_amount_send,
        bypass_issuer_check,
        state,
    ) {
        return Ok(make_strict_send_result_with_asset(
            convert_receive_to_send_code(err.code),
            err.no_issuer_asset,
            None,
        ));
    }

    let success = PathPaymentStrictSendResultSuccess {
        offers: offers_claimed.try_into().unwrap(),
        last: SimplePaymentResult {
            destination: dest,
            asset: op.dest_asset.clone(),
            amount: max_amount_send,
        },
    };
    Ok(make_strict_send_result(
        PathPaymentStrictSendResultCode::Success,
        Some(success),
    ))
}

/// Execute an asset transfer from source to destination.
struct TransferError {
    code: PathPaymentStrictReceiveResultCode,
    no_issuer_asset: Option<Asset>,
}

fn check_issuer(asset: &Asset, state: &LedgerStateManager) -> std::result::Result<(), TransferError> {
    if let Some(issuer) = issuer_for_asset(asset) {
        if state.get_account(issuer).is_none() {
            return Err(TransferError {
                code: PathPaymentStrictReceiveResultCode::NoIssuer,
                no_issuer_asset: Some(asset.clone()),
            });
        }
    }
    Ok(())
}

fn should_bypass_issuer_check(
    path: &[Asset],
    send_asset: &Asset,
    dest_asset: &Asset,
    dest: &AccountId,
) -> bool {
    !matches!(dest_asset, Asset::Native)
        && path.is_empty()
        && send_asset == dest_asset
        && issuer_for_asset(dest_asset) == Some(dest)
}

fn update_source_balance(
    source: &AccountId,
    asset: &Asset,
    amount: i64,
    bypass_issuer_check: bool,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> std::result::Result<(), TransferError> {
    if matches!(asset, Asset::Native) {
        let source_account = state.get_account(source).ok_or(TransferError {
            code: PathPaymentStrictReceiveResultCode::Underfunded,
            no_issuer_asset: None,
        })?;
        let min_balance = state
            .minimum_balance_for_account(source_account, context.protocol_version, 0)
            .map_err(|_| TransferError {
                code: PathPaymentStrictReceiveResultCode::Malformed,
                no_issuer_asset: None,
            })?;
        let available =
            source_account.balance - min_balance - account_liabilities(source_account).selling;
        if available < amount {
            return Err(TransferError {
                code: PathPaymentStrictReceiveResultCode::Underfunded,
                no_issuer_asset: None,
            });
        }
        let source_account_mut = state.get_account_mut(source).ok_or(TransferError {
            code: PathPaymentStrictReceiveResultCode::Underfunded,
            no_issuer_asset: None,
        })?;
        source_account_mut.balance -= amount;
        return Ok(());
    }

    if !bypass_issuer_check {
        check_issuer(asset, state)?;
    }

    if issuer_for_asset(asset) == Some(source) {
        return Ok(());
    }

    let source_trustline = state.get_trustline(source, asset).ok_or(TransferError {
        code: PathPaymentStrictReceiveResultCode::SrcNoTrust,
        no_issuer_asset: None,
    })?;
    // Check source is authorized - this is unconditional (not dependent on issuer's auth_required)
    // The AUTH_REQUIRED flag on issuer only affects whether NEW trustlines start authorized,
    // but once a trustline exists, its AUTHORIZED flag controls whether it can send.
    if !is_trustline_authorized(source_trustline.flags) {
        return Err(TransferError {
            code: PathPaymentStrictReceiveResultCode::SrcNotAuthorized,
            no_issuer_asset: None,
        });
    }
    let available =
        source_trustline.balance - trustline_liabilities(source_trustline).selling;
    if available < amount {
        return Err(TransferError {
            code: PathPaymentStrictReceiveResultCode::Underfunded,
            no_issuer_asset: None,
        });
    }

    let source_trustline_mut =
        state.get_trustline_mut(source, asset).ok_or(TransferError {
            code: PathPaymentStrictReceiveResultCode::SrcNoTrust,
            no_issuer_asset: None,
        })?;
    source_trustline_mut.balance -= amount;
    Ok(())
}

fn update_dest_balance(
    dest: &AccountId,
    asset: &Asset,
    amount: i64,
    bypass_issuer_check: bool,
    state: &mut LedgerStateManager,
) -> std::result::Result<(), TransferError> {
    if matches!(asset, Asset::Native) {
        let dest_account = state.get_account(dest).ok_or(TransferError {
            code: PathPaymentStrictReceiveResultCode::NoDestination,
            no_issuer_asset: None,
        })?;
        let max_receive =
            i64::MAX - dest_account.balance - account_liabilities(dest_account).buying;
        if max_receive < amount {
            return Err(TransferError {
                code: PathPaymentStrictReceiveResultCode::LineFull,
                no_issuer_asset: None,
            });
        }
        let dest_account_mut = state.get_account_mut(dest).ok_or(TransferError {
            code: PathPaymentStrictReceiveResultCode::NoDestination,
            no_issuer_asset: None,
        })?;
        dest_account_mut.balance += amount;
        return Ok(());
    }

    if !bypass_issuer_check {
        check_issuer(asset, state)?;
    }

    if issuer_for_asset(asset) == Some(dest) {
        return Ok(());
    }

    let dest_trustline = state.get_trustline(dest, asset).ok_or(TransferError {
        code: PathPaymentStrictReceiveResultCode::NoTrust,
        no_issuer_asset: None,
    })?;
    // Check destination is authorized - this is unconditional (not dependent on issuer's auth_required)
    if !is_trustline_authorized(dest_trustline.flags) {
        return Err(TransferError {
            code: PathPaymentStrictReceiveResultCode::NotAuthorized,
            no_issuer_asset: None,
        });
    }
    let available =
        dest_trustline.limit - dest_trustline.balance - trustline_liabilities(dest_trustline).buying;
    if available < amount {
        return Err(TransferError {
            code: PathPaymentStrictReceiveResultCode::LineFull,
            no_issuer_asset: None,
        });
    }
    let dest_trustline_mut = state.get_trustline_mut(dest, asset).ok_or(TransferError {
        code: PathPaymentStrictReceiveResultCode::NoTrust,
        no_issuer_asset: None,
    })?;
    dest_trustline_mut.balance += amount;
    Ok(())
}

const AUTHORIZED_FLAG: u32 = TrustLineFlags::AuthorizedFlag as u32;
const AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG: u32 =
    TrustLineFlags::AuthorizedToMaintainLiabilitiesFlag as u32;

fn is_trustline_authorized(flags: u32) -> bool {
    flags & AUTHORIZED_FLAG != 0
}

fn is_authorized_to_maintain_liabilities(flags: u32) -> bool {
    flags & (AUTHORIZED_FLAG | AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG) != 0
}

fn issuer_for_asset(asset: &Asset) -> Option<&AccountId> {
    match asset {
        Asset::Native => None,
        Asset::CreditAlphanum4(a) => Some(&a.issuer),
        Asset::CreditAlphanum12(a) => Some(&a.issuer),
    }
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConvertResult {
    Ok,
    Partial,
    FilterStopCrossSelf,
}

fn convert_with_offers_and_pools(
    source: &AccountId,
    send_asset: &Asset,
    max_send: i64,
    amount_send: &mut i64,
    recv_asset: &Asset,
    max_recv: i64,
    amount_recv: &mut i64,
    round: RoundingType,
    offer_trail: &mut Vec<ClaimAtom>,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<ConvertResult> {
    if round == RoundingType::Normal {
        return convert_with_offers(
            source,
            send_asset,
            max_send,
            amount_send,
            recv_asset,
            max_recv,
            amount_recv,
            round,
            offer_trail,
            state,
            context,
        );
    }

    let pool_exchange = compute_pool_exchange(
        send_asset,
        max_send,
        recv_asset,
        max_recv,
        round,
        state,
    )?;

    if pool_exchange.is_none() {
        return convert_with_offers(
            source,
            send_asset,
            max_send,
            amount_send,
            recv_asset,
            max_recv,
            amount_recv,
            round,
            offer_trail,
            state,
            context,
        );
    }

    let mut book_amount_send = 0;
    let mut book_amount_recv = 0;
    let mut book_offer_trail = Vec::new();
    let mut temp_state = state.clone();
    let book_res = convert_with_offers(
        source,
        send_asset,
        max_send,
        &mut book_amount_send,
        recv_asset,
        max_recv,
        &mut book_amount_recv,
        round,
        &mut book_offer_trail,
        &mut temp_state,
        context,
    )?;

    let pool_exchange = pool_exchange.unwrap();
    let use_book = match book_res {
        ConvertResult::Ok => {
            let lhs = (pool_exchange.send as i128) * (book_amount_recv as i128);
            let rhs = (pool_exchange.recv as i128) * (book_amount_send as i128);
            lhs > rhs
        }
        _ => false,
    };

    if use_book {
        *amount_send = book_amount_send;
        *amount_recv = book_amount_recv;
        offer_trail.clear();
        offer_trail.extend(book_offer_trail);
        return Ok(book_res);
    }

    offer_trail.clear();
    if apply_pool_exchange(
        send_asset,
        recv_asset,
        pool_exchange.send,
        pool_exchange.recv,
        state,
    )? {
        *amount_send = pool_exchange.send;
        *amount_recv = pool_exchange.recv;
        offer_trail.push(ClaimAtom::LiquidityPool(ClaimLiquidityAtom {
            liquidity_pool_id: pool_exchange.pool_id,
            asset_sold: recv_asset.clone(),
            amount_sold: pool_exchange.recv,
            asset_bought: send_asset.clone(),
            amount_bought: pool_exchange.send,
        }));
        return Ok(ConvertResult::Ok);
    }

    convert_with_offers(
        source,
        send_asset,
        max_send,
        amount_send,
        recv_asset,
        max_recv,
        amount_recv,
        round,
        offer_trail,
        state,
        context,
    )
}

fn convert_with_offers(
    source: &AccountId,
    send_asset: &Asset,
    max_send: i64,
    amount_send: &mut i64,
    recv_asset: &Asset,
    max_recv: i64,
    amount_recv: &mut i64,
    round: RoundingType,
    offer_trail: &mut Vec<ClaimAtom>,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<ConvertResult> {
    offer_trail.clear();
    *amount_send = 0;
    *amount_recv = 0;

    let mut max_send = max_send;
    let mut max_recv = max_recv;
    let mut need_more = max_send > 0 && max_recv > 0;
    while need_more {
        let offer = state.best_offer(send_asset, recv_asset);
        let Some(offer) = offer else {
            break;
        };

        if offer.seller_id == *source {
            return Ok(ConvertResult::FilterStopCrossSelf);
        }

        let (recv, send, wheat_stays) = cross_offer_v10(
            &offer,
            max_recv,
            max_send,
            round,
            offer_trail,
            state,
            context,
        )?;

        if recv == 0 && send == 0 {
            return Ok(ConvertResult::Partial);
        }

        *amount_send += send;
        *amount_recv += recv;
        max_send -= send;
        max_recv -= recv;
        need_more = !wheat_stays && max_send > 0 && max_recv > 0;
        if !need_more {
            return Ok(ConvertResult::Ok);
        }
        if wheat_stays {
            return Ok(ConvertResult::Partial);
        }
    }

    Ok(if need_more {
        ConvertResult::Partial
    } else {
        ConvertResult::Ok
    })
}

fn cross_offer_v10(
    offer: &stellar_xdr::curr::OfferEntry,
    max_recv: i64,
    max_send: i64,
    round: RoundingType,
    offer_trail: &mut Vec<ClaimAtom>,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<(i64, i64, bool)> {
    let sheep = offer.buying.clone();
    let wheat = offer.selling.clone();
    let seller = offer.seller_id.clone();

    let (selling_liab, buying_liab) = offer_liabilities_sell(offer.amount, &offer.price)?;
    apply_liabilities_delta(
        &seller,
        &offer.selling,
        &offer.buying,
        -selling_liab,
        -buying_liab,
        state,
    )?;

    let max_wheat_send =
        offer.amount.min(can_sell_at_most(&seller, &wheat, state, context)?);
    let max_sheep_receive = can_buy_at_most(&seller, &sheep, state);
    let exchange = exchange_v10(
        offer.price.clone(),
        max_wheat_send,
        max_recv,
        max_send,
        max_sheep_receive,
        round,
    )
    .map_err(map_exchange_error)?;

    let num_wheat_received = exchange.num_wheat_received;
    let num_sheep_send = exchange.num_sheep_send;
    let wheat_stays = exchange.wheat_stays;

    if num_sheep_send != 0 {
        apply_balance_delta(&seller, &sheep, num_sheep_send, state)?;
    }
    if num_wheat_received != 0 {
        apply_balance_delta(&seller, &wheat, -num_wheat_received, state)?;
    }

    let mut new_amount = offer.amount;
    if wheat_stays {
        new_amount = new_amount.saturating_sub(num_wheat_received);
    } else {
        new_amount = 0;
    }

    if new_amount == 0 {
        let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
            seller_id: seller.clone(),
            offer_id: offer.offer_id,
        });
        if state.entry_sponsor(&ledger_key).is_some() {
            state.remove_entry_sponsorship_and_update_counts(&ledger_key, &seller, 1)?;
        }
        state.delete_offer(&seller, offer.offer_id);
        if let Some(account) = state.get_account_mut(&seller) {
            if account.num_sub_entries > 0 {
                account.num_sub_entries -= 1;
            }
        }
    } else {
        let updated = stellar_xdr::curr::OfferEntry {
            amount: new_amount,
            ..offer.clone()
        };
        state.update_offer(updated);
        let (new_selling, new_buying) = offer_liabilities_sell(new_amount, &offer.price)?;
        apply_liabilities_delta(
            &seller,
            &offer.selling,
            &offer.buying,
            new_selling,
            new_buying,
            state,
        )?;
    }

    if num_wheat_received > 0 && num_sheep_send > 0 {
        offer_trail.push(ClaimAtom::OrderBook(ClaimOfferAtom {
            seller_id: seller,
            offer_id: offer.offer_id,
            asset_sold: wheat,
            amount_sold: num_wheat_received,
            asset_bought: sheep,
            amount_bought: num_sheep_send,
        }));
    }

    Ok((num_wheat_received, num_sheep_send, wheat_stays))
}

fn can_sell_at_most(
    source: &AccountId,
    asset: &Asset,
    state: &LedgerStateManager,
    context: &LedgerContext,
) -> Result<i64> {
    if matches!(asset, Asset::Native) {
        let Some(account) = state.get_account(source) else {
            return Ok(0);
        };
        let min_balance =
            state.minimum_balance_for_account(account, context.protocol_version, 0)?;
        let available = account.balance - min_balance - account_liabilities(account).selling;
        return Ok(available.max(0));
    }

    if issuer_for_asset(asset) == Some(source) {
        return Ok(i64::MAX);
    }

    let Some(trustline) = state.get_trustline(source, asset) else {
        return Ok(0);
    };
    if !is_authorized_to_maintain_liabilities(trustline.flags) {
        return Ok(0);
    }
    let available = trustline.balance - trustline_liabilities(trustline).selling;
    Ok(available.max(0))
}

fn can_buy_at_most(source: &AccountId, asset: &Asset, state: &LedgerStateManager) -> i64 {
    if matches!(asset, Asset::Native) {
        let Some(account) = state.get_account(source) else {
            return 0;
        };
        let available =
            i64::MAX - account.balance - account_liabilities(account).buying;
        return available.max(0);
    }

    if issuer_for_asset(asset) == Some(source) {
        return i64::MAX;
    }

    let Some(trustline) = state.get_trustline(source, asset) else {
        return 0;
    };
    if !is_authorized_to_maintain_liabilities(trustline.flags) {
        return 0;
    }
    let available =
        trustline.limit - trustline.balance - trustline_liabilities(trustline).buying;
    available.max(0)
}

fn apply_balance_delta(
    account_id: &AccountId,
    asset: &Asset,
    amount: i64,
    state: &mut LedgerStateManager,
) -> Result<()> {
    if matches!(asset, Asset::Native) {
        let Some(account) = state.get_account_mut(account_id) else {
            return Err(TxError::Internal("missing account for balance update".into()));
        };
        let new_balance = account
            .balance
            .checked_add(amount)
            .ok_or_else(|| TxError::Internal("balance overflow".into()))?;
        if new_balance < 0 {
            return Err(TxError::Internal("balance underflow".into()));
        }
        account.balance = new_balance;
        return Ok(());
    }

    if issuer_for_asset(asset) == Some(account_id) {
        return Ok(());
    }

    let Some(tl) = state.get_trustline_mut(account_id, asset) else {
        return Err(TxError::Internal("missing trustline for balance update".into()));
    };
    let new_balance = tl
        .balance
        .checked_add(amount)
        .ok_or_else(|| TxError::Internal("trustline balance overflow".into()))?;
    if new_balance < 0 || new_balance > tl.limit {
        return Err(TxError::Internal("trustline balance out of bounds".into()));
    }
    tl.balance = new_balance;
    Ok(())
}

fn offer_liabilities_sell(amount: i64, price: &Price) -> Result<(i64, i64)> {
    let res = exchange_v10_without_price_error_thresholds(
        price.clone(),
        amount,
        i64::MAX,
        i64::MAX,
        i64::MAX,
        RoundingType::Normal,
    )
    .map_err(map_exchange_error)?;
    Ok((res.num_wheat_received, res.num_sheep_send))
}

fn apply_liabilities_delta(
    account_id: &AccountId,
    selling: &Asset,
    buying: &Asset,
    selling_delta: i64,
    buying_delta: i64,
    state: &mut LedgerStateManager,
) -> Result<()> {
    if matches!(selling, Asset::Native) {
        let Some(account) = state.get_account_mut(account_id) else {
            return Err(TxError::Internal("missing account for liabilities".into()));
        };
        let liab = ensure_account_liabilities(account);
        update_liabilities(liab, 0, selling_delta)?;
    } else if issuer_for_asset(selling) != Some(account_id) {
        let Some(trustline) = state.get_trustline_mut(account_id, selling) else {
            return Err(TxError::Internal("missing trustline for liabilities".into()));
        };
        let liab = ensure_trustline_liabilities(trustline);
        update_liabilities(liab, 0, selling_delta)?;
    }

    if matches!(buying, Asset::Native) {
        let Some(account) = state.get_account_mut(account_id) else {
            return Err(TxError::Internal("missing account for liabilities".into()));
        };
        let liab = ensure_account_liabilities(account);
        update_liabilities(liab, buying_delta, 0)?;
    } else if issuer_for_asset(buying) != Some(account_id) {
        let Some(trustline) = state.get_trustline_mut(account_id, buying) else {
            return Err(TxError::Internal("missing trustline for liabilities".into()));
        };
        let liab = ensure_trustline_liabilities(trustline);
        update_liabilities(liab, buying_delta, 0)?;
    }

    Ok(())
}

fn update_liabilities(liab: &mut Liabilities, buying_delta: i64, selling_delta: i64) -> Result<()> {
    let new_buying = liab
        .buying
        .checked_add(buying_delta)
        .ok_or_else(|| TxError::Internal("liabilities overflow".into()))?;
    let new_selling = liab
        .selling
        .checked_add(selling_delta)
        .ok_or_else(|| TxError::Internal("liabilities overflow".into()))?;
    if new_buying < 0 || new_selling < 0 {
        return Err(TxError::Internal("liabilities underflow".into()));
    }
    liab.buying = new_buying;
    liab.selling = new_selling;
    Ok(())
}

fn ensure_account_liabilities(account: &mut AccountEntry) -> &mut Liabilities {
    if matches!(account.ext, AccountEntryExt::V0) {
        account.ext = AccountEntryExt::V1(AccountEntryExtensionV1 {
            liabilities: Liabilities {
                buying: 0,
                selling: 0,
            },
            ext: AccountEntryExtensionV1Ext::V0,
        });
    }
    match &mut account.ext {
        AccountEntryExt::V1(v1) => &mut v1.liabilities,
        AccountEntryExt::V0 => unreachable!("account liabilities not initialized"),
    }
}

fn ensure_trustline_liabilities(trustline: &mut TrustLineEntry) -> &mut Liabilities {
    if matches!(trustline.ext, TrustLineEntryExt::V0) {
        trustline.ext = TrustLineEntryExt::V1(TrustLineEntryV1 {
            liabilities: Liabilities {
                buying: 0,
                selling: 0,
            },
            ext: TrustLineEntryV1Ext::V0,
        });
    }
    match &mut trustline.ext {
        TrustLineEntryExt::V1(v1) => &mut v1.liabilities,
        TrustLineEntryExt::V0 => unreachable!("trustline liabilities not initialized"),
    }
}

struct PoolExchange {
    pool_id: PoolId,
    send: i64,
    recv: i64,
}

fn compute_pool_exchange(
    send_asset: &Asset,
    max_send: i64,
    recv_asset: &Asset,
    max_recv: i64,
    round: RoundingType,
    state: &LedgerStateManager,
) -> Result<Option<PoolExchange>> {
    let pool_id = pool_id_for_assets(send_asset, recv_asset)?;
    let Some(pool) = state.get_liquidity_pool(&pool_id) else {
        return Ok(None);
    };
    let LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) = &pool.body;

    if cp.reserve_a <= 0 || cp.reserve_b <= 0 {
        return Ok(None);
    }

    let fee_bps = LIQUIDITY_POOL_FEE_V18 as i64;
    let (reserves_to, reserves_from, max_send, max_recv) =
        if send_asset == &cp.params.asset_a && recv_asset == &cp.params.asset_b {
            (cp.reserve_a, cp.reserve_b, max_send, max_recv)
        } else if send_asset == &cp.params.asset_b && recv_asset == &cp.params.asset_a {
            (cp.reserve_b, cp.reserve_a, max_send, max_recv)
        } else {
            return Ok(None);
        };

    let mut to_pool = 0i64;
    let mut from_pool = 0i64;
    let ok = exchange_with_pool(
        reserves_to,
        max_send,
        &mut to_pool,
        reserves_from,
        max_recv,
        &mut from_pool,
        fee_bps,
        round,
    )?;
    if !ok {
        return Ok(None);
    }

    Ok(Some(PoolExchange {
        pool_id,
        send: to_pool,
        recv: from_pool,
    }))
}

fn apply_pool_exchange(
    send_asset: &Asset,
    recv_asset: &Asset,
    to_pool: i64,
    from_pool: i64,
    state: &mut LedgerStateManager,
) -> Result<bool> {
    let pool_id = pool_id_for_assets(send_asset, recv_asset)?;
    let Some(pool) = state.get_liquidity_pool_mut(&pool_id) else {
        return Ok(false);
    };
    let LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) = &mut pool.body;

    if send_asset == &cp.params.asset_a && recv_asset == &cp.params.asset_b {
        cp.reserve_a = cp.reserve_a.checked_add(to_pool).ok_or_else(|| {
            TxError::Internal("pool reserve overflow".into())
        })?;
        cp.reserve_b = cp.reserve_b.checked_sub(from_pool).ok_or_else(|| {
            TxError::Internal("pool reserve underflow".into())
        })?;
    } else if send_asset == &cp.params.asset_b && recv_asset == &cp.params.asset_a {
        cp.reserve_b = cp.reserve_b.checked_add(to_pool).ok_or_else(|| {
            TxError::Internal("pool reserve overflow".into())
        })?;
        cp.reserve_a = cp.reserve_a.checked_sub(from_pool).ok_or_else(|| {
            TxError::Internal("pool reserve underflow".into())
        })?;
    } else {
        return Ok(false);
    }

    Ok(true)
}

fn pool_id_for_assets(send_asset: &Asset, recv_asset: &Asset) -> Result<PoolId> {
    let params = LiquidityPoolParameters::LiquidityPoolConstantProduct(
        stellar_xdr::curr::LiquidityPoolConstantProductParameters {
            asset_a: std::cmp::min(send_asset.clone(), recv_asset.clone()),
            asset_b: std::cmp::max(send_asset.clone(), recv_asset.clone()),
            fee: LIQUIDITY_POOL_FEE_V18 as i32,
        },
    );
    let xdr = params.to_xdr(Limits::none())?;
    let mut hasher = Sha256::new();
    hasher.update(&xdr);
    Ok(PoolId(Hash(hasher.finalize().into())))
}

fn exchange_with_pool(
    reserves_to_pool: i64,
    max_send_to_pool: i64,
    to_pool: &mut i64,
    reserves_from_pool: i64,
    max_receive_from_pool: i64,
    from_pool: &mut i64,
    fee_bps: i64,
    round: RoundingType,
) -> Result<bool> {
    const MAX_BPS: i64 = 10_000;
    if fee_bps < 0 || fee_bps >= MAX_BPS {
        return Err(TxError::Internal("pool fee out of range".into()));
    }
    if reserves_to_pool <= 0 || reserves_from_pool <= 0 {
        return Err(TxError::Internal("non-positive pool reserves".into()));
    }

    match round {
        RoundingType::PathPaymentStrictSend => {
            if max_receive_from_pool != i64::MAX {
                return Err(TxError::Internal("strict send with bounded receive".into()));
            }
            let max_receive_from_pool = reserves_from_pool;

            if max_send_to_pool > i64::MAX - reserves_to_pool {
                return Ok(false);
            }
            *to_pool = max_send_to_pool;

            let denominator = u128::from(MAX_BPS as u64) * u128::from(reserves_to_pool as u64)
                + u128::from((MAX_BPS - fee_bps) as u64) * u128::from(*to_pool as u64);

            let numerator = u128::from((MAX_BPS - fee_bps) as u64)
                * u128::from(reserves_from_pool as u64)
                * u128::from(*to_pool as u64);

            let value = numerator / denominator;
            if value > i64::MAX as u128 {
                return Err(TxError::Internal("pool exchange overflow".into()));
            }
            *from_pool = value as i64;

            if *from_pool > max_receive_from_pool || *from_pool == 0 {
                return Ok(false);
            }
            Ok(true)
        }
        RoundingType::PathPaymentStrictReceive => {
            if max_send_to_pool != i64::MAX {
                return Err(TxError::Internal("strict receive with bounded send".into()));
            }
            let max_send_to_pool = i64::MAX - reserves_to_pool;
            if max_receive_from_pool >= reserves_from_pool {
                return Ok(false);
            }
            *from_pool = max_receive_from_pool;

            let numerator = u128::from(MAX_BPS as u64)
                * u128::from(reserves_to_pool as u64)
                * u128::from(*from_pool as u64);
            let denominator = u128::from((reserves_from_pool - *from_pool) as u64)
                * u128::from((MAX_BPS - fee_bps) as u64);

            if denominator == 0 {
                return Ok(false);
            }
            let value = (numerator + denominator - 1) / denominator;
            if value > i64::MAX as u128 {
                return Err(TxError::Internal("pool exchange overflow".into()));
            }
            *to_pool = value as i64;
            Ok(*to_pool <= max_send_to_pool)
        }
        RoundingType::Normal => Ok(false),
    }
}

fn map_exchange_error(err: ExchangeError) -> TxError {
    TxError::Internal(format!("offer exchange error: {err:?}"))
}

fn account_liabilities(account: &AccountEntry) -> Liabilities {
    match &account.ext {
        AccountEntryExt::V0 => Liabilities {
            buying: 0,
            selling: 0,
        },
        AccountEntryExt::V1(v1) => v1.liabilities.clone(),
    }
}

fn trustline_liabilities(trustline: &TrustLineEntry) -> Liabilities {
    match &trustline.ext {
        TrustLineEntryExt::V0 => Liabilities {
            buying: 0,
            selling: 0,
        },
        TrustLineEntryExt::V1(v1) => v1.liabilities.clone(),
    }
}

/// Convert PathPaymentStrictReceiveResultCode to PathPaymentStrictSendResultCode.
fn convert_receive_to_send_code(
    code: PathPaymentStrictReceiveResultCode,
) -> PathPaymentStrictSendResultCode {
    match code {
        PathPaymentStrictReceiveResultCode::Success => PathPaymentStrictSendResultCode::Success,
        PathPaymentStrictReceiveResultCode::Malformed => PathPaymentStrictSendResultCode::Malformed,
        PathPaymentStrictReceiveResultCode::Underfunded => {
            PathPaymentStrictSendResultCode::Underfunded
        }
        PathPaymentStrictReceiveResultCode::SrcNoTrust => {
            PathPaymentStrictSendResultCode::SrcNoTrust
        }
        PathPaymentStrictReceiveResultCode::SrcNotAuthorized => {
            PathPaymentStrictSendResultCode::SrcNotAuthorized
        }
        PathPaymentStrictReceiveResultCode::NoDestination => {
            PathPaymentStrictSendResultCode::NoDestination
        }
        PathPaymentStrictReceiveResultCode::NoTrust => PathPaymentStrictSendResultCode::NoTrust,
        PathPaymentStrictReceiveResultCode::NotAuthorized => {
            PathPaymentStrictSendResultCode::NotAuthorized
        }
        PathPaymentStrictReceiveResultCode::LineFull => PathPaymentStrictSendResultCode::LineFull,
        PathPaymentStrictReceiveResultCode::NoIssuer => PathPaymentStrictSendResultCode::NoIssuer,
        PathPaymentStrictReceiveResultCode::TooFewOffers => {
            PathPaymentStrictSendResultCode::TooFewOffers
        }
        PathPaymentStrictReceiveResultCode::OfferCrossSelf => {
            PathPaymentStrictSendResultCode::OfferCrossSelf
        }
        PathPaymentStrictReceiveResultCode::OverSendmax => {
            // No direct equivalent, use TooFewOffers
            PathPaymentStrictSendResultCode::TooFewOffers
        }
    }
}

/// Create a PathPaymentStrictReceive result.
fn make_strict_receive_result(
    code: PathPaymentStrictReceiveResultCode,
    success: Option<PathPaymentStrictReceiveResultSuccess>,
) -> OperationResult {
    make_strict_receive_result_with_asset(code, None, success)
}

fn make_strict_receive_result_with_asset(
    code: PathPaymentStrictReceiveResultCode,
    no_issuer_asset: Option<Asset>,
    success: Option<PathPaymentStrictReceiveResultSuccess>,
) -> OperationResult {
    let result = match code {
        PathPaymentStrictReceiveResultCode::Success => {
            PathPaymentStrictReceiveResult::Success(success.unwrap())
        }
        PathPaymentStrictReceiveResultCode::Malformed => PathPaymentStrictReceiveResult::Malformed,
        PathPaymentStrictReceiveResultCode::Underfunded => {
            PathPaymentStrictReceiveResult::Underfunded
        }
        PathPaymentStrictReceiveResultCode::SrcNoTrust => {
            PathPaymentStrictReceiveResult::SrcNoTrust
        }
        PathPaymentStrictReceiveResultCode::SrcNotAuthorized => {
            PathPaymentStrictReceiveResult::SrcNotAuthorized
        }
        PathPaymentStrictReceiveResultCode::NoDestination => {
            PathPaymentStrictReceiveResult::NoDestination
        }
        PathPaymentStrictReceiveResultCode::NoTrust => PathPaymentStrictReceiveResult::NoTrust,
        PathPaymentStrictReceiveResultCode::NotAuthorized => {
            PathPaymentStrictReceiveResult::NotAuthorized
        }
        PathPaymentStrictReceiveResultCode::LineFull => PathPaymentStrictReceiveResult::LineFull,
        PathPaymentStrictReceiveResultCode::NoIssuer => {
            // NoIssuer takes an Asset parameter
            PathPaymentStrictReceiveResult::NoIssuer(no_issuer_asset.unwrap_or(Asset::Native))
        }
        PathPaymentStrictReceiveResultCode::TooFewOffers => {
            PathPaymentStrictReceiveResult::TooFewOffers
        }
        PathPaymentStrictReceiveResultCode::OfferCrossSelf => {
            PathPaymentStrictReceiveResult::OfferCrossSelf
        }
        PathPaymentStrictReceiveResultCode::OverSendmax => {
            PathPaymentStrictReceiveResult::OverSendmax
        }
    };

    OperationResult::OpInner(OperationResultTr::PathPaymentStrictReceive(result))
}

/// Create a PathPaymentStrictSend result.
fn make_strict_send_result(
    code: PathPaymentStrictSendResultCode,
    success: Option<PathPaymentStrictSendResultSuccess>,
) -> OperationResult {
    make_strict_send_result_with_asset(code, None, success)
}

fn make_strict_send_result_with_asset(
    code: PathPaymentStrictSendResultCode,
    no_issuer_asset: Option<Asset>,
    success: Option<PathPaymentStrictSendResultSuccess>,
) -> OperationResult {
    let result = match code {
        PathPaymentStrictSendResultCode::Success => {
            PathPaymentStrictSendResult::Success(success.unwrap())
        }
        PathPaymentStrictSendResultCode::Malformed => PathPaymentStrictSendResult::Malformed,
        PathPaymentStrictSendResultCode::Underfunded => PathPaymentStrictSendResult::Underfunded,
        PathPaymentStrictSendResultCode::SrcNoTrust => PathPaymentStrictSendResult::SrcNoTrust,
        PathPaymentStrictSendResultCode::SrcNotAuthorized => {
            PathPaymentStrictSendResult::SrcNotAuthorized
        }
        PathPaymentStrictSendResultCode::NoDestination => {
            PathPaymentStrictSendResult::NoDestination
        }
        PathPaymentStrictSendResultCode::NoTrust => PathPaymentStrictSendResult::NoTrust,
        PathPaymentStrictSendResultCode::NotAuthorized => {
            PathPaymentStrictSendResult::NotAuthorized
        }
        PathPaymentStrictSendResultCode::LineFull => PathPaymentStrictSendResult::LineFull,
        PathPaymentStrictSendResultCode::NoIssuer => {
            PathPaymentStrictSendResult::NoIssuer(no_issuer_asset.unwrap_or(Asset::Native))
        }
        PathPaymentStrictSendResultCode::TooFewOffers => PathPaymentStrictSendResult::TooFewOffers,
        PathPaymentStrictSendResultCode::OfferCrossSelf => {
            PathPaymentStrictSendResult::OfferCrossSelf
        }
        PathPaymentStrictSendResultCode::UnderDestmin => PathPaymentStrictSendResult::UnderDestmin,
    };

    OperationResult::OpInner(OperationResultTr::PathPaymentStrictSend(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    const AUTH_REQUIRED_FLAG: u32 = 0x1;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    fn create_test_muxed_account(seed: u8) -> MuxedAccount {
        MuxedAccount::Ed25519(Uint256([seed; 32]))
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

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    fn create_test_trustline(
        account_id: AccountId,
        asset: TrustLineAsset,
        balance: i64,
        limit: i64,
        flags: u32,
    ) -> TrustLineEntry {
        TrustLineEntry {
            account_id,
            asset,
            balance,
            limit,
            flags,
            ext: TrustLineEntryExt::V0,
        }
    }

    fn create_test_trustline_with_liabilities(
        account_id: AccountId,
        asset: TrustLineAsset,
        balance: i64,
        limit: i64,
        flags: u32,
        buying_liab: i64,
        selling_liab: i64,
    ) -> TrustLineEntry {
        TrustLineEntry {
            account_id,
            asset,
            balance,
            limit,
            flags,
            ext: TrustLineEntryExt::V1(TrustLineEntryV1 {
                liabilities: Liabilities {
                    buying: buying_liab,
                    selling: selling_liab,
                },
                ext: TrustLineEntryV1Ext::V0,
            }),
        }
    }

    fn create_asset(issuer: &AccountId) -> Asset {
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer.clone(),
        })
    }

    #[test]
    fn test_path_payment_strict_receive_native() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);

        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 50_000_000));

        let op = PathPaymentStrictReceiveOp {
            send_asset: Asset::Native,
            send_max: 20_000_000,
            destination: create_test_muxed_account(1),
            dest_asset: Asset::Native,
            dest_amount: 10_000_000,
            path: vec![].try_into().unwrap(),
        };

        let result = execute_path_payment_strict_receive(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        // Verify balances
        assert_eq!(state.get_account(&source_id).unwrap().balance, 90_000_000);
        assert_eq!(state.get_account(&dest_id).unwrap().balance, 60_000_000);
    }

    #[test]
    fn test_path_payment_strict_send_native() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);

        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 50_000_000));

        let op = PathPaymentStrictSendOp {
            send_asset: Asset::Native,
            send_amount: 10_000_000,
            destination: create_test_muxed_account(1),
            dest_asset: Asset::Native,
            dest_min: 5_000_000,
            path: vec![].try_into().unwrap(),
        };

        let result = execute_path_payment_strict_send(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        // Verify balances
        assert_eq!(state.get_account(&source_id).unwrap().balance, 90_000_000);
        assert_eq!(state.get_account(&dest_id).unwrap().balance, 60_000_000);
    }

    #[test]
    fn test_path_payment_no_destination() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = PathPaymentStrictReceiveOp {
            send_asset: Asset::Native,
            send_max: 20_000_000,
            destination: create_test_muxed_account(1), // Non-existent
            dest_asset: Asset::Native,
            dest_amount: 10_000_000,
            path: vec![].try_into().unwrap(),
        };

        let result = execute_path_payment_strict_receive(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::PathPaymentStrictReceive(r)) => {
                assert!(matches!(r, PathPaymentStrictReceiveResult::NoDestination));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_path_payment_credit_no_issuer() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(9);
        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 100_000_000));

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            100,
            1_000_000,
            AUTHORIZED_FLAG,
        ));
        state.create_trustline(create_test_trustline(
            dest_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            1_000_000,
            AUTHORIZED_FLAG,
        ));

        let op = PathPaymentStrictReceiveOp {
            send_asset: asset.clone(),
            send_max: 100,
            destination: create_test_muxed_account(1),
            dest_asset: asset,
            dest_amount: 10,
            path: vec![].try_into().unwrap(),
        };

        let result = execute_path_payment_strict_receive(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::PathPaymentStrictReceive(r)) => {
                if let PathPaymentStrictReceiveResult::NoIssuer(asset) = r {
                    assert_eq!(asset, create_asset(&issuer_id));
                } else {
                    panic!("Unexpected result type");
                }
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_path_payment_credit_src_not_authorized() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(9);
        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 100_000_000));
        state
            .get_account_mut(&issuer_id)
            .unwrap()
            .flags = AUTH_REQUIRED_FLAG;

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            100,
            1_000_000,
            0,
        ));
        state.create_trustline(create_test_trustline(
            dest_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            1_000_000,
            AUTHORIZED_FLAG,
        ));

        let op = PathPaymentStrictReceiveOp {
            send_asset: asset.clone(),
            send_max: 100,
            destination: create_test_muxed_account(1),
            dest_asset: asset,
            dest_amount: 10,
            path: vec![].try_into().unwrap(),
        };

        let result = execute_path_payment_strict_receive(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::PathPaymentStrictReceive(r)) => {
                assert!(matches!(r, PathPaymentStrictReceiveResult::SrcNotAuthorized));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_path_payment_credit_not_authorized_dest() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(9);
        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 100_000_000));
        state
            .get_account_mut(&issuer_id)
            .unwrap()
            .flags = AUTH_REQUIRED_FLAG;

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            100,
            1_000_000,
            AUTHORIZED_FLAG,
        ));
        state.create_trustline(create_test_trustline(
            dest_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            1_000_000,
            0,
        ));

        let op = PathPaymentStrictReceiveOp {
            send_asset: asset.clone(),
            send_max: 100,
            destination: create_test_muxed_account(1),
            dest_asset: asset,
            dest_amount: 10,
            path: vec![].try_into().unwrap(),
        };

        let result = execute_path_payment_strict_receive(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::PathPaymentStrictReceive(r)) => {
                assert!(matches!(r, PathPaymentStrictReceiveResult::NotAuthorized));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_path_payment_strict_send_credit_no_issuer() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(9);
        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 100_000_000));

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            100,
            1_000_000,
            AUTHORIZED_FLAG,
        ));
        state.create_trustline(create_test_trustline(
            dest_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            1_000_000,
            AUTHORIZED_FLAG,
        ));

        let op = PathPaymentStrictSendOp {
            send_asset: asset.clone(),
            send_amount: 10,
            destination: create_test_muxed_account(1),
            dest_asset: asset,
            dest_min: 1,
            path: vec![].try_into().unwrap(),
        };

        let result =
            execute_path_payment_strict_send(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::PathPaymentStrictSend(r)) => {
                if let PathPaymentStrictSendResult::NoIssuer(asset) = r {
                    assert_eq!(asset, create_asset(&issuer_id));
                } else {
                    panic!("Unexpected result type");
                }
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_path_payment_credit_line_full_with_liabilities() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(9);
        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 100_000_000));

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            100,
            1_000_000,
            AUTHORIZED_FLAG,
        ));
        state.create_trustline(create_test_trustline_with_liabilities(
            dest_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            90,
            100,
            AUTHORIZED_FLAG,
            10,
            0,
        ));

        let op = PathPaymentStrictReceiveOp {
            send_asset: asset.clone(),
            send_max: 100,
            destination: create_test_muxed_account(1),
            dest_asset: asset,
            dest_amount: 1,
            path: vec![].try_into().unwrap(),
        };

        let result = execute_path_payment_strict_receive(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::PathPaymentStrictReceive(r)) => {
                assert!(matches!(r, PathPaymentStrictReceiveResult::LineFull));
            }
            _ => panic!("Unexpected result type"),
        }
    }
}
