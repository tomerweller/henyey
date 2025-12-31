//! Path Payment operation execution.
//!
//! This module implements the execution logic for PathPaymentStrictReceive
//! and PathPaymentStrictSend operations, which transfer assets through a path.

use stellar_xdr::curr::{
    AccountId, Asset, ClaimAtom, OperationResult, OperationResultTr, PathPaymentStrictReceiveOp,
    PathPaymentStrictReceiveResult, PathPaymentStrictReceiveResultCode,
    PathPaymentStrictReceiveResultSuccess, PathPaymentStrictSendOp, PathPaymentStrictSendResult,
    PathPaymentStrictSendResultCode, PathPaymentStrictSendResultSuccess, SimplePaymentResult,
};

use crate::frame::muxed_to_account_id;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::{Result, TxError};

/// Execute a PathPaymentStrictReceive operation.
///
/// This operation sends at most `send_max` of `send_asset` to receive exactly
/// `dest_amount` of `dest_asset` at the destination.
pub fn execute_path_payment_strict_receive(
    op: &PathPaymentStrictReceiveOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    let dest = muxed_to_account_id(&op.destination);

    // Validate amounts
    if op.send_max <= 0 || op.dest_amount <= 0 {
        return Ok(make_strict_receive_result(
            PathPaymentStrictReceiveResultCode::Malformed,
            None,
        ));
    }

    // Check destination exists
    if state.get_account(&dest).is_none() {
        return Ok(make_strict_receive_result(
            PathPaymentStrictReceiveResultCode::NoDestination,
            None,
        ));
    }

    // For now, we only support direct payments (no path)
    // A full implementation would walk through the path and execute trades
    if !op.path.is_empty() {
        // Path payments through the order book require offer matching
        // For now, return too few offers if there's a path
        return Ok(make_strict_receive_result(
            PathPaymentStrictReceiveResultCode::TooFewOffers,
            None,
        ));
    }

    // Direct payment: send_asset must equal dest_asset
    if op.send_asset != op.dest_asset {
        return Ok(make_strict_receive_result(
            PathPaymentStrictReceiveResultCode::TooFewOffers,
            None,
        ));
    }

    // Check send_max is sufficient for dest_amount (1:1 for same asset)
    if op.send_max < op.dest_amount {
        return Ok(make_strict_receive_result(
            PathPaymentStrictReceiveResultCode::OverSendmax,
            None,
        ));
    }

    // Execute the payment
    let send_amount = op.dest_amount; // For same asset, 1:1 exchange
    match execute_asset_transfer(source, &dest, &op.send_asset, send_amount, &op.dest_asset, op.dest_amount, state) {
        Ok(_) => {
            let success = PathPaymentStrictReceiveResultSuccess {
                offers: vec![].try_into().unwrap(),
                last: SimplePaymentResult {
                    destination: dest,
                    asset: op.dest_asset.clone(),
                    amount: op.dest_amount,
                },
            };
            Ok(make_strict_receive_result(
                PathPaymentStrictReceiveResultCode::Success,
                Some(success),
            ))
        }
        Err(code) => Ok(make_strict_receive_result(code, None)),
    }
}

/// Execute a PathPaymentStrictSend operation.
///
/// This operation sends exactly `send_amount` of `send_asset` to receive at least
/// `dest_min` of `dest_asset` at the destination.
pub fn execute_path_payment_strict_send(
    op: &PathPaymentStrictSendOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    let dest = muxed_to_account_id(&op.destination);

    // Validate amounts
    if op.send_amount <= 0 || op.dest_min <= 0 {
        return Ok(make_strict_send_result(
            PathPaymentStrictSendResultCode::Malformed,
            None,
        ));
    }

    // Check destination exists
    if state.get_account(&dest).is_none() {
        return Ok(make_strict_send_result(
            PathPaymentStrictSendResultCode::NoDestination,
            None,
        ));
    }

    // For now, we only support direct payments (no path)
    if !op.path.is_empty() {
        return Ok(make_strict_send_result(
            PathPaymentStrictSendResultCode::TooFewOffers,
            None,
        ));
    }

    // Direct payment: send_asset must equal dest_asset
    if op.send_asset != op.dest_asset {
        return Ok(make_strict_send_result(
            PathPaymentStrictSendResultCode::TooFewOffers,
            None,
        ));
    }

    // Check dest_min is met (1:1 for same asset)
    if op.send_amount < op.dest_min {
        return Ok(make_strict_send_result(
            PathPaymentStrictSendResultCode::UnderDestmin,
            None,
        ));
    }

    // Execute the payment
    let dest_amount = op.send_amount; // For same asset, 1:1 exchange
    match execute_asset_transfer(source, &dest, &op.send_asset, op.send_amount, &op.dest_asset, dest_amount, state) {
        Ok(_) => {
            let success = PathPaymentStrictSendResultSuccess {
                offers: vec![].try_into().unwrap(),
                last: SimplePaymentResult {
                    destination: dest,
                    asset: op.dest_asset.clone(),
                    amount: dest_amount,
                },
            };
            Ok(make_strict_send_result(
                PathPaymentStrictSendResultCode::Success,
                Some(success),
            ))
        }
        Err(code) => Ok(make_strict_send_result(
            convert_receive_to_send_code(code),
            None,
        )),
    }
}

/// Execute an asset transfer from source to destination.
fn execute_asset_transfer(
    source: &AccountId,
    dest: &AccountId,
    send_asset: &Asset,
    send_amount: i64,
    dest_asset: &Asset,
    dest_amount: i64,
    state: &mut LedgerStateManager,
) -> std::result::Result<(), PathPaymentStrictReceiveResultCode> {
    match send_asset {
        Asset::Native => {
            // Native asset transfer
            let source_account = state
                .get_account(source)
                .ok_or(PathPaymentStrictReceiveResultCode::Underfunded)?;

            let source_min_balance = state.minimum_balance(source_account.num_sub_entries);
            let available = source_account.balance - source_min_balance;
            if available < send_amount {
                return Err(PathPaymentStrictReceiveResultCode::Underfunded);
            }

            // Deduct from source
            let source_account_mut = state
                .get_account_mut(source)
                .ok_or(PathPaymentStrictReceiveResultCode::Underfunded)?;
            source_account_mut.balance -= send_amount;

            // Credit to destination (native)
            if matches!(dest_asset, Asset::Native) {
                let dest_account_mut = state
                    .get_account_mut(dest)
                    .ok_or(PathPaymentStrictReceiveResultCode::NoDestination)?;
                dest_account_mut.balance += dest_amount;
            } else {
                // Cross-asset not supported for direct payments
                return Err(PathPaymentStrictReceiveResultCode::TooFewOffers);
            }
        }
        Asset::CreditAlphanum4(_) | Asset::CreditAlphanum12(_) => {
            // Credit asset transfer
            let source_trustline = state
                .get_trustline(source, send_asset)
                .ok_or(PathPaymentStrictReceiveResultCode::SrcNoTrust)?;

            if source_trustline.balance < send_amount {
                return Err(PathPaymentStrictReceiveResultCode::Underfunded);
            }

            // For credit assets, dest_asset must match for direct transfer
            if send_asset != dest_asset {
                return Err(PathPaymentStrictReceiveResultCode::TooFewOffers);
            }

            let dest_trustline = state
                .get_trustline(dest, dest_asset)
                .ok_or(PathPaymentStrictReceiveResultCode::NoTrust)?;

            let dest_available = dest_trustline.limit - dest_trustline.balance;
            if dest_available < dest_amount {
                return Err(PathPaymentStrictReceiveResultCode::LineFull);
            }

            // Update source trustline
            let source_trustline_mut = state
                .get_trustline_mut(source, send_asset)
                .ok_or(PathPaymentStrictReceiveResultCode::SrcNoTrust)?;
            source_trustline_mut.balance -= send_amount;

            // Update destination trustline
            let dest_trustline_mut = state
                .get_trustline_mut(dest, dest_asset)
                .ok_or(PathPaymentStrictReceiveResultCode::NoTrust)?;
            dest_trustline_mut.balance += dest_amount;
        }
    }

    Ok(())
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
            PathPaymentStrictReceiveResult::NoIssuer(Asset::Native)
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
            PathPaymentStrictSendResult::NoIssuer(Asset::Native)
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
}
