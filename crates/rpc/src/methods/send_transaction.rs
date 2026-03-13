//! Handler for the `sendTransaction` JSON-RPC method.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::json;
use stellar_xdr::curr::{Limits, ReadXdr, TransactionEnvelope, TransactionResultCode};

use crate::context::RpcContext;
use crate::error::JsonRpcError;
use crate::util::{self, XdrFormat};

pub async fn handle(
    ctx: &Arc<RpcContext>,
    params: serde_json::Value,
) -> Result<serde_json::Value, JsonRpcError> {
    let format = util::parse_format(&params)?;

    let tx_b64 = params
        .get("transaction")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError::invalid_params("missing 'transaction' parameter"))?;

    let tx_bytes = BASE64
        .decode(tx_b64)
        .map_err(|e| JsonRpcError::invalid_params(format!("invalid base64: {}", e)))?;

    let tx_env = TransactionEnvelope::from_xdr(&tx_bytes, Limits::none())
        .map_err(|e| JsonRpcError::invalid_params(format!("invalid XDR: {}", e)))?;

    // Compute the transaction hash
    let network_id =
        henyey_common::NetworkId::from_passphrase(&ctx.app.info().network_passphrase);
    let mut frame = henyey_tx::TransactionFrame::with_network(tx_env.clone(), network_id);
    let hash = frame
        .compute_hash(&network_id)
        .map(|h| h.to_hex())
        .unwrap_or_default();

    let ledger = ctx.app.ledger_summary();

    // Submit to herder
    let result = ctx.app.submit_transaction(tx_env.clone()).await;

    // Build base response with fields common to all outcomes
    let close_time = ledger.close_time.to_string();
    let mut obj = serde_json::Map::new();
    obj.insert("hash".into(), json!(hash));
    obj.insert("latestLedger".into(), json!(ledger.num));
    obj.insert("latestLedgerCloseTime".into(), json!(close_time));

    match result {
        henyey_herder::TxQueueResult::Added => {
            obj.insert("status".into(), json!("PENDING"));
        }
        henyey_herder::TxQueueResult::Duplicate => {
            obj.insert("status".into(), json!("DUPLICATE"));
        }
        henyey_herder::TxQueueResult::QueueFull
        | henyey_herder::TxQueueResult::TryAgainLater => {
            obj.insert("status".into(), json!("TRY_AGAIN_LATER"));
        }
        henyey_herder::TxQueueResult::Invalid(code) => {
            obj.insert("status".into(), json!("ERROR"));
            let error_result = build_error_result(code);
            util::insert_xdr_field(&mut obj, "errorResult", &error_result, format)?;
            // Empty diagnostic events array
            match format {
                XdrFormat::Base64 => {
                    obj.insert("diagnosticEventsXdr".into(), json!([]));
                }
                XdrFormat::Json => {
                    obj.insert("diagnosticEventsJson".into(), json!([]));
                }
            }
        }
        henyey_herder::TxQueueResult::Banned => {
            obj.insert("status".into(), json!("ERROR"));
            let error_result =
                build_error_result(Some(TransactionResultCode::TxTooLate));
            util::insert_xdr_field(&mut obj, "errorResult", &error_result, format)?;
        }
        henyey_herder::TxQueueResult::FeeTooLow => {
            obj.insert("status".into(), json!("ERROR"));
            let error_result =
                build_error_result(Some(TransactionResultCode::TxInsufficientFee));
            util::insert_xdr_field(&mut obj, "errorResult", &error_result, format)?;
        }
        henyey_herder::TxQueueResult::Filtered => {
            obj.insert("status".into(), json!("ERROR"));
            let error_result =
                build_error_result(Some(TransactionResultCode::TxFailed));
            util::insert_xdr_field(&mut obj, "errorResult", &error_result, format)?;
        }
    }

    Ok(serde_json::Value::Object(obj))
}

/// Build an error TransactionResult for the response using the actual error code.
fn build_error_result(
    code: Option<TransactionResultCode>,
) -> stellar_xdr::curr::TransactionResult {
    use henyey_tx::TransactionResultCodeExt;
    use stellar_xdr::curr::{
        TransactionResult, TransactionResultExt, TransactionResultResult,
    };

    let result = code
        .map(|c| c.to_xdr_result())
        .unwrap_or(TransactionResultResult::TxInternalError);

    TransactionResult {
        fee_charged: 0,
        result,
        ext: TransactionResultExt::V0,
    }
}
