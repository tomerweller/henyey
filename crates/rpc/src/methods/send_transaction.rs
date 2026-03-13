//! Handler for the `sendTransaction` JSON-RPC method.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::json;
use stellar_xdr::curr::{Limits, ReadXdr, TransactionEnvelope, WriteXdr};

use crate::context::RpcContext;
use crate::error::JsonRpcError;

pub async fn handle(
    ctx: &Arc<RpcContext>,
    params: serde_json::Value,
) -> Result<serde_json::Value, JsonRpcError> {
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
    let mut resp = json!({
        "hash": hash,
        "latestLedger": ledger.num,
        "latestLedgerCloseTime": close_time
    });
    let obj = resp.as_object_mut().unwrap();

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
        henyey_herder::TxQueueResult::Invalid(_code) => {
            obj.insert("status".into(), json!("ERROR"));
            obj.insert("errorResultXdr".into(), json!(build_error_result_xdr()));
            obj.insert("diagnosticEventsXdr".into(), json!([]));
        }
        henyey_herder::TxQueueResult::Banned
        | henyey_herder::TxQueueResult::FeeTooLow
        | henyey_herder::TxQueueResult::Filtered => {
            obj.insert("status".into(), json!("ERROR"));
        }
    }

    Ok(resp)
}

/// Build a minimal error TransactionResult XDR for the response.
///
/// Currently always returns a generic `TxFailed` result. A more complete
/// implementation would map the actual error code.
fn build_error_result_xdr() -> String {
    use stellar_xdr::curr::{
        TransactionResult, TransactionResultExt,
        TransactionResultResult,
    };

    // Build a minimal TransactionResult
    let result = TransactionResult {
        fee_charged: 0,
        result: TransactionResultResult::TxFailed(stellar_xdr::curr::VecM::default()),
        ext: TransactionResultExt::V0,
    };

    match result.to_xdr(Limits::none()) {
        Ok(bytes) => BASE64.encode(&bytes),
        Err(_) => String::new(),
    }
}
