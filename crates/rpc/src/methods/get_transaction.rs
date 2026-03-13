//! Handler for the `getTransaction` JSON-RPC method.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::json;
use stellar_xdr::curr::{Limits, ReadXdr, TransactionEnvelope};

use crate::context::RpcContext;
use crate::error::JsonRpcError;
use crate::util;

pub async fn handle(
    ctx: &Arc<RpcContext>,
    params: serde_json::Value,
) -> Result<serde_json::Value, JsonRpcError> {
    let hash = params
        .get("hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError::invalid_params("missing 'hash' parameter"))?;

    let ledger = ctx.app.ledger_summary();
    let oldest = util::oldest_ledger(&ctx.app);

    // Look up the oldest ledger close time
    let oldest_close_time = ctx
        .app
        .database()
        .with_connection(|conn| {
            use henyey_db::LedgerQueries;
            conn.load_ledger_header(oldest)
        })
        .ok()
        .flatten()
        .map(|h| h.scp_value.close_time.0.to_string())
        .unwrap_or_else(|| "0".to_string());

    // Look up the transaction in the database
    let tx_record = ctx
        .app
        .database()
        .with_connection(|conn| {
            use henyey_db::HistoryQueries;
            conn.load_transaction(hash)
        })
        .map_err(|e| JsonRpcError::internal(format!("database error: {}", e)))?;

    match tx_record {
        Some(record) => {
            let envelope_xdr = BASE64.encode(&record.body);
            // DB stores TransactionResultPair; extract just TransactionResult for the API
            let result_xdr = match util::extract_result_xdr(&record.result) {
                Some(result_bytes) => BASE64.encode(&result_bytes),
                None => BASE64.encode(&record.result), // fallback
            };
            let result_meta_xdr = record
                .meta
                .as_ref()
                .map(|m| BASE64.encode(m))
                .unwrap_or_default();

            // Look up the ledger close time
            let created_at = ctx
                .app
                .database()
                .with_connection(|conn| {
                    use henyey_db::LedgerQueries;
                    conn.load_ledger_header(record.ledger_seq)
                })
                .ok()
                .flatten()
                .map(|h| h.scp_value.close_time.0.to_string())
                .unwrap_or_else(|| "0".to_string());

            // Determine status from the result XDR
            let status = util::determine_tx_status(&record.result);

            // Detect fee bump from the envelope
            let fee_bump = TransactionEnvelope::from_xdr(&record.body, Limits::none())
                .map(|env| matches!(env, TransactionEnvelope::TxFeeBump(_)))
                .unwrap_or(false);

            let mut tx = json!({
                "status": status,
                "latestLedger": ledger.num,
                "latestLedgerCloseTime": ledger.close_time.to_string(),
                "oldestLedger": oldest,
                "oldestLedgerCloseTime": oldest_close_time,
                "ledger": record.ledger_seq,
                "createdAt": created_at,
                "applicationOrder": record.tx_index + 1,
                "feeBump": fee_bump,
                "envelopeXdr": envelope_xdr,
                "resultXdr": result_xdr,
                "resultMetaXdr": result_meta_xdr
            });

            // Extract diagnostic events from meta if available
            if let Some(ref meta_bytes) = record.meta {
                if let Some(events_xdr) = util::extract_diagnostic_events_xdr(meta_bytes) {
                    tx.as_object_mut()
                        .unwrap()
                        .insert("diagnosticEventsXdr".into(), json!(events_xdr));
                }
            }

            Ok(tx)
        }
        None => Ok(json!({
            "status": "NOT_FOUND",
            "latestLedger": ledger.num,
            "latestLedgerCloseTime": ledger.close_time.to_string(),
            "oldestLedger": oldest,
            "oldestLedgerCloseTime": oldest_close_time
        })),
    }
}
