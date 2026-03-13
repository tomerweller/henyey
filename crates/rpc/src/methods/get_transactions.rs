//! Handler for the `getTransactions` JSON-RPC method.
//!
//! Returns a paginated list of transactions within a ledger range.
//! Supports cursor-based pagination using TOID (Total Order ID) values.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::json;
use stellar_xdr::curr::{Limits, ReadXdr, TransactionEnvelope};

use crate::context::RpcContext;
use crate::error::JsonRpcError;
use crate::util;

/// Default number of transactions returned per query.
const DEFAULT_TX_LIMIT: u32 = 10;
/// Maximum number of transactions that can be requested in a single query.
const MAX_TX_LIMIT: u32 = 200;

pub async fn handle(
    ctx: &Arc<RpcContext>,
    params: serde_json::Value,
) -> Result<serde_json::Value, JsonRpcError> {
    let ledger = ctx.app.ledger_summary();
    let oldest = util::oldest_ledger(&ctx.app);

    // Look up oldest ledger close time
    let oldest_close_time = get_ledger_close_time(ctx, oldest);

    // Parse parameters
    let start_ledger = params
        .get("startLedger")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    let pagination = params.get("pagination");
    let cursor = pagination
        .and_then(|p| p.get("cursor"))
        .and_then(|v| v.as_str());
    let limit = pagination
        .and_then(|p| p.get("limit"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    // Validate pagination
    let (effective_start, effective_cursor, effective_limit) = util::validate_pagination(
        start_ledger,
        cursor,
        limit,
        DEFAULT_TX_LIMIT,
        MAX_TX_LIMIT,
        oldest,
        ledger.num,
    )?;

    // Convert cursor to (start_ledger, start_tx_index) for the DB query
    let (query_start_ledger, query_start_tx_index) = match effective_cursor {
        Some(toid) => {
            let (l, tx_order, _) = util::toid_decode(toid);
            // tx_order in TOID is 1-based application order; DB txindex is 0-based
            (l, Some(tx_order.saturating_sub(1)))
        }
        None => (effective_start, None),
    };

    // End ledger for query: latest + 1 (exclusive upper bound)
    let end_ledger = ledger.num + 1;

    // Query transactions from database
    let records = ctx
        .app
        .database()
        .with_connection(|conn| {
            use henyey_db::HistoryQueries;
            conn.load_transactions_in_range(
                query_start_ledger,
                query_start_tx_index,
                end_ledger,
                effective_limit,
            )
        })
        .map_err(|e| JsonRpcError::internal(format!("database error: {}", e)))?;

    // Build response
    let mut transactions = Vec::with_capacity(records.len());
    let mut last_cursor = String::new();

    for record in &records {
        let status = util::determine_tx_status(&record.result);

        let envelope_xdr = BASE64.encode(&record.body);
        let result_xdr = match util::extract_result_xdr(&record.result) {
            Some(result_bytes) => BASE64.encode(&result_bytes),
            None => BASE64.encode(&record.result),
        };
        let result_meta_xdr = record
            .meta
            .as_ref()
            .map(|m| BASE64.encode(m))
            .unwrap_or_default();

        // Detect fee bump from the envelope
        let fee_bump = is_fee_bump_envelope(&record.body);

        // Application order is 1-based (txindex is 0-based in DB)
        let application_order = record.tx_index + 1;

        // Ledger close time — returned as a number (not string) per upstream getTransactions
        let created_at = get_ledger_close_time_num(ctx, record.ledger_seq);

        // Build TOID cursor for this transaction
        let toid = util::toid_encode(record.ledger_seq, application_order, 0);
        last_cursor = toid.to_string();

        let mut tx = json!({
            "status": status,
            "applicationOrder": application_order,
            "feeBump": fee_bump,
            "envelopeXdr": envelope_xdr,
            "resultXdr": result_xdr,
            "resultMetaXdr": result_meta_xdr,
            "ledger": record.ledger_seq,
            "createdAt": created_at,
            "txHash": record.tx_id
        });

        // Extract diagnostic events from meta if available
        if let Some(ref meta_bytes) = record.meta {
            if let Some(events_xdr) = util::extract_diagnostic_events_xdr(meta_bytes) {
                tx.as_object_mut()
                    .unwrap()
                    .insert("diagnosticEventsXdr".into(), json!(events_xdr));
            }
        }

        transactions.push(tx);
    }

    Ok(json!({
        "transactions": transactions,
        "latestLedger": ledger.num,
        "latestLedgerCloseTime": ledger.close_time.to_string(),
        "oldestLedger": oldest,
        "oldestLedgerCloseTime": oldest_close_time,
        "cursor": last_cursor
    }))
}

/// Check if a transaction envelope is a fee bump.
fn is_fee_bump_envelope(envelope_bytes: &[u8]) -> bool {
    TransactionEnvelope::from_xdr(envelope_bytes, Limits::none())
        .map(|env| matches!(env, TransactionEnvelope::TxFeeBump(_)))
        .unwrap_or(false)
}

/// Get ledger close time as a number (for getTransactions — upstream returns number).
fn get_ledger_close_time_num(ctx: &RpcContext, ledger_seq: u32) -> u64 {
    ctx.app
        .database()
        .with_connection(|conn| {
            use henyey_db::LedgerQueries;
            conn.load_ledger_header(ledger_seq)
        })
        .ok()
        .flatten()
        .map(|h| h.scp_value.close_time.0)
        .unwrap_or(0)
}

/// Get ledger close time as a string (for response envelope fields).
fn get_ledger_close_time(ctx: &RpcContext, ledger_seq: u32) -> String {
    get_ledger_close_time_num(ctx, ledger_seq).to_string()
}

