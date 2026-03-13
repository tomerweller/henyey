//! Handler for the `getEvents` JSON-RPC method.

use std::sync::Arc;

use serde_json::json;

use crate::context::RpcContext;
use crate::error::JsonRpcError;
use crate::util::format_unix_timestamp_utc;

/// Default number of events returned per query.
const DEFAULT_EVENTS_LIMIT: u64 = 100;
/// Maximum number of events that can be requested in a single query.
const MAX_EVENTS_LIMIT: u64 = 10_000;

pub async fn handle(
    ctx: &Arc<RpcContext>,
    params: serde_json::Value,
) -> Result<serde_json::Value, JsonRpcError> {
    let ledger = ctx.app.ledger_summary();

    let start_ledger = params
        .get("startLedger")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .ok_or_else(|| JsonRpcError::invalid_params("missing 'startLedger' parameter"))?;

    let end_ledger = params
        .get("endLedger")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    // Parse filters
    let (event_type, contract_ids, topic_filters) =
        parse_event_filters(params.get("filters").and_then(|v| v.as_array()));

    // Parse pagination
    let pagination = params.get("pagination");
    let limit = pagination
        .and_then(|p| p.get("limit"))
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_EVENTS_LIMIT)
        .min(MAX_EVENTS_LIMIT) as u32;
    let cursor = pagination
        .and_then(|p| p.get("cursor"))
        .and_then(|v| v.as_str());

    // Query events from database
    let events = ctx
        .app
        .database()
        .with_connection(|conn| {
            use henyey_db::EventQueries;
            conn.query_events(
                start_ledger,
                end_ledger,
                event_type,
                &contract_ids,
                &topic_filters,
                cursor,
                limit,
            )
        })
        .map_err(|e| JsonRpcError::internal(format!("database error: {}", e)))?;

    // Look up ledger close times for the events
    let mut event_json: Vec<serde_json::Value> = Vec::with_capacity(events.len());
    for event in &events {
        let close_time = get_ledger_close_time(ctx, event.ledger_seq);

        let event_type_str = match event.event_type {
            0 => "contract",
            1 => "system",
            2 => "diagnostic",
            _ => "contract",
        };

        // Extract value from the ContractEvent XDR
        let value_xdr = extract_event_value(&event.event_xdr);

        let mut obj = json!({
            "type": event_type_str,
            "ledger": event.ledger_seq,
            "ledgerClosedAt": close_time,
            "contractId": event.contract_id,
            "id": event.id,
            "operationIndex": event.op_index,
            "transactionIndex": event.tx_index,
            "txHash": event.tx_hash,
            "inSuccessfulContractCall": event.in_successful_contract_call,
            "topic": event.topics,
            "value": value_xdr,
        });

        // Remove null contractId for system events
        if event.contract_id.is_none() {
            obj.as_object_mut()
                .unwrap()
                .insert("contractId".to_string(), json!(""));
        }

        event_json.push(obj);
    }

    let last_cursor = events.last().map(|e| e.id.as_str()).unwrap_or("");

    Ok(json!({
        "events": event_json,
        "cursor": last_cursor,
        "latestLedger": ledger.num,
        "latestLedgerCloseTime": ledger.close_time.to_string(),
        "oldestLedger": 1,
        "oldestLedgerCloseTime": "0"
    }))
}

/// Parse event filter parameters from the JSON-RPC request.
///
/// Returns `(event_type, contract_ids, topic_filters)`.
fn parse_event_filters(
    filters: Option<&Vec<serde_json::Value>>,
) -> (Option<&'static str>, Vec<String>, Vec<Vec<String>>) {
    let mut event_type: Option<&'static str> = None;
    let mut contract_ids = Vec::new();
    let mut topic_filters = Vec::new();

    let Some(filter_array) = filters else {
        return (event_type, contract_ids, topic_filters);
    };

    for filter in filter_array {
        if let Some(t) = filter.get("type").and_then(|v| v.as_str()) {
            event_type = Some(match t {
                "contract" => "contract",
                "system" => "system",
                "diagnostic" => "diagnostic",
                _ => "contract",
            });
        }

        if let Some(cids) = filter.get("contractIds").and_then(|v| v.as_array()) {
            contract_ids.extend(cids.iter().filter_map(|v| v.as_str().map(String::from)));
        }

        // Topics is an array of arrays: [["topic1_a", "topic1_b"], ["*"], ...]
        // Each inner array is OR alternatives for that position.
        if let Some(topics_arr) = filter.get("topics").and_then(|v| v.as_array()) {
            for topic_set in topics_arr {
                if let Some(alternatives) = topic_set.as_array() {
                    let alt_strings: Vec<String> =
                        alternatives.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    topic_filters.push(alt_strings);
                }
            }
        }
    }

    (event_type, contract_ids, topic_filters)
}

fn get_ledger_close_time(ctx: &RpcContext, ledger_seq: u32) -> String {
    ctx.app
        .database()
        .with_connection(|conn| {
            use henyey_db::LedgerQueries;
            conn.load_ledger_header(ledger_seq)
        })
        .ok()
        .flatten()
        .map(|h| {
            let ts = h.scp_value.close_time.0;
            format_unix_timestamp_utc(ts)
        })
        .unwrap_or_default()
}

/// Extract the value XDR (base64) from a ContractEvent's body.
fn extract_event_value(event_xdr_b64: &str) -> String {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use stellar_xdr::curr::{ContractEvent, ContractEventBody, Limits, ReadXdr, WriteXdr};

    let bytes = match BASE64.decode(event_xdr_b64) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };

    let event = match ContractEvent::from_xdr(&bytes, Limits::none()) {
        Ok(e) => e,
        Err(_) => return String::new(),
    };

    match event.body {
        ContractEventBody::V0(body) => body
            .data
            .to_xdr(Limits::none())
            .ok()
            .map(|b| BASE64.encode(&b))
            .unwrap_or_default(),
    }
}
