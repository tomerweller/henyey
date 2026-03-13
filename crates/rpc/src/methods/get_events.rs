use std::sync::Arc;

use serde_json::json;

use crate::context::RpcContext;
use crate::error::JsonRpcError;

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
    let filters = params.get("filters").and_then(|v| v.as_array());

    let mut event_type: Option<&str> = None;
    let mut contract_ids: Vec<String> = Vec::new();
    let mut topic_filters: Vec<Vec<String>> = Vec::new();

    if let Some(filter_array) = filters {
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
                for cid in cids {
                    if let Some(s) = cid.as_str() {
                        contract_ids.push(s.to_string());
                    }
                }
            }

            // Topics is an array of arrays: [["topic1_a", "topic1_b"], ["*"], ...]
            // Each inner array is OR alternatives for that position
            if let Some(topics_arr) = filter.get("topics").and_then(|v| v.as_array()) {
                for topic_set in topics_arr {
                    if let Some(alternatives) = topic_set.as_array() {
                        let mut alt_strings: Vec<String> = Vec::new();
                        for alt in alternatives {
                            if let Some(s) = alt.as_str() {
                                alt_strings.push(s.to_string());
                            }
                        }
                        topic_filters.push(alt_strings);
                    }
                }
            }
        }
    }

    // Parse pagination
    let pagination = params.get("pagination");
    let limit = pagination
        .and_then(|p| p.get("limit"))
        .and_then(|v| v.as_u64())
        .unwrap_or(100)
        .min(10000) as u32;
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
            // Format as ISO 8601
            let ts = h.scp_value.close_time.0;
            format_timestamp(ts)
        })
        .unwrap_or_default()
}

fn format_timestamp(unix_ts: u64) -> String {
    // Simple UTC timestamp formatting
    let secs = unix_ts as i64;
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year/month/day from days since 1970-01-01
    let mut days = days_since_epoch;
    let mut year = 1970i32;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let leap = is_leap_year(year);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut month = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md {
            month = i;
            break;
        }
        days -= md;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month + 1,
        days + 1,
        hours,
        minutes,
        seconds
    )
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
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
