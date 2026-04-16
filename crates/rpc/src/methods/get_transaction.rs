//! Handler for the `getTransaction` JSON-RPC method.

use std::sync::Arc;

use serde_json::json;

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

    let format = util::parse_format(&params)?;

    let lctx = util::LedgerContext::from_app(ctx).await?;

    // Look up the transaction and its close time in a single blocking DB call
    let hash_owned = hash.to_string();
    let tx_record_with_time = util::blocking_db(ctx, move |db| {
        db.with_connection(|conn| {
            use henyey_db::{HistoryQueries, LedgerQueries};
            let record = conn.load_transaction(&hash_owned)?;
            match record {
                Some(record) => {
                    let close_time = conn
                        .batch_close_times(&[record.ledger_seq])?
                        .get(&record.ledger_seq)
                        .copied()
                        .unwrap_or(0);
                    Ok(Some((record, close_time)))
                }
                None => Ok(None),
            }
        })
    })
    .await
    .map_err(|e| {
        tracing::warn!(error = ?e, "get_transaction DB error");
        JsonRpcError::internal("database error")
    })?;

    match tx_record_with_time {
        Some((record, close_time)) => {
            let created_at = close_time.to_string();

            let mut obj = super::transaction_response::build_transaction_object(
                &record,
                json!(created_at),
                format,
                false,
            )?;
            lctx.insert_json_fields(&mut obj);

            Ok(serde_json::Value::Object(obj))
        }
        None => {
            let mut result = json!({ "status": "NOT_FOUND" });
            lctx.insert_json_fields(result.as_object_mut().unwrap());
            Ok(result)
        }
    }
}
