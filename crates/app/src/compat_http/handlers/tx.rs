//! stellar-core compatible `/tx` handler.
//!
//! Accepts `GET /tx?blob=<base64 TransactionEnvelope XDR>` and returns
//! stellar-core's exact response format with status strings.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use stellar_xdr::curr::{Limits, ReadXdr, TransactionEnvelope};

use crate::compat_http::CompatServerState;

/// Query parameters for `GET /tx?blob=...`.
#[derive(Deserialize)]
pub(crate) struct TxQueryParams {
    blob: Option<String>,
}

/// GET /tx?blob=<base64>
///
/// Submits a transaction in stellar-core's exact wire format.
/// Returns `{"status": "PENDING"}` or `{"status": "ERROR", "error": "..."}`.
pub(crate) async fn compat_tx_handler(
    State(state): State<Arc<CompatServerState>>,
    Query(params): Query<TxQueryParams>,
) -> impl IntoResponse {
    let blob = match params.blob {
        Some(b) if !b.is_empty() => b,
        _ => {
            return Json(serde_json::json!({
                "exception": "Must specify a tx blob: tx?blob=<tx in xdr format>"
            }))
            .into_response();
        }
    };

    // Decode base64 to TransactionEnvelope XDR.
    let tx_bytes = match BASE64.decode(&blob) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Json(serde_json::json!({
                "exception": format!("Failed to decode tx blob: {}", e)
            }))
            .into_response();
        }
    };

    let tx_env = match TransactionEnvelope::from_xdr(&tx_bytes, Limits::none()) {
        Ok(tx) => tx,
        Err(e) => {
            return Json(serde_json::json!({
                "exception": format!("Failed to parse tx envelope: {}", e)
            }))
            .into_response();
        }
    };

    // Submit to the herder.
    let result = state.app.submit_transaction(tx_env);

    // Map to stellar-core status strings.
    use henyey_herder::TxQueueResult;
    let response: CompatTxResponse = match result {
        TxQueueResult::Added => CompatTxResponse {
            status: "PENDING".to_string(),
            error: None,
        },
        TxQueueResult::Duplicate => CompatTxResponse {
            status: "DUPLICATE".to_string(),
            error: None,
        },
        TxQueueResult::TryAgainLater | TxQueueResult::QueueFull => CompatTxResponse {
            status: "TRY_AGAIN_LATER".to_string(),
            error: None,
        },
        TxQueueResult::Filtered => CompatTxResponse {
            status: "FILTERED".to_string(),
            error: None,
        },
        TxQueueResult::Invalid(code) => {
            // stellar-core puts the base64-encoded TransactionResult XDR
            // in the "error" field. We use the result code name as a fallback
            // since the full XDR result is not always available in our current
            // TxQueueResult.
            let error_str = code.map_or("txInternalError".to_string(), |c| c.name().to_string());
            CompatTxResponse {
                status: "ERROR".to_string(),
                error: Some(error_str),
            }
        }
        TxQueueResult::Banned => CompatTxResponse {
            status: "ERROR".to_string(),
            error: Some("Transaction is banned".to_string()),
        },
        TxQueueResult::FeeTooLow => CompatTxResponse {
            status: "ERROR".to_string(),
            error: Some("txINSUFFICIENT_FEE".to_string()),
        }
    };

    Json(response).into_response()
}

/// stellar-core compatible tx submission response.
#[derive(Serialize)]
struct CompatTxResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}
