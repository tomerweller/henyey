//! Handler for /tx (transaction submission).

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use henyey_common::NetworkId;
use henyey_tx::TransactionFrame;

use super::super::types::{SubmitTxRequest, SubmitTxResponse};
use super::super::ServerState;

pub(crate) async fn submit_tx_handler(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<SubmitTxRequest>,
) -> impl IntoResponse {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use stellar_xdr::curr::{Limits, ReadXdr, TransactionEnvelope};

    // Decode and validate the transaction
    let tx_bytes = match STANDARD.decode(&request.tx) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitTxResponse {
                    success: false,
                    hash: None,
                    error: Some(format!("Invalid base64: {}", e)),
                }),
            );
        }
    };

    // Parse the transaction envelope
    let tx_env = match TransactionEnvelope::from_xdr(&tx_bytes, Limits::none()) {
        Ok(env) => env,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitTxResponse {
                    success: false,
                    hash: None,
                    error: Some(format!("Invalid XDR: {}", e)),
                }),
            );
        }
    };

    let network_id = NetworkId::from_passphrase(&state.app.info().network_passphrase);
    let mut frame = TransactionFrame::with_network(tx_env.clone(), network_id);
    let hash = frame.compute_hash(&network_id).ok();
    let result = state.app.submit_transaction(tx_env);

    let (success, error) = match result {
        henyey_herder::TxQueueResult::Added => (true, None),
        henyey_herder::TxQueueResult::Duplicate => {
            (true, Some("Transaction already in queue".to_string()))
        }
        henyey_herder::TxQueueResult::QueueFull => {
            (false, Some("Transaction queue full".to_string()))
        }
        henyey_herder::TxQueueResult::FeeTooLow => {
            (false, Some("Transaction fee too low".to_string()))
        }
        henyey_herder::TxQueueResult::Invalid(code) => {
            let msg = match code {
                Some(c) => format!("Transaction invalid: {}", c),
                None => "Transaction invalid".to_string(),
            };
            (false, Some(msg))
        }
        henyey_herder::TxQueueResult::Banned => {
            (false, Some("Transaction from banned source".to_string()))
        }
        henyey_herder::TxQueueResult::Filtered => (
            false,
            Some("Transaction filtered by operation type".to_string()),
        ),
        henyey_herder::TxQueueResult::TryAgainLater => (
            false,
            Some("Account already has pending transaction".to_string()),
        ),
    };

    (
        StatusCode::OK,
        Json(SubmitTxResponse {
            success,
            hash: hash.map(|value| value.to_hex()),
            error,
        }),
    )
}
