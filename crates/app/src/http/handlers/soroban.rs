//! Handler for /sorobaninfo endpoint.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};

use super::super::types::{SorobanInfoParams, SorobanInfoResponse};
use super::super::ServerState;

pub(crate) async fn sorobaninfo_handler(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<SorobanInfoParams>,
) -> impl IntoResponse {
    let format = params.format.as_deref().unwrap_or("basic");

    let protocol_version = state.app.ledger_info().protocol_version;

    match format {
        "basic" => {
            let Some(info) = state.app.soroban_network_info() else {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "error": "Soroban config not available (ledger not initialized or pre-protocol 20)",
                        "protocol_version": protocol_version
                    })),
                );
            };

            let response = SorobanInfoResponse::from_network_info(&info, protocol_version);
            // `serde_json::to_value` cannot fail here: SorobanInfoResponse
            // is composed entirely of primitive integer types and nested
            // structs of the same. There is no Serialize-failing variant
            // (no map with non-string keys, no custom error). Future
            // additions must preserve this invariant.
            (
                StatusCode::OK,
                Json(serde_json::to_value(response).unwrap()),
            )
        }
        "detailed" | "upgrade_xdr" => (
            StatusCode::OK,
            Json(serde_json::json!({
                "error": format!("Format '{}' not yet implemented", format),
                "available_formats": ["basic"]
            })),
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("Unknown format: {}", format),
                "available_formats": ["basic", "detailed", "upgrade_xdr"]
            })),
        ),
    }
}
