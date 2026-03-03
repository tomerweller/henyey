//! stellar-core compatible `/metrics` handler.
//!
//! stellar-core returns medida JSON format. For now, we proxy the native
//! metrics handler's Prometheus text output. Full medida JSON conversion
//! is tracked as a future enhancement (B5 in the parity plan).

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;

use crate::compat_http::CompatServerState;

/// GET /metrics
///
/// Returns a minimal metrics response. Full medida JSON conversion is a
/// future enhancement. For now, returns basic metrics that stellar-rpc
/// cares about (primarily for health checking).
pub(crate) async fn compat_metrics_handler(
    State(state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    let app = &state.app;
    let (seq, _, _, _) = app.ledger_info();
    let (pending_count, authenticated_count) = app.peer_counts().await;

    // Return a minimal medida-style JSON that covers what stellar-rpc
    // typically inspects from metrics.
    Json(serde_json::json!({
        "metrics": {
            "ledger.ledger.close": {
                "count": seq,
            },
            "peer.peer.count": {
                "count": authenticated_count + pending_count,
            },
            "herder.pending.transactions": {
                "count": app.pending_transaction_count(),
            }
        }
    }))
}
