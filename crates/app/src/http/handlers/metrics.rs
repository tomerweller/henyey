//! Handler for /metrics endpoint (Prometheus format).

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse};

use super::super::types::MetricsResponse;
use super::super::ServerState;

pub(crate) async fn metrics_handler(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    let app_state = state.app.state().await;
    let uptime = state.start_time.elapsed().as_secs();
    let ledger_seq = state.app.ledger_info().ledger_seq;
    let peer_count = state.app.peer_snapshots().await.len();
    let pending_transactions = state.app.pending_transaction_count() as u64;
    let app_info = state.app.info();

    let metrics = MetricsResponse {
        ledger_seq,
        peer_count,
        pending_transactions,
        uptime_seconds: uptime,
        state: format!("{}", app_state),
        is_validator: app_info.is_validator,
    };

    // Return Prometheus-style text format
    let mut prometheus_text = format!(
        "# HELP stellar_ledger_sequence Current ledger sequence number\n\
         # TYPE stellar_ledger_sequence gauge\n\
         stellar_ledger_sequence {}\n\
         # HELP stellar_peer_count Number of connected peers\n\
         # TYPE stellar_peer_count gauge\n\
         stellar_peer_count {}\n\
         # HELP stellar_pending_transactions Number of pending transactions\n\
         # TYPE stellar_pending_transactions gauge\n\
         stellar_pending_transactions {}\n\
         # HELP stellar_uptime_seconds Node uptime in seconds\n\
         # TYPE stellar_uptime_seconds counter\n\
         stellar_uptime_seconds {}\n\
         # HELP stellar_is_validator Whether this node is a validator\n\
         # TYPE stellar_is_validator gauge\n\
         stellar_is_validator {}\n",
        metrics.ledger_seq,
        metrics.peer_count,
        metrics.pending_transactions,
        metrics.uptime_seconds,
        if metrics.is_validator { 1 } else { 0 }
    );

    // Add meta stream metrics if active
    if app_info.meta_stream_bytes_total > 0 || app_info.meta_stream_writes_total > 0 {
        prometheus_text.push_str(&format!(
            "# HELP stellar_meta_stream_bytes_total Total bytes written to metadata output stream\n\
             # TYPE stellar_meta_stream_bytes_total counter\n\
             stellar_meta_stream_bytes_total {}\n\
             # HELP stellar_meta_stream_writes_total Total frames written to metadata output stream\n\
             # TYPE stellar_meta_stream_writes_total counter\n\
             stellar_meta_stream_writes_total {}\n",
            app_info.meta_stream_bytes_total, app_info.meta_stream_writes_total
        ));
    }

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        prometheus_text,
    )
}
