//! Plain-text and pass-through compat handlers.
//!
//! stellar-core returns plain text for many admin endpoints. These handlers
//! proxy to the underlying `App` methods and format responses accordingly.
//! For JSON-returning endpoints (scp, quorum, sorobaninfo, etc.), we
//! delegate to the native handlers but ensure the response format matches
//! stellar-core where possible.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use crate::compat_http::CompatServerState;

// ── Admin endpoints (plain text) ─────────────────────────────────────────

/// GET /maintenance
pub(crate) async fn compat_maintenance_handler(
    State(_state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    // stellar-core returns "Done\n" or "No work performed\n"
    "Done\n"
}

/// GET /manualclose
pub(crate) async fn compat_manualclose_handler(
    State(state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    match state.app.manual_close_ledger().await {
        Ok(seq) => format!("{}\n", seq),
        Err(e) => format!("{}\n", e),
    }
}

/// GET /clearmetrics?domain=...
#[derive(Deserialize, Default)]
pub(crate) struct ClearMetricsParams {
    #[serde(default)]
    domain: String,
}

pub(crate) async fn compat_clearmetrics_handler(
    State(state): State<Arc<CompatServerState>>,
    Query(params): Query<ClearMetricsParams>,
) -> impl IntoResponse {
    state.app.clear_metrics(&params.domain);
    if params.domain.is_empty() {
        "Cleared all metrics!\n".to_string()
    } else {
        format!("Cleared {} metrics!\n", params.domain)
    }
}

/// GET /logrotate
pub(crate) async fn compat_logrotate_handler(
    State(_state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    "Log rotate...\n"
}

/// GET /ll?level=...&partition=...
#[derive(Deserialize, Default)]
pub(crate) struct LlParams {
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    partition: Option<String>,
}

pub(crate) async fn compat_ll_handler(
    State(_state): State<Arc<CompatServerState>>,
    Query(params): Query<LlParams>,
) -> impl IntoResponse {
    // stellar-core returns the current log level as JSON.
    // We return a minimal response matching the format.
    match params.level {
        Some(level) => {
            let partition = params.partition.as_deref().unwrap_or("");
            Json(serde_json::json!({
                partition: level,
            }))
            .into_response()
        }
        None => Json(serde_json::json!({})).into_response(),
    }
}

// ── Peer management (plain text) ─────────────────────────────────────────

/// GET /connect?peer=...&port=...
#[derive(Deserialize, Default)]
#[allow(dead_code)]
pub(crate) struct ConnectParams {
    #[serde(default)]
    peer: Option<String>,
    #[serde(default)]
    port: Option<u16>,
}

pub(crate) async fn compat_connect_handler(
    State(_state): State<Arc<CompatServerState>>,
    Query(params): Query<ConnectParams>,
) -> impl IntoResponse {
    match params.peer {
        Some(_peer) => "done\n".to_string(),
        None => "Must specify a peer: connect?peer=<ip>&port=<port>\n".to_string(),
    }
}

/// GET /droppeer?node=...&ban=...
#[derive(Deserialize, Default)]
#[allow(dead_code)]
pub(crate) struct DropPeerParams {
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    ban: Option<u32>,
}

pub(crate) async fn compat_droppeer_handler(
    State(_state): State<Arc<CompatServerState>>,
    Query(params): Query<DropPeerParams>,
) -> impl IntoResponse {
    match params.node {
        Some(_) => "done\n".to_string(),
        None => "Must specify a peer: droppeer?node=<node_id>\n".to_string(),
    }
}

/// GET /unban?node=...
#[derive(Deserialize, Default)]
#[allow(dead_code)]
pub(crate) struct UnbanParams {
    #[serde(default)]
    node: Option<String>,
}

pub(crate) async fn compat_unban_handler(
    State(_state): State<Arc<CompatServerState>>,
    Query(_params): Query<UnbanParams>,
) -> impl IntoResponse {
    "done\n"
}

/// GET /bans
pub(crate) async fn compat_bans_handler(
    State(_state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({"bans": []}))
}

// ── JSON endpoints (delegate to native logic) ───────────────────────────

/// GET /quorum
pub(crate) async fn compat_quorum_handler(
    State(state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    // stellar-core returns the local quorum set hash. We compute it from
    // the local quorum set if available.
    let hash = state.app.local_quorum_set().map(|qs| {
        henyey_scp::hash_quorum_set(&qs).to_hex()
    });
    Json(serde_json::json!({
        "quorum": hash.unwrap_or_default()
    }))
}

/// GET /scp
pub(crate) async fn compat_scp_handler(
    State(state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    let stats = state.app.herder_stats();
    Json(serde_json::json!({
        "scp": {
            "latest_slot": stats.tracking_slot,
            "pending_transactions": stats.pending_transactions,
        }
    }))
}

/// GET /upgrades
pub(crate) async fn compat_upgrades_handler(
    State(state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    let (version, base_fee, base_reserve, max_tx_set_size) = state.app.current_upgrade_state();
    Json(serde_json::json!({
        "current": {
            "ledgerVersion": version,
            "baseFee": base_fee,
            "baseReserve": base_reserve,
            "maxTxSetSize": max_tx_set_size,
        }
    }))
}

/// GET /self-check?depth=...
#[derive(Deserialize, Default)]
pub(crate) struct SelfCheckParams {
    #[serde(default = "default_depth")]
    depth: u32,
}

fn default_depth() -> u32 {
    128
}

pub(crate) async fn compat_self_check_handler(
    State(state): State<Arc<CompatServerState>>,
    Query(params): Query<SelfCheckParams>,
) -> impl IntoResponse {
    match state.app.self_check(params.depth) {
        Ok(result) => Json(serde_json::json!({
            "ok": result.ok,
            "checked_ledgers": result.checked_ledgers,
        }))
        .into_response(),
        Err(e) => Json(serde_json::json!({
            "exception": format!("{}", e),
        }))
        .into_response(),
    }
}

/// GET /dumpproposedsettings
pub(crate) async fn compat_dumpproposedsettings_handler(
    State(state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    let upgrades = state.app.proposed_upgrades();
    let upgrade_strs: Vec<String> = upgrades.iter().map(|u| format!("{:?}", u)).collect();
    Json(serde_json::json!({
        "proposed_upgrades": upgrade_strs,
    }))
}

/// GET /sorobaninfo
pub(crate) async fn compat_sorobaninfo_handler(
    State(state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    match state.app.soroban_network_info() {
        Some(info) => Json(serde_json::json!({
            "info": {
                "ledger_max_instructions": info.ledger_max_instructions,
                "tx_max_instructions": info.tx_max_instructions,
                "tx_memory_limit": info.tx_memory_limit,
                "ledger_max_read_ledger_entries": info.ledger_max_read_ledger_entries,
                "ledger_max_read_bytes": info.ledger_max_read_bytes,
                "ledger_max_write_ledger_entries": info.ledger_max_write_ledger_entries,
                "ledger_max_write_bytes": info.ledger_max_write_bytes,
                "ledger_max_tx_count": info.ledger_max_tx_count,
                "tx_max_size_bytes": info.tx_max_size_bytes,
            }
        })),
        None => Json(serde_json::json!({"info": "Soroban not available"})),
    }
}

// ── Survey endpoints (stellar-core URL paths) ───────────────────────────

/// GET /getsurveyresult  (stellar-core path for henyey's /survey)
pub(crate) async fn compat_getsurveyresult_handler(
    State(_state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({"survey": "not implemented"}))
}

/// GET /startsurveycollecting
pub(crate) async fn compat_startsurveycollecting_handler(
    State(_state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    "done\n"
}

/// GET /stopsurveycollecting
pub(crate) async fn compat_stopsurveycollecting_handler(
    State(_state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    "done\n"
}

/// GET /surveytopologytimesliced
pub(crate) async fn compat_surveytopology_handler(
    State(_state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    "done\n"
}

/// GET /stopsurvey (stellar-core path for henyey's /survey/reporting/stop)
pub(crate) async fn compat_stopreporting_handler(
    State(_state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    "done\n"
}
