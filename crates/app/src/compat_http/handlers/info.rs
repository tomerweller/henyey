//! stellar-core compatible `/info` handler.
//!
//! Wraps the response in `{"info": {...}}` with camelCase field names
//! matching stellar-core's `ApplicationImpl::getJsonInfo()`.

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use crate::app::AppState;
use crate::compat_http::CompatServerState;

/// GET /info
///
/// Returns node info in stellar-core's exact JSON format.
pub(crate) async fn compat_info_handler(
    State(state): State<Arc<CompatServerState>>,
) -> impl IntoResponse {
    let app = &state.app;
    let app_state = app.state().await;

    let ledger = app.ledger_summary();
    let (pending_count, authenticated_count) = app.peer_counts().await;

    // Map henyey AppState to stellar-core state string.
    let state_str = match app_state {
        AppState::Initializing => "Booting",
        AppState::CatchingUp => "Catching up",
        AppState::Synced => "Synced!",
        AppState::Validating => "Synced!",
        AppState::ShuttingDown => "Stopping",
    };

    let info = CompatInfoResponse {
        build: format!("henyey-v{}", env!("CARGO_PKG_VERSION")),
        protocol_version: ledger.version,
        state: state_str.to_string(),
        started_on: state.started_on.clone(),
        ledger: CompatLedgerInfo {
            num: ledger.num,
            hash: ledger.hash.to_hex(),
            close_time: ledger.close_time,
            version: ledger.version,
            base_fee: ledger.base_fee,
            base_reserve: ledger.base_reserve,
            max_tx_set_size: ledger.max_tx_set_size,
            flags: if ledger.flags != 0 {
                Some(ledger.flags)
            } else {
                None
            },
            age: ledger.age,
        },
        peers: CompatPeerInfo {
            pending_count,
            authenticated_count,
        },
        network: app.config().network.passphrase.clone(),
        status: Vec::new(),
    };

    Json(CompatInfoWrapper { info })
}

/// Top-level wrapper: `{"info": {...}}`
#[derive(Serialize)]
struct CompatInfoWrapper {
    info: CompatInfoResponse,
}

/// stellar-core compatible info response.
///
/// Field names match stellar-core's `getJsonInfo()` output exactly.
#[derive(Serialize)]
struct CompatInfoResponse {
    build: String,
    protocol_version: u32,
    state: String,
    #[serde(rename = "startedOn")]
    started_on: String,
    ledger: CompatLedgerInfo,
    peers: CompatPeerInfo,
    network: String,
    status: Vec<String>,
}

/// Ledger info with stellar-core's camelCase field names.
#[derive(Serialize)]
struct CompatLedgerInfo {
    num: u32,
    hash: String,
    #[serde(rename = "closeTime")]
    close_time: u64,
    version: u32,
    #[serde(rename = "baseFee")]
    base_fee: u32,
    #[serde(rename = "baseReserve")]
    base_reserve: u32,
    #[serde(rename = "maxTxSetSize")]
    max_tx_set_size: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    flags: Option<u32>,
    age: u64,
}

/// Peer count info (stellar-core uses snake_case here, inconsistently).
#[derive(Serialize)]
struct CompatPeerInfo {
    pending_count: usize,
    authenticated_count: usize,
}
