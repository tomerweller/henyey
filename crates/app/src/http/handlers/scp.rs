//! Handler for /scp endpoint.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::Json,
};

use super::super::types::{ScpInfoResponse, ScpParams, ScpSlotInfo};
use super::super::ServerState;

pub(crate) async fn scp_handler(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<ScpParams>,
) -> Json<ScpInfoResponse> {
    let limit = params.limit.unwrap_or(2).min(20);
    let slots = state
        .app
        .scp_slot_snapshots(limit)
        .into_iter()
        .map(ScpSlotInfo::from)
        .collect();
    Json(ScpInfoResponse {
        node: state.app.info().public_key,
        slots,
    })
}

impl From<crate::app::ScpSlotSnapshot> for ScpSlotInfo {
    fn from(snapshot: crate::app::ScpSlotSnapshot) -> Self {
        let slot = snapshot.slot;
        Self {
            slot_index: slot.slot_index,
            is_externalized: slot.is_externalized,
            is_nominating: slot.is_nominating,
            fully_validated: slot.fully_validated,
            ballot_phase: slot.ballot_phase,
            nomination_round: slot.nomination_round,
            ballot_round: slot.ballot_round,
            envelope_count: snapshot.envelope_count,
        }
    }
}
