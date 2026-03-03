//! Types for survey endpoints.

use serde::{Deserialize, Serialize};

/// Response for survey command endpoints.
#[derive(Serialize)]
pub struct SurveyCommandResponse {
    pub success: bool,
    pub message: String,
}

/// Query parameters for starting survey collecting.
#[derive(Deserialize)]
pub struct StartSurveyParams {
    pub nonce: u32,
}

/// Query parameters for requesting topology from a peer.
#[derive(Deserialize)]
pub struct SurveyTopologyParams {
    pub node: String,
    pub inbound_index: Option<u32>,
    pub outbound_index: Option<u32>,
}
