//! Types for administrative endpoints (log levels, maintenance, etc).

use serde::{Deserialize, Serialize};

/// Query parameters for /ll endpoint.
#[derive(Deserialize)]
pub struct LlParams {
    pub level: Option<String>,
    pub partition: Option<String>,
}

/// Response for the /ll endpoint.
#[derive(Serialize)]
pub struct LlResponse {
    pub levels: std::collections::HashMap<String, String>,
}

/// Query parameters for /manualclose endpoint.
#[derive(Deserialize)]
pub struct ManualCloseParams {
    #[serde(rename = "ledgerSeq")]
    pub ledger_seq: Option<u32>,
    #[serde(rename = "closeTime")]
    pub close_time: Option<u64>,
}

/// Response for the /manualclose endpoint.
#[derive(Serialize)]
pub struct ManualCloseResponse {
    pub success: bool,
    pub ledger_seq: Option<u32>,
    pub message: Option<String>,
}

/// Query parameters for /clearmetrics endpoint.
#[derive(Deserialize)]
pub struct ClearMetricsParams {
    pub domain: Option<String>,
}

/// Response for the /clearmetrics endpoint.
#[derive(Serialize)]
pub struct ClearMetricsResponse {
    pub message: String,
}

/// Query parameters for /maintenance endpoint.
#[derive(Deserialize)]
pub struct MaintenanceParams {
    pub queue: Option<String>,
    pub count: Option<u32>,
}

/// Response for the /maintenance endpoint.
#[derive(Serialize)]
pub struct MaintenanceResponse {
    pub message: String,
}

/// Response for the /logrotate endpoint.
#[derive(Serialize)]
pub struct LogRotateResponse {
    pub message: String,
}
