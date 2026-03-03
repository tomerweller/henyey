//! Types for transaction submission endpoints.

use serde::{Deserialize, Serialize};

/// Request for submitting a transaction.
#[derive(Deserialize)]
pub struct SubmitTxRequest {
    /// Base64-encoded XDR transaction envelope.
    pub tx: String,
}

/// Response for transaction submission.
#[derive(Serialize)]
pub struct SubmitTxResponse {
    pub success: bool,
    pub hash: Option<String>,
    pub error: Option<String>,
}
