use std::sync::Arc;

use serde_json::json;

use crate::context::RpcContext;
use crate::error::JsonRpcError;

/// Default ledger retention window (number of ledgers kept).
const DEFAULT_LEDGER_RETENTION_WINDOW: u32 = 2880;

pub async fn handle(ctx: &Arc<RpcContext>) -> Result<serde_json::Value, JsonRpcError> {
    let ledger = ctx.app.ledger_summary();

    // stellar-rpc returns "healthy" whenever the server is reachable
    let status = "healthy";
    let oldest_ledger = ledger
        .num
        .saturating_sub(DEFAULT_LEDGER_RETENTION_WINDOW)
        .max(1);

    Ok(json!({
        "status": status,
        "latestLedger": ledger.num,
        "oldestLedger": oldest_ledger,
        "ledgerRetentionWindow": DEFAULT_LEDGER_RETENTION_WINDOW
    }))
}
