use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::json;
use stellar_xdr::curr::{Limits, WriteXdr};

use crate::context::RpcContext;
use crate::error::JsonRpcError;

pub async fn handle(ctx: &Arc<RpcContext>) -> Result<serde_json::Value, JsonRpcError> {
    let ledger = ctx.app.ledger_summary();
    let hash = ledger.hash.to_hex();

    // Encode the LedgerHeader as base64 XDR.
    // Re-serializing from the in-memory header is deterministic and avoids
    // an extra DB round-trip for the raw bytes.
    let header = ctx.app.ledger_manager().current_header();
    let header_xdr = header
        .to_xdr(Limits::none())
        .map(|b| BASE64.encode(&b))
        .unwrap_or_default();

    // Load full LedgerCloseMeta from the database for metadataXdr.
    let metadata_xdr = ctx
        .app
        .database()
        .with_connection(|conn| {
            use henyey_db::LedgerCloseMetaQueries;
            conn.load_ledger_close_meta(ledger.num)
        })
        .ok()
        .flatten()
        .map(|meta_bytes| BASE64.encode(&meta_bytes))
        .unwrap_or_default();

    Ok(json!({
        "id": hash,
        "protocolVersion": ledger.version,
        "sequence": ledger.num,
        "closeTime": ledger.close_time.to_string(),
        "headerXdr": header_xdr,
        "metadataXdr": metadata_xdr
    }))
}
