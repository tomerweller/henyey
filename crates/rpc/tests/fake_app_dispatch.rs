//! Integration tests for RPC dispatch using a lightweight [`FakeRpcApp`].
//!
//! These tests exercise the JSON-RPC dispatch layer, envelope validation,
//! error codes, and response shapes without booting a full simulation node.
//! They supplement (not replace) the simulation-backed tests in
//! `http_dispatch.rs` and `corrupt_data.rs`.

mod common;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use henyey_herder::TxQueueResult;
use serde_json::json;
use stellar_xdr::curr::{
    Limits, Memo, MuxedAccount, Preconditions, SequenceNumber, Transaction, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
};

use common::fake_app::{FakeRpcApp, FakeRpcTestHarness};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal valid base64-encoded TransactionEnvelope for sendTransaction.
fn valid_tx_b64() -> String {
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
        fee: 100,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![].try_into().unwrap(),
        ext: TransactionExt::V0,
    };
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![].try_into().unwrap(),
    });
    BASE64.encode(env.to_xdr(Limits::none()).unwrap())
}

fn assert_envelope(resp: &serde_json::Value, expected_id: &serde_json::Value) {
    assert_eq!(resp["jsonrpc"], json!("2.0"), "jsonrpc must be \"2.0\"");
    assert_eq!(resp["id"], *expected_id, "id must be echoed");
    assert!(
        resp.get("result").is_some() ^ resp.get("error").is_some(),
        "exactly one of result|error must be present: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Core method tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fake_get_health() {
    let h = FakeRpcTestHarness::start_default().await;
    let id = json!(1);
    let (status, resp) = h
        .post_rpc(json!({"jsonrpc": "2.0", "id": id, "method": "getHealth"}))
        .await;

    assert_eq!(status, 200);
    assert_envelope(&resp, &id);
    let result = &resp["result"];
    assert!(result["status"].is_string(), "getHealth.result.status");
    assert!(
        result["latestLedger"].is_number(),
        "getHealth.result.latestLedger"
    );
    assert!(
        result["oldestLedger"].is_number(),
        "getHealth.result.oldestLedger"
    );
    assert!(
        result["ledgerRetentionWindow"].is_number(),
        "getHealth.result.ledgerRetentionWindow"
    );
}

#[tokio::test]
async fn fake_get_health_with_close_time() {
    // Set close_time far in the past so health becomes "unhealthy"
    let app = FakeRpcApp::builder()
        .ledger_seq(50)
        .close_time(1_000_000) // Very old
        .protocol_version(25)
        .build();
    let h = FakeRpcTestHarness::start(app).await;
    let id = json!("health-close-time");
    let (status, resp) = h
        .post_rpc(json!({"jsonrpc": "2.0", "id": id, "method": "getHealth"}))
        .await;

    assert_eq!(status, 200);
    assert_envelope(&resp, &id);
    assert_eq!(
        resp["result"]["status"].as_str().unwrap(),
        "unhealthy",
        "ledger with ancient close_time should be unhealthy"
    );
}

#[tokio::test]
async fn fake_get_network() {
    let h = FakeRpcTestHarness::start_default().await;
    let id = json!("net");
    let (status, resp) = h
        .post_rpc(json!({"jsonrpc": "2.0", "id": id, "method": "getNetwork"}))
        .await;

    assert_eq!(status, 200);
    assert_envelope(&resp, &id);
    assert_eq!(
        resp["result"]["passphrase"].as_str().unwrap(),
        "Test SDF Network ; September 2015"
    );
}

#[tokio::test]
async fn fake_get_version_info() {
    let h = FakeRpcTestHarness::start_default().await;
    let id = json!("ver");
    let (status, resp) = h
        .post_rpc(json!({"jsonrpc": "2.0", "id": id, "method": "getVersionInfo"}))
        .await;

    assert_eq!(status, 200);
    assert_envelope(&resp, &id);
    let result = &resp["result"];
    assert_eq!(result["version"].as_str().unwrap(), "0.0.0-test");
    assert_eq!(result["commitHash"].as_str().unwrap(), "deadbeef");
    assert_eq!(
        result["buildTimestamp"].as_str().unwrap(),
        "2024-01-01T00:00:00Z"
    );
}

#[tokio::test]
async fn fake_get_fee_stats() {
    let h = FakeRpcTestHarness::start_default().await;
    let id = json!("fees");
    let (status, resp) = h
        .post_rpc(json!({"jsonrpc": "2.0", "id": id, "method": "getFeeStats"}))
        .await;

    assert_eq!(status, 200);
    assert_envelope(&resp, &id);
    let result = &resp["result"];
    assert!(
        result["sorobanInclusionFee"].is_object(),
        "sorobanInclusionFee"
    );
    assert!(result["inclusionFee"].is_object(), "inclusionFee");
    assert!(result["latestLedger"].is_number(), "latestLedger");
}

// ---------------------------------------------------------------------------
// Error handling tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fake_unknown_method() {
    let h = FakeRpcTestHarness::start_default().await;
    let id = json!("unk");
    let (status, resp) = h
        .post_rpc(json!({"jsonrpc": "2.0", "id": id, "method": "doesNotExist"}))
        .await;

    assert_eq!(status, 200);
    assert_envelope(&resp, &id);
    assert_eq!(
        resp["error"]["code"],
        json!(-32601),
        "unknown method must return Method not found (-32601)"
    );
}

#[tokio::test]
async fn fake_invalid_jsonrpc_version() {
    let h = FakeRpcTestHarness::start_default().await;
    let id = json!("bad-ver");
    let (status, resp) = h
        .post_rpc(json!({"jsonrpc": "1.0", "id": id, "method": "getHealth"}))
        .await;

    assert_eq!(status, 200);
    assert_envelope(&resp, &id);
    assert_eq!(
        resp["error"]["code"],
        json!(-32600),
        "wrong jsonrpc version must return invalid request (-32600)"
    );
}

// ---------------------------------------------------------------------------
// sendTransaction — all TxQueueResult branches
// ---------------------------------------------------------------------------

async fn send_tx_with_result(result: TxQueueResult) -> serde_json::Value {
    let app = FakeRpcApp::builder().submit_result(result).build();
    let h = FakeRpcTestHarness::start(app).await;
    let tx_b64 = valid_tx_b64();
    let id = json!("send");
    let (status, resp) = h
        .post_rpc(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "sendTransaction",
            "params": {"transaction": tx_b64}
        }))
        .await;
    assert_eq!(status, 200);
    assert_envelope(&resp, &id);
    resp["result"].clone()
}

#[tokio::test]
async fn fake_send_transaction_added() {
    let result = send_tx_with_result(TxQueueResult::Added).await;
    assert_eq!(result["status"].as_str().unwrap(), "PENDING");
    assert!(result["hash"].is_string());
    assert!(result["latestLedger"].is_number());
}

#[tokio::test]
async fn fake_send_transaction_duplicate() {
    let result = send_tx_with_result(TxQueueResult::Duplicate).await;
    assert_eq!(result["status"].as_str().unwrap(), "DUPLICATE");
}

#[tokio::test]
async fn fake_send_transaction_queue_full() {
    let result = send_tx_with_result(TxQueueResult::QueueFull).await;
    assert_eq!(result["status"].as_str().unwrap(), "TRY_AGAIN_LATER");
}

#[tokio::test]
async fn fake_send_transaction_try_again_later() {
    let result = send_tx_with_result(TxQueueResult::TryAgainLater).await;
    assert_eq!(result["status"].as_str().unwrap(), "TRY_AGAIN_LATER");
}

#[tokio::test]
async fn fake_send_transaction_invalid_with_code() {
    use stellar_xdr::curr::TransactionResultCode;
    let result = send_tx_with_result(TxQueueResult::Invalid(Some(
        TransactionResultCode::TxFailed,
    )))
    .await;
    assert_eq!(result["status"].as_str().unwrap(), "ERROR");
    assert!(
        result.get("errorResultXdr").is_some() || result.get("errorResult").is_some(),
        "ERROR response must include errorResult"
    );
}

#[tokio::test]
async fn fake_send_transaction_invalid_none() {
    let result = send_tx_with_result(TxQueueResult::Invalid(None)).await;
    assert_eq!(result["status"].as_str().unwrap(), "ERROR");
}

#[tokio::test]
async fn fake_send_transaction_banned() {
    let result = send_tx_with_result(TxQueueResult::Banned).await;
    assert_eq!(result["status"].as_str().unwrap(), "ERROR");
}

#[tokio::test]
async fn fake_send_transaction_fee_too_low() {
    let result = send_tx_with_result(TxQueueResult::FeeTooLow).await;
    assert_eq!(result["status"].as_str().unwrap(), "ERROR");
}

#[tokio::test]
async fn fake_send_transaction_filtered() {
    let result = send_tx_with_result(TxQueueResult::Filtered).await;
    assert_eq!(result["status"].as_str().unwrap(), "ERROR");
}
