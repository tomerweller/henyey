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

// ---------------------------------------------------------------------------
// Ledger consistency regression tests
// ---------------------------------------------------------------------------

use henyey_rpc::RpcAppHandle;
use stellar_xdr::curr::{
    Hash, LedgerHeader, LedgerHeaderExt, ReadXdr, StellarValue, StellarValueExt, TimePoint,
};

/// Build a minimal [`LedgerHeader`] at the given sequence and close time.
fn test_header(seq: u32, close_time: u64) -> LedgerHeader {
    LedgerHeader {
        ledger_version: 25,
        previous_ledger_hash: Hash([0; 32]),
        scp_value: StellarValue {
            tx_set_hash: Hash([0; 32]),
            close_time: TimePoint(close_time),
            upgrades: vec![].try_into().unwrap(),
            ext: StellarValueExt::Basic,
        },
        tx_set_result_hash: Hash([0; 32]),
        bucket_list_hash: Hash([0; 32]),
        ledger_seq: seq,
        total_coins: 0,
        fee_pool: 0,
        inflation_seq: 0,
        id_pool: 0,
        base_fee: 100,
        base_reserve: 5_000_000,
        max_tx_set_size: 100,
        skip_list: [Hash([0; 32]), Hash([0; 32]), Hash([0; 32]), Hash([0; 32])],
        ext: LedgerHeaderExt::V0,
    }
}

/// Helper: assert `ledger_summary()` and `ledger_snapshot()` agree on all
/// RPC-exposed header-derived fields.
fn assert_summary_snapshot_consistent(app: &FakeRpcApp) {
    let summary = app.ledger_summary();
    let snap = app.ledger_snapshot();

    assert_eq!(
        summary.num, snap.header.ledger_seq,
        "summary.num must equal snapshot.header.ledger_seq"
    );
    assert_eq!(
        summary.close_time, snap.header.scp_value.close_time.0,
        "summary.close_time must equal snapshot close_time"
    );
    assert_eq!(
        summary.version, snap.header.ledger_version,
        "summary.version must equal snapshot.header.ledger_version"
    );
    assert_eq!(
        summary.base_fee, snap.header.base_fee,
        "summary.base_fee must equal snapshot.header.base_fee"
    );
    assert_eq!(
        summary.base_reserve, snap.header.base_reserve,
        "summary.base_reserve must equal snapshot.header.base_reserve"
    );
    assert_eq!(
        summary.hash, snap.hash,
        "summary.hash must equal snapshot.hash"
    );
}

/// (a) Scalar-only builder: summary and snapshot agree on all fields.
#[test]
fn consistency_scalar_only_builder() {
    let app = FakeRpcApp::builder()
        .ledger_seq(50)
        .close_time(1_700_000_000)
        .protocol_version(25)
        .base_fee(200)
        .build();

    assert_summary_snapshot_consistent(&app);

    let snap = app.ledger_snapshot();
    assert_eq!(snap.header.ledger_seq, 50);
    assert_eq!(snap.header.scp_value.close_time.0, 1_700_000_000);
    assert_eq!(snap.header.ledger_version, 25);
    assert_eq!(snap.header.base_fee, 200);
}

/// (b) header_snapshot-only builder: summary and snapshot agree.
#[test]
fn consistency_header_snapshot_only() {
    let header = test_header(42, 1_600_000_000);
    let app = FakeRpcApp::builder().header_snapshot(header).build();

    assert_summary_snapshot_consistent(&app);

    let snap = app.ledger_snapshot();
    assert_eq!(snap.header.ledger_seq, 42);
    assert_eq!(snap.header.scp_value.close_time.0, 1_600_000_000);
}

/// (c) header_snapshot + all four scalar overrides: overrides win, hash
/// reflects the fully mutated header.
#[test]
fn consistency_header_snapshot_with_scalar_overrides() {
    let base_header = test_header(10, 1_500_000_000);
    let app = FakeRpcApp::builder()
        .header_snapshot(base_header)
        .ledger_seq(99)
        .close_time(1_800_000_000)
        .protocol_version(26)
        .base_fee(500)
        .build();

    assert_summary_snapshot_consistent(&app);

    let snap = app.ledger_snapshot();
    assert_eq!(snap.header.ledger_seq, 99);
    assert_eq!(snap.header.scp_value.close_time.0, 1_800_000_000);
    assert_eq!(snap.header.ledger_version, 26);
    assert_eq!(snap.header.base_fee, 500);

    // Verify hash matches what we'd compute from the mutated header.
    let expected_hash = henyey_ledger::compute_header_hash(&snap.header).expect("header hash");
    assert_eq!(
        snap.hash, expected_hash,
        "hash must reflect the mutated header"
    );
}

/// (d) Default builder: hash is non-zero and summary/snapshot agree.
#[test]
fn consistency_default_builder() {
    let app = FakeRpcApp::default();
    assert_summary_snapshot_consistent(&app);

    let snap = app.ledger_snapshot();
    assert_ne!(
        snap.hash,
        henyey_common::Hash256::default(),
        "default builder should produce a non-zero hash"
    );
}

/// getLatestLedger via the simple scalar builder path: verify in-memory fields
/// match `headerXdr` and the builder inputs.
#[tokio::test]
async fn fake_get_latest_ledger_scalar_builder() {
    let app = FakeRpcApp::builder()
        .ledger_seq(77)
        .close_time(1_700_000_000)
        .protocol_version(25)
        .base_fee(150)
        .build();
    let h = FakeRpcTestHarness::start(app).await;
    let id = json!("latest-scalar");
    let (status, resp) = h
        .post_rpc(json!({"jsonrpc": "2.0", "id": id, "method": "getLatestLedger"}))
        .await;

    assert_eq!(status, 200);
    assert_envelope(&resp, &id);
    let result = &resp["result"];

    assert_eq!(result["sequence"].as_u64().unwrap(), 77);
    assert_eq!(result["protocolVersion"].as_u64().unwrap(), 25);
    let close_time: u64 = result["closeTime"]
        .as_str()
        .expect("closeTime string")
        .parse()
        .expect("closeTime parses");
    assert_eq!(close_time, 1_700_000_000);

    // Decode headerXdr and verify it matches the in-memory fields.
    let header_b64 = result["headerXdr"].as_str().expect("headerXdr");
    let header_bytes = BASE64.decode(header_b64).expect("valid base64");
    let header = LedgerHeader::from_xdr(&header_bytes, Limits::none()).expect("valid header XDR");

    assert_eq!(header.ledger_seq, 77);
    assert_eq!(header.ledger_version, 25);
    assert_eq!(header.scp_value.close_time.0, 1_700_000_000);
    assert_eq!(header.base_fee, 150);

    // Verify id == hex(SHA-256(headerXdr bytes))
    use sha2::{Digest, Sha256};
    let computed_hash = Sha256::digest(&header_bytes);
    let computed_hex = hex::encode(computed_hash);
    assert_eq!(
        result["id"].as_str().unwrap(),
        computed_hex,
        "response id must equal SHA-256 of headerXdr bytes"
    );
}
