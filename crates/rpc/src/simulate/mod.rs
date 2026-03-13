//! Soroban transaction simulation for `simulateTransaction`.
//!
//! Supports all three Soroban operation types:
//! - `InvokeHostFunction`: Full host function simulation via recording mode
//! - `ExtendFootprintTtl`: TTL extension resource/fee estimation
//! - `RestoreFootprint`: Archived entry restore resource/fee estimation

mod snapshot;

pub(crate) use snapshot::BucketListSnapshotSource;

use std::rc::Rc;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::json;
use soroban_env_host_p25 as soroban_host;
use stellar_xdr::curr::{
    ContractDataDurability, ExtendFootprintTtlOp, ExtensionPoint, HostFunction,
    InvokeHostFunctionOp, LedgerEntryType, LedgerFootprint, LedgerKey, Limits, OperationBody,
    ReadXdr, RestoreFootprintOp, SorobanResources, SorobanTransactionData,
    SorobanTransactionDataExt, TransactionEnvelope, WriteXdr,
};

use crate::context::RpcContext;
use crate::error::JsonRpcError;
use crate::util::{self, XdrFormat};

/// Multiplicative adjustment factor for refundable fees (soroban-simulation default).
const REFUNDABLE_FEE_ADJUSTMENT_FACTOR: f64 = 1.15;

// ---------------------------------------------------------------------------
// Operation extraction
// ---------------------------------------------------------------------------

/// The three Soroban operation kinds we can simulate.
enum SorobanOp {
    InvokeHostFunction(HostFunction),
    ExtendFootprintTtl {
        keys: Vec<LedgerKey>,
        extend_to: u32,
    },
    RestoreFootprint {
        keys: Vec<LedgerKey>,
    },
}

/// Extract the Soroban operation, source account, and optional footprint from the envelope.
fn extract_soroban_op(
    tx_env: &TransactionEnvelope,
) -> Result<(stellar_xdr::curr::AccountId, SorobanOp), JsonRpcError> {
    let (source, ops, ext) = match tx_env {
        TransactionEnvelope::Tx(tx) => (&tx.tx.source_account, &tx.tx.operations, &tx.tx.ext),
        TransactionEnvelope::TxV0(_) => {
            return Err(JsonRpcError::invalid_params("v0 transactions not supported"));
        }
        TransactionEnvelope::TxFeeBump(fb) => match &fb.tx.inner_tx {
            stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                (&inner.tx.source_account, &inner.tx.operations, &inner.tx.ext)
            }
        },
    };

    let source_account = muxed_to_account_id(source);

    if ops.len() != 1 {
        return Err(JsonRpcError::invalid_params(
            "simulateTransaction requires exactly one operation",
        ));
    }

    match &ops[0].body {
        OperationBody::InvokeHostFunction(op) => {
            Ok((source_account, SorobanOp::InvokeHostFunction(op.host_function.clone())))
        }
        OperationBody::ExtendFootprintTtl(op) => {
            let keys = extract_footprint_keys(ext)?;
            Ok((
                source_account,
                SorobanOp::ExtendFootprintTtl {
                    keys,
                    extend_to: op.extend_to,
                },
            ))
        }
        OperationBody::RestoreFootprint(_) => {
            let keys = extract_footprint_keys(ext)?;
            Ok((source_account, SorobanOp::RestoreFootprint { keys }))
        }
        _ => Err(JsonRpcError::invalid_params(
            "operation must be InvokeHostFunction, ExtendFootprintTtl, or RestoreFootprint",
        )),
    }
}

fn muxed_to_account_id(source: &stellar_xdr::curr::MuxedAccount) -> stellar_xdr::curr::AccountId {
    match source {
        stellar_xdr::curr::MuxedAccount::Ed25519(key) => {
            stellar_xdr::curr::AccountId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                key.clone(),
            ))
        }
        stellar_xdr::curr::MuxedAccount::MuxedEd25519(muxed) => {
            stellar_xdr::curr::AccountId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                muxed.ed25519.clone(),
            ))
        }
    }
}

/// Extract the read_only + read_write keys from the SorobanTransactionData footprint
/// embedded in the transaction envelope's ext field.
fn extract_footprint_keys(
    ext: &stellar_xdr::curr::TransactionExt,
) -> Result<Vec<LedgerKey>, JsonRpcError> {
    let soroban_data = match ext {
        stellar_xdr::curr::TransactionExt::V1(data) => data,
        _ => {
            return Err(JsonRpcError::invalid_params(
                "ExtendFootprintTtl/RestoreFootprint requires SorobanTransactionData in tx ext",
            ));
        }
    };
    let footprint = &soroban_data.resources.footprint;
    let mut keys = Vec::with_capacity(
        footprint.read_only.len() + footprint.read_write.len(),
    );
    keys.extend(footprint.read_only.iter().cloned());
    keys.extend(footprint.read_write.iter().cloned());
    Ok(keys)
}

// ---------------------------------------------------------------------------
// Handler entry point
// ---------------------------------------------------------------------------

pub async fn handle(
    ctx: &Arc<RpcContext>,
    params: serde_json::Value,
) -> Result<serde_json::Value, JsonRpcError> {
    let format = util::parse_format(&params)?;

    let tx_b64 = params
        .get("transaction")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError::invalid_params("missing 'transaction' parameter"))?;

    let tx_bytes = BASE64
        .decode(tx_b64)
        .map_err(|e| JsonRpcError::invalid_params(format!("invalid base64: {e}")))?;

    let tx_env = TransactionEnvelope::from_xdr(&tx_bytes, Limits::none())
        .map_err(|e| JsonRpcError::invalid_params(format!("invalid XDR: {e}")))?;

    let (source_account, soroban_op) = extract_soroban_op(&tx_env)?;

    // Get bucket list snapshot
    let bl_snapshot = ctx
        .app
        .bucket_snapshot_manager()
        .copy_searchable_live_snapshot()
        .ok_or_else(|| JsonRpcError::internal("bucket list snapshot not available"))?;

    // Get ledger info
    let ledger = ctx.app.ledger_summary();
    let soroban_info = ctx
        .app
        .soroban_network_info()
        .ok_or_else(|| JsonRpcError::internal("soroban network config not available"))?;

    let network_id = henyey_common::NetworkId::from_passphrase(&ctx.app.info().network_passphrase);

    let ledger_info = soroban_host::LedgerInfo {
        protocol_version: ledger.version,
        sequence_number: ledger.num,
        timestamp: ledger.close_time,
        network_id: network_id.0 .0,
        base_reserve: ledger.base_reserve,
        min_temp_entry_ttl: soroban_info.min_temporary_ttl,
        min_persistent_entry_ttl: soroban_info.min_persistent_ttl,
        max_entry_ttl: soroban_info.max_entry_ttl,
    };

    let snapshot_source = BucketListSnapshotSource::new(bl_snapshot, ledger.num);

    match soroban_op {
        SorobanOp::InvokeHostFunction(host_fn) => {
            handle_invoke(
                host_fn,
                source_account,
                ledger_info,
                snapshot_source,
                &soroban_info,
                ledger.num,
                format,
            )
            .await
        }
        SorobanOp::ExtendFootprintTtl { keys, extend_to } => {
            let soroban_info_clone = soroban_info.clone();
            let result = tokio::task::spawn_blocking(move || {
                simulate_extend_ttl_op(
                    &snapshot_source,
                    &ledger_info,
                    &keys,
                    extend_to,
                    &soroban_info_clone,
                )
            })
            .await
            .map_err(|e| JsonRpcError::internal(format!("simulation task failed: {e}")))?;

            match result {
                Ok(tx_data) => build_footprint_response(tx_data, &soroban_info, ledger.num, format),
                Err(e) => build_error_response(e, ledger.num),
            }
        }
        SorobanOp::RestoreFootprint { keys } => {
            let soroban_info_clone = soroban_info.clone();
            let result = tokio::task::spawn_blocking(move || {
                simulate_restore_op(&snapshot_source, &ledger_info, &keys, &soroban_info_clone)
            })
            .await
            .map_err(|e| JsonRpcError::internal(format!("simulation task failed: {e}")))?;

            match result {
                Ok(tx_data) => build_footprint_response(tx_data, &soroban_info, ledger.num, format),
                Err(e) => build_error_response(e, ledger.num),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// InvokeHostFunction path (existing logic, refactored)
// ---------------------------------------------------------------------------

async fn handle_invoke(
    host_fn: HostFunction,
    source_account: stellar_xdr::curr::AccountId,
    ledger_info: soroban_host::LedgerInfo,
    snapshot_source: BucketListSnapshotSource,
    soroban_info: &henyey_ledger::SorobanNetworkInfo,
    latest_ledger: u32,
    format: XdrFormat,
) -> Result<serde_json::Value, JsonRpcError> {
    let host_fn_clone = host_fn.clone();
    let source_account_clone = source_account.clone();

    let result = tokio::task::spawn_blocking(move || {
        run_invoke_simulation(host_fn_clone, source_account_clone, ledger_info, snapshot_source)
    })
    .await
    .map_err(|e| JsonRpcError::internal(format!("simulation task failed: {e}")))?;

    match result {
        Ok(sim_output) => build_invoke_response(
            sim_output.recording_result,
            sim_output.diagnostic_events,
            soroban_info,
            latest_ledger,
            &host_fn,
            &source_account,
            format,
        ),
        Err(e) => build_error_response(e, latest_ledger),
    }
}

struct InvokeSimulationOutput {
    recording_result: soroban_host::e2e_invoke::InvokeHostFunctionRecordingModeResult,
    diagnostic_events: Vec<stellar_xdr::curr::DiagnosticEvent>,
}

fn run_invoke_simulation(
    host_fn: HostFunction,
    source_account: stellar_xdr::curr::AccountId,
    ledger_info: soroban_host::LedgerInfo,
    snapshot_source: BucketListSnapshotSource,
) -> Result<InvokeSimulationOutput, String> {
    use soroban_host::budget::Budget;
    use soroban_host::e2e_invoke::{
        invoke_host_function_in_recording_mode, RecordingInvocationAuthMode,
    };

    let budget = Budget::default();
    let mut diagnostic_events = Vec::new();
    let seed: [u8; 32] = rand::random();

    let result = invoke_host_function_in_recording_mode(
        &budget,
        true, // enable_diagnostics
        &host_fn,
        &source_account,
        RecordingInvocationAuthMode::Recording(false),
        ledger_info,
        Rc::new(snapshot_source),
        seed,
        &mut diagnostic_events,
    );

    match result {
        Ok(recording_result) => match &recording_result.invoke_result {
            Ok(_) => Ok(InvokeSimulationOutput {
                recording_result,
                diagnostic_events,
            }),
            Err(e) => Err(format!("host function invocation failed: {e:?}")),
        },
        Err(e) => Err(format!("simulation failed: {e:?}")),
    }
}

// ---------------------------------------------------------------------------
// ExtendFootprintTtl simulation
// ---------------------------------------------------------------------------

/// Simulate an `ExtendFootprintTtlOp`.
///
/// For each key in the footprint, look up the current entry and TTL. Skip entries
/// that don't exist, don't have a TTL, or already have a live-until >= the requested
/// extension. Compute rent fee changes for the remaining entries.
///
/// Mirrors `soroban-simulation::simulate_extend_ttl_op`.
fn simulate_extend_ttl_op(
    snapshot: &BucketListSnapshotSource,
    ledger_info: &soroban_host::LedgerInfo,
    keys: &[LedgerKey],
    extend_to: u32,
    soroban_info: &henyey_ledger::SorobanNetworkInfo,
) -> Result<SorobanTransactionData, String> {
    use soroban_host::e2e_invoke::entry_size_for_rent;
    use soroban_host::fees::LedgerEntryRentChange;
    use soroban_host::ledger_info::get_key_durability;

    let budget = soroban_host::budget::Budget::default();
    let new_live_until = ledger_info.sequence_number.saturating_add(extend_to);

    let mut rent_changes = Vec::with_capacity(keys.len());
    let mut extended_keys = Vec::with_capacity(keys.len());

    for key in keys {
        let durability = get_key_durability(key).ok_or_else(|| {
            format!(
                "cannot extend TTL for key {:?}: only contract data/code entries have TTL",
                key.discriminant()
            )
        })?;

        let Some((entry, live_until)) = snapshot.get_unfiltered(key) else {
            continue; // entry doesn't exist, skip
        };

        let current_live_until = live_until.ok_or_else(|| {
            format!("missing TTL for key that must have TTL: {:?}", key.discriminant())
        })?;

        // Skip entries that don't need extension
        if new_live_until <= current_live_until {
            continue;
        }

        // Expired entries cannot be extended (must be restored first)
        if current_live_until < ledger_info.sequence_number {
            return Err(format!(
                "cannot extend TTL for expired entry (live_until={current_live_until}, \
                 current_ledger={}). Restore the entry first.",
                ledger_info.sequence_number
            ));
        }

        extended_keys.push(key.clone());

        let entry_xdr_size = entry
            .to_xdr(Limits::none())
            .map(|b| b.len() as u32)
            .unwrap_or(0);
        let entry_size = entry_size_for_rent(&budget, &entry, entry_xdr_size)
            .map_err(|e| format!("entry_size_for_rent failed: {e:?}"))?;

        rent_changes.push(LedgerEntryRentChange {
            is_persistent: durability == ContractDataDurability::Persistent,
            is_code_entry: matches!(key.discriminant(), LedgerEntryType::ContractCode),
            old_size_bytes: entry_size,
            new_size_bytes: entry_size,
            old_live_until_ledger: current_live_until,
            new_live_until_ledger: new_live_until,
        });
    }

    extended_keys.sort();

    let resources = SorobanResources {
        footprint: LedgerFootprint {
            read_only: extended_keys
                .try_into()
                .map_err(|_| "too many keys for footprint".to_string())?,
            read_write: Default::default(),
        },
        instructions: 0,
        disk_read_bytes: 0,
        write_bytes: 0,
    };

    let operation = OperationBody::ExtendFootprintTtl(ExtendFootprintTtlOp {
        ext: ExtensionPoint::V0,
        extend_to,
    });

    let tx_size = estimate_tx_size_for_op(&operation, &resources);
    let resource_fee = compute_resource_fee_with_rent(
        &resources,
        &rent_changes,
        soroban_info,
        ledger_info.sequence_number,
        0, // no contract events
        tx_size,
    );

    Ok(SorobanTransactionData {
        ext: SorobanTransactionDataExt::V0,
        resources,
        resource_fee,
    })
}

// ---------------------------------------------------------------------------
// RestoreFootprint simulation
// ---------------------------------------------------------------------------

/// Simulate a `RestoreFootprintOp`.
///
/// For each key, verify it is a persistent contract data/code entry. Look up the
/// entry and its TTL. Skip entries that are still live. For expired entries,
/// compute the cost of restoring them with TTL = min_persistent_entry_ttl.
///
/// Mirrors `soroban-simulation::simulate_restore_op`.
fn simulate_restore_op(
    snapshot: &BucketListSnapshotSource,
    ledger_info: &soroban_host::LedgerInfo,
    keys: &[LedgerKey],
    soroban_info: &henyey_ledger::SorobanNetworkInfo,
) -> Result<SorobanTransactionData, String> {
    use soroban_host::e2e_invoke::entry_size_for_rent;
    use soroban_host::fees::LedgerEntryRentChange;
    use soroban_host::ledger_info::get_key_durability;

    let budget = soroban_host::budget::Budget::default();
    let restored_live_until = ledger_info
        .min_live_until_ledger_checked(ContractDataDurability::Persistent)
        .ok_or("min persistent live_until ledger overflows")?;

    let mut rent_changes = Vec::with_capacity(keys.len());
    let mut restored_keys = Vec::with_capacity(keys.len());
    let mut restored_bytes = 0u32;

    for key in keys {
        let durability = get_key_durability(key);
        if durability != Some(ContractDataDurability::Persistent) {
            return Err(format!(
                "cannot restore key {:?}: only persistent entries can be restored",
                key.discriminant()
            ));
        }

        let (entry, live_until) = snapshot
            .get_unfiltered(key)
            .ok_or_else(|| format!("missing entry to restore for key {:?}", key.discriminant()))?;

        let current_live_until = live_until.ok_or_else(|| {
            format!("missing TTL for key that must have TTL: {:?}", key.discriminant())
        })?;

        // Skip entries that are still live (not expired)
        if current_live_until >= ledger_info.sequence_number {
            continue;
        }

        restored_keys.push(key.clone());

        let entry_xdr_size = entry
            .to_xdr(Limits::none())
            .map(|b| b.len() as u32)
            .unwrap_or(0);
        let entry_rent_size = entry_size_for_rent(&budget, &entry, entry_xdr_size)
            .map_err(|e| format!("entry_size_for_rent failed: {e:?}"))?;

        restored_bytes = restored_bytes.saturating_add(entry_xdr_size);

        rent_changes.push(LedgerEntryRentChange {
            is_persistent: true,
            is_code_entry: matches!(key.discriminant(), LedgerEntryType::ContractCode),
            old_size_bytes: 0,
            new_size_bytes: entry_rent_size,
            old_live_until_ledger: 0,
            new_live_until_ledger: restored_live_until,
        });
    }

    restored_keys.sort();

    let resources = SorobanResources {
        footprint: LedgerFootprint {
            read_only: Default::default(),
            read_write: restored_keys
                .try_into()
                .map_err(|_| "too many keys for footprint".to_string())?,
        },
        instructions: 0,
        disk_read_bytes: restored_bytes,
        write_bytes: restored_bytes,
    };

    let operation = OperationBody::RestoreFootprint(RestoreFootprintOp {
        ext: ExtensionPoint::V0,
    });

    let tx_size = estimate_tx_size_for_op(&operation, &resources);
    let resource_fee = compute_resource_fee_with_rent(
        &resources,
        &rent_changes,
        soroban_info,
        ledger_info.sequence_number,
        0, // no contract events
        tx_size,
    );

    Ok(SorobanTransactionData {
        ext: SorobanTransactionDataExt::V0,
        resources,
        resource_fee,
    })
}

// ---------------------------------------------------------------------------
// Response builders
// ---------------------------------------------------------------------------

fn build_invoke_response(
    sim_result: soroban_host::e2e_invoke::InvokeHostFunctionRecordingModeResult,
    diagnostic_events: Vec<stellar_xdr::curr::DiagnosticEvent>,
    soroban_info: &henyey_ledger::SorobanNetworkInfo,
    latest_ledger: u32,
    host_fn: &HostFunction,
    _source_account: &stellar_xdr::curr::AccountId,
    format: XdrFormat,
) -> Result<serde_json::Value, JsonRpcError> {
    let resources = &sim_result.resources;

    // Apply resource adjustments (mirrors soroban-simulation default_adjustment)
    let mut adjusted_resources = resources.clone();
    adjust_resources(&mut adjusted_resources);

    // Compute rent changes for fee estimation
    let rent_changes = soroban_host::e2e_invoke::extract_rent_changes(&sim_result.ledger_changes);

    // Estimate the transaction size for fee computation
    let op = OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
        host_function: host_fn.clone(),
        auth: sim_result
            .auth
            .clone()
            .try_into()
            .unwrap_or_default(),
    });
    let tx_size = estimate_tx_size_for_op(&op, &adjusted_resources);

    // Build SorobanTransactionData
    let soroban_data = SorobanTransactionData {
        ext: SorobanTransactionDataExt::V0,
        resources: adjusted_resources,
        resource_fee: compute_invoke_resource_fee(
            resources,
            &rent_changes,
            soroban_info,
            latest_ledger,
            sim_result.contract_events_and_return_value_size,
            tx_size,
        ),
    };

    let min_resource_fee = soroban_data.resource_fee;

    let mut obj = serde_json::Map::new();

    // transactionData XDR
    util::insert_xdr_field(&mut obj, "transactionData", &soroban_data, format)?;

    obj.insert("minResourceFee".into(), json!(min_resource_fee.to_string()));
    obj.insert(
        "cost".into(),
        json!({
            "cpuInsns": resources.instructions.to_string(),
            "memBytes": "0"
        }),
    );
    obj.insert("latestLedger".into(), json!(latest_ledger));

    // Diagnostic events
    if !diagnostic_events.is_empty() {
        util::insert_xdr_array_field(&mut obj, "events", &diagnostic_events, format)?;
    }

    // Encode auth entries and return value
    let auth = &sim_result.auth;
    let return_value = match &sim_result.invoke_result {
        Ok(val) => Some(val.clone()),
        Err(_) => None,
    };

    if !auth.is_empty() || return_value.is_some() {
        let mut result_obj = serde_json::Map::new();

        // auth array
        match format {
            XdrFormat::Base64 => {
                let auth_b64: Vec<serde_json::Value> = auth
                    .iter()
                    .filter_map(|a| {
                        a.to_xdr(Limits::none())
                            .ok()
                            .map(|b| serde_json::Value::String(BASE64.encode(&b)))
                    })
                    .collect();
                result_obj.insert("auth".into(), serde_json::Value::Array(auth_b64));
            }
            XdrFormat::Json => {
                let auth_json: Vec<serde_json::Value> = auth
                    .iter()
                    .filter_map(|a| serde_json::to_value(a).ok())
                    .collect();
                result_obj.insert("authJson".into(), serde_json::Value::Array(auth_json));
            }
        }

        // return value
        if let Some(rv) = &return_value {
            util::insert_xdr_field(&mut result_obj, "xdr_val", rv, format)?;
            // Upstream uses "xdr" for base64, "xdrJson" for JSON
            match format {
                XdrFormat::Base64 => {
                    if let Some(val) = result_obj.remove("xdr_valXdr") {
                        result_obj.insert("xdr".into(), val);
                    }
                }
                XdrFormat::Json => {
                    if let Some(val) = result_obj.remove("xdr_valJson") {
                        result_obj.insert("xdrJson".into(), val);
                    }
                }
            }
        }

        obj.insert(
            "results".into(),
            json!([serde_json::Value::Object(result_obj)]),
        );
    }

    Ok(serde_json::Value::Object(obj))
}

/// Build the response for ExtendFootprintTtl / RestoreFootprint.
///
/// These operations produce no results, no auth, and no return value — just
/// `transactionData` and `minResourceFee`.
fn build_footprint_response(
    tx_data: SorobanTransactionData,
    _soroban_info: &henyey_ledger::SorobanNetworkInfo,
    latest_ledger: u32,
    format: XdrFormat,
) -> Result<serde_json::Value, JsonRpcError> {
    let min_resource_fee = tx_data.resource_fee;
    let mut obj = serde_json::Map::new();

    util::insert_xdr_field(&mut obj, "transactionData", &tx_data, format)?;
    obj.insert("minResourceFee".into(), json!(min_resource_fee.to_string()));
    obj.insert(
        "cost".into(),
        json!({
            "cpuInsns": "0",
            "memBytes": "0"
        }),
    );
    obj.insert("latestLedger".into(), json!(latest_ledger));

    Ok(serde_json::Value::Object(obj))
}

fn build_error_response(
    error: String,
    latest_ledger: u32,
) -> Result<serde_json::Value, JsonRpcError> {
    Ok(json!({
        "error": error,
        "transactionData": "",
        "minResourceFee": "0",
        "cost": {
            "cpuInsns": "0",
            "memBytes": "0"
        },
        "latestLedger": latest_ledger
    }))
}

// ---------------------------------------------------------------------------
// Resource adjustments
// ---------------------------------------------------------------------------

/// Apply soroban-simulation default adjustment: max(x + additive, floor(x * mult)).
fn sim_adjust(value: u32, multiplicative: f64, additive: u32) -> u32 {
    if value == 0 {
        return 0;
    }
    let mult_adjusted = (value as f64 * multiplicative).floor() as u32;
    (value.saturating_add(additive)).max(mult_adjusted)
}

/// Apply resource adjustment factors matching soroban-simulation defaults.
fn adjust_resources(resources: &mut SorobanResources) {
    resources.instructions = sim_adjust(resources.instructions, 1.04, 50_000);
    resources.disk_read_bytes = sim_adjust(resources.disk_read_bytes, 1.0, 2_000);
    resources.write_bytes = sim_adjust(resources.write_bytes, 1.0, 2_000);
}

// ---------------------------------------------------------------------------
// Transaction size estimation
// ---------------------------------------------------------------------------

/// Estimate the XDR-encoded transaction size for fee computation.
///
/// Mirrors soroban-simulation: builds a max-size synthetic envelope with
/// 20 signatures and full preconditions, then applies the tx_size adjustment.
fn estimate_tx_size_for_op(
    operation: &OperationBody,
    resources: &SorobanResources,
) -> u32 {
    use stellar_xdr::curr::*;

    let soroban_data = SorobanTransactionData {
        ext: SorobanTransactionDataExt::V0,
        resources: SorobanResources {
            footprint: resources.footprint.clone(),
            instructions: 0,
            disk_read_bytes: 0,
            write_bytes: 0,
        },
        resource_fee: 0,
    };

    let sig = DecoratedSignature {
        hint: SignatureHint([0u8; 4]),
        signature: Signature::try_from(vec![0u8; 64]).unwrap_or_default(),
    };
    let sigs: Vec<DecoratedSignature> = (0..20).map(|_| sig.clone()).collect();

    let source = MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
        id: 0,
        ed25519: Uint256([0u8; 32]),
    });

    let tx = Transaction {
        source_account: source.clone(),
        fee: u32::MAX,
        seq_num: SequenceNumber(0),
        cond: Preconditions::V2(PreconditionsV2 {
            time_bounds: Some(TimeBounds {
                min_time: TimePoint(0),
                max_time: TimePoint(0),
            }),
            ledger_bounds: Some(LedgerBounds {
                min_ledger: 0,
                max_ledger: 0,
            }),
            min_seq_num: Some(SequenceNumber(0)),
            min_seq_age: Duration(0),
            min_seq_ledger_gap: 0,
            extra_signers: vec![
                SignerKey::Ed25519(Uint256([0u8; 32])),
                SignerKey::Ed25519(Uint256([0u8; 32])),
            ]
            .try_into()
            .unwrap_or_default(),
        }),
        memo: Memo::None,
        operations: vec![Operation {
            source_account: Some(source),
            body: operation.clone(),
        }]
        .try_into()
        .unwrap_or_default(),
        ext: TransactionExt::V1(soroban_data),
    };

    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: sigs.try_into().unwrap_or_default(),
    });

    let raw_size = envelope
        .to_xdr(Limits::none())
        .map(|b| b.len() as u32)
        .unwrap_or(300);

    // Apply tx_size adjustment: max(x + 500, floor(x * 1.1))
    sim_adjust(raw_size, 1.1, 500)
}

// ---------------------------------------------------------------------------
// Fee computation
// ---------------------------------------------------------------------------

/// Build `FeeConfiguration` from `SorobanNetworkInfo`.
fn build_fee_config(
    soroban_info: &henyey_ledger::SorobanNetworkInfo,
) -> soroban_host::fees::FeeConfiguration {
    soroban_host::fees::FeeConfiguration {
        fee_per_instruction_increment: soroban_info.fee_rate_per_instructions_increment,
        fee_per_disk_read_entry: soroban_info.fee_read_ledger_entry,
        fee_per_write_entry: soroban_info.fee_write_ledger_entry,
        fee_per_disk_read_1kb: soroban_info.fee_read_1kb,
        fee_per_write_1kb: soroban_info.fee_write_1kb,
        fee_per_historical_1kb: soroban_info.fee_historical_1kb,
        fee_per_contract_event_1kb: soroban_info.fee_contract_events_size_1kb,
        fee_per_transaction_size_1kb: soroban_info.fee_transaction_size_1kb,
    }
}

/// Build `RentFeeConfiguration` from `SorobanNetworkInfo`.
fn build_rent_fee_config(
    soroban_info: &henyey_ledger::SorobanNetworkInfo,
) -> soroban_host::fees::RentFeeConfiguration {
    use soroban_host::fees::{RentFeeConfiguration, RentWriteFeeConfiguration};

    let rent_write_config = RentWriteFeeConfiguration {
        state_target_size_bytes: soroban_info.state_target_size_bytes,
        rent_fee_1kb_state_size_low: soroban_info.rent_fee_1kb_state_size_low,
        rent_fee_1kb_state_size_high: soroban_info.rent_fee_1kb_state_size_high,
        state_size_rent_fee_growth_factor: soroban_info.state_size_rent_fee_growth_factor,
    };
    let fee_per_rent_1kb = soroban_host::fees::compute_rent_write_fee_per_1kb(
        soroban_info.average_bucket_list_size as i64,
        &rent_write_config,
    );

    RentFeeConfiguration {
        fee_per_write_1kb: soroban_info.fee_write_1kb,
        fee_per_rent_1kb,
        fee_per_write_entry: soroban_info.fee_write_ledger_entry,
        persistent_rent_rate_denominator: soroban_info.persistent_rent_rate_denominator,
        temporary_rent_rate_denominator: soroban_info.temp_rent_rate_denominator,
    }
}

/// Compute resource fee for InvokeHostFunction (includes rent).
fn compute_invoke_resource_fee(
    resources: &SorobanResources,
    rent_changes: &[soroban_host::fees::LedgerEntryRentChange],
    soroban_info: &henyey_ledger::SorobanNetworkInfo,
    current_ledger_seq: u32,
    contract_events_and_return_value_size: u32,
    tx_size: u32,
) -> i64 {
    use soroban_host::fees::{compute_rent_fee, compute_transaction_resource_fee, TransactionResources};

    let tx_resources = TransactionResources {
        instructions: resources.instructions,
        disk_read_entries: resources.footprint.read_only.len() as u32
            + resources.footprint.read_write.len() as u32,
        write_entries: resources.footprint.read_write.len() as u32,
        disk_read_bytes: resources.disk_read_bytes,
        write_bytes: resources.write_bytes,
        contract_events_size_bytes: contract_events_and_return_value_size,
        transaction_size_bytes: tx_size,
    };

    let fee_config = build_fee_config(soroban_info);
    let (non_refundable, refundable) =
        compute_transaction_resource_fee(&tx_resources, &fee_config);

    let rent_fee = compute_rent_fee(
        rent_changes,
        &build_rent_fee_config(soroban_info),
        current_ledger_seq,
    );

    // Apply adjustment to refundable fee + rent (matches soroban-simulation default)
    let total_refundable = refundable.saturating_add(rent_fee);
    let adjusted_refundable = if total_refundable > 0 {
        ((total_refundable as f64) * REFUNDABLE_FEE_ADJUSTMENT_FACTOR).floor() as i64
    } else {
        0
    };
    non_refundable.saturating_add(adjusted_refundable)
}

/// Compute resource fee for ExtendTTL/Restore operations (rent-dominant).
///
/// These operations have no instructions and no contract events, but do have
/// rent fees that dominate the cost.
fn compute_resource_fee_with_rent(
    resources: &SorobanResources,
    rent_changes: &[soroban_host::fees::LedgerEntryRentChange],
    soroban_info: &henyey_ledger::SorobanNetworkInfo,
    current_ledger_seq: u32,
    contract_events_size: u32,
    tx_size: u32,
) -> i64 {
    use soroban_host::fees::{compute_rent_fee, compute_transaction_resource_fee, TransactionResources};

    let tx_resources = TransactionResources {
        instructions: resources.instructions,
        disk_read_entries: resources.footprint.read_only.len() as u32
            + resources.footprint.read_write.len() as u32,
        write_entries: resources.footprint.read_write.len() as u32,
        disk_read_bytes: resources.disk_read_bytes,
        write_bytes: resources.write_bytes,
        contract_events_size_bytes: contract_events_size,
        transaction_size_bytes: tx_size,
    };

    let fee_config = build_fee_config(soroban_info);
    let rent_fee_config = build_rent_fee_config(soroban_info);

    let (non_refundable, refundable) =
        compute_transaction_resource_fee(&tx_resources, &fee_config);

    let rent_fee = compute_rent_fee(rent_changes, &rent_fee_config, current_ledger_seq);

    let total_refundable = refundable.saturating_add(rent_fee);
    let adjusted_refundable = if total_refundable > 0 {
        ((total_refundable as f64) * REFUNDABLE_FEE_ADJUSTMENT_FACTOR).floor() as i64
    } else {
        0
    };
    non_refundable.saturating_add(adjusted_refundable)
}
