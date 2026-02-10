//! Operation execution dispatcher.
//!
//! This module provides the main entry point for executing Stellar operations.
//! Each operation type has its own submodule with the specific execution logic.

use soroban_env_host24::xdr::ReadXdr as ReadXdrP24;
use soroban_env_host_p24 as soroban_env_host24;
use soroban_env_host_p25 as soroban_env_host25;
use henyey_common::{protocol_version_is_before, ProtocolVersion};
use stellar_xdr::curr::{
    AccountId, ContractEvent, DiagnosticEvent, ExtendFootprintTtlResult, Operation, OperationBody,
    OperationResult, OperationResultTr, RestoreFootprintResult, SorobanTransactionData, WriteXdr,
};

use crate::frame::muxed_to_account_id;
use crate::soroban::{PersistentModuleCache, SorobanConfig};
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;

mod account_merge;
mod bump_sequence;
mod change_trust;
mod claimable_balance;
mod clawback;
mod create_account;
mod extend_footprint_ttl;
mod inflation;
mod invoke_host_function;
mod liquidity_pool;
mod manage_data;
mod manage_offer;
mod offer_exchange;
mod path_payment;
mod payment;
mod restore_footprint;
mod set_options;
mod sponsorship;
mod trust_flags;

pub use account_merge::execute_account_merge;
pub use bump_sequence::execute_bump_sequence;
pub use change_trust::execute_change_trust;
pub use claimable_balance::{execute_claim_claimable_balance, execute_create_claimable_balance};
pub use clawback::{execute_clawback, execute_clawback_claimable_balance};
pub use create_account::execute_create_account;
pub use extend_footprint_ttl::execute_extend_footprint_ttl;
pub use inflation::execute_inflation;
pub use invoke_host_function::execute_invoke_host_function;
pub use liquidity_pool::{execute_liquidity_pool_deposit, execute_liquidity_pool_withdraw};
pub use manage_data::execute_manage_data;
pub use manage_offer::{
    execute_create_passive_sell_offer, execute_manage_buy_offer, execute_manage_sell_offer,
};
pub use offer_exchange::{exchange_v10, ExchangeError, ExchangeResult, RoundingType};
pub use path_payment::{execute_path_payment_strict_receive, execute_path_payment_strict_send};
pub use payment::execute_payment;
pub use restore_footprint::execute_restore_footprint;
pub use set_options::execute_set_options;
pub use sponsorship::{
    execute_begin_sponsoring_future_reserves, execute_end_sponsoring_future_reserves,
    execute_revoke_sponsorship,
};
pub use trust_flags::{execute_allow_trust, execute_set_trust_line_flags};

/// Execute a single operation.
///
/// This is the main dispatch function that routes to the appropriate
/// operation-specific executor based on the operation type.
///
/// # Arguments
///
/// * `op` - The operation to execute
/// * `source_account_id` - The transaction's source account (used if operation has no explicit source)
/// * `state` - The ledger state manager
/// * `context` - The ledger context
///
/// # Returns
///
/// Returns the operation result, which may indicate success or a specific failure code.
pub struct SorobanOperationMeta {
    /// Contract/system events emitted by the operation.
    pub events: Vec<ContractEvent>,
    /// Diagnostic events emitted during execution.
    pub diagnostic_events: Vec<DiagnosticEvent>,
    /// Return value for invoke host function (if any).
    pub return_value: Option<stellar_xdr::curr::ScVal>,
    /// Contract events + return value size in bytes.
    pub event_size_bytes: u32,
    /// Rent fee charged for storage changes.
    pub rent_fee: i64,
    /// Entries restored from the live BucketList (expired TTL but not yet evicted).
    /// These need RESTORED ledger entry changes emitted in transaction meta.
    pub live_bucket_list_restores: Vec<crate::soroban::protocol::LiveBucketListRestore>,
    /// Entries restored from the hot archive (for RestoreFootprint).
    /// These need RESTORED ledger entry changes emitted in transaction meta.
    /// Contains both the key and the entry value.
    pub hot_archive_restores: Vec<HotArchiveRestore>,
    /// Indices of entries ACTUALLY restored from hot archive in THIS transaction.
    /// This is a subset of the transaction envelope's archived_soroban_entries,
    /// excluding entries that were already restored by a previous transaction
    /// in the same ledger. Used to determine whether to emit INIT vs LIVE changes.
    pub actual_restored_indices: Vec<u32>,
}

/// Entry restored from the hot archive.
#[derive(Debug, Clone)]
pub struct HotArchiveRestore {
    /// The key of the restored entry.
    pub key: stellar_xdr::curr::LedgerKey,
    /// The restored entry value.
    pub entry: stellar_xdr::curr::LedgerEntry,
}

pub struct OperationExecutionResult {
    pub result: OperationResult,
    pub soroban_meta: Option<SorobanOperationMeta>,
}

impl OperationExecutionResult {
    fn new(result: OperationResult) -> Self {
        Self {
            result,
            soroban_meta: None,
        }
    }

    fn with_soroban_meta(result: OperationResult, meta: SorobanOperationMeta) -> Self {
        Self {
            result,
            soroban_meta: Some(meta),
        }
    }
}

struct RentSnapshot {
    key: stellar_xdr::curr::LedgerKey,
    is_persistent: bool,
    is_code_entry: bool,
    old_size_bytes: u32,
    old_live_until: u32,
}

struct RentChange {
    is_persistent: bool,
    is_code_entry: bool,
    old_size_bytes: u32,
    new_size_bytes: u32,
    old_live_until_ledger: u32,
    new_live_until_ledger: u32,
}

fn ledger_key_hash(key: &stellar_xdr::curr::LedgerKey) -> stellar_xdr::curr::Hash {
    use sha2::{Digest, Sha256};
    use stellar_xdr::curr::WriteXdr;

    let mut hasher = Sha256::new();
    if let Ok(bytes) = key.to_xdr(stellar_xdr::curr::Limits::none()) {
        hasher.update(&bytes);
    }
    stellar_xdr::curr::Hash(hasher.finalize().into())
}

pub fn entry_size_for_rent_by_protocol(
    protocol_version: u32,
    entry: &stellar_xdr::curr::LedgerEntry,
    entry_xdr_size: u32,
) -> u32 {
    entry_size_for_rent_by_protocol_with_cost_params(protocol_version, entry, entry_xdr_size, None)
}

/// Like `entry_size_for_rent_by_protocol`, but accepts optional on-chain cost
/// parameters (cpu_cost_params, mem_cost_params) so that the budget used for
/// computing WASM module memory cost matches the network configuration.
///
/// When `cost_params` is `None`, falls back to `Budget::default()` which uses
/// hard-coded cost model parameters. For deterministic parity with stellar-core
/// stellar-core, callers should pass the actual on-chain cost params whenever
/// available.
pub fn entry_size_for_rent_by_protocol_with_cost_params(
    protocol_version: u32,
    entry: &stellar_xdr::curr::LedgerEntry,
    entry_xdr_size: u32,
    cost_params: Option<(
        &stellar_xdr::curr::ContractCostParams,
        &stellar_xdr::curr::ContractCostParams,
    )>,
) -> u32 {
    if protocol_version_is_before(protocol_version, ProtocolVersion::V25) {
        let budget = match cost_params {
            Some((cpu, mem)) => build_budget_p24(cpu, mem),
            None => soroban_env_host24::budget::Budget::default(),
        };
        let entry = convert_ledger_entry_to_p24(entry);
        entry
            .and_then(|entry| {
                soroban_env_host24::e2e_invoke::entry_size_for_rent(&budget, &entry, entry_xdr_size)
                    .ok()
            })
            .unwrap_or(entry_xdr_size)
    } else {
        let budget = match cost_params {
            Some((cpu, mem)) => build_budget_p25(cpu, mem),
            None => soroban_env_host25::budget::Budget::default(),
        };
        convert_ledger_entry_to_p25(entry)
            .and_then(|entry| {
                soroban_env_host25::e2e_invoke::entry_size_for_rent(&budget, &entry, entry_xdr_size)
                    .ok()
            })
            .unwrap_or(entry_xdr_size)
    }
}

/// Build a P24 Budget from on-chain cost parameters.
fn build_budget_p24(
    cpu_cost_params: &stellar_xdr::curr::ContractCostParams,
    mem_cost_params: &stellar_xdr::curr::ContractCostParams,
) -> soroban_env_host24::budget::Budget {
    let cpu = convert_cost_params_to_p24(cpu_cost_params);
    let mem = convert_cost_params_to_p24(mem_cost_params);
    match (cpu, mem) {
        (Some(cpu), Some(mem)) => {
            // Use limits of 0 — we only need the cost model, not actual metering
            soroban_env_host24::budget::Budget::try_from_configs(0, 0, cpu, mem)
                .unwrap_or_else(|_| soroban_env_host24::budget::Budget::default())
        }
        _ => soroban_env_host24::budget::Budget::default(),
    }
}

/// Build a P25 Budget from on-chain cost parameters.
fn build_budget_p25(
    cpu_cost_params: &stellar_xdr::curr::ContractCostParams,
    mem_cost_params: &stellar_xdr::curr::ContractCostParams,
) -> soroban_env_host25::budget::Budget {
    let cpu = convert_cost_params_to_p25(cpu_cost_params);
    let mem = convert_cost_params_to_p25(mem_cost_params);
    match (cpu, mem) {
        (Some(cpu), Some(mem)) => {
            soroban_env_host25::budget::Budget::try_from_configs(0, 0, cpu, mem)
                .unwrap_or_else(|_| soroban_env_host25::budget::Budget::default())
        }
        _ => soroban_env_host25::budget::Budget::default(),
    }
}

fn convert_cost_params_to_p24(
    params: &stellar_xdr::curr::ContractCostParams,
) -> Option<soroban_env_host24::xdr::ContractCostParams> {
    let bytes = params.to_xdr(stellar_xdr::curr::Limits::none()).ok()?;
    soroban_env_host24::xdr::ContractCostParams::from_xdr(
        &bytes,
        soroban_env_host24::xdr::Limits::none(),
    )
    .ok()
}

fn convert_cost_params_to_p25(
    params: &stellar_xdr::curr::ContractCostParams,
) -> Option<soroban_env_host25::xdr::ContractCostParams> {
    use soroban_env_host25::xdr::ReadXdr as _;
    let bytes = params.to_xdr(stellar_xdr::curr::Limits::none()).ok()?;
    soroban_env_host25::xdr::ContractCostParams::from_xdr(
        &bytes,
        soroban_env_host25::xdr::Limits::none(),
    )
    .ok()
}

fn convert_ledger_entry_to_p25(
    entry: &stellar_xdr::curr::LedgerEntry,
) -> Option<soroban_env_host25::xdr::LedgerEntry> {
    use soroban_env_host25::xdr::ReadXdr as _;
    let bytes = entry.to_xdr(stellar_xdr::curr::Limits::none()).ok()?;
    soroban_env_host25::xdr::LedgerEntry::from_xdr(&bytes, soroban_env_host25::xdr::Limits::none())
        .ok()
}

fn convert_ledger_entry_to_p24(
    entry: &stellar_xdr::curr::LedgerEntry,
) -> Option<soroban_env_host24::xdr::LedgerEntry> {
    let bytes = entry.to_xdr(stellar_xdr::curr::Limits::none()).ok()?;
    soroban_env_host24::xdr::LedgerEntry::from_xdr(&bytes, soroban_env_host24::xdr::Limits::none())
        .ok()
}

fn rent_snapshot_for_keys(
    keys: &[stellar_xdr::curr::LedgerKey],
    state: &LedgerStateManager,
    protocol_version: u32,
    cost_params: Option<(
        &stellar_xdr::curr::ContractCostParams,
        &stellar_xdr::curr::ContractCostParams,
    )>,
) -> Vec<RentSnapshot> {
    let mut snapshots = Vec::new();
    for key in keys {
        let Some(entry) = state.get_entry(key) else {
            continue;
        };
        let entry_xdr = entry
            .to_xdr(stellar_xdr::curr::Limits::none())
            .unwrap_or_default();
        let entry_size = entry_size_for_rent_by_protocol_with_cost_params(
            protocol_version,
            &entry,
            entry_xdr.len() as u32,
            cost_params,
        );
        let key_hash = ledger_key_hash(key);
        let old_live_until = state
            .get_ttl(&key_hash)
            .map(|ttl| ttl.live_until_ledger_seq)
            .unwrap_or(0);
        let (is_persistent, is_code_entry) = match key {
            stellar_xdr::curr::LedgerKey::ContractCode(_) => (true, true),
            stellar_xdr::curr::LedgerKey::ContractData(cd) => (
                cd.durability == stellar_xdr::curr::ContractDataDurability::Persistent,
                false,
            ),
            _ => (false, false),
        };
        snapshots.push(RentSnapshot {
            key: key.clone(),
            is_persistent,
            is_code_entry,
            old_size_bytes: entry_size,
            old_live_until,
        });
    }
    snapshots
}

fn rent_changes_from_snapshots(
    snapshots: &[RentSnapshot],
    state: &LedgerStateManager,
    protocol_version: u32,
    cost_params: Option<(
        &stellar_xdr::curr::ContractCostParams,
        &stellar_xdr::curr::ContractCostParams,
    )>,
) -> Vec<RentChange> {
    let mut changes = Vec::new();
    for snapshot in snapshots {
        let Some(entry) = state.get_entry(&snapshot.key) else {
            tracing::debug!(?snapshot.key, "rent_changes_from_snapshots: entry not found, skipping");
            continue;
        };
        let entry_xdr = entry
            .to_xdr(stellar_xdr::curr::Limits::none())
            .unwrap_or_default();
        let new_size_bytes = entry_size_for_rent_by_protocol_with_cost_params(
            protocol_version,
            &entry,
            entry_xdr.len() as u32,
            cost_params,
        );
        let key_hash = ledger_key_hash(&snapshot.key);
        let new_live_until = state
            .get_ttl(&key_hash)
            .map(|ttl| ttl.live_until_ledger_seq)
            .unwrap_or(snapshot.old_live_until);

        tracing::debug!(
            ?snapshot.key,
            old_size_bytes = snapshot.old_size_bytes,
            new_size_bytes,
            old_live_until = snapshot.old_live_until,
            new_live_until,
            "rent_changes_from_snapshots: processing entry"
        );

        if new_live_until <= snapshot.old_live_until && new_size_bytes <= snapshot.old_size_bytes {
            tracing::debug!(?snapshot.key, "rent_changes_from_snapshots: no change needed, skipping");
            continue;
        }
        changes.push(RentChange {
            is_persistent: snapshot.is_persistent,
            is_code_entry: snapshot.is_code_entry,
            old_size_bytes: snapshot.old_size_bytes,
            new_size_bytes,
            old_live_until_ledger: snapshot.old_live_until,
            new_live_until_ledger: new_live_until,
        });
    }
    tracing::debug!(
        changes_count = changes.len(),
        "rent_changes_from_snapshots: total changes"
    );
    changes
}

fn rent_fee_config_p25_to_p24(
    config: &soroban_env_host25::fees::RentFeeConfiguration,
) -> soroban_env_host24::fees::RentFeeConfiguration {
    soroban_env_host24::fees::RentFeeConfiguration {
        fee_per_write_1kb: config.fee_per_write_1kb,
        fee_per_rent_1kb: config.fee_per_rent_1kb,
        fee_per_write_entry: config.fee_per_write_entry,
        persistent_rent_rate_denominator: config.persistent_rent_rate_denominator,
        temporary_rent_rate_denominator: config.temporary_rent_rate_denominator,
    }
}

fn compute_rent_fee_by_protocol(
    protocol_version: u32,
    rent_changes: &[RentChange],
    config: &soroban_env_host25::fees::RentFeeConfiguration,
    ledger_seq: u32,
) -> i64 {
    let fee = if protocol_version_is_before(protocol_version, ProtocolVersion::V25) {
        let changes: Vec<soroban_env_host24::fees::LedgerEntryRentChange> = rent_changes
            .iter()
            .map(|change| soroban_env_host24::fees::LedgerEntryRentChange {
                is_persistent: change.is_persistent,
                is_code_entry: change.is_code_entry,
                old_size_bytes: change.old_size_bytes,
                new_size_bytes: change.new_size_bytes,
                old_live_until_ledger: change.old_live_until_ledger,
                new_live_until_ledger: change.new_live_until_ledger,
            })
            .collect();
        let p24_config = rent_fee_config_p25_to_p24(config);
        tracing::debug!(
            fee_per_write_1kb = p24_config.fee_per_write_1kb,
            fee_per_rent_1kb = p24_config.fee_per_rent_1kb,
            fee_per_write_entry = p24_config.fee_per_write_entry,
            persistent_rent_rate_denominator = p24_config.persistent_rent_rate_denominator,
            temporary_rent_rate_denominator = p24_config.temporary_rent_rate_denominator,
            "compute_rent_fee_by_protocol: P24 config"
        );
        soroban_env_host24::fees::compute_rent_fee(&changes, &p24_config, ledger_seq)
    } else {
        let changes: Vec<soroban_env_host25::fees::LedgerEntryRentChange> = rent_changes
            .iter()
            .map(|change| soroban_env_host25::fees::LedgerEntryRentChange {
                is_persistent: change.is_persistent,
                is_code_entry: change.is_code_entry,
                old_size_bytes: change.old_size_bytes,
                new_size_bytes: change.new_size_bytes,
                old_live_until_ledger: change.old_live_until_ledger,
                new_live_until_ledger: change.new_live_until_ledger,
            })
            .collect();
        soroban_env_host25::fees::compute_rent_fee(&changes, config, ledger_seq)
    };
    tracing::debug!(
        rent_fee = fee,
        changes_count = rent_changes.len(),
        protocol_version,
        ledger_seq,
        "compute_rent_fee_by_protocol: computed rent fee"
    );
    fee
}

pub fn execute_operation(
    op: &Operation,
    source_account_id: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationExecutionResult> {
    execute_operation_with_soroban(
        op,
        source_account_id,
        source_account_id,
        0,
        0,
        state,
        context,
        None,
        None,
        None, // No module cache for simple execution
        None, // No hot archive for simple execution
    )
}

/// Execute a single operation with optional Soroban transaction data.
///
/// This variant is used for Soroban operations that need access to the footprint
/// and network configuration.
///
/// # Arguments
///
/// * `soroban_config` - Optional Soroban config with cost parameters. Required for
///   accurate Soroban transaction execution. If None, uses default config which may
///   produce incorrect results.
/// * `module_cache` - Optional persistent module cache for reusing compiled WASM
///   across transactions. Significantly improves performance for contracts.
/// * `hot_archive` - Optional hot archive lookup for Protocol 23+ entry restoration
#[allow(clippy::too_many_arguments)]
pub fn execute_operation_with_soroban(
    op: &Operation,
    source_account_id: &AccountId,
    tx_source_id: &AccountId,
    tx_seq: i64,
    op_index: u32,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
    soroban_data: Option<&SorobanTransactionData>,
    soroban_config: Option<&SorobanConfig>,
    module_cache: Option<&PersistentModuleCache>,
    hot_archive: Option<&dyn crate::soroban::HotArchiveLookup>,
) -> Result<OperationExecutionResult> {
    // Get the actual source for this operation
    // If the operation has an explicit source, use it; otherwise use the transaction source
    let op_source = op
        .source_account
        .as_ref()
        .map(muxed_to_account_id)
        .unwrap_or_else(|| source_account_id.clone());

    // Check that the operation's source account exists.
    // This matches stellar-core's OperationFrame::checkSourceAccount().
    // If the source account doesn't exist (e.g., it was merged by a prior operation),
    // return opNO_ACCOUNT.
    if state.get_account(&op_source).is_none() {
        return Ok(OperationExecutionResult::new(OperationResult::OpNoAccount));
    }

    match &op.body {
        OperationBody::CreateAccount(op_data) => Ok(OperationExecutionResult::new(
            create_account::execute_create_account(op_data, &op_source, state, context)?,
        )),
        OperationBody::Payment(op_data) => Ok(OperationExecutionResult::new(
            payment::execute_payment(op_data, &op_source, state, context)?,
        )),
        OperationBody::ChangeTrust(op_data) => Ok(OperationExecutionResult::new(
            change_trust::execute_change_trust(op_data, &op_source, state, context)?,
        )),
        OperationBody::ManageData(op_data) => Ok(OperationExecutionResult::new(
            manage_data::execute_manage_data(op_data, &op_source, state, context)?,
        )),
        OperationBody::BumpSequence(op_data) => Ok(OperationExecutionResult::new(
            bump_sequence::execute_bump_sequence(op_data, &op_source, state, context)?,
        )),
        OperationBody::AccountMerge(dest) => Ok(OperationExecutionResult::new(
            account_merge::execute_account_merge(dest, &op_source, state, context)?,
        )),
        OperationBody::SetOptions(op_data) => Ok(OperationExecutionResult::new(
            set_options::execute_set_options(op_data, &op_source, state, context)?,
        )),
        // Soroban operations
        OperationBody::InvokeHostFunction(op_data) => {
            // Use provided config or default for Soroban execution
            let default_config = SorobanConfig::default();
            let config = soroban_config.unwrap_or(&default_config);
            invoke_host_function::execute_invoke_host_function(
                op_data,
                &op_source,
                state,
                context,
                soroban_data,
                config,
                module_cache,
                hot_archive,
            )
        }
        OperationBody::ExtendFootprintTtl(op_data) => {
            let default_config = SorobanConfig::default();
            let config = soroban_config.unwrap_or(&default_config);
            let snapshots = soroban_data
                .map(|data| {
                    let mut keys = Vec::new();
                    keys.extend(data.resources.footprint.read_only.iter().cloned());
                    keys.extend(data.resources.footprint.read_write.iter().cloned());
                    rent_snapshot_for_keys(
                        &keys,
                        state,
                        context.protocol_version,
                        soroban_config.map(|c| (&c.cpu_cost_params, &c.mem_cost_params)),
                    )
                })
                .unwrap_or_default();
            let result = extend_footprint_ttl::execute_extend_footprint_ttl(
                op_data,
                &op_source,
                state,
                context,
                soroban_data,
            )?;
            let mut exec = OperationExecutionResult::new(result);
            if matches!(
                exec.result,
                OperationResult::OpInner(OperationResultTr::ExtendFootprintTtl(
                    ExtendFootprintTtlResult::Success
                ))
            ) {
                let rent_changes = rent_changes_from_snapshots(
                    &snapshots,
                    state,
                    context.protocol_version,
                    soroban_config.map(|c| (&c.cpu_cost_params, &c.mem_cost_params)),
                );
                let rent_fee = compute_rent_fee_by_protocol(
                    context.protocol_version,
                    &rent_changes,
                    &config.rent_fee_config,
                    context.sequence,
                );
                exec.soroban_meta = Some(SorobanOperationMeta {
                    events: Vec::new(),
                    diagnostic_events: Vec::new(),
                    return_value: None,
                    event_size_bytes: 0,
                    rent_fee,
                    live_bucket_list_restores: Vec::new(),
                    hot_archive_restores: Vec::new(),
                    actual_restored_indices: Vec::new(),
                });
            }
            Ok(exec)
        }
        OperationBody::RestoreFootprint(op_data) => {
            let default_config = SorobanConfig::default();
            let config = soroban_config.unwrap_or(&default_config);
            // For RestoreFootprint, we need to track which entries are ACTUALLY restored.
            // stellar-core only computes rent for entries that need restoration (not already live).
            //
            // Per stellar-core RestoreFootprintOpFrame::doApply():
            // 1. If TTL exists and isLive (TTL >= current_ledger) -> skip (already live)
            // 2. If no TTL exists -> check hot archive
            //    - If hot archive entry found -> include (restore from hot archive)
            //    - If no hot archive entry -> skip (entry doesn't exist)
            // 3. If TTL exists but expired (TTL < current_ledger) -> include (restore from live BL)
            let mut snapshots = Vec::new();
            let mut hot_archive_restores = Vec::new();
            if let Some(data) = soroban_data {
                for key in data.resources.footprint.read_write.iter() {
                    // Only compute rent for entries that need restoration
                    let key_hash = ledger_key_hash(key);
                    let current_ttl = state.get_ttl(&key_hash).map(|t| t.live_until_ledger_seq);

                    // Case 1: TTL exists and entry is live -> skip
                    if let Some(ttl) = current_ttl {
                        if ttl >= context.sequence {
                            continue;
                        }
                        // Case 3: TTL exists but expired -> restore from live bucket list
                        if let Some(entry) = state.get_entry(key) {
                            let entry_xdr = entry
                                .to_xdr(stellar_xdr::curr::Limits::none())
                                .unwrap_or_default();
                            let entry_size = entry_size_for_rent_by_protocol_with_cost_params(
                                context.protocol_version,
                                &entry,
                                entry_xdr.len() as u32,
                                soroban_config.map(|c| (&c.cpu_cost_params, &c.mem_cost_params)),
                            );
                            let (is_persistent, is_code_entry) = match key {
                                stellar_xdr::curr::LedgerKey::ContractCode(_) => (true, true),
                                stellar_xdr::curr::LedgerKey::ContractData(cd) => (
                                    cd.durability
                                        == stellar_xdr::curr::ContractDataDurability::Persistent,
                                    false,
                                ),
                                _ => (false, false),
                            };
                            snapshots.push(RentSnapshot {
                                key: key.clone(),
                                is_persistent,
                                is_code_entry,
                                old_size_bytes: entry_size,
                                old_live_until: ttl,
                            });
                        }
                    } else {
                        // Case 2: No TTL -> check hot archive
                        // Per stellar-core createEntryRentChangeWithoutModification():
                        // When entryLiveUntilLedger is std::nullopt (no previous TTL):
                        //   - old_size_bytes = 0
                        //   - old_live_until_ledger = 0
                        // This is different from expired entries where we use the actual old size.
                        if let Some(ha) = hot_archive {
                            if let Some(entry) = ha.get(key) {
                                let (is_persistent, is_code_entry) = match key {
                                    stellar_xdr::curr::LedgerKey::ContractCode(_) => (true, true),
                                    stellar_xdr::curr::LedgerKey::ContractData(cd) => (
                                        cd.durability
                                            == stellar_xdr::curr::ContractDataDurability::Persistent,
                                        false,
                                    ),
                                    _ => (false, false),
                                };
                                snapshots.push(RentSnapshot {
                                    key: key.clone(),
                                    is_persistent,
                                    is_code_entry,
                                    old_size_bytes: 0, // Hot archive entries: old_size_bytes = 0
                                    old_live_until: 0, // Hot archive entries: old_live_until = 0
                                });
                                // Track this entry for RESTORED metadata emission
                                hot_archive_restores.push(HotArchiveRestore {
                                    key: key.clone(),
                                    entry: entry.clone(),
                                });
                            }
                        }
                    }
                }
            }
            // Convert HotArchiveRestore to HotArchiveRestoreEntry for execute_restore_footprint
            let ha_restore_entries: Vec<restore_footprint::HotArchiveRestoreEntry> =
                hot_archive_restores
                    .iter()
                    .map(|r| restore_footprint::HotArchiveRestoreEntry {
                        key: r.key.clone(),
                        entry: r.entry.clone(),
                    })
                    .collect();
            let result = restore_footprint::execute_restore_footprint(
                op_data,
                &op_source,
                state,
                context,
                soroban_data,
                config.min_persistent_entry_ttl,
                &ha_restore_entries,
            )?;
            let mut exec = OperationExecutionResult::new(result);
            if matches!(
                exec.result,
                OperationResult::OpInner(OperationResultTr::RestoreFootprint(
                    RestoreFootprintResult::Success
                ))
            ) {
                let rent_changes = rent_changes_from_snapshots(
                    &snapshots,
                    state,
                    context.protocol_version,
                    soroban_config.map(|c| (&c.cpu_cost_params, &c.mem_cost_params)),
                );
                let rent_fee = compute_rent_fee_by_protocol(
                    context.protocol_version,
                    &rent_changes,
                    &config.rent_fee_config,
                    context.sequence,
                );
                exec.soroban_meta = Some(SorobanOperationMeta {
                    events: Vec::new(),
                    diagnostic_events: Vec::new(),
                    return_value: None,
                    event_size_bytes: 0,
                    rent_fee,
                    live_bucket_list_restores: Vec::new(),
                    hot_archive_restores,
                    actual_restored_indices: Vec::new(),
                });
            }
            Ok(exec)
        }
        // DEX operations
        OperationBody::PathPaymentStrictReceive(op_data) => Ok(OperationExecutionResult::new(
            path_payment::execute_path_payment_strict_receive(op_data, &op_source, state, context)?,
        )),
        OperationBody::PathPaymentStrictSend(op_data) => Ok(OperationExecutionResult::new(
            path_payment::execute_path_payment_strict_send(op_data, &op_source, state, context)?,
        )),
        OperationBody::ManageSellOffer(op_data) => Ok(OperationExecutionResult::new(
            manage_offer::execute_manage_sell_offer(op_data, &op_source, state, context)?,
        )),
        OperationBody::ManageBuyOffer(op_data) => Ok(OperationExecutionResult::new(
            manage_offer::execute_manage_buy_offer(op_data, &op_source, state, context)?,
        )),
        OperationBody::CreatePassiveSellOffer(op_data) => Ok(OperationExecutionResult::new(
            manage_offer::execute_create_passive_sell_offer(op_data, &op_source, state, context)?,
        )),
        OperationBody::AllowTrust(op_data) => Ok(OperationExecutionResult::new(
            trust_flags::execute_allow_trust(op_data, &op_source, state, context)?,
        )),
        OperationBody::Inflation => Ok(OperationExecutionResult::new(
            inflation::execute_inflation(&op_source, state, context)?,
        )),
        OperationBody::CreateClaimableBalance(op_data) => Ok(OperationExecutionResult::new(
            claimable_balance::execute_create_claimable_balance(
                op_data,
                &op_source,
                tx_source_id,
                tx_seq,
                op_index,
                state,
                context,
            )?,
        )),
        OperationBody::ClaimClaimableBalance(op_data) => Ok(OperationExecutionResult::new(
            claimable_balance::execute_claim_claimable_balance(
                op_data, &op_source, state, context,
            )?,
        )),
        OperationBody::BeginSponsoringFutureReserves(op_data) => Ok(OperationExecutionResult::new(
            sponsorship::execute_begin_sponsoring_future_reserves(
                op_data, &op_source, state, context,
            )?,
        )),
        OperationBody::EndSponsoringFutureReserves => Ok(OperationExecutionResult::new(
            sponsorship::execute_end_sponsoring_future_reserves(&op_source, state, context)?,
        )),
        OperationBody::RevokeSponsorship(op_data) => Ok(OperationExecutionResult::new(
            sponsorship::execute_revoke_sponsorship(op_data, &op_source, state, context)?,
        )),
        OperationBody::Clawback(op_data) => Ok(OperationExecutionResult::new(
            clawback::execute_clawback(op_data, &op_source, state, context)?,
        )),
        OperationBody::ClawbackClaimableBalance(op_data) => Ok(OperationExecutionResult::new(
            clawback::execute_clawback_claimable_balance(op_data, &op_source, state, context)?,
        )),
        OperationBody::SetTrustLineFlags(op_data) => Ok(OperationExecutionResult::new(
            trust_flags::execute_set_trust_line_flags(op_data, &op_source, state, context)?,
        )),
        OperationBody::LiquidityPoolDeposit(op_data) => Ok(OperationExecutionResult::new(
            liquidity_pool::execute_liquidity_pool_deposit(op_data, &op_source, state, context)?,
        )),
        OperationBody::LiquidityPoolWithdraw(op_data) => Ok(OperationExecutionResult::new(
            liquidity_pool::execute_liquidity_pool_withdraw(op_data, &op_source, state, context)?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_account_id() -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32])))
    }

    fn create_test_account(account_id: AccountId, balance: i64) -> AccountEntry {
        AccountEntry {
            account_id,
            balance,
            seq_num: SequenceNumber(1),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: vec![].try_into().unwrap(),
            ext: AccountEntryExt::V0,
        }
    }

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    #[test]
    fn test_inflation_operation_dispatch() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id();

        // Add the source account to state
        state.create_account(create_test_account(source.clone(), 100_000_000));

        // Test that Inflation returns NotTime (deprecated since Protocol 12)
        let op = Operation {
            source_account: None,
            body: OperationBody::Inflation,
        };

        let result = execute_operation(&op, &source, &mut state, &context).expect("execute op");

        // Inflation is deprecated and returns NotTime
        match result.result {
            OperationResult::OpInner(OperationResultTr::Inflation(r)) => {
                assert!(matches!(r, InflationResult::NotTime));
            }
            _ => panic!("Expected Inflation result"),
        }
    }

    // === OperationExecutionResult tests ===

    #[test]
    fn test_operation_execution_result_new() {
        let op_result = OperationResult::OpBadAuth;
        let result = OperationExecutionResult::new(op_result);

        assert!(result.soroban_meta.is_none());
        match result.result {
            OperationResult::OpBadAuth => {}
            _ => panic!("Expected OpBadAuth"),
        }
    }

    #[test]
    fn test_operation_execution_result_with_soroban_meta() {
        let op_result =
            OperationResult::OpInner(OperationResultTr::Inflation(InflationResult::NotTime));
        let meta = SorobanOperationMeta {
            events: vec![],
            diagnostic_events: vec![],
            return_value: None,
            event_size_bytes: 100,
            rent_fee: 500,
            live_bucket_list_restores: vec![],
            hot_archive_restores: vec![],
            actual_restored_indices: vec![],
        };

        let result = OperationExecutionResult::with_soroban_meta(op_result, meta);

        assert!(result.soroban_meta.is_some());
        let soroban_meta = result.soroban_meta.unwrap();
        assert_eq!(soroban_meta.event_size_bytes, 100);
        assert_eq!(soroban_meta.rent_fee, 500);
    }

    // === SorobanOperationMeta tests ===

    #[test]
    fn test_soroban_operation_meta_default_values() {
        let meta = SorobanOperationMeta {
            events: vec![],
            diagnostic_events: vec![],
            return_value: None,
            event_size_bytes: 0,
            rent_fee: 0,
            live_bucket_list_restores: vec![],
            hot_archive_restores: vec![],
            actual_restored_indices: vec![],
        };

        assert!(meta.events.is_empty());
        assert!(meta.diagnostic_events.is_empty());
        assert!(meta.return_value.is_none());
        assert_eq!(meta.event_size_bytes, 0);
        assert_eq!(meta.rent_fee, 0);
    }

    #[test]
    fn test_soroban_operation_meta_with_return_value() {
        let meta = SorobanOperationMeta {
            events: vec![],
            diagnostic_events: vec![],
            return_value: Some(ScVal::I32(42)),
            event_size_bytes: 50,
            rent_fee: 100,
            live_bucket_list_restores: vec![],
            hot_archive_restores: vec![],
            actual_restored_indices: vec![1, 2, 3],
        };

        assert!(meta.return_value.is_some());
        match meta.return_value.unwrap() {
            ScVal::I32(v) => assert_eq!(v, 42),
            _ => panic!("Expected I32"),
        }
        assert_eq!(meta.actual_restored_indices.len(), 3);
    }

    // === HotArchiveRestore tests ===

    #[test]
    fn test_hot_archive_restore_struct() {
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: create_test_account_id(),
        });
        let entry = LedgerEntry {
            last_modified_ledger_seq: 100,
            data: LedgerEntryData::Account(create_test_account(
                create_test_account_id(),
                1_000_000,
            )),
            ext: LedgerEntryExt::V0,
        };

        let restore = HotArchiveRestore {
            key: key.clone(),
            entry: entry.clone(),
        };

        assert_eq!(restore.entry.last_modified_ledger_seq, 100);
    }

    #[test]
    fn test_hot_archive_restore_debug() {
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: create_test_account_id(),
        });
        let entry = LedgerEntry {
            last_modified_ledger_seq: 50,
            data: LedgerEntryData::Account(create_test_account(create_test_account_id(), 500_000)),
            ext: LedgerEntryExt::V0,
        };

        let restore = HotArchiveRestore { key, entry };
        let debug_str = format!("{:?}", restore);
        assert!(debug_str.contains("HotArchiveRestore"));
    }

    // === ledger_key_hash tests ===

    #[test]
    fn test_ledger_key_hash_account() {
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: create_test_account_id(),
        });

        let hash = ledger_key_hash(&key);
        // Hash should be 32 bytes (256 bits)
        assert_eq!(hash.0.len(), 32);
        // Same key should produce same hash
        let hash2 = ledger_key_hash(&key);
        assert_eq!(hash.0, hash2.0);
    }

    #[test]
    fn test_ledger_key_hash_different_keys() {
        let key1 = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32]))),
        });
        let key2 = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1u8; 32]))),
        });

        let hash1 = ledger_key_hash(&key1);
        let hash2 = ledger_key_hash(&key2);

        // Different keys should produce different hashes
        assert_ne!(hash1.0, hash2.0);
    }

    // === BumpSequence operation dispatch ===

    #[test]
    fn test_bump_sequence_operation_dispatch() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id();

        state.create_account(create_test_account(source.clone(), 100_000_000));

        let op = Operation {
            source_account: None,
            body: OperationBody::BumpSequence(BumpSequenceOp {
                bump_to: SequenceNumber(10),
            }),
        };

        let result = execute_operation(&op, &source, &mut state, &context).expect("execute op");

        match result.result {
            OperationResult::OpInner(OperationResultTr::BumpSequence(r)) => {
                assert!(matches!(r, BumpSequenceResult::Success));
            }
            _ => panic!("Expected BumpSequence result"),
        }
    }

    // === CreateAccount operation dispatch ===

    #[test]
    fn test_create_account_operation_dispatch() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id();

        state.create_account(create_test_account(source.clone(), 100_000_000));

        let new_account = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([5u8; 32])));

        let op = Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: new_account.clone(),
                starting_balance: 10_000_000,
            }),
        };

        let result = execute_operation(&op, &source, &mut state, &context).expect("execute op");

        match result.result {
            OperationResult::OpInner(OperationResultTr::CreateAccount(r)) => {
                assert!(matches!(r, CreateAccountResult::Success));
            }
            _ => panic!("Expected CreateAccount result"),
        }
    }

    // === Payment operation dispatch ===

    #[test]
    fn test_payment_operation_dispatch_no_dest() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id();

        state.create_account(create_test_account(source.clone(), 100_000_000));

        let dest = MuxedAccount::Ed25519(Uint256([5u8; 32]));

        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: dest,
                asset: Asset::Native,
                amount: 1_000_000,
            }),
        };

        let result = execute_operation(&op, &source, &mut state, &context).expect("execute op");

        // Should fail because destination account doesn't exist
        match result.result {
            OperationResult::OpInner(OperationResultTr::Payment(PaymentResult::NoDestination)) => {}
            _ => panic!("Expected Payment NoDestination result"),
        }
    }

    // === ManageData operation dispatch ===

    #[test]
    fn test_manage_data_operation_dispatch() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id();

        state.create_account(create_test_account(source.clone(), 100_000_000));

        let op = Operation {
            source_account: None,
            body: OperationBody::ManageData(ManageDataOp {
                data_name: String64::try_from(b"testkey".to_vec()).unwrap(),
                data_value: Some(DataValue(vec![1, 2, 3, 4].try_into().unwrap())),
            }),
        };

        let result = execute_operation(&op, &source, &mut state, &context).expect("execute op");

        match result.result {
            OperationResult::OpInner(OperationResultTr::ManageData(ManageDataResult::Success)) => {}
            _ => panic!("Expected ManageData Success result"),
        }
    }

    // === Operation with explicit source ===

    #[test]
    fn test_operation_with_explicit_source() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let tx_source = create_test_account_id();
        let op_source = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([9u8; 32])));

        // Create both accounts
        state.create_account(create_test_account(tx_source.clone(), 100_000_000));
        state.create_account(create_test_account(op_source.clone(), 100_000_000));

        // Operation with explicit source different from tx source
        let op = Operation {
            source_account: Some(MuxedAccount::Ed25519(Uint256([9u8; 32]))),
            body: OperationBody::BumpSequence(BumpSequenceOp {
                bump_to: SequenceNumber(10),
            }),
        };

        let result = execute_operation(&op, &tx_source, &mut state, &context).expect("execute op");

        match result.result {
            OperationResult::OpInner(OperationResultTr::BumpSequence(r)) => {
                assert!(matches!(r, BumpSequenceResult::Success));
            }
            _ => panic!("Expected BumpSequence result"),
        }
    }
}
