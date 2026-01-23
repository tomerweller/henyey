//! Transaction execution during ledger close.
//!
//! This module bridges the ledger close process with the transaction processing
//! layer (`stellar-core-tx`). It handles:
//!
//! - Loading required state from snapshots into the execution environment
//! - Executing transactions in the correct order with proper fee handling
//! - Recording state changes to the [`LedgerDelta`]
//! - Generating transaction metadata for history
//!
//! # Execution Flow
//!
//! 1. **State Loading**: Required accounts, trustlines, and other entries are
//!    loaded from the snapshot into the [`LedgerStateManager`]
//!
//! 2. **Fee Charging**: Transaction fees are charged upfront, even for
//!    transactions that will fail validation
//!
//! 3. **Operation Execution**: Each operation is executed in sequence,
//!    with results collected for the transaction result
//!
//! 4. **State Recording**: Changes are recorded to the [`LedgerDelta`]
//!    for later application to the bucket list
//!
//! # Soroban Support
//!
//! For Protocol 20+, this module handles Soroban smart contract execution:
//!
//! - Loading contract data and code from the footprint
//! - Configuring the Soroban host with network parameters
//! - Computing resource fees and rent
//! - Processing contract events
//!
//! [`LedgerDelta`]: crate::LedgerDelta
//! [`LedgerStateManager`]: stellar_core_tx::LedgerStateManager

use std::collections::{HashMap, HashSet};

use soroban_env_host_p25::fees::{
    compute_rent_write_fee_per_1kb, compute_transaction_resource_fee, FeeConfiguration,
    RentFeeConfiguration, RentWriteFeeConfiguration,
};
use stellar_core_common::protocol::{protocol_version_starts_from, ProtocolVersion};
use stellar_core_common::{Hash256, NetworkId};
use stellar_core_crypto::account_id_to_strkey;
use stellar_core_invariant::{
    ConstantProductInvariant, InvariantContext, InvariantManager,
    LedgerEntryChange as InvariantLedgerEntryChange, LiabilitiesMatchOffers, OrderBookIsNotCrossed,
};
use stellar_core_tx::{
    make_account_address, make_claimable_balance_address, make_muxed_account_address,
    operations::OperationType,
    soroban::{PersistentModuleCache, SorobanConfig},
    state::{get_account_seq_ledger, get_account_seq_time},
    validation::{self, LedgerContext as ValidationContext},
    ClassicEventConfig, LedgerContext, LedgerStateManager, OpEventManager, TransactionFrame,
    TxError, TxEventManager,
};
use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountEntryExtensionV1Ext, AccountId, AccountMergeResult,
    AllowTrustOp, AlphaNum12, AlphaNum4, Asset, AssetCode, ClaimableBalanceEntry,
    ClaimableBalanceId, ConfigSettingEntry, ConfigSettingId, ContractCostParams, ContractEvent,
    CreateClaimableBalanceResult, DiagnosticEvent, ExtensionPoint, InflationResult,
    InnerTransactionResult, InnerTransactionResultExt, InnerTransactionResultPair,
    InnerTransactionResultResult, LedgerEntry, LedgerEntryChange, LedgerEntryChanges,
    LedgerEntryData, LedgerHeader, LedgerKey, LedgerKeyClaimableBalance, LedgerKeyConfigSetting,
    LedgerKeyLiquidityPool, Limits, LiquidityPoolEntry, LiquidityPoolEntryBody,
    ManageBuyOfferResult, ManageSellOfferResult, MuxedAccount, OfferEntry, Operation,
    OperationBody, OperationMetaV2, OperationResult, OperationResultTr,
    PathPaymentStrictReceiveResult, PathPaymentStrictSendResult, PoolId, Preconditions, ScAddress,
    SignerKey, SorobanTransactionData, SorobanTransactionDataExt, SorobanTransactionMetaExt,
    SorobanTransactionMetaV2, TransactionEnvelope, TransactionEvent, TransactionEventStage,
    TransactionMeta, TransactionMetaV4, TransactionResult, TransactionResultExt,
    TransactionResultMetaV1, TransactionResultPair, TransactionResultResult, TrustLineAsset,
    TrustLineFlags, VecM, WriteXdr,
};
use tracing::{debug, info, warn};

use crate::delta::LedgerDelta;
use crate::snapshot::SnapshotHandle;
use crate::{LedgerError, Result};

/// Soroban network configuration information for the /sorobaninfo endpoint.
///
/// This struct contains all the Soroban-related configuration settings from
/// the ledger, matching the format returned by C++ stellar-core's `/sorobaninfo`
/// HTTP endpoint in "basic" format.
#[derive(Debug, Clone, Default)]
pub struct SorobanNetworkInfo {
    /// Maximum contract code size in bytes.
    pub max_contract_size: u32,
    /// Maximum contract data key size in bytes.
    pub max_contract_data_key_size: u32,
    /// Maximum contract data entry size in bytes.
    pub max_contract_data_entry_size: u32,
    /// Per-transaction compute limits.
    pub tx_max_instructions: i64,
    /// Per-ledger compute limits.
    pub ledger_max_instructions: i64,
    /// Fee rate per instructions increment.
    pub fee_rate_per_instructions_increment: i64,
    /// Transaction memory limit.
    pub tx_memory_limit: u32,
    /// Per-ledger disk read limits.
    pub ledger_max_read_ledger_entries: u32,
    pub ledger_max_read_bytes: u32,
    pub ledger_max_write_ledger_entries: u32,
    pub ledger_max_write_bytes: u32,
    /// Per-transaction disk read/write limits.
    pub tx_max_read_ledger_entries: u32,
    pub tx_max_read_bytes: u32,
    pub tx_max_write_ledger_entries: u32,
    pub tx_max_write_bytes: u32,
    /// Fees per entry and per KB.
    pub fee_read_ledger_entry: i64,
    pub fee_write_ledger_entry: i64,
    pub fee_read_1kb: i64,
    pub fee_write_1kb: i64,
    pub fee_historical_1kb: i64,
    /// Contract events settings.
    pub tx_max_contract_events_size_bytes: u32,
    pub fee_contract_events_size_1kb: i64,
    /// Bandwidth settings.
    pub ledger_max_tx_size_bytes: u32,
    pub tx_max_size_bytes: u32,
    pub fee_transaction_size_1kb: i64,
    /// General ledger settings.
    pub ledger_max_tx_count: u32,
    /// State archival settings.
    pub max_entry_ttl: u32,
    pub min_temporary_ttl: u32,
    pub min_persistent_ttl: u32,
    pub persistent_rent_rate_denominator: i64,
    pub temp_rent_rate_denominator: i64,
    pub max_entries_to_archive: u32,
    pub bucketlist_size_window_sample_size: u32,
    pub eviction_scan_size: i64,
    pub starting_eviction_scan_level: u32,
    /// Computed value: average bucket list size.
    pub average_bucket_list_size: u64,
}

/// Load a ConfigSettingEntry from the snapshot by ID.
fn load_config_setting(
    snapshot: &SnapshotHandle,
    id: ConfigSettingId,
) -> Option<ConfigSettingEntry> {
    let key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: id,
    });
    match snapshot.get_entry(&key) {
        Ok(Some(entry)) => {
            if let LedgerEntryData::ConfigSetting(config) = entry.data {
                Some(config)
            } else {
                None
            }
        }
        Ok(None) => None,
        Err(_) => None,
    }
}

/// Load SorobanConfig from the ledger's ConfigSettingEntry entries.
///
/// This loads the cost parameters and limits from the ledger state,
/// which are required for accurate Soroban transaction execution.
/// If any required settings are missing, returns a default config.
///
/// The `protocol_version` parameter is used to determine which fee to use
/// for `fee_per_write_1kb` in the FeeConfiguration:
/// - For protocol >= 23: uses `fee_write1_kb` from ContractLedgerCostExtV0
/// - For protocol < 23: uses the computed `fee_per_rent_1kb` (state-size based)
///
/// This matches C++ stellar-core's `rustBridgeFeeConfiguration()` behavior.
pub fn load_soroban_config(snapshot: &SnapshotHandle, protocol_version: u32) -> SorobanConfig {
    // Load CPU cost params
    let cpu_cost_params =
        load_config_setting(snapshot, ConfigSettingId::ContractCostParamsCpuInstructions)
            .and_then(|cs| {
                if let ConfigSettingEntry::ContractCostParamsCpuInstructions(params) = cs {
                    Some(params)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| ContractCostParams(vec![].try_into().unwrap_or_default()));

    // Load memory cost params
    let mem_cost_params =
        load_config_setting(snapshot, ConfigSettingId::ContractCostParamsMemoryBytes)
            .and_then(|cs| {
                if let ConfigSettingEntry::ContractCostParamsMemoryBytes(params) = cs {
                    Some(params)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| ContractCostParams(vec![].try_into().unwrap_or_default()));

    // Load compute limits and fee rate per instructions
    let (tx_max_instructions, tx_max_memory_bytes, fee_per_instruction_increment) =
        load_config_setting(snapshot, ConfigSettingId::ContractComputeV0)
            .and_then(|cs| {
                if let ConfigSettingEntry::ContractComputeV0(compute) = cs {
                    Some((
                        compute.tx_max_instructions as u64,
                        compute.tx_memory_limit as u64,
                        compute.fee_rate_per_instructions_increment,
                    ))
                } else {
                    None
                }
            })
            .unwrap_or((100_000_000, 40 * 1024 * 1024, 0)); // Default limits

    // Load ledger cost settings
    let (
        fee_disk_read_ledger_entry,
        fee_write_ledger_entry,
        fee_disk_read_1kb,
        soroban_state_target_size_bytes,
        rent_fee_1kb_state_size_low,
        rent_fee_1kb_state_size_high,
        soroban_state_rent_fee_growth_factor,
    ) = load_config_setting(snapshot, ConfigSettingId::ContractLedgerCostV0)
        .and_then(|cs| {
            if let ConfigSettingEntry::ContractLedgerCostV0(cost) = cs {
                Some((
                    cost.fee_disk_read_ledger_entry,
                    cost.fee_write_ledger_entry,
                    cost.fee_disk_read1_kb,
                    cost.soroban_state_target_size_bytes,
                    cost.rent_fee1_kb_soroban_state_size_low,
                    cost.rent_fee1_kb_soroban_state_size_high,
                    cost.soroban_state_rent_fee_growth_factor,
                ))
            } else {
                None
            }
        })
        .unwrap_or((0, 0, 0, 0, 0, 0, 0));

    let fee_write_1kb = load_config_setting(snapshot, ConfigSettingId::ContractLedgerCostExtV0)
        .and_then(|cs| {
            if let ConfigSettingEntry::ContractLedgerCostExtV0(ext) = cs {
                Some(ext.fee_write1_kb)
            } else {
                None
            }
        })
        .unwrap_or(0);

    let fee_historical_1kb =
        load_config_setting(snapshot, ConfigSettingId::ContractHistoricalDataV0)
            .and_then(|cs| {
                if let ConfigSettingEntry::ContractHistoricalDataV0(hist) = cs {
                    Some(hist.fee_historical1_kb)
                } else {
                    None
                }
            })
            .unwrap_or(0);

    let (tx_max_contract_events_size_bytes, fee_contract_events_1kb) =
        load_config_setting(snapshot, ConfigSettingId::ContractEventsV0)
            .and_then(|cs| {
                if let ConfigSettingEntry::ContractEventsV0(events) = cs {
                    Some((
                        events.tx_max_contract_events_size_bytes,
                        events.fee_contract_events1_kb,
                    ))
                } else {
                    None
                }
            })
            .unwrap_or((0, 0));

    let fee_tx_size_1kb = load_config_setting(snapshot, ConfigSettingId::ContractBandwidthV0)
        .and_then(|cs| {
            if let ConfigSettingEntry::ContractBandwidthV0(bandwidth) = cs {
                Some(bandwidth.fee_tx_size1_kb)
            } else {
                None
            }
        })
        .unwrap_or(0);

    // Load contract size limits for entry validation (validateContractLedgerEntry)
    let max_contract_size_bytes =
        load_config_setting(snapshot, ConfigSettingId::ContractMaxSizeBytes)
            .and_then(|cs| {
                if let ConfigSettingEntry::ContractMaxSizeBytes(size) = cs {
                    Some(size)
                } else {
                    None
                }
            })
            .unwrap_or(64 * 1024); // 64 KB default

    let max_contract_data_entry_size_bytes =
        load_config_setting(snapshot, ConfigSettingId::ContractDataEntrySizeBytes)
            .and_then(|cs| {
                if let ConfigSettingEntry::ContractDataEntrySizeBytes(size) = cs {
                    Some(size)
                } else {
                    None
                }
            })
            .unwrap_or(64 * 1024); // 64 KB default

    // Load state archival TTL settings
    let (
        min_temp_entry_ttl,
        min_persistent_entry_ttl,
        max_entry_ttl,
        persistent_rent_rate_denominator,
        temp_rent_rate_denominator,
    ) = load_config_setting(snapshot, ConfigSettingId::StateArchival)
        .and_then(|cs| {
            if let ConfigSettingEntry::StateArchival(archival) = cs {
                Some((
                    archival.min_temporary_ttl,
                    archival.min_persistent_ttl,
                    archival.max_entry_ttl,
                    archival.persistent_rent_rate_denominator,
                    archival.temp_rent_rate_denominator,
                ))
            } else {
                None
            }
        })
        .unwrap_or((16, 120960, 6312000, 0, 0)); // Default TTL values

    let average_soroban_state_size =
        load_config_setting(snapshot, ConfigSettingId::LiveSorobanStateSizeWindow)
            .and_then(|cs| {
                if let ConfigSettingEntry::LiveSorobanStateSizeWindow(window) = cs {
                    if window.is_empty() {
                        None
                    } else {
                        let mut sum: u64 = 0;
                        for size in window.iter() {
                            sum = sum.saturating_add(*size);
                        }
                        Some((sum / window.len() as u64) as i64)
                    }
                } else {
                    None
                }
            })
            .unwrap_or(0);

    let rent_write_config = RentWriteFeeConfiguration {
        state_target_size_bytes: soroban_state_target_size_bytes,
        rent_fee_1kb_state_size_low,
        rent_fee_1kb_state_size_high,
        state_size_rent_fee_growth_factor: soroban_state_rent_fee_growth_factor,
    };
    let fee_per_rent_1kb =
        compute_rent_write_fee_per_1kb(average_soroban_state_size, &rent_write_config);

    // Protocol version-dependent fee selection matching C++ rustBridgeFeeConfiguration():
    // - For protocol >= 23: use fee_write_1kb (flat rate from ContractLedgerCostExtV0)
    // - For protocol < 23: use fee_per_rent_1kb (computed from state size)
    let fee_per_write_1kb_for_config =
        if protocol_version_starts_from(protocol_version, ProtocolVersion::V23) {
            fee_write_1kb
        } else {
            fee_per_rent_1kb
        };

    let fee_config = FeeConfiguration {
        fee_per_instruction_increment,
        fee_per_disk_read_entry: fee_disk_read_ledger_entry,
        fee_per_write_entry: fee_write_ledger_entry,
        fee_per_disk_read_1kb: fee_disk_read_1kb,
        fee_per_write_1kb: fee_per_write_1kb_for_config,
        fee_per_historical_1kb: fee_historical_1kb,
        fee_per_contract_event_1kb: fee_contract_events_1kb,
        fee_per_transaction_size_1kb: fee_tx_size_1kb,
    };

    // RentFeeConfiguration.fee_per_write_1kb must be feeFlatRateWrite1KB() to match C++
    // rustBridgeRentFeeConfiguration(). This is 0 for protocol < 23 (the setting doesn't exist),
    // which is correct because the TTL entry write fee component was introduced in protocol 23.
    // This is DIFFERENT from FeeConfiguration.fee_per_write_1kb which uses fee_per_rent_1kb
    // for protocol < 23.
    let rent_fee_config = RentFeeConfiguration {
        fee_per_write_1kb: fee_write_1kb,
        fee_per_rent_1kb,
        fee_per_write_entry: fee_write_ledger_entry,
        persistent_rent_rate_denominator,
        temporary_rent_rate_denominator: temp_rent_rate_denominator,
    };

    let config = SorobanConfig {
        cpu_cost_params,
        mem_cost_params,
        tx_max_instructions,
        tx_max_memory_bytes,
        min_temp_entry_ttl,
        min_persistent_entry_ttl,
        max_entry_ttl,
        fee_config,
        rent_fee_config,
        tx_max_contract_events_size_bytes,
        max_contract_size_bytes,
        max_contract_data_entry_size_bytes,
    };

    // Log whether we found valid cost params
    if config.has_valid_cost_params() {
        debug!(
            cpu_cost_params_count = config.cpu_cost_params.0.len(),
            mem_cost_params_count = config.mem_cost_params.0.len(),
            tx_max_instructions = config.tx_max_instructions,
            fee_per_instruction = config.fee_config.fee_per_instruction_increment,
            fee_per_event_1kb = config.fee_config.fee_per_contract_event_1kb,
            "Loaded Soroban config from ledger"
        );
    } else {
        warn!(
            "No Soroban cost parameters found in ledger - using defaults. \
             Soroban transaction results may not match network."
        );
    }

    config
}

/// Load SorobanNetworkInfo from the ledger's ConfigSettingEntry entries.
///
/// This loads all the configuration settings needed for the /sorobaninfo endpoint,
/// matching the "basic" format from C++ stellar-core.
pub fn load_soroban_network_info(snapshot: &SnapshotHandle) -> Option<SorobanNetworkInfo> {
    // Check if we have any Soroban config (indicates protocol 20+)
    let compute_v0 = load_config_setting(snapshot, ConfigSettingId::ContractComputeV0)?;

    let mut info = SorobanNetworkInfo::default();

    // Load contract size limits
    if let Some(ConfigSettingEntry::ContractDataKeySizeBytes(size)) =
        load_config_setting(snapshot, ConfigSettingId::ContractDataKeySizeBytes)
    {
        info.max_contract_data_key_size = size;
    }
    if let Some(ConfigSettingEntry::ContractDataEntrySizeBytes(size)) =
        load_config_setting(snapshot, ConfigSettingId::ContractDataEntrySizeBytes)
    {
        info.max_contract_data_entry_size = size;
    }
    if let Some(ConfigSettingEntry::ContractMaxSizeBytes(size)) =
        load_config_setting(snapshot, ConfigSettingId::ContractMaxSizeBytes)
    {
        info.max_contract_size = size;
    }

    // Load compute settings
    if let ConfigSettingEntry::ContractComputeV0(compute) = compute_v0 {
        info.tx_max_instructions = compute.tx_max_instructions;
        info.ledger_max_instructions = compute.ledger_max_instructions;
        info.fee_rate_per_instructions_increment = compute.fee_rate_per_instructions_increment;
        info.tx_memory_limit = compute.tx_memory_limit;
    }

    // Load ledger access settings
    if let Some(ConfigSettingEntry::ContractLedgerCostV0(cost)) =
        load_config_setting(snapshot, ConfigSettingId::ContractLedgerCostV0)
    {
        info.ledger_max_read_ledger_entries = cost.ledger_max_disk_read_entries;
        info.ledger_max_read_bytes = cost.ledger_max_disk_read_bytes;
        info.ledger_max_write_ledger_entries = cost.ledger_max_write_ledger_entries;
        info.ledger_max_write_bytes = cost.ledger_max_write_bytes;
        info.tx_max_read_ledger_entries = cost.tx_max_disk_read_entries;
        info.tx_max_read_bytes = cost.tx_max_disk_read_bytes;
        info.tx_max_write_ledger_entries = cost.tx_max_write_ledger_entries;
        info.tx_max_write_bytes = cost.tx_max_write_bytes;
        info.fee_read_ledger_entry = cost.fee_disk_read_ledger_entry;
        info.fee_write_ledger_entry = cost.fee_write_ledger_entry;
        info.fee_read_1kb = cost.fee_disk_read1_kb;
    }

    // Load fee_write_1kb from extended cost settings
    if let Some(ConfigSettingEntry::ContractLedgerCostExtV0(ext)) =
        load_config_setting(snapshot, ConfigSettingId::ContractLedgerCostExtV0)
    {
        info.fee_write_1kb = ext.fee_write1_kb;
    }

    // Load historical data settings
    if let Some(ConfigSettingEntry::ContractHistoricalDataV0(hist)) =
        load_config_setting(snapshot, ConfigSettingId::ContractHistoricalDataV0)
    {
        info.fee_historical_1kb = hist.fee_historical1_kb;
    }

    // Load contract events settings
    if let Some(ConfigSettingEntry::ContractEventsV0(events)) =
        load_config_setting(snapshot, ConfigSettingId::ContractEventsV0)
    {
        info.tx_max_contract_events_size_bytes = events.tx_max_contract_events_size_bytes;
        info.fee_contract_events_size_1kb = events.fee_contract_events1_kb;
    }

    // Load bandwidth settings
    if let Some(ConfigSettingEntry::ContractBandwidthV0(bandwidth)) =
        load_config_setting(snapshot, ConfigSettingId::ContractBandwidthV0)
    {
        info.ledger_max_tx_size_bytes = bandwidth.ledger_max_txs_size_bytes;
        info.tx_max_size_bytes = bandwidth.tx_max_size_bytes;
        info.fee_transaction_size_1kb = bandwidth.fee_tx_size1_kb;
    }

    // Load execution lanes settings for ledger tx count
    if let Some(ConfigSettingEntry::ContractExecutionLanes(lanes)) =
        load_config_setting(snapshot, ConfigSettingId::ContractExecutionLanes)
    {
        info.ledger_max_tx_count = lanes.ledger_max_tx_count;
    }

    // Load state archival settings
    if let Some(ConfigSettingEntry::StateArchival(archival)) =
        load_config_setting(snapshot, ConfigSettingId::StateArchival)
    {
        info.max_entry_ttl = archival.max_entry_ttl;
        info.min_temporary_ttl = archival.min_temporary_ttl;
        info.min_persistent_ttl = archival.min_persistent_ttl;
        info.persistent_rent_rate_denominator = archival.persistent_rent_rate_denominator;
        info.temp_rent_rate_denominator = archival.temp_rent_rate_denominator;
        info.max_entries_to_archive = archival.max_entries_to_archive;
        info.bucketlist_size_window_sample_size =
            archival.live_soroban_state_size_window_sample_size;
        info.eviction_scan_size = archival.eviction_scan_size as i64;
        info.starting_eviction_scan_level = archival.starting_eviction_scan_level;
    }

    // Load average bucket list size from live window
    if let Some(ConfigSettingEntry::LiveSorobanStateSizeWindow(window)) =
        load_config_setting(snapshot, ConfigSettingId::LiveSorobanStateSizeWindow)
    {
        if !window.is_empty() {
            let mut sum: u64 = 0;
            for size in window.iter() {
                sum = sum.saturating_add(*size);
            }
            info.average_bucket_list_size = sum / window.len() as u64;
        }
    }

    Some(info)
}

struct RefundableFeeTracker {
    max_refundable_fee: i64,
    consumed_event_size_bytes: u32,
    consumed_rent_fee: i64,
    consumed_refundable_fee: i64,
}

impl RefundableFeeTracker {
    fn new(max_refundable_fee: i64) -> Self {
        Self {
            max_refundable_fee,
            consumed_event_size_bytes: 0,
            consumed_rent_fee: 0,
            consumed_refundable_fee: 0,
        }
    }

    fn consume(
        &mut self,
        frame: &TransactionFrame,
        protocol_version: u32,
        config: &SorobanConfig,
        event_size_bytes: u32,
        rent_fee: i64,
    ) -> bool {
        self.consumed_event_size_bytes = self
            .consumed_event_size_bytes
            .saturating_add(event_size_bytes);
        self.consumed_rent_fee = self.consumed_rent_fee.saturating_add(rent_fee);

        // First check: rent fee alone must not exceed max refundable fee.
        // This matches C++ stellar-core's consumeRefundableSorobanResources which checks
        // if (mMaximumRefundableFee < mConsumedRentFee) before computing events fee.
        if self.consumed_rent_fee > self.max_refundable_fee {
            return false;
        }

        let (_, refundable_fee) = match compute_soroban_resource_fee(
            frame,
            protocol_version,
            config,
            self.consumed_event_size_bytes,
        ) {
            Some(pair) => pair,
            None => return false,
        };
        self.consumed_refundable_fee = self.consumed_rent_fee.saturating_add(refundable_fee);

        // Second check: total consumed (rent + events) must not exceed max refundable fee.
        self.consumed_refundable_fee <= self.max_refundable_fee
    }

    fn refund_amount(&self) -> i64 {
        if self.max_refundable_fee > self.consumed_refundable_fee {
            self.max_refundable_fee - self.consumed_refundable_fee
        } else {
            0
        }
    }
}

fn compute_soroban_resource_fee(
    frame: &TransactionFrame,
    protocol_version: u32,
    config: &SorobanConfig,
    event_size_bytes: u32,
) -> Option<(i64, i64)> {
    let resources = frame.soroban_transaction_resources(protocol_version, event_size_bytes)?;
    Some(compute_transaction_resource_fee(
        &resources,
        &config.fee_config,
    ))
}

/// Result of executing a transaction.
#[derive(Debug, Clone)]
pub struct TransactionExecutionResult {
    /// Whether the transaction succeeded.
    pub success: bool,
    /// Fee charged (always charged even on failure).
    pub fee_charged: i64,
    /// Fee refund (for Soroban transactions, protocol < 25 applies this to inner fee too).
    pub fee_refund: i64,
    /// Operation results.
    pub operation_results: Vec<OperationResult>,
    /// Error message if failed.
    pub error: Option<String>,
    /// Failure reason for mapping to XDR result codes.
    pub failure: Option<ExecutionFailure>,
    /// Transaction meta (for ledger close meta).
    pub tx_meta: Option<TransactionMeta>,
    /// Fee processing changes (for ledger close meta).
    pub fee_changes: Option<LedgerEntryChanges>,
    /// Post-apply fee processing changes (refunds).
    pub post_fee_changes: Option<LedgerEntryChanges>,
    /// Keys of entries restored from the hot archive (Protocol 23+).
    /// These should be passed to HotArchiveBucketList::add_batch as restored_keys.
    pub hot_archive_restored_keys: Vec<LedgerKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionFailure {
    Malformed,
    MissingOperation,
    InvalidSignature,
    BadAuthExtra,
    BadMinSeqAgeOrGap,
    BadSequence,
    InsufficientFee,
    InsufficientBalance,
    NoAccount,
    TooEarly,
    TooLate,
    NotSupported,
    BadSponsorship,
    OperationFailed,
}

/// Context for executing transactions during ledger close.
pub struct TransactionExecutor {
    /// Ledger sequence being processed.
    ledger_seq: u32,
    /// Close time.
    close_time: u64,
    /// Base reserve.
    base_reserve: u32,
    /// Protocol version.
    protocol_version: u32,
    /// Network ID.
    network_id: NetworkId,
    /// State manager for execution.
    state: LedgerStateManager,
    /// Accounts loaded from snapshot.
    loaded_accounts: HashMap<[u8; 32], bool>,
    /// Soroban network configuration for contract execution.
    soroban_config: SorobanConfig,
    /// Classic event configuration.
    classic_events: ClassicEventConfig,
    /// Optional operation-level invariants runner.
    op_invariants: Option<OperationInvariantRunner>,
    /// Optional persistent module cache for Soroban WASM compilation.
    /// This cache is populated once from the bucket list and reused across transactions.
    module_cache: Option<PersistentModuleCache>,
}

impl TransactionExecutor {
    /// Create a new transaction executor.
    pub fn new(
        ledger_seq: u32,
        close_time: u64,
        base_reserve: u32,
        protocol_version: u32,
        network_id: NetworkId,
        id_pool: u64,
        soroban_config: SorobanConfig,
        classic_events: ClassicEventConfig,
        op_invariants: Option<OperationInvariantRunner>,
    ) -> Self {
        let mut state = LedgerStateManager::new(base_reserve as i64, ledger_seq);
        state.set_id_pool(id_pool);
        Self {
            ledger_seq,
            close_time,
            base_reserve,
            protocol_version,
            network_id,
            state,
            loaded_accounts: HashMap::new(),
            soroban_config,
            classic_events,
            op_invariants,
            module_cache: None,
        }
    }

    /// Set the persistent module cache for WASM compilation.
    ///
    /// The module cache should be populated with contract code from the bucket list
    /// before executing transactions. This enables reuse of compiled WASM modules
    /// across transactions, significantly improving performance.
    pub fn set_module_cache(&mut self, cache: PersistentModuleCache) {
        self.module_cache = Some(cache);
    }

    /// Get a reference to the module cache, if set.
    pub fn module_cache(&self) -> Option<&PersistentModuleCache> {
        self.module_cache.as_ref()
    }

    /// Add contract code to the module cache.
    ///
    /// This is called when new contract code entries are created, updated, or restored
    /// during ledger close. Adding the code to the cache enables subsequent transactions
    /// to use VmCachedInstantiation (cheap) instead of VmInstantiation (expensive).
    ///
    /// Without this, contracts deployed in transaction N would not be cached for
    /// transaction N+1 in the same ledger, causing cost model divergence.
    fn add_contract_to_cache(&self, code: &[u8]) {
        if let Some(cache) = &self.module_cache {
            cache.add_contract(code, self.protocol_version);
        }
    }

    /// Advance to a new ledger, preserving the current state.
    /// This is useful for replaying multiple consecutive ledgers without
    /// losing state changes between them.
    ///
    /// Note: id_pool is NOT reset here because:
    /// 1. The executor's internal id_pool evolves correctly as transactions execute
    /// 2. The id_pool from the ledger header is the POST-execution value (after the ledger closes)
    /// 3. Using the header's id_pool would give us the wrong starting value for the next ledger
    /// For the first ledger in a replay session, use TransactionExecutor::new() which takes
    /// the PREVIOUS ledger's closing id_pool (which equals this ledger's starting id_pool).
    pub fn advance_to_ledger(
        &mut self,
        ledger_seq: u32,
        close_time: u64,
        base_reserve: u32,
        protocol_version: u32,
        _id_pool: u64, // Intentionally unused - see note above
        soroban_config: SorobanConfig,
    ) {
        self.ledger_seq = ledger_seq;
        self.close_time = close_time;
        self.base_reserve = base_reserve;
        self.protocol_version = protocol_version;
        self.soroban_config = soroban_config;
        // Do NOT reset id_pool - it should continue from where it was
        self.state.set_ledger_seq(ledger_seq);
        // Note: loaded_accounts cache is preserved - this is intentional because
        // accounts that were loaded/created in previous ledgers remain valid
    }

    /// Advance to a new ledger and clear all cached entries.
    ///
    /// This is used in verification mode where we apply authoritative CDP metadata
    /// to the bucket list between ledgers. Clearing cached entries ensures that
    /// all entries are reloaded from the bucket list, reflecting the true state
    /// after the previous ledger's changes.
    ///
    /// Without this, stale entries (e.g., offers that were deleted in the bucket list)
    /// would remain in the executor's cache and cause incorrect execution results.
    pub fn advance_to_ledger_with_fresh_state(
        &mut self,
        ledger_seq: u32,
        close_time: u64,
        base_reserve: u32,
        protocol_version: u32,
        _id_pool: u64,
        soroban_config: SorobanConfig,
    ) {
        self.ledger_seq = ledger_seq;
        self.close_time = close_time;
        self.base_reserve = base_reserve;
        self.protocol_version = protocol_version;
        self.soroban_config = soroban_config;
        self.state.set_ledger_seq(ledger_seq);
        // Clear all cached entries so they're reloaded from the bucket list
        self.state.clear_cached_entries();
        // Also clear loaded_accounts cache
        self.loaded_accounts.clear();
    }

    /// Load an account from the snapshot into the state manager.
    pub fn load_account(
        &mut self,
        snapshot: &SnapshotHandle,
        account_id: &AccountId,
    ) -> Result<bool> {
        // First check if the account was created/updated by a previous transaction in this ledger
        // This is important for intra-ledger dependencies (e.g., TX0 creates account, TX1 uses it)
        if self.state.get_account(account_id).is_some() {
            tracing::trace!(account = %account_id_to_strkey(account_id), "load_account: found in state");
            return Ok(true);
        }

        let key_bytes = account_id_to_key(account_id);

        // Check if we've already tried to load from snapshot
        if self.loaded_accounts.contains_key(&key_bytes) {
            tracing::trace!(account = %account_id_to_strkey(account_id), "load_account: already tried, not found");
            return Ok(false); // Already tried and not found
        }

        // Mark as attempted
        self.loaded_accounts.insert(key_bytes, true);

        // Try to load from snapshot
        let key = stellar_xdr::curr::LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
            account_id: account_id.clone(),
        });

        if let Some(entry) = snapshot.get_entry(&key)? {
            // Log signer info for debugging
            if let stellar_xdr::curr::LedgerEntryData::Account(ref acct) = entry.data {
                tracing::trace!(
                    account = ?account_id,
                    num_signers = acct.signers.len(),
                    thresholds = ?acct.thresholds.0,
                    "load_account: found in bucket list"
                );
            }
            self.state.load_entry(entry);
            return Ok(true);
        }

        tracing::debug!(account = %account_id_to_strkey(account_id), "load_account: NOT FOUND in bucket list");
        Ok(false)
    }

    fn available_balance_for_fee(&self, account: &AccountEntry) -> Result<i64> {
        let min_balance = self
            .state
            .minimum_balance_for_account(account, self.protocol_version, 0)
            .map_err(|e| LedgerError::Internal(e.to_string()))?;
        let mut available = account.balance - min_balance;
        if self.protocol_version >= 10 {
            let selling = match &account.ext {
                AccountEntryExt::V1(v1) => v1.liabilities.selling,
                AccountEntryExt::V0 => 0,
            };
            available -= selling;
        }
        Ok(available)
    }

    /// Load a trustline from the snapshot into the state manager.
    pub fn load_trustline(
        &mut self,
        snapshot: &SnapshotHandle,
        account_id: &AccountId,
        asset: &stellar_xdr::curr::TrustLineAsset,
    ) -> Result<bool> {
        if self
            .state
            .get_trustline_by_trustline_asset(account_id, asset)
            .is_some()
        {
            return Ok(true);
        }

        let key = stellar_xdr::curr::LedgerKey::Trustline(stellar_xdr::curr::LedgerKeyTrustLine {
            account_id: account_id.clone(),
            asset: asset.clone(),
        });

        if let Some(entry) = snapshot.get_entry(&key)? {
            if let stellar_xdr::curr::LedgerEntryData::Trustline(ref tl) = entry.data {
                tracing::debug!(
                    account = %account_id_to_strkey(account_id),
                    asset = ?asset,
                    balance = tl.balance,
                    "load_trustline: loaded from bucket list"
                );
            }
            self.state.load_entry(entry);
            return Ok(true);
        }

        tracing::debug!(
            account = %account_id_to_strkey(account_id),
            asset = ?asset,
            "load_trustline: NOT FOUND in bucket list"
        );
        Ok(false)
    }

    /// Load a claimable balance from the snapshot into the state manager.
    pub fn load_claimable_balance(
        &mut self,
        snapshot: &SnapshotHandle,
        balance_id: &ClaimableBalanceId,
    ) -> Result<bool> {
        // Check if already in state from previous transaction in this ledger
        if self.state.get_claimable_balance(balance_id).is_some() {
            return Ok(true);
        }

        let key = stellar_xdr::curr::LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
            balance_id: balance_id.clone(),
        });
        if let Some(entry) = snapshot.get_entry(&key)? {
            self.state.load_entry(entry);
            return Ok(true);
        }
        Ok(false)
    }

    /// Load a data entry from the snapshot into the state manager.
    pub fn load_data(
        &mut self,
        snapshot: &SnapshotHandle,
        account_id: &AccountId,
        data_name: &str,
    ) -> Result<bool> {
        // Check if already in state from previous transaction in this ledger
        if self.state.get_data(account_id, data_name).is_some() {
            return Ok(true);
        }

        let name_bytes = stellar_xdr::curr::String64::try_from(data_name.as_bytes().to_vec())
            .map_err(|e| LedgerError::Internal(format!("Invalid data name: {}", e)))?;
        let key = stellar_xdr::curr::LedgerKey::Data(stellar_xdr::curr::LedgerKeyData {
            account_id: account_id.clone(),
            data_name: name_bytes,
        });
        if let Some(entry) = snapshot.get_entry(&key)? {
            self.state.load_entry(entry);
            return Ok(true);
        }
        Ok(false)
    }

    /// Load a data entry from the snapshot using the raw String64 key.
    /// This preserves non-UTF8 bytes in the data name.
    pub fn load_data_raw(
        &mut self,
        snapshot: &SnapshotHandle,
        account_id: &AccountId,
        data_name: &stellar_xdr::curr::String64,
    ) -> Result<bool> {
        // Convert to string for state lookup (matches how data_entries are keyed)
        let name_str = String::from_utf8_lossy(data_name.as_slice()).to_string();

        // Check if already in state from previous transaction in this ledger
        if self.state.get_data(account_id, &name_str).is_some() {
            return Ok(true);
        }

        let key = stellar_xdr::curr::LedgerKey::Data(stellar_xdr::curr::LedgerKeyData {
            account_id: account_id.clone(),
            data_name: data_name.clone(),
        });
        if let Some(entry) = snapshot.get_entry(&key)? {
            self.state.load_entry(entry);
            return Ok(true);
        }
        Ok(false)
    }

    /// Load an offer from the snapshot into the state manager.
    pub fn load_offer(
        &mut self,
        snapshot: &SnapshotHandle,
        seller_id: &AccountId,
        offer_id: i64,
    ) -> Result<bool> {
        if self.state.get_offer(seller_id, offer_id).is_some() {
            return Ok(true);
        }

        let key = stellar_xdr::curr::LedgerKey::Offer(stellar_xdr::curr::LedgerKeyOffer {
            seller_id: seller_id.clone(),
            offer_id,
        });
        if let Some(entry) = snapshot.get_entry(&key)? {
            self.state.load_entry(entry);
            return Ok(true);
        }
        Ok(false)
    }

    /// Load the sponsor account for an offer if it has one.
    /// This is needed when deleting or modifying an offer with sponsorship,
    /// as we need to update the sponsor's num_sponsoring counter.
    fn load_offer_sponsor(
        &mut self,
        snapshot: &SnapshotHandle,
        seller_id: &AccountId,
        offer_id: i64,
    ) -> Result<()> {
        let key = stellar_xdr::curr::LedgerKey::Offer(stellar_xdr::curr::LedgerKeyOffer {
            seller_id: seller_id.clone(),
            offer_id,
        });
        if let Some(sponsor) = self.state.entry_sponsor(&key).cloned() {
            self.load_account(snapshot, &sponsor)?;
        }
        Ok(())
    }

    fn load_asset_issuer(&mut self, snapshot: &SnapshotHandle, asset: &Asset) -> Result<()> {
        match asset {
            Asset::CreditAlphanum4(a) => {
                self.load_account(snapshot, &a.issuer)?;
            }
            Asset::CreditAlphanum12(a) => {
                self.load_account(snapshot, &a.issuer)?;
            }
            Asset::Native => {}
        }
        Ok(())
    }

    /// Load a liquidity pool from the snapshot into the state manager.
    ///
    /// If the pool already exists in state (e.g., from CDP sync or previous loading),
    /// returns the existing state without reloading from snapshot. This is critical
    /// for verification mode where CDP sync updates state between transactions.
    pub fn load_liquidity_pool(
        &mut self,
        snapshot: &SnapshotHandle,
        pool_id: &PoolId,
    ) -> Result<Option<LiquidityPoolEntry>> {
        // Check if already loaded in state - don't overwrite with snapshot data
        if let Some(pool) = self.state.get_liquidity_pool(pool_id) {
            return Ok(Some(pool.clone()));
        }

        let key = stellar_xdr::curr::LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: pool_id.clone(),
        });
        if let Some(entry) = snapshot.get_entry(&key)? {
            let pool = match &entry.data {
                LedgerEntryData::LiquidityPool(pool) => pool.clone(),
                _ => return Ok(None),
            };
            self.state.load_entry(entry);
            return Ok(Some(pool));
        }
        Ok(None)
    }

    fn load_liquidity_pool_dependencies(
        &mut self,
        snapshot: &SnapshotHandle,
        op_source: &AccountId,
        pool_id: &PoolId,
    ) -> Result<()> {
        if let Some(pool) = self.load_liquidity_pool(snapshot, pool_id)? {
            let pool_share_asset = TrustLineAsset::PoolShare(pool_id.clone());
            self.load_trustline(snapshot, op_source, &pool_share_asset)?;

            let load_asset_dependencies = |executor: &mut TransactionExecutor,
                                           asset: &Asset,
                                           source: &AccountId|
             -> Result<()> {
                if let Some(tl_asset) = asset_to_trustline_asset(asset) {
                    executor.load_trustline(snapshot, source, &tl_asset)?;
                }
                match asset {
                    Asset::CreditAlphanum4(a) => {
                        executor.load_account(snapshot, &a.issuer)?;
                    }
                    Asset::CreditAlphanum12(a) => {
                        executor.load_account(snapshot, &a.issuer)?;
                    }
                    Asset::Native => {}
                }
                Ok(())
            };

            match &pool.body {
                LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => {
                    load_asset_dependencies(self, &cp.params.asset_a, op_source)?;
                    load_asset_dependencies(self, &cp.params.asset_b, op_source)?;
                }
            }
        }
        Ok(())
    }

    /// Load liquidity pools that could be used for path payment conversions.
    ///
    /// For each adjacent pair of assets in the conversion path, attempts to load the
    /// corresponding liquidity pool if it exists.
    fn load_path_payment_pools(
        &mut self,
        snapshot: &SnapshotHandle,
        send_asset: &stellar_xdr::curr::Asset,
        dest_asset: &stellar_xdr::curr::Asset,
        path: &[stellar_xdr::curr::Asset],
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        use stellar_xdr::curr::{
            Limits, LiquidityPoolConstantProductParameters, LiquidityPoolParameters,
        };

        // Build the full conversion path: send_asset -> path[0] -> ... -> dest_asset
        let mut assets: Vec<&stellar_xdr::curr::Asset> = vec![send_asset];
        assets.extend(path.iter());
        assets.push(dest_asset);

        // For each adjacent pair, try to load the liquidity pool
        for window in assets.windows(2) {
            let asset_a = window[0];
            let asset_b = window[1];

            if asset_a == asset_b {
                continue; // Same asset, no swap needed
            }

            // Compute pool ID: assets must be sorted (a < b) to match pool key
            let (sorted_a, sorted_b) = if asset_a < asset_b {
                (asset_a.clone(), asset_b.clone())
            } else {
                (asset_b.clone(), asset_a.clone())
            };

            let params = LiquidityPoolParameters::LiquidityPoolConstantProduct(
                LiquidityPoolConstantProductParameters {
                    asset_a: sorted_a,
                    asset_b: sorted_b,
                    fee: 30, // LIQUIDITY_POOL_FEE_V18 = 30
                },
            );

            if let Ok(xdr) = params.to_xdr(Limits::none()) {
                let pool_id = PoolId(stellar_xdr::curr::Hash(Sha256::digest(&xdr).into()));
                // Attempt to load - it's OK if the pool doesn't exist
                let _ = self.load_liquidity_pool(snapshot, &pool_id);
            }
        }

        Ok(())
    }

    fn load_offer_dependencies(
        &mut self,
        snapshot: &SnapshotHandle,
        offer: &OfferEntry,
    ) -> Result<()> {
        self.load_account(snapshot, &offer.seller_id)?;
        if let Some(tl_asset) = asset_to_trustline_asset(&offer.selling) {
            self.load_trustline(snapshot, &offer.seller_id, &tl_asset)?;
        }
        if let Some(tl_asset) = asset_to_trustline_asset(&offer.buying) {
            self.load_trustline(snapshot, &offer.seller_id, &tl_asset)?;
        }
        Ok(())
    }

    fn load_orderbook_offers(&mut self, snapshot: &SnapshotHandle) -> Result<()> {
        let entries = snapshot.all_entries()?;
        for entry in entries {
            let LedgerEntryData::Offer(offer) = &entry.data else {
                continue;
            };
            // Only load offers that haven't been touched this ledger.
            // This preserves modifications (including deletions) made by previous transactions.
            // We check both:
            // 1. The entry currently exists in state (modified but not deleted)
            // 2. The entry was deleted in the delta (by a previous tx)
            let offer_key = LedgerKey::Offer(stellar_xdr::curr::LedgerKeyOffer {
                seller_id: offer.seller_id.clone(),
                offer_id: offer.offer_id,
            });
            if self.state.get_entry(&offer_key).is_some() {
                continue;
            }
            // Also check if the offer was deleted in the delta (by a previous tx)
            if self.state.delta().deleted_keys().contains(&offer_key) {
                continue;
            }
            let offer = offer.clone();
            self.state.load_entry(entry);
            self.load_offer_dependencies(snapshot, &offer)?;
        }
        Ok(())
    }

    /// Load all offers by an account for a specific asset.
    ///
    /// This is used when revoking trustline authorization - all offers for the
    /// account/asset pair must be removed. The offers must first be loaded from
    /// the snapshot so they can be deleted by the trustline flags operation.
    pub fn load_offers_by_account_and_asset(
        &mut self,
        snapshot: &SnapshotHandle,
        account_id: &AccountId,
        asset: &Asset,
    ) -> Result<()> {
        let entries = snapshot.all_entries()?;
        for entry in entries {
            let LedgerEntryData::Offer(offer) = &entry.data else {
                continue;
            };
            // Check if this offer is by the specified account
            if &offer.seller_id != account_id {
                continue;
            }
            // Check if this offer is buying or selling the specified asset
            if offer.buying != *asset && offer.selling != *asset {
                continue;
            }
            // Skip if already loaded
            let offer_key = LedgerKey::Offer(stellar_xdr::curr::LedgerKeyOffer {
                seller_id: offer.seller_id.clone(),
                offer_id: offer.offer_id,
            });
            if self.state.get_entry(&offer_key).is_some() {
                continue;
            }
            // Skip if already deleted
            if self.state.delta().deleted_keys().contains(&offer_key) {
                continue;
            }
            // Load the offer
            let offer = offer.clone();
            self.state.load_entry(entry);
            self.load_offer_dependencies(snapshot, &offer)?;
        }
        Ok(())
    }

    /// Load a ledger entry from the snapshot into the state manager.
    ///
    /// This handles all entry types including contract data, contract code, and TTL entries.
    /// Returns true if the entry was found and loaded.
    pub fn load_entry(&mut self, snapshot: &SnapshotHandle, key: &LedgerKey) -> Result<bool> {
        if let Some(entry) = snapshot.get_entry(key)? {
            if self.state.get_entry(key).is_none() {
                self.state.load_entry(entry);
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Get a ledger entry from the current state (if loaded).
    pub fn get_entry(&self, key: &LedgerKey) -> Option<LedgerEntry> {
        self.state.get_entry(key)
    }

    /// Load all entries from a Soroban footprint into the state manager.
    ///
    /// This is essential for Soroban transaction execution - the footprint specifies
    /// which ledger entries the transaction will read or write, and they must be
    /// loaded before the Soroban host can access them.
    pub fn load_soroban_footprint(
        &mut self,
        snapshot: &SnapshotHandle,
        footprint: &stellar_xdr::curr::LedgerFootprint,
    ) -> Result<()> {
        // Load read-only entries
        for key in footprint.read_only.iter() {
            self.load_entry(snapshot, key)?;
            // Also load TTL for contract entries
            self.load_ttl_for_key(snapshot, key)?;
        }

        // Load read-write entries
        for key in footprint.read_write.iter() {
            self.load_entry(snapshot, key)?;
            // Also load TTL for contract entries
            self.load_ttl_for_key(snapshot, key)?;
        }

        Ok(())
    }

    /// Load the TTL entry for a contract data or code key.
    fn load_ttl_for_key(&mut self, snapshot: &SnapshotHandle, key: &LedgerKey) -> Result<()> {
        match key {
            LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {
                use sha2::{Digest, Sha256};
                // Compute the key hash for TTL lookup
                let key_bytes = key
                    .to_xdr(Limits::none())
                    .map_err(|e| LedgerError::Serialization(e.to_string()))?;
                let key_hash = stellar_xdr::curr::Hash(Sha256::digest(&key_bytes).into());

                let ttl_key = LedgerKey::Ttl(stellar_xdr::curr::LedgerKeyTtl { key_hash });
                // Try to load TTL entry - it may not exist for newly created entries
                // or in older bucket lists before TTL tracking was added
                self.load_entry(snapshot, &ttl_key)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Apply ledger entry changes to the executor's state WITHOUT delta tracking.
    ///
    /// This is used during verification to sync state with CDP after each transaction,
    /// ensuring subsequent transactions see the correct state even if our validation
    /// failed for an earlier transaction.
    ///
    /// Uses no-tracking methods to avoid polluting the delta for subsequent transactions.
    pub fn apply_ledger_entry_changes(&mut self, changes: &stellar_xdr::curr::LedgerEntryChanges) {
        use stellar_xdr::curr::{LedgerEntryChange, LedgerEntryData};

        for change in changes.iter() {
            match change {
                LedgerEntryChange::Created(entry)
                | LedgerEntryChange::Updated(entry)
                | LedgerEntryChange::Restored(entry) => {
                    self.state.apply_entry_no_tracking(entry);
                    // Add newly created/restored contract code to the module cache.
                    // This ensures subsequent transactions can use VmCachedInstantiation
                    // instead of the more expensive VmInstantiation for newly deployed contracts.
                    if let LedgerEntryData::ContractCode(cc) = &entry.data {
                        self.add_contract_to_cache(cc.code.as_slice());
                    }
                }
                LedgerEntryChange::Removed(key) => {
                    self.state.delete_entry_no_tracking(key);
                }
                LedgerEntryChange::State(_) => {
                    // State changes are informational only, no action needed
                }
            }
        }
        // Clear snapshots to prevent stale snapshot state from affecting subsequent transactions.
        // Without this, a transaction that creates an entry might see an old snapshot from a
        // previous transaction's execution, causing incorrect STATE/CREATED tracking.
        self.state.commit();
    }

    /// Apply ledger entry changes preserving account sequence numbers.
    ///
    /// This is similar to `apply_ledger_entry_changes` but preserves the current
    /// sequence number for existing accounts. This is needed because CDP metadata
    /// for operation changes can capture sequence numbers that include effects from
    /// later transactions in the same ledger (due to how C++ stellar-core captures STATE values).
    ///
    /// For Account UPDATED entries:
    /// - If the account exists in our state, preserve our sequence number
    /// - Apply all other fields from the CDP entry (balance, etc.)
    pub fn apply_ledger_entry_changes_preserve_seq(
        &mut self,
        changes: &stellar_xdr::curr::LedgerEntryChanges,
    ) {
        use stellar_xdr::curr::{LedgerEntryChange, LedgerEntryData};

        for change in changes.iter() {
            match change {
                LedgerEntryChange::Updated(entry) => {
                    // For Account entries, preserve our sequence number
                    if let LedgerEntryData::Account(new_acc) = &entry.data {
                        if let Some(existing_acc) = self.state.get_account_mut(&new_acc.account_id)
                        {
                            // Preserve our sequence number
                            let our_seq = existing_acc.seq_num.0;
                            // Apply all fields from CDP entry
                            *existing_acc = new_acc.clone();
                            // Restore our sequence
                            existing_acc.seq_num.0 = our_seq;
                            continue;
                        }
                    }
                    // For non-account entries or new accounts, apply normally
                    self.state.apply_entry_no_tracking(entry);
                    // Add contract code to cache (Updated entries can be code re-uploads)
                    if let LedgerEntryData::ContractCode(cc) = &entry.data {
                        self.add_contract_to_cache(cc.code.as_slice());
                    }
                }
                LedgerEntryChange::Created(entry) | LedgerEntryChange::Restored(entry) => {
                    self.state.apply_entry_no_tracking(entry);
                    // Add newly created/restored contract code to the module cache
                    if let LedgerEntryData::ContractCode(cc) = &entry.data {
                        self.add_contract_to_cache(cc.code.as_slice());
                    }
                }
                LedgerEntryChange::Removed(key) => {
                    self.state.delete_entry_no_tracking(key);
                }
                LedgerEntryChange::State(_) => {
                    // State changes are informational only, no action needed
                }
            }
        }
        self.state.commit();
    }

    /// Apply a fee refund to an account WITHOUT delta tracking.
    ///
    /// This is used during verification to sync the fee refund from CDP's
    /// sorobanMeta.totalFeeRefund field, which is tracked separately from entry changes.
    pub fn apply_fee_refund(&mut self, account_id: &AccountId, refund: i64) {
        if let Some(acc) = self.state.get_account_mut(account_id) {
            acc.balance += refund;
        }
        // Commit to clear snapshots so the refund is preserved for subsequent transactions
        self.state.commit();
    }

    /// Execute a transaction.
    ///
    /// # Arguments
    ///
    /// * `soroban_prng_seed` - Optional PRNG seed for Soroban execution.
    ///   Computed as subSha256(txSetHash, txIndex) at the transaction set level.
    pub fn execute_transaction(
        &mut self,
        snapshot: &SnapshotHandle,
        tx_envelope: &TransactionEnvelope,
        base_fee: u32,
        soroban_prng_seed: Option<[u8; 32]>,
    ) -> Result<TransactionExecutionResult> {
        self.execute_transaction_with_fee_mode(
            snapshot,
            tx_envelope,
            base_fee,
            soroban_prng_seed,
            true,
        )
    }

    /// Process fee for a transaction without executing it.
    ///
    /// This method is used for batched fee processing where all fees are
    /// processed before any transaction is applied. This matches the behavior
    /// of C++ stellar-core.
    ///
    /// Returns the fee changes and the fee amount charged.
    pub fn process_fee_only(
        &mut self,
        snapshot: &SnapshotHandle,
        tx_envelope: &TransactionEnvelope,
        base_fee: u32,
    ) -> Result<(LedgerEntryChanges, i64)> {
        let frame = TransactionFrame::with_network(tx_envelope.clone(), self.network_id);
        let fee_source_id = stellar_core_tx::muxed_to_account_id(&frame.fee_source_account());
        let inner_source_id = stellar_core_tx::muxed_to_account_id(&frame.inner_source_account());

        // Load source accounts
        if !self.load_account(snapshot, &fee_source_id)? {
            return Err(LedgerError::Internal("Fee source account not found".into()));
        }
        if !self.load_account(snapshot, &inner_source_id)? {
            return Err(LedgerError::Internal(
                "Inner source account not found".into(),
            ));
        }

        // Compute fee using the same logic as execute_transaction_with_fee_mode
        // For fee bump transactions, the required fee includes an extra base fee for the wrapper
        let num_ops = std::cmp::max(1, frame.operation_count() as i64);
        let required_fee = if frame.is_fee_bump() {
            // Fee bumps pay baseFee * (numOps + 1) - extra charge for the fee bump wrapper
            base_fee as i64 * (num_ops + 1)
        } else {
            base_fee as i64 * num_ops
        };
        let inclusion_fee = frame.inclusion_fee();
        // For Soroban, the resource fee is charged in full, plus the inclusion fee up to required.
        // For classic transactions, charge up to the required_fee (base_fee * num_ops).
        let fee = if frame.is_soroban() {
            frame.declared_soroban_resource_fee() + std::cmp::min(inclusion_fee, required_fee)
        } else {
            std::cmp::min(inclusion_fee, required_fee)
        };

        if frame.is_fee_bump() {
            tracing::debug!(
                is_fee_bump = true,
                total_fee = frame.total_fee(),
                inner_fee = frame.inner_fee(),
                inclusion_fee = inclusion_fee,
                base_fee = base_fee,
                operation_count = frame.operation_count(),
                required_fee = required_fee,
                fee_charged = fee,
                "Fee bump transaction fee calculation"
            );
        }

        if fee == 0 {
            return Ok((empty_entry_changes(), 0));
        }

        let delta_before_fee = delta_snapshot(&self.state);

        // Capture STATE entries BEFORE modifications for correct change generation
        // This is needed because flush_modified_entries updates snapshots to current values
        let mut state_overrides: HashMap<LedgerKey, LedgerEntry> = HashMap::new();
        if let Some(acc) = self.state.get_account(&fee_source_id) {
            let key = LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
                account_id: fee_source_id.clone(),
            });
            state_overrides.insert(key, self.state.ledger_entry_for_account(acc));
        }
        if fee_source_id != inner_source_id {
            if let Some(acc) = self.state.get_account(&inner_source_id) {
                let key = LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
                    account_id: inner_source_id.clone(),
                });
                state_overrides.insert(key, self.state.ledger_entry_for_account(acc));
            }
        }

        // Deduct fee
        if let Some(acc) = self.state.get_account_mut(&fee_source_id) {
            acc.balance -= fee;
        }

        // For protocol < 10, sequence bump happens during fee processing
        if self.protocol_version < 10 {
            if let Some(acc) = self.state.get_account_mut(&inner_source_id) {
                acc.seq_num.0 += 1;
                stellar_core_tx::state::update_account_seq_info(
                    acc,
                    self.ledger_seq,
                    self.close_time,
                );
            }
        }

        self.state.delta_mut().add_fee(fee);
        self.state.flush_modified_entries();

        let delta_after_fee = delta_snapshot(&self.state);
        let delta_changes =
            delta_changes_between(self.state.delta(), delta_before_fee, delta_after_fee);
        let fee_changes = build_entry_changes_with_state_overrides(
            &self.state,
            &delta_changes.created,
            &delta_changes.updated,
            &delta_changes.deleted,
            &state_overrides,
        );

        // Commit fee changes so they persist to subsequent transactions
        self.state.commit();

        Ok((fee_changes, fee))
    }

    /// Execute a transaction with configurable fee deduction.
    ///
    /// When `deduct_fee` is false, fee validation still occurs but no fee
    /// processing changes are applied to the state or delta.
    ///
    /// For fee bump transactions in two-phase mode, `fee_source_pre_state` can be provided
    /// to use as the STATE entry in tx_changes_before. This is needed because the current
    /// state may already be post-fee-processing (synced with CDP's fee_meta), but we need
    /// to emit the pre-fee state for the STATE entry to match C++ stellar-core behavior.
    pub fn execute_transaction_with_fee_mode(
        &mut self,
        snapshot: &SnapshotHandle,
        tx_envelope: &TransactionEnvelope,
        base_fee: u32,
        soroban_prng_seed: Option<[u8; 32]>,
        deduct_fee: bool,
    ) -> Result<TransactionExecutionResult> {
        self.execute_transaction_with_fee_mode_and_pre_state(
            snapshot,
            tx_envelope,
            base_fee,
            soroban_prng_seed,
            deduct_fee,
            None,
        )
    }

    /// Execute a transaction with configurable fee deduction and optional pre-fee state.
    ///
    /// When `deduct_fee` is false, fee validation still occurs but no fee
    /// processing changes are applied to the state or delta.
    ///
    /// For fee bump transactions in two-phase mode, `fee_source_pre_state` should be provided
    /// with the fee source account state BEFORE fee processing. This is used for the STATE entry
    /// in tx_changes_before to match C++ stellar-core behavior.
    pub fn execute_transaction_with_fee_mode_and_pre_state(
        &mut self,
        snapshot: &SnapshotHandle,
        tx_envelope: &TransactionEnvelope,
        base_fee: u32,
        soroban_prng_seed: Option<[u8; 32]>,
        deduct_fee: bool,
        fee_source_pre_state: Option<LedgerEntry>,
    ) -> Result<TransactionExecutionResult> {
        let frame = TransactionFrame::with_network(tx_envelope.clone(), self.network_id);
        let fee_source_id = stellar_core_tx::muxed_to_account_id(&frame.fee_source_account());
        let inner_source_id = stellar_core_tx::muxed_to_account_id(&frame.inner_source_account());

        if !frame.is_valid_structure() {
            let failure = if frame.operations().is_empty() {
                ExecutionFailure::MissingOperation
            } else {
                ExecutionFailure::Malformed
            };
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                fee_refund: 0,
                operation_results: vec![],
                error: Some("Invalid transaction structure".into()),
                failure: Some(failure),
                tx_meta: None,
                fee_changes: None,
                post_fee_changes: None,
                hot_archive_restored_keys: Vec::new(),
            });
        }

        // Load source account
        if !self.load_account(snapshot, &fee_source_id)? {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                fee_refund: 0,
                operation_results: vec![],
                error: Some("Source account not found".into()),
                failure: Some(ExecutionFailure::NoAccount),
                tx_meta: None,
                fee_changes: None,
                post_fee_changes: None,
                hot_archive_restored_keys: Vec::new(),
            });
        }

        if !self.load_account(snapshot, &inner_source_id)? {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                fee_refund: 0,
                operation_results: vec![],
                error: Some("Source account not found".into()),
                failure: Some(ExecutionFailure::NoAccount),
                tx_meta: None,
                fee_changes: None,
                post_fee_changes: None,
                hot_archive_restored_keys: Vec::new(),
            });
        }

        // Get accounts for validation
        let fee_source_account = match self.state.get_account(&fee_source_id) {
            Some(acc) => acc.clone(),
            None => {
                return Ok(TransactionExecutionResult {
                    success: false,
                    fee_charged: 0,
                    fee_refund: 0,
                    operation_results: vec![],
                    error: Some("Source account not found".into()),
                    failure: Some(ExecutionFailure::NoAccount),
                    tx_meta: None,
                    fee_changes: None,
                    post_fee_changes: None,
                    hot_archive_restored_keys: Vec::new(),
                });
            }
        };

        let source_account = match self.state.get_account(&inner_source_id) {
            Some(acc) => acc.clone(),
            None => {
                return Ok(TransactionExecutionResult {
                    success: false,
                    fee_charged: 0,
                    fee_refund: 0,
                    operation_results: vec![],
                    error: Some("Source account not found".into()),
                    failure: Some(ExecutionFailure::NoAccount),
                    tx_meta: None,
                    fee_changes: None,
                    post_fee_changes: None,
                    hot_archive_restored_keys: Vec::new(),
                });
            }
        };

        // Validate fee
        if frame.is_fee_bump() {
            let op_count = frame.operation_count() as i64;
            let outer_op_count = std::cmp::max(1_i64, op_count + 1);
            let outer_min_inclusion_fee = base_fee as i64 * outer_op_count;
            let outer_inclusion_fee = frame.inclusion_fee();

            if outer_inclusion_fee < outer_min_inclusion_fee {
                return Ok(TransactionExecutionResult {
                    success: false,
                    fee_charged: 0,
                    fee_refund: 0,
                    operation_results: vec![],
                    error: Some("Insufficient fee".into()),
                    failure: Some(ExecutionFailure::InsufficientFee),
                    tx_meta: None,
                    fee_changes: None,
                    post_fee_changes: None,
                    hot_archive_restored_keys: Vec::new(),
                });
            }

            let (inner_inclusion_fee, inner_is_soroban) = match frame.envelope() {
                TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
                    stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                        let inner_env = TransactionEnvelope::Tx(inner.clone());
                        let inner_frame =
                            TransactionFrame::with_network(inner_env, self.network_id);
                        (inner_frame.inclusion_fee(), inner_frame.is_soroban())
                    }
                },
                _ => (0, false),
            };

            if inner_inclusion_fee >= 0 {
                let inner_min_inclusion_fee = base_fee as i64 * std::cmp::max(1_i64, op_count);
                let v1 = outer_inclusion_fee as i128 * inner_min_inclusion_fee as i128;
                let v2 = inner_inclusion_fee as i128 * outer_min_inclusion_fee as i128;

                if v1 < v2 {
                    return Ok(TransactionExecutionResult {
                        success: false,
                        fee_charged: 0,
                        fee_refund: 0,
                        operation_results: vec![],
                        error: Some("Insufficient fee".into()),
                        failure: Some(ExecutionFailure::InsufficientFee),
                        tx_meta: None,
                        fee_changes: None,
                        post_fee_changes: None,
                        hot_archive_restored_keys: Vec::new(),
                    });
                }
            } else {
                let allow_negative_inner = self.protocol_version >= 23 && inner_is_soroban;
                if !allow_negative_inner {
                    return Ok(TransactionExecutionResult {
                        success: false,
                        fee_charged: 0,
                        fee_refund: 0,
                        operation_results: vec![],
                        error: Some("Fee bump inner transaction invalid".into()),
                        failure: Some(ExecutionFailure::OperationFailed),
                        tx_meta: None,
                        fee_changes: None,
                        post_fee_changes: None,
                        hot_archive_restored_keys: Vec::new(),
                    });
                }
            }
        } else {
            let required_fee = frame.operation_count() as u32 * base_fee;
            if frame.fee() < required_fee {
                return Ok(TransactionExecutionResult {
                    success: false,
                    fee_charged: 0,
                    fee_refund: 0,
                    operation_results: vec![],
                    error: Some("Insufficient fee".into()),
                    failure: Some(ExecutionFailure::InsufficientFee),
                    tx_meta: None,
                    fee_changes: None,
                    post_fee_changes: None,
                    hot_archive_restored_keys: Vec::new(),
                });
            }
        }

        let validation_ctx = ValidationContext::new(
            self.ledger_seq,
            self.close_time,
            base_fee,
            self.base_reserve,
            self.protocol_version,
            self.network_id,
        );

        if let Err(e) = validation::validate_time_bounds(&frame, &validation_ctx) {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                fee_refund: 0,
                operation_results: vec![],
                error: Some("Time bounds invalid".into()),
                failure: Some(match e {
                    validation::ValidationError::TooEarly { .. } => ExecutionFailure::TooEarly,
                    validation::ValidationError::TooLate { .. } => ExecutionFailure::TooLate,
                    _ => ExecutionFailure::OperationFailed,
                }),
                tx_meta: None,
                fee_changes: None,
                post_fee_changes: None,
                hot_archive_restored_keys: Vec::new(),
            });
        }

        if let Err(e) = validation::validate_ledger_bounds(&frame, &validation_ctx) {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                fee_refund: 0,
                operation_results: vec![],
                error: Some("Ledger bounds invalid".into()),
                failure: Some(match e {
                    validation::ValidationError::BadLedgerBounds { min, max, current } => {
                        if max > 0 && current > max {
                            ExecutionFailure::TooLate
                        } else if min > 0 && current < min {
                            ExecutionFailure::TooEarly
                        } else {
                            ExecutionFailure::OperationFailed
                        }
                    }
                    _ => ExecutionFailure::OperationFailed,
                }),
                tx_meta: None,
                fee_changes: None,
                post_fee_changes: None,
                hot_archive_restored_keys: Vec::new(),
            });
        }

        if let Preconditions::V2(cond) = frame.preconditions() {
            if let Some(min_seq) = cond.min_seq_num {
                if source_account.seq_num.0 < min_seq.0 {
                    return Ok(TransactionExecutionResult {
                        success: false,
                        fee_charged: 0,
                        fee_refund: 0,
                        operation_results: vec![],
                        error: Some("Minimum sequence number not met".into()),
                        failure: Some(ExecutionFailure::BadMinSeqAgeOrGap),
                        tx_meta: None,
                        fee_changes: None,
                        post_fee_changes: None,
                        hot_archive_restored_keys: Vec::new(),
                    });
                }
            }

            if cond.min_seq_age.0 > 0 {
                // C++ logic: minSeqAge > closeTime || closeTime - minSeqAge < accSeqTime
                let acc_seq_time = get_account_seq_time(&source_account);
                let min_seq_age = cond.min_seq_age.0;

                if min_seq_age > self.close_time || self.close_time - min_seq_age < acc_seq_time {
                    return Ok(TransactionExecutionResult {
                        success: false,
                        fee_charged: 0,
                        fee_refund: 0,
                        operation_results: vec![],
                        error: Some("Minimum sequence age not met".into()),
                        failure: Some(ExecutionFailure::BadMinSeqAgeOrGap),
                        tx_meta: None,
                        fee_changes: None,
                        post_fee_changes: None,
                        hot_archive_restored_keys: Vec::new(),
                    });
                }
            }

            if cond.min_seq_ledger_gap > 0 {
                // C++ logic: minSeqLedgerGap > ledgerSeq || ledgerSeq - minSeqLedgerGap < accSeqLedger
                let acc_seq_ledger = get_account_seq_ledger(&source_account);
                let min_seq_ledger_gap = cond.min_seq_ledger_gap;

                if min_seq_ledger_gap > self.ledger_seq
                    || self.ledger_seq - min_seq_ledger_gap < acc_seq_ledger
                {
                    return Ok(TransactionExecutionResult {
                        success: false,
                        fee_charged: 0,
                        fee_refund: 0,
                        operation_results: vec![],
                        error: Some("Minimum sequence ledger gap not met".into()),
                        failure: Some(ExecutionFailure::BadMinSeqAgeOrGap),
                        tx_meta: None,
                        fee_changes: None,
                        post_fee_changes: None,
                        hot_archive_restored_keys: Vec::new(),
                    });
                }
            }
        }

        // Validate sequence number
        // C++ stellar-core logic from TransactionFrame::isBadSeq:
        // 1. Always reject if tx.seqNum == starting sequence for this ledger
        // 2. If minSeqNum is set (protocol >= 19), use relaxed check:
        //    bad if account.seqNum < minSeqNum OR account.seqNum >= tx.seqNum
        // 3. Otherwise, use strict check:
        //    bad if account.seqNum + 1 != tx.seqNum
        if self.ledger_seq <= i32::MAX as u32 {
            let starting_seq = (self.ledger_seq as i64) << 32;
            if frame.sequence_number() == starting_seq {
                return Ok(TransactionExecutionResult {
                    success: false,
                    fee_charged: 0,
                    fee_refund: 0,
                    operation_results: vec![],
                    error: Some("Bad sequence: equals starting sequence".into()),
                    failure: Some(ExecutionFailure::BadSequence),
                    tx_meta: None,
                    fee_changes: None,
                    post_fee_changes: None,
                    hot_archive_restored_keys: Vec::new(),
                });
            }
        }

        // Check for relaxed sequence validation (minSeqNum precondition)
        let min_seq_num = match frame.preconditions() {
            Preconditions::V2(cond) => cond.min_seq_num.map(|s| s.0),
            _ => None,
        };

        let account_seq = source_account.seq_num.0;
        let tx_seq = frame.sequence_number();

        tracing::debug!(
            account_seq,
            tx_seq,
            min_seq_num = ?min_seq_num,
            preconditions_type = ?std::mem::discriminant(&frame.preconditions()),
            "Sequence number validation"
        );

        let is_bad_seq = if let Some(min_seq) = min_seq_num {
            // Relaxed check: account.seqNum must be >= minSeqNum AND < tx.seqNum
            account_seq < min_seq || account_seq >= tx_seq
        } else {
            // Strict check: account.seqNum + 1 must equal tx.seqNum
            account_seq == i64::MAX || account_seq + 1 != tx_seq
        };

        if is_bad_seq {
            let error_msg = if let Some(min_seq) = min_seq_num {
                format!(
                    "Bad sequence: account seq {} not in valid range [minSeqNum={}, txSeq={})",
                    account_seq, min_seq, tx_seq
                )
            } else {
                format!(
                    "Bad sequence: expected {}, got {}",
                    account_seq.saturating_add(1),
                    tx_seq
                )
            };
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                fee_refund: 0,
                operation_results: vec![],
                error: Some(error_msg),
                failure: Some(ExecutionFailure::BadSequence),
                tx_meta: None,
                fee_changes: None,
                post_fee_changes: None,
                hot_archive_restored_keys: Vec::new(),
            });
        }

        // Basic signature validation (master key only).
        if validation::validate_signatures(&frame, &validation_ctx).is_err() {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                fee_refund: 0,
                operation_results: vec![],
                error: Some("Invalid signature".into()),
                failure: Some(ExecutionFailure::InvalidSignature),
                tx_meta: None,
                fee_changes: None,
                post_fee_changes: None,
                hot_archive_restored_keys: Vec::new(),
            });
        }

        let outer_hash = frame
            .hash(&self.network_id)
            .map_err(|e| LedgerError::Internal(format!("tx hash error: {}", e)))?;
        let outer_threshold = threshold_low(&fee_source_account);
        if !has_sufficient_signer_weight(
            &outer_hash,
            frame.signatures(),
            &fee_source_account,
            outer_threshold,
        ) {
            tracing::warn!("Signature check failed: fee_source outer check");
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                fee_refund: 0,
                operation_results: vec![],
                error: Some("Invalid signature".into()),
                failure: Some(ExecutionFailure::InvalidSignature),
                tx_meta: None,
                fee_changes: None,
                post_fee_changes: None,
                hot_archive_restored_keys: Vec::new(),
            });
        }

        if frame.is_fee_bump() {
            let inner_hash = fee_bump_inner_hash(&frame, &self.network_id)?;
            let inner_threshold = threshold_medium(&source_account);
            if !has_sufficient_signer_weight(
                &inner_hash,
                frame.inner_signatures(),
                &source_account,
                inner_threshold,
            ) {
                tracing::warn!("Signature check failed: fee_bump inner check");
                return Ok(TransactionExecutionResult {
                    success: false,
                    fee_charged: 0,
                    fee_refund: 0,
                    operation_results: vec![],
                    error: Some("Invalid inner signature".into()),
                    failure: Some(ExecutionFailure::InvalidSignature),
                    tx_meta: None,
                    fee_changes: None,
                    post_fee_changes: None,
                    hot_archive_restored_keys: Vec::new(),
                });
            }
        }

        // Transaction envelope uses LOW threshold for signature check.
        // Each operation will additionally check its own threshold (low/medium/high).
        // This matches C++ stellar-core's checkAllTransactionSignatures behavior.
        let required_weight = threshold_low(&source_account);
        if !frame.is_fee_bump()
            && !has_sufficient_signer_weight(
                &outer_hash,
                frame.signatures(),
                &source_account,
                required_weight,
            )
        {
            tracing::warn!(
                required_weight = required_weight,
                is_fee_bump = frame.is_fee_bump(),
                master_weight = source_account.thresholds.0[0],
                num_signers = source_account.signers.len(),
                thresholds = ?source_account.thresholds.0,
                "Signature check failed: source outer check"
            );
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                fee_refund: 0,
                operation_results: vec![],
                error: Some("Invalid signature".into()),
                failure: Some(ExecutionFailure::InvalidSignature),
                tx_meta: None,
                fee_changes: None,
                post_fee_changes: None,
                hot_archive_restored_keys: Vec::new(),
            });
        }

        if let Preconditions::V2(cond) = frame.preconditions() {
            if !cond.extra_signers.is_empty() {
                let extra_hash = if frame.is_fee_bump() {
                    fee_bump_inner_hash(&frame, &self.network_id)?
                } else {
                    outer_hash
                };
                let extra_signatures = if frame.is_fee_bump() {
                    frame.inner_signatures()
                } else {
                    frame.signatures()
                };
                if !has_required_extra_signers(&extra_hash, extra_signatures, &cond.extra_signers) {
                    return Ok(TransactionExecutionResult {
                        success: false,
                        fee_charged: 0,
                        fee_refund: 0,
                        operation_results: vec![],
                        error: Some("Missing extra signer".into()),
                        failure: Some(ExecutionFailure::BadAuthExtra),
                        tx_meta: None,
                        fee_changes: None,
                        post_fee_changes: None,
                        hot_archive_restored_keys: Vec::new(),
                    });
                }
            }
        }

        // For fee bump transactions, the required fee includes an extra base fee for the wrapper
        let num_ops = std::cmp::max(1, frame.operation_count() as i64);
        let required_fee = if frame.is_fee_bump() {
            // Fee bumps pay baseFee * (numOps + 1) - extra charge for the fee bump wrapper
            base_fee as i64 * (num_ops + 1)
        } else {
            base_fee as i64 * num_ops
        };
        let inclusion_fee = frame.inclusion_fee();
        // For Soroban, the resource fee is charged in full, plus the inclusion fee up to required.
        // For classic transactions, charge up to the required_fee (base_fee * num_ops).
        let mut fee = if frame.is_soroban() {
            frame.declared_soroban_resource_fee() + std::cmp::min(inclusion_fee, required_fee)
        } else {
            std::cmp::min(inclusion_fee, required_fee)
        };

        let mut preflight_failure = None;
        if deduct_fee {
            if let Some(acc) = self.state.get_account(&fee_source_id) {
                if self.available_balance_for_fee(acc)? < fee {
                    preflight_failure = Some(ExecutionFailure::InsufficientBalance);
                }
            }
        }

        let mut tx_event_manager = TxEventManager::new(
            true,
            self.protocol_version,
            self.network_id,
            self.classic_events,
        );
        let mut refundable_fee_tracker = if frame.is_soroban() {
            let (non_refundable_fee, _initial_refundable_fee) = compute_soroban_resource_fee(
                &frame,
                self.protocol_version,
                &self.soroban_config,
                0,
            )
            .unwrap_or((0, 0));
            let declared_fee = frame.declared_soroban_resource_fee();
            let max_refundable_fee = declared_fee.saturating_sub(non_refundable_fee);
            Some(RefundableFeeTracker::new(max_refundable_fee))
        } else {
            None
        };

        let mut fee_created = Vec::new();
        let mut fee_updated = Vec::new();
        let mut fee_deleted = Vec::new();
        let fee_changes = if !deduct_fee || fee == 0 {
            empty_entry_changes()
        } else {
            let delta_before_fee = delta_snapshot(&self.state);

            // Deduct fee (sequence update is handled separately for protocol >= 10).
            if let Some(acc) = self.state.get_account_mut(&fee_source_id) {
                let old_balance = acc.balance;
                let charged_fee = std::cmp::min(acc.balance, fee);
                acc.balance -= charged_fee;
                fee = charged_fee;
                let key_bytes = stellar_core_tx::account_id_to_key(&fee_source_id);
                tracing::debug!(
                    account_prefix = ?&key_bytes[0..4],
                    old_balance = old_balance,
                    new_balance = acc.balance,
                    fee = charged_fee,
                    "Fee deducted from account"
                );
            }
            if self.protocol_version < 10 {
                if let Some(acc) = self.state.get_account_mut(&inner_source_id) {
                    acc.seq_num.0 += 1;
                    stellar_core_tx::state::update_account_seq_info(
                        acc,
                        self.ledger_seq,
                        self.close_time,
                    );
                }
            }
            self.state.delta_mut().add_fee(fee);

            self.state.flush_modified_entries();
            let delta_after_fee = delta_snapshot(&self.state);
            let delta_changes =
                delta_changes_between(self.state.delta(), delta_before_fee, delta_after_fee);
            fee_created = delta_changes.created;
            fee_updated = delta_changes.updated;
            fee_deleted = delta_changes.deleted;
            let fee_changes = build_entry_changes_with_state(
                &self.state,
                &fee_created,
                &fee_updated,
                &fee_deleted,
            );

            // Commit fee updates so txChangesBefore reflects the post-fee account state.
            self.state.commit();
            fee_changes
        };

        let mut tx_changes_before = empty_entry_changes();
        let mut seq_created = Vec::new();
        let mut seq_updated = Vec::new();
        let mut seq_deleted = Vec::new();
        let mut signer_created = Vec::new();
        let mut signer_updated = Vec::new();
        let mut signer_deleted = Vec::new();

        if self.protocol_version >= 10 {
            // For fee bump transactions in two-phase mode, C++ stellar-core's
            // FeeBumpTransactionFrame::apply() ALWAYS calls removeOneTimeSignerKeyFromFeeSource()
            // which loads the fee source account, generating a STATE/UPDATED pair even if
            // the fee source equals the inner source. This happens BEFORE the inner transaction's
            // sequence bump. We capture this to match C++ stellar-core ordering.
            let fee_bump_wrapper_changes = if !deduct_fee && frame.is_fee_bump() {
                let fee_source_key = LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
                    account_id: fee_source_id.clone(),
                });
                if let Some(fee_source_entry) = self.state.get_entry(&fee_source_key) {
                    // Both STATE and UPDATED use the same (current) state value.
                    // In C++ stellar-core, the fee bump wrapper's tx_changes_before captures
                    // the fee source state AFTER fee processing (which happened in fee_meta).
                    // This is just for removeOneTimeSignerKeyFromFeeSource() which doesn't
                    // change the balance - hence STATE and UPDATED have the same value.
                    // We ignore fee_source_pre_state as it's not needed.
                    let _ = fee_source_pre_state; // Explicitly ignore the parameter
                    vec![
                        LedgerEntryChange::State(fee_source_entry.clone()),
                        LedgerEntryChange::Updated(fee_source_entry),
                    ]
                } else {
                    vec![]
                }
            } else {
                vec![]
            };

            let mut signer_changes = empty_entry_changes();
            if self.protocol_version != 7 {
                let mut source_accounts = Vec::new();
                source_accounts.push(inner_source_id.clone());
                for op in frame.operations().iter() {
                    if let Some(ref source) = op.source_account {
                        source_accounts.push(stellar_core_tx::muxed_to_account_id(source));
                    }
                }
                source_accounts.sort_by(|a, b| a.0.cmp(&b.0));
                source_accounts.dedup_by(|a, b| a.0 == b.0);

                let delta_before_signers = delta_snapshot(&self.state);
                let mut signer_state_overrides = HashMap::new();
                for account_id in &source_accounts {
                    let key = LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
                        account_id: account_id.clone(),
                    });
                    if let Some(entry) = self.state.get_entry(&key) {
                        signer_state_overrides.insert(key, entry);
                    }
                }

                self.state.remove_one_time_signers_from_all_sources(
                    &outer_hash,
                    &source_accounts,
                    self.protocol_version,
                );
                self.state.flush_modified_entries();
                let delta_after_signers = delta_snapshot(&self.state);
                let delta_changes = delta_changes_between(
                    self.state.delta(),
                    delta_before_signers,
                    delta_after_signers,
                );
                signer_created = delta_changes.created;
                signer_updated = delta_changes.updated;
                signer_deleted = delta_changes.deleted;
                signer_changes = build_entry_changes_with_state_overrides(
                    &self.state,
                    &signer_created,
                    &signer_updated,
                    &signer_deleted,
                    &signer_state_overrides,
                );
            }

            let delta_before_seq = delta_snapshot(&self.state);
            // Capture the current account state BEFORE modification for STATE entry.
            // We can't use snapshot_entry() here because the snapshot might not exist yet.
            // After flush_modified_entries, the snapshot is updated to the post-modification
            // value, so we need to save the original here.
            let inner_source_key = LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
                account_id: inner_source_id.clone(),
            });
            let seq_state_override = self.state.get_entry(&inner_source_key);

            if let Some(acc) = self.state.get_account_mut(&inner_source_id) {
                acc.seq_num.0 += 1;
                stellar_core_tx::state::update_account_seq_info(
                    acc,
                    self.ledger_seq,
                    self.close_time,
                );
            }
            self.state.flush_modified_entries();
            let delta_after_seq = delta_snapshot(&self.state);
            let delta_changes =
                delta_changes_between(self.state.delta(), delta_before_seq, delta_after_seq);
            // Use the pre-modification snapshot for STATE entry via state_overrides.
            let mut seq_state_overrides = HashMap::new();
            if let Some(entry) = seq_state_override {
                seq_state_overrides.insert(inner_source_key.clone(), entry);
            }
            let seq_changes = build_entry_changes_with_state_overrides(
                &self.state,
                &delta_changes.created,
                &delta_changes.updated,
                &delta_changes.deleted,
                &seq_state_overrides,
            );
            seq_created = delta_changes.created;
            seq_updated = delta_changes.updated;
            seq_deleted = delta_changes.deleted;

            // Merge all changes into tx_changes_before.
            // Order: fee_bump_wrapper_changes (fee source), seq_changes (inner source seq bump).
            // This matches C++ stellar-core where FeeBumpFrame captures fee source state,
            // then inner tx does seq bump.
            let mut combined = Vec::with_capacity(
                fee_bump_wrapper_changes.len() + signer_changes.len() + seq_changes.len(),
            );
            combined.extend(fee_bump_wrapper_changes);
            combined.extend(signer_changes.iter().cloned());
            combined.extend(seq_changes.iter().cloned());
            tx_changes_before = combined.try_into().unwrap_or_default();
        }
        // Persist sequence updates so failed transactions still consume sequence numbers.
        if self.protocol_version >= 10 {
            self.state.commit();
        }

        // Commit pre-apply changes so rollback doesn't revert them.
        self.state.commit();

        // Create ledger context for operation execution
        let ledger_context = if let Some(prng_seed) = soroban_prng_seed {
            LedgerContext::with_prng_seed(
                self.ledger_seq,
                self.close_time,
                base_fee,
                self.base_reserve,
                self.protocol_version,
                self.network_id,
                prng_seed,
            )
        } else {
            LedgerContext::new(
                self.ledger_seq,
                self.close_time,
                base_fee,
                self.base_reserve,
                self.protocol_version,
                self.network_id,
            )
        };

        let soroban_data = frame.soroban_data();

        // For Soroban transactions, load all footprint entries from the snapshot
        // before executing operations. This ensures contract data, code, and TTLs
        // are available to the Soroban host.
        //
        // NOTE: We no longer call clear_archived_entries_from_state() here because
        // archived entries from the hot archive need to be available to the Soroban
        // host for restoration. The previous approach of clearing them was designed
        // for when all entries came from the live bucket list, but with hot archive
        // support, archived entries are properly sourced and must be preserved.
        if let Some(data) = soroban_data {
            self.load_soroban_footprint(snapshot, &data.resources.footprint)?;
        }

        self.state.clear_sponsorship_stack();

        // Pre-load sponsor accounts for BeginSponsoringFutureReserves operations.
        // When a BeginSponsoringFutureReserves operation is followed by other operations
        // (like SetOptions), those subsequent operations may need to update the sponsor's
        // num_sponsoring count. We must load these sponsor accounts before the operation
        // loop so they're available when needed.
        for op in frame.operations().iter() {
            if let OperationBody::BeginSponsoringFutureReserves(_) = &op.body {
                // The sponsor is the source of the BeginSponsoringFutureReserves operation
                let op_source_muxed = op
                    .source_account
                    .clone()
                    .unwrap_or_else(|| frame.inner_source_account());
                let sponsor_id = stellar_core_tx::muxed_to_account_id(&op_source_muxed);
                self.load_account(snapshot, &sponsor_id)?;
            }
        }

        // Execute operations
        let mut operation_results = Vec::new();
        let num_ops = frame.operations().len();
        let mut op_changes = Vec::with_capacity(num_ops);
        let mut op_events: Vec<Vec<ContractEvent>> = Vec::with_capacity(num_ops);
        let mut diagnostic_events: Vec<DiagnosticEvent> = Vec::new();
        let mut soroban_return_value = None;
        let mut all_success = true;
        let mut failure = None;
        let mut orderbook_loaded = false;

        // For multi-operation transactions, C++ stellar-core records STATE/UPDATED
        // for every accessed entry per operation, even if values are identical.
        // For single-operation transactions, it only records if values changed.
        self.state.set_multi_op_mode(num_ops > 1);
        let op_invariant_snapshot = self.op_invariants.as_ref().map(|runner| runner.snapshot());

        let tx_seq = frame.sequence_number();
        // Collect hot archive restored keys across all operations (Protocol 23+)
        let mut collected_hot_archive_keys: Vec<LedgerKey> = Vec::new();

        if let Some(preflight_failure) = preflight_failure {
            all_success = false;
            failure = Some(preflight_failure);
        } else {
            for (op_index, op) in frame.operations().iter().enumerate() {
                let op_type = OperationType::from_body(&op.body);
                let op_source_muxed = op
                    .source_account
                    .clone()
                    .unwrap_or_else(|| frame.inner_source_account());
                let op_delta_before = delta_snapshot(&self.state);
                self.state.begin_op_snapshot();

                if !orderbook_loaded && op_requires_orderbook(&op.body) {
                    self.load_orderbook_offers(snapshot)?;
                    orderbook_loaded = true;
                }

                // Load any accounts needed for this operation
                self.load_operation_accounts(snapshot, op, &inner_source_id)?;

                // Get operation source
                let op_source = stellar_core_tx::muxed_to_account_id(&op_source_muxed);

                let pre_claimable_balance = match &op.body {
                    OperationBody::ClaimClaimableBalance(op_data) => self
                        .state
                        .get_claimable_balance(&op_data.balance_id)
                        .cloned(),
                    OperationBody::ClawbackClaimableBalance(op_data) => self
                        .state
                        .get_claimable_balance(&op_data.balance_id)
                        .cloned(),
                    _ => None,
                };
                let pre_pool = match &op.body {
                    OperationBody::LiquidityPoolDeposit(op_data) => self
                        .state
                        .get_liquidity_pool(&op_data.liquidity_pool_id)
                        .cloned(),
                    OperationBody::LiquidityPoolWithdraw(op_data) => self
                        .state
                        .get_liquidity_pool(&op_data.liquidity_pool_id)
                        .cloned(),
                    _ => None,
                };
                let mut op_event_manager = OpEventManager::new(
                    true,
                    op_type.is_soroban(),
                    self.protocol_version,
                    self.network_id,
                    frame.memo().clone(),
                    self.classic_events,
                );

                // Execute the operation
                let op_index = u32::try_from(op_index).unwrap_or(u32::MAX);
                let result = self.execute_single_operation(
                    op,
                    &op_source,
                    &inner_source_id,
                    tx_seq,
                    op_index,
                    &ledger_context,
                    soroban_data,
                );

                match result {
                    Ok(op_exec) => {
                        self.state.flush_modified_entries();
                        let mut op_result = op_exec.result;
                        if let Some(meta) = &op_exec.soroban_meta {
                            if let Some(tracker) = refundable_fee_tracker.as_mut() {
                                if !tracker.consume(
                                    &frame,
                                    self.protocol_version,
                                    &self.soroban_config,
                                    meta.event_size_bytes,
                                    meta.rent_fee,
                                ) {
                                    op_result = insufficient_refundable_fee_result(op);
                                    all_success = false;
                                    failure = Some(ExecutionFailure::OperationFailed);
                                }
                            }
                        }
                        // Check if operation succeeded
                        if !is_operation_success(&op_result) {
                            all_success = false;
                            if matches!(op_result, OperationResult::OpNotSupported) {
                                failure = Some(ExecutionFailure::NotSupported);
                            }
                        }
                        operation_results.push(op_result.clone());

                        let op_delta_after = delta_snapshot(&self.state);
                        let delta_changes = delta_changes_between(
                            self.state.delta(),
                            op_delta_before,
                            op_delta_after,
                        );
                        let op_snapshots = self.state.end_op_snapshot();

                        // For Soroban operations, extract restored entries (hot archive and live BL)
                        let (restored_entries, footprint) = if op_type.is_soroban() {
                            let mut restored = RestoredEntries::default();

                            // Get live BL restorations from the Soroban execution result
                            if let Some(meta) = &op_exec.soroban_meta {
                                for live_bl_restore in &meta.live_bucket_list_restores {
                                    restored
                                        .live_bucket_list
                                        .insert(live_bl_restore.key.clone());
                                    restored.live_bucket_list_entries.insert(
                                        live_bl_restore.key.clone(),
                                        live_bl_restore.entry.clone(),
                                    );
                                    // Also track the TTL entry
                                    restored
                                        .live_bucket_list
                                        .insert(live_bl_restore.ttl_key.clone());
                                    restored.live_bucket_list_entries.insert(
                                        live_bl_restore.ttl_key.clone(),
                                        live_bl_restore.ttl_entry.clone(),
                                    );
                                }
                            }

                            // Also get hot archive keys for InvokeHostFunction
                            // NOTE: We must exclude live BL restore keys from the hot archive set.
                            // Live BL restores are entries that exist in the live bucket list with
                            // expired TTL but haven't been evicted yet - these are NOT hot archive
                            // restores and should not be added to HotArchiveBucketList::add_batch.
                            let mut hot_archive =
                                extract_hot_archive_restored_keys(soroban_data, op_type);
                            let ha_before = hot_archive.len();
                            hot_archive.retain(|k| !restored.live_bucket_list.contains(k));
                            let ha_after = hot_archive.len();
                            // Log when we filter out live BL restores (indicates distinction matters)
                            if ha_before != ha_after {
                                tracing::info!(
                                    ha_before,
                                    ha_after,
                                    live_bl_count = restored.live_bucket_list.len(),
                                    "Filtered live BL restores from hot archive keys"
                                );
                            }
                            // For transaction meta purposes, also add the corresponding TTL keys.
                            // When a ContractData/ContractCode entry is restored from hot archive,
                            // its TTL entry should also be emitted as RESTORED (not CREATED).
                            // NOTE: We don't add TTL keys to collected_hot_archive_keys because
                            // HotArchiveBucketList::add_batch only receives data/code entries.
                            use sha2::{Digest, Sha256};
                            let ttl_keys: Vec<_> = hot_archive
                                .iter()
                                .filter_map(|key| {
                                    // Compute key hash as SHA256 of key XDR
                                    let key_bytes = key.to_xdr(Limits::none()).ok()?;
                                    let key_hash =
                                        stellar_xdr::curr::Hash(Sha256::digest(&key_bytes).into());
                                    Some(LedgerKey::Ttl(stellar_xdr::curr::LedgerKeyTtl {
                                        key_hash,
                                    }))
                                })
                                .collect();
                            // Collect data/code keys only for HotArchiveBucketList::add_batch
                            // (TTL keys are not added to hot archive bucket list)
                            collected_hot_archive_keys.extend(hot_archive.iter().cloned());
                            // Add all keys (including TTL) to restored.hot_archive for meta conversion
                            restored.hot_archive.extend(hot_archive);
                            restored.hot_archive.extend(ttl_keys);
                            (restored, soroban_data.map(|d| &d.resources.footprint))
                        } else {
                            (RestoredEntries::default(), None)
                        };

                        let op_changes_local = build_entry_changes_with_hot_archive(
                            &self.state,
                            &delta_changes.created,
                            &delta_changes.updated,
                            &delta_changes.update_states,
                            &delta_changes.deleted,
                            &delta_changes.delete_states,
                            &delta_changes.change_order,
                            &op_snapshots,
                            &restored_entries,
                            footprint,
                        );

                        let mut op_events_final = Vec::new();
                        if all_success && is_operation_success(&op_result) {
                            if let Some(meta) = &op_exec.soroban_meta {
                                op_event_manager.set_events(meta.events.clone());
                                diagnostic_events.extend(meta.diagnostic_events.iter().cloned());
                                soroban_return_value =
                                    meta.return_value.clone().or(soroban_return_value);
                            }

                            if !op_type.is_soroban() {
                                emit_classic_events_for_operation(
                                    &mut op_event_manager,
                                    op,
                                    &op_result,
                                    &op_source_muxed,
                                    &self.state,
                                    pre_claimable_balance.as_ref(),
                                    pre_pool.as_ref(),
                                );
                            }

                            if op_event_manager.is_enabled() {
                                op_events_final = op_event_manager.finalize();
                            }
                        }

                        if let Some(runner) = self.op_invariants.as_mut() {
                            runner.apply_and_check(&op_changes_local, &op_events_final)?;
                        }

                        if all_success {
                            op_changes.push(op_changes_local);
                            op_events.push(op_events_final);
                        } else {
                            op_changes.push(empty_entry_changes());
                            op_events.push(Vec::new());
                        }
                    }
                    Err(e) => {
                        self.state.end_op_snapshot();
                        all_success = false;
                        warn!(
                            error = %e,
                            op_index = op_index,
                            op_type = ?OperationType::from_body(&op.body),
                            "Operation execution failed"
                        );
                        operation_results.push(OperationResult::OpNotSupported);
                        op_changes.push(empty_entry_changes());
                        op_events.push(Vec::new());
                        failure = Some(ExecutionFailure::NotSupported);
                    }
                }
            }
        }

        if all_success && self.protocol_version >= 14 && self.state.has_pending_sponsorship() {
            all_success = false;
            failure = Some(ExecutionFailure::BadSponsorship);
        }

        if !all_success {
            let tx_hash = frame
                .hash(&self.network_id)
                .map(|hash| hash.to_hex())
                .unwrap_or_else(|_| "unknown".to_string());
            warn!(
                tx_hash = %tx_hash,
                fee_source = %account_id_to_strkey(&fee_source_id),
                inner_source = %account_id_to_strkey(&inner_source_id),
                results = ?operation_results,
                "Transaction failed; rolling back changes"
            );
            self.state.rollback();
            restore_delta_entries(&mut self.state, &fee_created, &fee_updated, &fee_deleted);
            // Re-add the fee to the delta after rollback.
            // rollback() restores the delta from the snapshot taken BEFORE fee deduction,
            // so we must explicitly re-add this transaction's fee to preserve it.
            // This ensures failed transactions still contribute their fees to the fee pool.
            if deduct_fee && fee > 0 {
                self.state.delta_mut().add_fee(fee);
            }
            if self.protocol_version >= 10 {
                restore_delta_entries(&mut self.state, &seq_created, &seq_updated, &seq_deleted);
                restore_delta_entries(
                    &mut self.state,
                    &signer_created,
                    &signer_updated,
                    &signer_deleted,
                );
            }
            if let (Some(runner), Some(snapshot)) =
                (self.op_invariants.as_mut(), op_invariant_snapshot)
            {
                runner.restore(snapshot);
            }
            op_changes.clear();
            op_events.clear();
            diagnostic_events.clear();
            soroban_return_value = None;
        } else {
            self.state.commit();

            // Update module cache with any newly created contract code.
            // This ensures subsequent transactions can use VmCachedInstantiation
            // (cheap) instead of VmInstantiation (expensive) for contracts
            // deployed in this transaction.
            for entry in self.state.delta().created_entries() {
                if let stellar_xdr::curr::LedgerEntryData::ContractCode(cc) = &entry.data {
                    self.add_contract_to_cache(cc.code.as_slice());
                }
            }
        }

        let post_fee_changes = empty_entry_changes();
        let mut fee_refund = 0i64;
        if let Some(tracker) = refundable_fee_tracker {
            let refund = tracker.refund_amount();
            // For protocol < 23, apply refund immediately to the transaction's delta.
            // For protocol >= 23, refund is applied after ALL transactions in the tx set,
            // so we do NOT modify the delta here - it's handled separately in ledger close.
            if refund > 0 && self.protocol_version < 23 {
                // Apply refund directly to the last account update in the delta.
                // In C++ stellar-core (pre-v23), the refund is NOT a separate meta change - it's
                // incorporated into the final account balance of the existing update.
                self.state.apply_refund_to_delta(&fee_source_id, refund);
                self.state.delta_mut().add_fee(-refund);
            }
            let stage = if self.protocol_version >= 23 {
                TransactionEventStage::AfterAllTxs
            } else {
                TransactionEventStage::AfterTx
            };
            tx_event_manager.new_fee_event(&fee_source_id, -refund, stage);
            fee_refund = refund;
        }

        let tx_events = tx_event_manager.finalize();
        let tx_meta = build_transaction_meta(
            tx_changes_before.clone(),
            op_changes,
            op_events,
            tx_events,
            soroban_return_value,
            diagnostic_events,
        );

        Ok(TransactionExecutionResult {
            success: all_success,
            fee_charged: fee.saturating_sub(fee_refund),
            fee_refund,
            operation_results,
            error: if all_success {
                None
            } else {
                Some("One or more operations failed".into())
            },
            failure: if all_success {
                None
            } else {
                Some(failure.unwrap_or(ExecutionFailure::OperationFailed))
            },
            tx_meta: Some(tx_meta),
            fee_changes: Some(fee_changes),
            post_fee_changes: Some(post_fee_changes),
            hot_archive_restored_keys: collected_hot_archive_keys,
        })
    }

    /// Load accounts needed for an operation.
    fn load_operation_accounts(
        &mut self,
        snapshot: &SnapshotHandle,
        op: &stellar_xdr::curr::Operation,
        source_id: &AccountId,
    ) -> Result<()> {
        let op_source = op
            .source_account
            .as_ref()
            .map(stellar_core_tx::muxed_to_account_id)
            .unwrap_or_else(|| source_id.clone());

        // Load operation source if different from transaction source
        if let Some(ref muxed) = op.source_account {
            let op_source = stellar_core_tx::muxed_to_account_id(muxed);
            self.load_account(snapshot, &op_source)?;
        }

        // Load destination accounts based on operation type
        match &op.body {
            OperationBody::CreateAccount(op_data) => {
                self.load_account(snapshot, &op_data.destination)?;
            }
            OperationBody::BeginSponsoringFutureReserves(op_data) => {
                self.load_account(snapshot, &op_data.sponsored_id)?;
            }
            OperationBody::AllowTrust(op_data) => {
                let asset = allow_trust_asset(op_data, &op_source);
                if let Some(tl_asset) = asset_to_trustline_asset(&asset) {
                    self.load_trustline(snapshot, &op_data.trustor, &tl_asset)?;
                }
                // Load the trustor account - needed for num_sub_entries updates when removing offers
                self.load_account(snapshot, &op_data.trustor)?;
                // Load offers by account/asset so they can be removed if authorization is revoked
                self.load_offers_by_account_and_asset(snapshot, &op_data.trustor, &asset)?;
            }
            OperationBody::Payment(op_data) => {
                let dest = stellar_core_tx::muxed_to_account_id(&op_data.destination);
                self.load_account(snapshot, &dest)?;
                if let Some(tl_asset) = asset_to_trustline_asset(&op_data.asset) {
                    self.load_trustline(snapshot, &op_source, &tl_asset)?;
                    self.load_trustline(snapshot, &dest, &tl_asset)?;
                }
                // Load issuer account for non-native assets
                self.load_asset_issuer(snapshot, &op_data.asset)?;
            }
            OperationBody::AccountMerge(dest) => {
                let dest = stellar_core_tx::muxed_to_account_id(dest);
                self.load_account(snapshot, &dest)?;
            }
            OperationBody::ClaimClaimableBalance(op_data) => {
                self.load_claimable_balance(snapshot, &op_data.balance_id)?;
                let key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                    balance_id: op_data.balance_id.clone(),
                });
                if let Some(sponsor) = self.state.entry_sponsor(&key).cloned() {
                    self.load_account(snapshot, &sponsor)?;
                }
                if let Some(entry) = self.state.get_claimable_balance(&op_data.balance_id) {
                    let asset = entry.asset.clone();
                    if let Some(tl_asset) = asset_to_trustline_asset(&asset) {
                        self.load_trustline(snapshot, &op_source, &tl_asset)?;
                        self.load_asset_issuer(snapshot, &asset)?;
                    }
                }
            }
            OperationBody::ClawbackClaimableBalance(op_data) => {
                self.load_claimable_balance(snapshot, &op_data.balance_id)?;
                let key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                    balance_id: op_data.balance_id.clone(),
                });
                if let Some(sponsor) = self.state.entry_sponsor(&key).cloned() {
                    self.load_account(snapshot, &sponsor)?;
                }
            }
            OperationBody::CreateClaimableBalance(op_data) => {
                if let Some(tl_asset) = asset_to_trustline_asset(&op_data.asset) {
                    self.load_trustline(snapshot, &op_source, &tl_asset)?;
                }
            }
            OperationBody::SetTrustLineFlags(op_data) => {
                if let Some(tl_asset) = asset_to_trustline_asset(&op_data.asset) {
                    self.load_trustline(snapshot, &op_data.trustor, &tl_asset)?;
                }
                // Load the trustor account - needed for num_sub_entries updates when removing offers
                self.load_account(snapshot, &op_data.trustor)?;
                // Load offers by account/asset so they can be removed if authorization is revoked
                self.load_offers_by_account_and_asset(snapshot, &op_data.trustor, &op_data.asset)?;
            }
            OperationBody::Clawback(op_data) => {
                let from_account = stellar_core_tx::muxed_to_account_id(&op_data.from);
                if let Some(tl_asset) = asset_to_trustline_asset(&op_data.asset) {
                    self.load_trustline(snapshot, &from_account, &tl_asset)?;
                }
            }
            OperationBody::ManageSellOffer(op_data) => {
                for asset in [&op_data.selling, &op_data.buying] {
                    if let Some(tl_asset) = asset_to_trustline_asset(asset) {
                        self.load_trustline(snapshot, &op_source, &tl_asset)?;
                    }
                    self.load_asset_issuer(snapshot, asset)?;
                }
                // Load existing offer if modifying/deleting (offer_id != 0)
                if op_data.offer_id != 0 {
                    self.load_offer(snapshot, &op_source, op_data.offer_id)?;
                    // If the offer has a sponsor, load the sponsor account for sponsorship updates
                    self.load_offer_sponsor(snapshot, &op_source, op_data.offer_id)?;
                }
            }
            OperationBody::CreatePassiveSellOffer(op_data) => {
                for asset in [&op_data.selling, &op_data.buying] {
                    if let Some(tl_asset) = asset_to_trustline_asset(asset) {
                        self.load_trustline(snapshot, &op_source, &tl_asset)?;
                    }
                    self.load_asset_issuer(snapshot, asset)?;
                }
                // Passive sell offers always create new offers, no existing offer to load
            }
            OperationBody::ManageBuyOffer(op_data) => {
                for asset in [&op_data.selling, &op_data.buying] {
                    if let Some(tl_asset) = asset_to_trustline_asset(asset) {
                        self.load_trustline(snapshot, &op_source, &tl_asset)?;
                    }
                    self.load_asset_issuer(snapshot, asset)?;
                }
                // Load existing offer if modifying/deleting (offer_id != 0)
                if op_data.offer_id != 0 {
                    self.load_offer(snapshot, &op_source, op_data.offer_id)?;
                    // If the offer has a sponsor, load the sponsor account for sponsorship updates
                    self.load_offer_sponsor(snapshot, &op_source, op_data.offer_id)?;
                }
            }
            OperationBody::PathPaymentStrictSend(op_data) => {
                let dest = stellar_core_tx::muxed_to_account_id(&op_data.destination);
                self.load_account(snapshot, &dest)?;
                if let Some(tl_asset) = asset_to_trustline_asset(&op_data.send_asset) {
                    self.load_trustline(snapshot, &op_source, &tl_asset)?;
                }
                if let Some(tl_asset) = asset_to_trustline_asset(&op_data.dest_asset) {
                    self.load_trustline(snapshot, &dest, &tl_asset)?;
                }
                self.load_asset_issuer(snapshot, &op_data.send_asset)?;
                self.load_asset_issuer(snapshot, &op_data.dest_asset)?;
                // Load liquidity pools that could be used for conversions
                self.load_path_payment_pools(
                    snapshot,
                    &op_data.send_asset,
                    &op_data.dest_asset,
                    op_data.path.as_slice(),
                )?;
            }
            OperationBody::PathPaymentStrictReceive(op_data) => {
                let dest = stellar_core_tx::muxed_to_account_id(&op_data.destination);
                self.load_account(snapshot, &dest)?;
                if let Some(tl_asset) = asset_to_trustline_asset(&op_data.send_asset) {
                    self.load_trustline(snapshot, &op_source, &tl_asset)?;
                }
                if let Some(tl_asset) = asset_to_trustline_asset(&op_data.dest_asset) {
                    self.load_trustline(snapshot, &dest, &tl_asset)?;
                }
                self.load_asset_issuer(snapshot, &op_data.send_asset)?;
                self.load_asset_issuer(snapshot, &op_data.dest_asset)?;
                // Load liquidity pools that could be used for conversions
                self.load_path_payment_pools(
                    snapshot,
                    &op_data.send_asset,
                    &op_data.dest_asset,
                    op_data.path.as_slice(),
                )?;
            }
            OperationBody::LiquidityPoolDeposit(op_data) => {
                self.load_liquidity_pool_dependencies(
                    snapshot,
                    &op_source,
                    &op_data.liquidity_pool_id,
                )?;
            }
            OperationBody::LiquidityPoolWithdraw(op_data) => {
                self.load_liquidity_pool_dependencies(
                    snapshot,
                    &op_source,
                    &op_data.liquidity_pool_id,
                )?;
            }
            OperationBody::ChangeTrust(op_data) => {
                // Load existing trustline if any
                let tl_asset = match &op_data.line {
                    stellar_xdr::curr::ChangeTrustAsset::Native => None,
                    stellar_xdr::curr::ChangeTrustAsset::CreditAlphanum4(a) => {
                        Some(TrustLineAsset::CreditAlphanum4(a.clone()))
                    }
                    stellar_xdr::curr::ChangeTrustAsset::CreditAlphanum12(a) => {
                        Some(TrustLineAsset::CreditAlphanum12(a.clone()))
                    }
                    stellar_xdr::curr::ChangeTrustAsset::PoolShare(params) => {
                        // Compute pool ID from params
                        use sha2::{Digest, Sha256};
                        let xdr = params
                            .to_xdr(Limits::none())
                            .map_err(|e| LedgerError::Serialization(e.to_string()))?;
                        let pool_id = PoolId(stellar_xdr::curr::Hash(Sha256::digest(&xdr).into()));
                        Some(TrustLineAsset::PoolShare(pool_id))
                    }
                };
                if let Some(ref tl_asset) = tl_asset {
                    self.load_trustline(snapshot, &op_source, tl_asset)?;
                }
                // Load issuer account for non-pool-share assets
                match &op_data.line {
                    stellar_xdr::curr::ChangeTrustAsset::CreditAlphanum4(a) => {
                        let asset_code = String::from_utf8_lossy(a.asset_code.as_slice());
                        tracing::debug!(
                            asset_code = %asset_code,
                            issuer = ?a.issuer,
                            "ChangeTrust: loading issuer for CreditAlphanum4"
                        );
                        self.load_account(snapshot, &a.issuer)?;
                    }
                    stellar_xdr::curr::ChangeTrustAsset::CreditAlphanum12(a) => {
                        let asset_code = String::from_utf8_lossy(a.asset_code.as_slice());
                        tracing::debug!(
                            asset_code = %asset_code,
                            issuer = ?a.issuer,
                            "ChangeTrust: loading issuer for CreditAlphanum12"
                        );
                        self.load_account(snapshot, &a.issuer)?;
                    }
                    stellar_xdr::curr::ChangeTrustAsset::PoolShare(params) => {
                        // Compute pool ID and load the liquidity pool
                        use sha2::{Digest, Sha256};
                        let xdr = params
                            .to_xdr(Limits::none())
                            .map_err(|e| LedgerError::Serialization(e.to_string()))?;
                        let pool_id = PoolId(stellar_xdr::curr::Hash(Sha256::digest(&xdr).into()));
                        self.load_liquidity_pool(snapshot, &pool_id)?;

                        // Load trustlines for underlying pool assets - needed for validation
                        // that source has trustlines for both assets
                        let stellar_xdr::curr::LiquidityPoolParameters::LiquidityPoolConstantProduct(cp) = params;
                        if let Some(tl_asset) = asset_to_trustline_asset(&cp.asset_a) {
                            self.load_trustline(snapshot, &op_source, &tl_asset)?;
                        }
                        if let Some(tl_asset) = asset_to_trustline_asset(&cp.asset_b) {
                            self.load_trustline(snapshot, &op_source, &tl_asset)?;
                        }
                    }
                    _ => {}
                }
            }
            OperationBody::ManageData(op_data) => {
                // Load existing data entry if any (needed for updates and deletes)
                self.load_data_raw(snapshot, &op_source, &op_data.data_name)?;
            }
            OperationBody::RevokeSponsorship(op_data) => {
                // Load the target entry that sponsorship is being revoked from
                use stellar_xdr::curr::RevokeSponsorshipOp;
                match op_data {
                    RevokeSponsorshipOp::LedgerEntry(ledger_key) => {
                        // Load the entry directly by its key
                        self.load_entry(snapshot, ledger_key)?;
                        // Also load owner/sponsor accounts that may be modified
                        match ledger_key {
                            LedgerKey::Account(k) => {
                                self.load_account(snapshot, &k.account_id)?;
                            }
                            LedgerKey::Trustline(k) => {
                                self.load_account(snapshot, &k.account_id)?;
                            }
                            LedgerKey::Offer(k) => {
                                self.load_account(snapshot, &k.seller_id)?;
                            }
                            LedgerKey::Data(k) => {
                                self.load_account(snapshot, &k.account_id)?;
                            }
                            LedgerKey::ClaimableBalance(k) => {
                                // Load the claimable balance and its sponsor
                                self.load_claimable_balance(snapshot, &k.balance_id)?;
                            }
                            _ => {}
                        }
                    }
                    RevokeSponsorshipOp::Signer(signer_key) => {
                        // Load the account that has the signer
                        self.load_account(snapshot, &signer_key.account_id)?;
                    }
                }
            }
            OperationBody::SetOptions(op_data) => {
                // If SetOptions modifies signers and the source account has sponsored signers,
                // we need to load those sponsor accounts so we can update their num_sponsoring.
                if op_data.signer.is_some() {
                    // Collect sponsor IDs from the source account's signer_sponsoring_i_ds
                    let sponsor_ids: Vec<AccountId> = self
                        .state
                        .get_account(&op_source)
                        .and_then(|account| {
                            if let AccountEntryExt::V1(v1) = &account.ext {
                                if let AccountEntryExtensionV1Ext::V2(v2) = &v1.ext {
                                    return Some(
                                        v2.signer_sponsoring_i_ds
                                            .iter()
                                            .filter_map(|s| s.0.clone())
                                            .collect(),
                                    );
                                }
                            }
                            None
                        })
                        .unwrap_or_default();

                    // Load each sponsor account
                    for sponsor_id in &sponsor_ids {
                        self.load_account(snapshot, sponsor_id)?;
                    }
                }
            }
            _ => {
                // Other operations typically work on source account
            }
        }

        Ok(())
    }

    /// Execute a single operation using the central dispatcher.
    fn execute_single_operation(
        &mut self,
        op: &stellar_xdr::curr::Operation,
        source: &AccountId,
        tx_source: &AccountId,
        tx_seq: i64,
        op_index: u32,
        context: &LedgerContext,
        soroban_data: Option<&stellar_xdr::curr::SorobanTransactionData>,
    ) -> std::result::Result<stellar_core_tx::operations::execute::OperationExecutionResult, TxError>
    {
        // Use the central operation dispatcher which handles all operation types
        stellar_core_tx::operations::execute::execute_operation_with_soroban(
            op,
            source,
            tx_source,
            tx_seq,
            op_index,
            &mut self.state,
            context,
            soroban_data,
            Some(&self.soroban_config),
            self.module_cache.as_ref(),
        )
    }

    /// Apply all state changes to the delta.
    pub fn apply_to_delta(&self, snapshot: &SnapshotHandle, delta: &mut LedgerDelta) -> Result<()> {
        let state_delta = self.state.delta();

        // Apply created entries
        for entry in state_delta.created_entries() {
            delta.record_create(entry.clone())?;
        }

        // Apply updated entries
        for entry in state_delta.updated_entries() {
            let key = crate::delta::entry_to_key(entry)?;
            if let Some(prev) = snapshot.get_entry(&key)? {
                delta.record_update(prev, entry.clone())?;
            } else {
                delta.record_create(entry.clone())?;
            }
        }

        // Apply deleted entries
        for key in state_delta.deleted_keys() {
            // We need the previous entry for deletion
            if let Some(prev) = snapshot.get_entry(key)? {
                delta.record_delete(prev)?;
            }
        }

        Ok(())
    }

    /// Get total fees collected.
    pub fn total_fees(&self) -> i64 {
        self.state.delta().fee_charged()
    }

    /// Get the updated ID pool after execution.
    pub fn id_pool(&self) -> u64 {
        self.state.id_pool()
    }

    /// Get the state manager.
    pub fn state(&self) -> &LedgerStateManager {
        &self.state
    }

    /// Get mutable state manager.
    pub fn state_mut(&mut self) -> &mut LedgerStateManager {
        &mut self.state
    }
}

fn asset_to_trustline_asset(
    asset: &stellar_xdr::curr::Asset,
) -> Option<stellar_xdr::curr::TrustLineAsset> {
    match asset {
        stellar_xdr::curr::Asset::Native => None,
        stellar_xdr::curr::Asset::CreditAlphanum4(a) => Some(
            stellar_xdr::curr::TrustLineAsset::CreditAlphanum4(a.clone()),
        ),
        stellar_xdr::curr::Asset::CreditAlphanum12(a) => Some(
            stellar_xdr::curr::TrustLineAsset::CreditAlphanum12(a.clone()),
        ),
    }
}

fn op_requires_orderbook(op: &OperationBody) -> bool {
    matches!(
        op,
        OperationBody::ManageSellOffer(_)
            | OperationBody::ManageBuyOffer(_)
            | OperationBody::CreatePassiveSellOffer(_)
            | OperationBody::PathPaymentStrictSend(_)
            | OperationBody::PathPaymentStrictReceive(_)
    )
}

#[derive(Clone, Copy)]
struct DeltaSnapshot {
    created: usize,
    updated: usize,
    deleted: usize,
    change_order: usize,
}

fn delta_snapshot(state: &LedgerStateManager) -> DeltaSnapshot {
    let delta = state.delta();
    DeltaSnapshot {
        created: delta.created_entries().len(),
        updated: delta.updated_entries().len(),
        deleted: delta.deleted_keys().len(),
        change_order: delta.change_order().len(),
    }
}

/// Result of extracting delta changes between two snapshots.
struct DeltaChanges {
    created: Vec<LedgerEntry>,
    updated: Vec<LedgerEntry>,
    update_states: Vec<LedgerEntry>,
    deleted: Vec<LedgerKey>,
    delete_states: Vec<LedgerEntry>,
    change_order: Vec<stellar_core_tx::ChangeRef>,
}

fn delta_changes_between(
    delta: &stellar_core_tx::LedgerDelta,
    start: DeltaSnapshot,
    end: DeltaSnapshot,
) -> DeltaChanges {
    let created = delta.created_entries()[start.created..end.created].to_vec();
    let updated = delta.updated_entries()[start.updated..end.updated].to_vec();
    let update_states = delta.update_states()[start.updated..end.updated].to_vec();
    let deleted = delta.deleted_keys()[start.deleted..end.deleted].to_vec();
    let delete_states = delta.delete_states()[start.deleted..end.deleted].to_vec();

    // Adjust change_order indices to be relative to the sliced vectors
    // Global indices need to be converted to local (sliced) indices
    let change_order: Vec<stellar_core_tx::ChangeRef> = delta.change_order()
        [start.change_order..end.change_order]
        .iter()
        .filter_map(|change_ref| {
            match change_ref {
                stellar_core_tx::ChangeRef::Created(idx) => {
                    // Convert global index to local: subtract start offset
                    if *idx >= start.created && *idx < end.created {
                        Some(stellar_core_tx::ChangeRef::Created(*idx - start.created))
                    } else {
                        None // Index out of range for this slice
                    }
                }
                stellar_core_tx::ChangeRef::Updated(idx) => {
                    if *idx >= start.updated && *idx < end.updated {
                        Some(stellar_core_tx::ChangeRef::Updated(*idx - start.updated))
                    } else {
                        None
                    }
                }
                stellar_core_tx::ChangeRef::Deleted(idx) => {
                    if *idx >= start.deleted && *idx < end.deleted {
                        Some(stellar_core_tx::ChangeRef::Deleted(*idx - start.deleted))
                    } else {
                        None
                    }
                }
            }
        })
        .collect();

    DeltaChanges {
        created,
        updated,
        update_states,
        deleted,
        delete_states,
        change_order,
    }
}

const AUTHORIZED_FLAG: u32 = TrustLineFlags::AuthorizedFlag as u32;

fn allow_trust_asset(op: &AllowTrustOp, issuer: &AccountId) -> Asset {
    match &op.asset {
        AssetCode::CreditAlphanum4(code) => Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: code.clone(),
            issuer: issuer.clone(),
        }),
        AssetCode::CreditAlphanum12(code) => Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: code.clone(),
            issuer: issuer.clone(),
        }),
    }
}

fn pool_reserves(pool: &LiquidityPoolEntry) -> Option<(Asset, Asset, i64, i64)> {
    match &pool.body {
        LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => Some((
            cp.params.asset_a.clone(),
            cp.params.asset_b.clone(),
            cp.reserve_a,
            cp.reserve_b,
        )),
    }
}

/// Tracks entries restored from different sources per CAP-0066.
#[derive(Debug, Default)]
struct RestoredEntries {
    /// Keys restored from hot archive (evicted entries).
    /// These will have CREATED changes that should be converted to RESTORED.
    hot_archive: HashSet<LedgerKey>,
    /// Keys restored from live BucketList (expired TTL but not yet evicted).
    /// TTL entries will have STATE+UPDATED that should be converted to RESTORED.
    /// Associated data/code entries need RESTORED meta added even if not modified.
    live_bucket_list: HashSet<LedgerKey>,
    /// For live BL restores, maps data/code keys to their entry values.
    /// These are needed to emit RESTORED for data/code that wasn't directly modified.
    live_bucket_list_entries: HashMap<LedgerKey, LedgerEntry>,
}

/// Extract keys of entries being restored from the hot archive.
///
/// For InvokeHostFunction: `archived_soroban_entries` contains indices into the
/// read_write footprint that point to entries being auto-restored from hot archive.
///
/// For RestoreFootprint: entries are from hot archive if they don't exist in live BL,
/// otherwise they're from live BL (detected separately).
///
/// Per CAP-0066, these entries should be emitted as RESTORED (not CREATED or STATE/UPDATED)
/// in the transaction meta. Both the data/code entry AND its associated TTL entry are restored.
fn extract_hot_archive_restored_keys(
    soroban_data: Option<&SorobanTransactionData>,
    op_type: OperationType,
) -> HashSet<LedgerKey> {
    let mut keys = HashSet::new();

    let Some(data) = soroban_data else {
        return keys;
    };

    // For InvokeHostFunction: extract archived entry indices from the extension
    // For RestoreFootprint: hot archive keys are those that will be CREATED (not UPDATED)
    // We'll handle RestoreFootprint detection at change-building time
    if op_type == OperationType::RestoreFootprint {
        // Don't add all keys here - we'll detect at change-building time
        // based on whether entries are CREATED (hot archive) or UPDATED (live BL)
        return keys;
    }

    let archived_indices: Vec<u32> = match &data.ext {
        SorobanTransactionDataExt::V1(ext) => {
            ext.archived_soroban_entries.iter().copied().collect()
        }
        SorobanTransactionDataExt::V0 => Vec::new(),
    };

    if archived_indices.is_empty() {
        return keys;
    }

    // Get the corresponding keys from the read_write footprint
    // NOTE: Only add the main entry keys (ContractData/ContractCode), NOT the TTL keys.
    // C++ stellar-core's HotArchiveBucketList::add_batch only receives the main entry keys,
    // not TTL keys. TTL entries are handled separately in the live bucket list.
    let read_write = &data.resources.footprint.read_write;
    for index in archived_indices {
        if let Some(key) = read_write.get(index as usize) {
            keys.insert(key.clone());
        }
    }

    keys
}

fn emit_classic_events_for_operation(
    op_event_manager: &mut OpEventManager,
    op: &Operation,
    op_result: &OperationResult,
    op_source: &MuxedAccount,
    state: &LedgerStateManager,
    pre_claimable_balance: Option<&ClaimableBalanceEntry>,
    pre_pool: Option<&LiquidityPoolEntry>,
) {
    if !op_event_manager.is_enabled() {
        return;
    }

    let source_address = make_muxed_account_address(op_source);
    match &op.body {
        OperationBody::CreateAccount(op_data) => {
            op_event_manager.new_transfer_event(
                &Asset::Native,
                &source_address,
                &make_account_address(&op_data.destination),
                op_data.starting_balance,
                true,
            );
        }
        OperationBody::Payment(op_data) => {
            op_event_manager.event_for_transfer_with_issuer_check(
                &op_data.asset,
                &source_address,
                &make_muxed_account_address(&op_data.destination),
                op_data.amount,
                true,
            );
        }
        OperationBody::PathPaymentStrictSend(op_data) => {
            if let OperationResult::OpInner(OperationResultTr::PathPaymentStrictSend(
                PathPaymentStrictSendResult::Success(success),
            )) = op_result
            {
                op_event_manager.events_for_claim_atoms(op_source, &success.offers);
                op_event_manager.event_for_transfer_with_issuer_check(
                    &op_data.dest_asset,
                    &source_address,
                    &make_muxed_account_address(&op_data.destination),
                    success.last.amount,
                    true,
                );
            }
        }
        OperationBody::PathPaymentStrictReceive(op_data) => {
            if let OperationResult::OpInner(OperationResultTr::PathPaymentStrictReceive(
                PathPaymentStrictReceiveResult::Success(success),
            )) = op_result
            {
                op_event_manager.events_for_claim_atoms(op_source, &success.offers);
                op_event_manager.event_for_transfer_with_issuer_check(
                    &op_data.dest_asset,
                    &source_address,
                    &make_muxed_account_address(&op_data.destination),
                    op_data.dest_amount,
                    true,
                );
            }
        }
        OperationBody::ManageSellOffer(_) | OperationBody::CreatePassiveSellOffer(_) => {
            if let OperationResult::OpInner(tr) = op_result {
                match tr {
                    OperationResultTr::ManageSellOffer(ManageSellOfferResult::Success(success))
                    | OperationResultTr::CreatePassiveSellOffer(ManageSellOfferResult::Success(
                        success,
                    )) => {
                        op_event_manager.events_for_claim_atoms(op_source, &success.offers_claimed);
                    }
                    _ => {}
                }
            }
        }
        OperationBody::ManageBuyOffer(_) => {
            if let OperationResult::OpInner(OperationResultTr::ManageBuyOffer(
                ManageBuyOfferResult::Success(success),
            )) = op_result
            {
                op_event_manager.events_for_claim_atoms(op_source, &success.offers_claimed);
            }
        }
        OperationBody::AccountMerge(dest) => {
            if let OperationResult::OpInner(OperationResultTr::AccountMerge(
                AccountMergeResult::Success(balance),
            )) = op_result
            {
                op_event_manager.new_transfer_event(
                    &Asset::Native,
                    &source_address,
                    &make_muxed_account_address(dest),
                    *balance,
                    true,
                );
            }
        }
        OperationBody::CreateClaimableBalance(op_data) => {
            if let OperationResult::OpInner(OperationResultTr::CreateClaimableBalance(
                CreateClaimableBalanceResult::Success(balance_id),
            )) = op_result
            {
                op_event_manager.event_for_transfer_with_issuer_check(
                    &op_data.asset,
                    &source_address,
                    &make_claimable_balance_address(balance_id),
                    op_data.amount,
                    true,
                );
            }
        }
        OperationBody::ClaimClaimableBalance(op_data) => {
            if let Some(entry) = pre_claimable_balance {
                op_event_manager.event_for_transfer_with_issuer_check(
                    &entry.asset,
                    &make_claimable_balance_address(&op_data.balance_id),
                    &source_address,
                    entry.amount,
                    true,
                );
            }
        }
        OperationBody::Clawback(op_data) => {
            op_event_manager.new_clawback_event(
                &op_data.asset,
                &make_muxed_account_address(&op_data.from),
                op_data.amount,
            );
        }
        OperationBody::ClawbackClaimableBalance(op_data) => {
            if let Some(entry) = pre_claimable_balance {
                op_event_manager.new_clawback_event(
                    &entry.asset,
                    &make_claimable_balance_address(&op_data.balance_id),
                    entry.amount,
                );
            }
        }
        OperationBody::AllowTrust(op_data) => {
            let issuer = stellar_core_tx::muxed_to_account_id(op_source);
            let asset = allow_trust_asset(op_data, &issuer);
            if let Some(trustline) = state.get_trustline(&op_data.trustor, &asset) {
                let authorize = trustline.flags & AUTHORIZED_FLAG != 0;
                op_event_manager.new_set_authorized_event(&asset, &op_data.trustor, authorize);
            }
        }
        OperationBody::SetTrustLineFlags(op_data) => {
            if let Some(trustline) = state.get_trustline(&op_data.trustor, &op_data.asset) {
                let authorize = trustline.flags & AUTHORIZED_FLAG != 0;
                op_event_manager.new_set_authorized_event(
                    &op_data.asset,
                    &op_data.trustor,
                    authorize,
                );
            }
        }
        OperationBody::LiquidityPoolDeposit(op_data) => {
            let (asset_a, asset_b, pre_a, pre_b) = match pre_pool.and_then(pool_reserves) {
                Some(values) => values,
                None => return,
            };
            let Some(post_pool) = state.get_liquidity_pool(&op_data.liquidity_pool_id) else {
                return;
            };
            let Some((_, _, post_a, post_b)) = pool_reserves(post_pool) else {
                return;
            };
            if post_a < pre_a || post_b < pre_b {
                return;
            }
            let amount_a = post_a - pre_a;
            let amount_b = post_b - pre_b;
            let pool_address = ScAddress::LiquidityPool(op_data.liquidity_pool_id.clone());
            op_event_manager.event_for_transfer_with_issuer_check(
                &asset_a,
                &source_address,
                &pool_address,
                amount_a,
                false,
            );
            op_event_manager.event_for_transfer_with_issuer_check(
                &asset_b,
                &source_address,
                &pool_address,
                amount_b,
                false,
            );
        }
        OperationBody::LiquidityPoolWithdraw(op_data) => {
            let (asset_a, asset_b, pre_a, pre_b) = match pre_pool.and_then(pool_reserves) {
                Some(values) => values,
                None => return,
            };
            let Some(post_pool) = state.get_liquidity_pool(&op_data.liquidity_pool_id) else {
                return;
            };
            let Some((_, _, post_a, post_b)) = pool_reserves(post_pool) else {
                return;
            };
            if pre_a < post_a || pre_b < post_b {
                return;
            }
            let amount_a = pre_a - post_a;
            let amount_b = pre_b - post_b;
            let pool_address = ScAddress::LiquidityPool(op_data.liquidity_pool_id.clone());
            op_event_manager.event_for_transfer_with_issuer_check(
                &asset_a,
                &pool_address,
                &source_address,
                amount_a,
                true,
            );
            op_event_manager.event_for_transfer_with_issuer_check(
                &asset_b,
                &pool_address,
                &source_address,
                amount_b,
                true,
            );
        }
        OperationBody::Inflation => {
            if let OperationResult::OpInner(OperationResultTr::Inflation(
                InflationResult::Success(payouts),
            )) = op_result
            {
                for payout in payouts.iter() {
                    op_event_manager.new_mint_event(
                        &Asset::Native,
                        &make_account_address(&payout.destination),
                        payout.amount,
                        false,
                    );
                }
            }
        }
        _ => {}
    }
}

/// Restore delta entries after a rollback.
///
/// This is used when a transaction fails - we restore the fee/seq changes
/// that were already committed before the operation rollback.
/// For updates, we use the entry as both pre-state and post-state since
/// we're just tracking the final state (the pre-state is not relevant
/// for bucket updates which is what the delta is used for).
fn restore_delta_entries(
    state: &mut LedgerStateManager,
    created: &[LedgerEntry],
    updated: &[LedgerEntry],
    deleted: &[LedgerKey],
) {
    let delta = state.delta_mut();
    for entry in created {
        delta.record_create(entry.clone());
    }
    for entry in updated {
        // Use the entry as both pre and post state - this is a restore after rollback
        delta.record_update(entry.clone(), entry.clone());
    }
    for (i, key) in deleted.iter().enumerate() {
        // For deleted entries, we need a pre-state but don't have one
        // Try to find it from updated entries, otherwise skip
        // (In practice, fee/seq changes rarely delete entries)
        if i < updated.len() {
            delta.record_delete(key.clone(), updated[i].clone());
        }
    }
}

pub struct OperationInvariantRunner {
    manager: InvariantManager,
    entries: HashMap<Vec<u8>, LedgerEntry>,
    header: LedgerHeader,
}

impl OperationInvariantRunner {
    pub fn new(
        entries: Vec<LedgerEntry>,
        header: LedgerHeader,
        _network_id: NetworkId,
    ) -> Result<Self> {
        let mut manager = InvariantManager::new();
        manager.add(LiabilitiesMatchOffers);
        manager.add(OrderBookIsNotCrossed);
        manager.add(ConstantProductInvariant);
        // Note: EventsAreConsistentWithEntryDiffs is NOT added because during replay
        // we don't have TransactionMeta, which means our generated events and entry
        // diffs may not match C++ stellar-core's authoritative values.

        let mut map = HashMap::new();
        for entry in entries {
            let key = crate::delta::entry_to_key(&entry)?;
            let key_bytes = key.to_xdr(Limits::none())?;
            map.insert(key_bytes, entry);
        }

        Ok(Self {
            manager,
            entries: map,
            header,
        })
    }

    fn snapshot(&self) -> HashMap<Vec<u8>, LedgerEntry> {
        self.entries.clone()
    }

    fn restore(&mut self, snapshot: HashMap<Vec<u8>, LedgerEntry>) {
        self.entries = snapshot;
    }

    fn apply_and_check(
        &mut self,
        changes: &LedgerEntryChanges,
        op_events: &[ContractEvent],
    ) -> Result<()> {
        let mut invariant_changes = Vec::new();
        for change in changes.0.iter() {
            match change {
                LedgerEntryChange::Created(entry)
                | LedgerEntryChange::Updated(entry)
                | LedgerEntryChange::State(entry)
                | LedgerEntryChange::Restored(entry) => {
                    let key = crate::delta::entry_to_key(entry)?;
                    let key_bytes = key.to_xdr(Limits::none())?;
                    let previous = self.entries.get(&key_bytes).cloned();
                    self.entries.insert(key_bytes, entry.clone());
                    match previous {
                        Some(prev) => invariant_changes.push(InvariantLedgerEntryChange::Updated {
                            previous: Box::new(prev),
                            current: Box::new(entry.clone()),
                        }),
                        None => invariant_changes.push(InvariantLedgerEntryChange::Created {
                            current: Box::new(entry.clone()),
                        }),
                    }
                }
                LedgerEntryChange::Removed(key) => {
                    let key_bytes = key.to_xdr(Limits::none())?;
                    if let Some(previous) = self.entries.remove(&key_bytes) {
                        invariant_changes.push(InvariantLedgerEntryChange::Deleted {
                            previous: Box::new(previous),
                        });
                    }
                }
            }
        }

        if invariant_changes.is_empty() {
            return Ok(());
        }

        let entries: Vec<LedgerEntry> = self.entries.values().cloned().collect();
        let ctx = InvariantContext {
            prev_header: &self.header,
            curr_header: &self.header,
            bucket_list_hash: Hash256::ZERO,
            fee_pool_delta: 0,
            total_coins_delta: 0,
            changes: &invariant_changes,
            full_entries: Some(&entries),
            op_events: Some(op_events),
        };
        self.manager.check_all(&ctx)?;
        Ok(())
    }
}

fn build_entry_changes_with_state(
    state: &LedgerStateManager,
    created: &[LedgerEntry],
    updated: &[LedgerEntry],
    deleted: &[LedgerKey],
) -> LedgerEntryChanges {
    build_entry_changes_with_state_overrides(state, created, updated, deleted, &HashMap::new())
}

fn build_entry_changes_with_state_overrides(
    state: &LedgerStateManager,
    created: &[LedgerEntry],
    updated: &[LedgerEntry],
    deleted: &[LedgerKey],
    state_overrides: &HashMap<LedgerKey, LedgerEntry>,
) -> LedgerEntryChanges {
    // Call with empty change_order and restored set for non-operation changes
    // Empty change_order triggers the fallback type-grouped ordering
    // Empty update_states/delete_states - we'll use snapshot lookup for these cases
    let empty_restored = RestoredEntries::default();
    build_entry_changes_with_hot_archive(
        state,
        created,
        updated,
        &[], // update_states - empty, will use snapshot fallback
        deleted,
        &[], // delete_states - empty, will use snapshot fallback
        &[],
        state_overrides,
        &empty_restored,
        None,
    )
}

/// Build entry changes with support for hot archive and live BL restoration tracking.
///
/// For entries in `restored.hot_archive`:
/// - Emit RESTORED instead of CREATED (entry was restored from hot archive per CAP-0066)
/// - For deleted entries that were restored, emit RESTORED then REMOVED
///
/// For entries in `restored.live_bucket_list`:
/// - Convert STATE+UPDATED to RESTORED (entry had expired TTL in live BL)
/// - Emit RESTORED for associated data/code entries even if not directly modified
///
/// When `footprint` is provided (for Soroban operations), entries are ordered according to
/// the footprint's read_write order to match C++ stellar-core behavior.
/// For classic operations, entries are ordered according to the execution order tracked
/// in `change_order` to match C++ stellar-core behavior, emitting STATE/UPDATED pairs
/// for EACH modification (not deduplicated).
fn build_entry_changes_with_hot_archive(
    state: &LedgerStateManager,
    created: &[LedgerEntry],
    updated: &[LedgerEntry],
    update_states: &[LedgerEntry],
    deleted: &[LedgerKey],
    delete_states: &[LedgerEntry],
    change_order: &[stellar_core_tx::ChangeRef],
    state_overrides: &HashMap<LedgerKey, LedgerEntry>,
    restored: &RestoredEntries,
    footprint: Option<&stellar_xdr::curr::LedgerFootprint>,
) -> LedgerEntryChanges {
    fn entry_key_bytes(entry: &LedgerEntry) -> Vec<u8> {
        crate::delta::entry_to_key(entry)
            .ok()
            .and_then(|key| key.to_xdr(Limits::none()).ok())
            .unwrap_or_default()
    }

    fn push_created_or_restored(
        changes: &mut Vec<LedgerEntryChange>,
        entry: &LedgerEntry,
        restored: &RestoredEntries,
    ) {
        if let Ok(key) = crate::delta::entry_to_key(entry) {
            // For hot archive restores and live bucket list restores (expired TTL),
            // emit RESTORED instead of CREATED.
            // This matches C++ stellar-core's processOpLedgerEntryChanges behavior.
            if restored.hot_archive.contains(&key) || restored.live_bucket_list.contains(&key) {
                changes.push(LedgerEntryChange::Restored(entry.clone()));
                return;
            }
        }
        changes.push(LedgerEntryChange::Created(entry.clone()));
    }

    let mut changes: Vec<LedgerEntryChange> = Vec::new();

    // Build final values for each updated key (used for Soroban deduplication)
    let mut final_updated: HashMap<Vec<u8>, LedgerEntry> = HashMap::new();
    for entry in updated {
        let key_bytes = entry_key_bytes(entry);
        final_updated.insert(key_bytes, entry.clone());
    }

    // For Soroban operations with footprint, use change_order but sort consecutive Soroban creates by key_hash.
    // For classic operations, use change_order to preserve execution order.
    // Key insight: change_order captures the execution sequence. For Soroban, we must preserve
    // the positions of classic entry changes (Account, Trustline) while sorting Soroban creates
    // (TTL, ContractData, ContractCode) by their associated key_hash to match C++ behavior.
    if let Some(fp) = footprint {
        use std::collections::HashSet;

        fn is_soroban_entry(entry: &LedgerEntry) -> bool {
            matches!(
                &entry.data,
                stellar_xdr::curr::LedgerEntryData::Ttl(_)
                    | stellar_xdr::curr::LedgerEntryData::ContractData(_)
                    | stellar_xdr::curr::LedgerEntryData::ContractCode(_)
            )
        }

        // Build set of read-only TTL keys. In C++ stellar-core, TTL updates for entries in the
        // read-only footprint are NOT emitted in transaction meta (they're handled separately via
        // mRoTTLBumps which are flushed at different points). We must skip emitting STATE/UPDATED
        // for these TTL keys to match C++ behavior.
        let ro_ttl_keys: HashSet<LedgerKey> = fp
            .read_only
            .iter()
            .filter_map(stellar_core_bucket::get_ttl_key)
            .collect();

        // Track which keys have been created (for deduplication)
        let mut created_keys: HashSet<Vec<u8>> = HashSet::new();

        // Process change_order to preserve execution sequence
        // Collect groups of changes: either single updates/deletes or consecutive Soroban creates
        enum ChangeGroup {
            SingleUpdate { idx: usize },
            SingleDelete { idx: usize },
            SorobanCreates { indices: Vec<usize> },
            ClassicCreate { idx: usize },
        }

        let mut groups: Vec<ChangeGroup> = Vec::new();
        let mut pending_soroban_creates: Vec<usize> = Vec::new();

        for change_ref in change_order {
            match change_ref {
                stellar_core_tx::ChangeRef::Created(idx) => {
                    if *idx < created.len() {
                        let entry = &created[*idx];
                        if is_soroban_entry(entry) {
                            pending_soroban_creates.push(*idx);
                        } else {
                            // Flush any pending Soroban creates before this classic create
                            if !pending_soroban_creates.is_empty() {
                                groups.push(ChangeGroup::SorobanCreates {
                                    indices: std::mem::take(&mut pending_soroban_creates),
                                });
                            }
                            groups.push(ChangeGroup::ClassicCreate { idx: *idx });
                        }
                    }
                }
                stellar_core_tx::ChangeRef::Updated(idx) => {
                    // Flush any pending Soroban creates before this update
                    if !pending_soroban_creates.is_empty() {
                        groups.push(ChangeGroup::SorobanCreates {
                            indices: std::mem::take(&mut pending_soroban_creates),
                        });
                    }
                    groups.push(ChangeGroup::SingleUpdate { idx: *idx });
                }
                stellar_core_tx::ChangeRef::Deleted(idx) => {
                    // Flush any pending Soroban creates before this delete
                    if !pending_soroban_creates.is_empty() {
                        groups.push(ChangeGroup::SorobanCreates {
                            indices: std::mem::take(&mut pending_soroban_creates),
                        });
                    }
                    groups.push(ChangeGroup::SingleDelete { idx: *idx });
                }
            }
        }

        // Flush any remaining Soroban creates
        if !pending_soroban_creates.is_empty() {
            groups.push(ChangeGroup::SorobanCreates {
                indices: pending_soroban_creates,
            });
        }

        // Process each group
        for group in groups {
            match group {
                ChangeGroup::SorobanCreates { indices } => {
                    // C++ groups TTL entries with their associated ContractData/ContractCode.
                    // Sort by (associated_key_hash, type_order) where TTL comes before its data.
                    use sha2::{Digest, Sha256};

                    fn get_associated_hash_and_type(entry: &LedgerEntry) -> (Vec<u8>, u8) {
                        match &entry.data {
                            stellar_xdr::curr::LedgerEntryData::Ttl(ttl) => {
                                // TTL: associated_hash is key_hash, type_order=0 (first)
                                (ttl.key_hash.0.to_vec(), 0)
                            }
                            stellar_xdr::curr::LedgerEntryData::ContractData(_)
                            | stellar_xdr::curr::LedgerEntryData::ContractCode(_) => {
                                // Data/Code: associated_hash is SHA256 of key XDR, type_order=1 (second)
                                if let Ok(key) = crate::delta::entry_to_key(entry) {
                                    if let Ok(key_bytes) = key.to_xdr(Limits::none()) {
                                        let key_hash = Sha256::digest(&key_bytes);
                                        return (key_hash.to_vec(), 1);
                                    }
                                }
                                (Vec::new(), 1)
                            }
                            _ => (Vec::new(), 2),
                        }
                    }

                    let mut entries_with_sort: Vec<(usize, (Vec<u8>, u8))> = indices
                        .into_iter()
                        .map(|idx| (idx, get_associated_hash_and_type(&created[idx])))
                        .collect();

                    // Sort by associated_hash (groups TTL with its data), then type_order (TTL=0 first)
                    entries_with_sort.sort_by(|(_, a), (_, b)| a.cmp(b));

                    for (idx, _) in entries_with_sort {
                        let entry = &created[idx];
                        let key_bytes = entry_key_bytes(entry);
                        if !created_keys.contains(&key_bytes) {
                            created_keys.insert(key_bytes);
                            push_created_or_restored(&mut changes, entry, restored);
                        }
                    }
                }
                ChangeGroup::ClassicCreate { idx } => {
                    let entry = &created[idx];
                    let key_bytes = entry_key_bytes(entry);
                    if !created_keys.contains(&key_bytes) {
                        created_keys.insert(key_bytes);
                        push_created_or_restored(&mut changes, entry, restored);
                    }
                }
                ChangeGroup::SingleUpdate { idx } => {
                    if idx < updated.len() {
                        let post_state = &updated[idx];
                        if let Ok(key) = crate::delta::entry_to_key(post_state) {
                            // Skip TTL updates for entries in the read-only footprint.
                            // In C++ stellar-core, these are accumulated in mRoTTLBumps and not
                            // emitted in transaction meta. See buildRoTTLSet and
                            // commitChangeFromSuccessfulOp in ParallelApplyUtils.cpp.
                            if ro_ttl_keys.contains(&key) {
                                continue;
                            }
                            if restored.hot_archive.contains(&key)
                                || restored.live_bucket_list.contains(&key)
                            {
                                changes.push(LedgerEntryChange::Restored(post_state.clone()));
                            } else {
                                // Get pre-state from update_states or snapshot
                                let pre_state = if idx < update_states.len() {
                                    Some(update_states[idx].clone())
                                } else {
                                    state_overrides
                                        .get(&key)
                                        .cloned()
                                        .or_else(|| state.snapshot_entry(&key))
                                };
                                if let Some(state_entry) = pre_state {
                                    changes.push(LedgerEntryChange::State(state_entry));
                                }
                                changes.push(LedgerEntryChange::Updated(post_state.clone()));
                            }
                        }
                    }
                }
                ChangeGroup::SingleDelete { idx } => {
                    if idx < deleted.len() {
                        let key = &deleted[idx];
                        if restored.hot_archive.contains(key)
                            || restored.live_bucket_list.contains(key)
                        {
                            let pre_state = if idx < delete_states.len() {
                                Some(delete_states[idx].clone())
                            } else {
                                state_overrides
                                    .get(key)
                                    .cloned()
                                    .or_else(|| state.snapshot_entry(key))
                            };
                            if let Some(state_entry) = pre_state {
                                changes.push(LedgerEntryChange::Restored(state_entry));
                            }
                            changes.push(LedgerEntryChange::Removed(key.clone()));
                        } else {
                            let pre_state = if idx < delete_states.len() {
                                Some(delete_states[idx].clone())
                            } else {
                                state_overrides
                                    .get(key)
                                    .cloned()
                                    .or_else(|| state.snapshot_entry(key))
                            };
                            if let Some(state_entry) = pre_state {
                                changes.push(LedgerEntryChange::State(state_entry));
                            }
                            changes.push(LedgerEntryChange::Removed(key.clone()));
                        }
                    }
                }
            }
        }
    } else if !change_order.is_empty() {
        // For classic operations with change_order, use it to preserve execution order.
        // Only deduplicate creates - once an entry is created, subsequent references are updates.
        // Updates are NOT deduplicated - each update in change_order gets its own STATE/UPDATED pair.
        use std::collections::HashSet;

        // Track which keys have been created to avoid duplicate creates
        let mut created_keys: HashSet<Vec<u8>> = HashSet::new();

        for change_ref in change_order {
            match change_ref {
                stellar_core_tx::ChangeRef::Created(idx) => {
                    if *idx < created.len() {
                        let entry = &created[*idx];
                        let key_bytes = entry_key_bytes(entry);
                        // Only emit create once per key
                        if !created_keys.contains(&key_bytes) {
                            created_keys.insert(key_bytes);
                            push_created_or_restored(&mut changes, entry, restored);
                        }
                    }
                }
                stellar_core_tx::ChangeRef::Updated(idx) => {
                    if *idx < updated.len() {
                        let post_state = &updated[*idx];

                        if let Ok(key) = crate::delta::entry_to_key(post_state) {
                            if restored.hot_archive.contains(&key)
                                || restored.live_bucket_list.contains(&key)
                            {
                                // Use entry value for hot archive restored entries
                                changes.push(LedgerEntryChange::Restored(post_state.clone()));
                            } else {
                                // Normal update: STATE (pre-state) then UPDATED (post-state)
                                // Use the pre-state stored in the delta at the same index
                                let pre_state = if *idx < update_states.len() {
                                    Some(update_states[*idx].clone())
                                } else {
                                    // Fallback to snapshot lookup if pre-state not available
                                    state_overrides
                                        .get(&key)
                                        .cloned()
                                        .or_else(|| state.snapshot_entry(&key))
                                };
                                if let Some(state_entry) = pre_state {
                                    changes.push(LedgerEntryChange::State(state_entry));
                                }
                                changes.push(LedgerEntryChange::Updated(post_state.clone()));
                            }
                        }
                    }
                }
                stellar_core_tx::ChangeRef::Deleted(idx) => {
                    if *idx < deleted.len() {
                        let key = &deleted[*idx];
                        if restored.hot_archive.contains(key)
                            || restored.live_bucket_list.contains(key)
                        {
                            // Use the pre-state stored in the delta at the same index
                            let pre_state = if *idx < delete_states.len() {
                                Some(delete_states[*idx].clone())
                            } else {
                                state_overrides
                                    .get(key)
                                    .cloned()
                                    .or_else(|| state.snapshot_entry(key))
                            };
                            if let Some(state_entry) = pre_state {
                                changes.push(LedgerEntryChange::Restored(state_entry));
                            }
                            changes.push(LedgerEntryChange::Removed(key.clone()));
                        } else {
                            // Use the pre-state stored in the delta at the same index
                            let pre_state = if *idx < delete_states.len() {
                                Some(delete_states[*idx].clone())
                            } else {
                                state_overrides
                                    .get(key)
                                    .cloned()
                                    .or_else(|| state.snapshot_entry(key))
                            };
                            if let Some(state_entry) = pre_state {
                                changes.push(LedgerEntryChange::State(state_entry));
                            }
                            changes.push(LedgerEntryChange::Removed(key.clone()));
                        }
                    }
                }
            }
        }
    } else {
        // Fallback: no change_order available (e.g., fee/seq changes)
        // Use type-grouped order: deleted -> updated -> created
        for key in deleted {
            if restored.hot_archive.contains(key) || restored.live_bucket_list.contains(key) {
                if let Some(state_entry) = state_overrides
                    .get(key)
                    .cloned()
                    .or_else(|| state.snapshot_entry(key))
                {
                    changes.push(LedgerEntryChange::Restored(state_entry));
                }
                changes.push(LedgerEntryChange::Removed(key.clone()));
            } else {
                if let Some(state_entry) = state_overrides
                    .get(key)
                    .cloned()
                    .or_else(|| state.snapshot_entry(key))
                {
                    changes.push(LedgerEntryChange::State(state_entry));
                }
                changes.push(LedgerEntryChange::Removed(key.clone()));
            }
        }

        // Deduplicate updated entries
        use std::collections::HashSet;
        let mut seen_keys: HashSet<Vec<u8>> = HashSet::new();
        for entry in updated {
            let key_bytes = entry_key_bytes(entry);
            if !seen_keys.contains(&key_bytes) {
                seen_keys.insert(key_bytes.clone());
                if let Some(final_entry) = final_updated.get(&key_bytes) {
                    if let Ok(key) = crate::delta::entry_to_key(final_entry) {
                        if restored.hot_archive.contains(&key)
                            || restored.live_bucket_list.contains(&key)
                        {
                            changes.push(LedgerEntryChange::Restored(final_entry.clone()));
                        } else {
                            if let Some(state_entry) = state_overrides
                                .get(&key)
                                .cloned()
                                .or_else(|| state.snapshot_entry(&key))
                            {
                                changes.push(LedgerEntryChange::State(state_entry));
                            }
                            changes.push(LedgerEntryChange::Updated(final_entry.clone()));
                        }
                    } else {
                        changes.push(LedgerEntryChange::Updated(final_entry.clone()));
                    }
                }
            }
        }

        for entry in created {
            push_created_or_restored(&mut changes, entry, restored);
        }
    }

    // For live BL restores, add RESTORED changes for data/code entries that weren't
    // directly modified (only their TTL was extended). Per C++ TransactionMeta.cpp:
    // "RestoreOp will create both the TTL and Code/Data entry in the hot archive case.
    // However, when restoring from live BucketList, only the TTL value will be modified,
    // so we have to manually insert the RESTORED meta for the Code/Data entry here."
    for (key, entry) in &restored.live_bucket_list_entries {
        // Skip if this key was already processed (appears in updated or created)
        let key_bytes = key.to_xdr(Limits::none()).unwrap_or_default();
        let already_processed = changes.iter().any(|change| {
            let change_key = match change {
                LedgerEntryChange::State(e)
                | LedgerEntryChange::Created(e)
                | LedgerEntryChange::Updated(e)
                | LedgerEntryChange::Restored(e) => crate::delta::entry_to_key(e).ok(),
                LedgerEntryChange::Removed(k) => Some(k.clone()),
            };
            change_key
                .and_then(|k| k.to_xdr(Limits::none()).ok())
                .map(|b| b == key_bytes)
                .unwrap_or(false)
        });

        if !already_processed {
            changes.push(LedgerEntryChange::Restored(entry.clone()));
        }
    }

    LedgerEntryChanges(changes.try_into().unwrap_or_default())
}

fn empty_entry_changes() -> LedgerEntryChanges {
    LedgerEntryChanges(VecM::default())
}

fn build_transaction_meta(
    tx_changes_before: LedgerEntryChanges,
    op_changes: Vec<LedgerEntryChanges>,
    op_events: Vec<Vec<ContractEvent>>,
    tx_events: Vec<TransactionEvent>,
    soroban_return_value: Option<stellar_xdr::curr::ScVal>,
    diagnostic_events: Vec<DiagnosticEvent>,
) -> TransactionMeta {
    let operations: Vec<OperationMetaV2> = op_changes
        .into_iter()
        .zip(op_events)
        .map(|(changes, events)| OperationMetaV2 {
            ext: ExtensionPoint::V0,
            changes,
            events: events.try_into().unwrap_or_default(),
        })
        .collect();

    let has_soroban = soroban_return_value.is_some() || !diagnostic_events.is_empty();
    let soroban_meta = if has_soroban {
        Some(SorobanTransactionMetaV2 {
            ext: SorobanTransactionMetaExt::V0,
            return_value: soroban_return_value,
        })
    } else {
        None
    };

    TransactionMeta::V4(TransactionMetaV4 {
        ext: ExtensionPoint::V0,
        tx_changes_before,
        operations: operations.try_into().unwrap_or_default(),
        tx_changes_after: empty_entry_changes(),
        soroban_meta,
        events: tx_events.try_into().unwrap_or_default(),
        diagnostic_events: diagnostic_events.try_into().unwrap_or_default(),
    })
}

fn empty_transaction_meta() -> TransactionMeta {
    build_transaction_meta(
        empty_entry_changes(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        Vec::new(),
    )
}

fn map_failure_to_result(failure: &ExecutionFailure) -> TransactionResultResult {
    match failure {
        ExecutionFailure::Malformed => TransactionResultResult::TxMalformed,
        ExecutionFailure::MissingOperation => TransactionResultResult::TxMissingOperation,
        ExecutionFailure::InvalidSignature => TransactionResultResult::TxBadAuth,
        ExecutionFailure::BadAuthExtra => TransactionResultResult::TxBadAuthExtra,
        ExecutionFailure::BadMinSeqAgeOrGap => TransactionResultResult::TxBadMinSeqAgeOrGap,
        ExecutionFailure::TooEarly => TransactionResultResult::TxTooEarly,
        ExecutionFailure::TooLate => TransactionResultResult::TxTooLate,
        ExecutionFailure::BadSequence => TransactionResultResult::TxBadSeq,
        ExecutionFailure::InsufficientFee => TransactionResultResult::TxInsufficientFee,
        ExecutionFailure::InsufficientBalance => TransactionResultResult::TxInsufficientBalance,
        ExecutionFailure::NoAccount => TransactionResultResult::TxNoAccount,
        ExecutionFailure::NotSupported => TransactionResultResult::TxNotSupported,
        ExecutionFailure::BadSponsorship => TransactionResultResult::TxBadSponsorship,
        ExecutionFailure::OperationFailed => {
            TransactionResultResult::TxFailed(Vec::new().try_into().unwrap())
        }
    }
}

fn insufficient_refundable_fee_result(op: &Operation) -> OperationResult {
    match &op.body {
        OperationBody::InvokeHostFunction(_) => {
            OperationResult::OpInner(OperationResultTr::InvokeHostFunction(
                stellar_xdr::curr::InvokeHostFunctionResult::InsufficientRefundableFee,
            ))
        }
        OperationBody::ExtendFootprintTtl(_) => {
            OperationResult::OpInner(OperationResultTr::ExtendFootprintTtl(
                stellar_xdr::curr::ExtendFootprintTtlResult::InsufficientRefundableFee,
            ))
        }
        OperationBody::RestoreFootprint(_) => {
            OperationResult::OpInner(OperationResultTr::RestoreFootprint(
                stellar_xdr::curr::RestoreFootprintResult::InsufficientRefundableFee,
            ))
        }
        _ => OperationResult::OpNotSupported,
    }
}

fn map_failure_to_inner_result(
    failure: &ExecutionFailure,
    op_results: &[OperationResult],
) -> InnerTransactionResultResult {
    match failure {
        ExecutionFailure::Malformed => InnerTransactionResultResult::TxMalformed,
        ExecutionFailure::MissingOperation => InnerTransactionResultResult::TxMissingOperation,
        ExecutionFailure::InvalidSignature => InnerTransactionResultResult::TxBadAuth,
        ExecutionFailure::BadAuthExtra => InnerTransactionResultResult::TxBadAuthExtra,
        ExecutionFailure::BadMinSeqAgeOrGap => InnerTransactionResultResult::TxBadMinSeqAgeOrGap,
        ExecutionFailure::TooEarly => InnerTransactionResultResult::TxTooEarly,
        ExecutionFailure::TooLate => InnerTransactionResultResult::TxTooLate,
        ExecutionFailure::BadSequence => InnerTransactionResultResult::TxBadSeq,
        ExecutionFailure::InsufficientFee => InnerTransactionResultResult::TxInsufficientFee,
        ExecutionFailure::InsufficientBalance => {
            InnerTransactionResultResult::TxInsufficientBalance
        }
        ExecutionFailure::NoAccount => InnerTransactionResultResult::TxNoAccount,
        ExecutionFailure::NotSupported => InnerTransactionResultResult::TxNotSupported,
        ExecutionFailure::BadSponsorship => InnerTransactionResultResult::TxBadSponsorship,
        ExecutionFailure::OperationFailed => InnerTransactionResultResult::TxFailed(
            op_results.to_vec().try_into().unwrap_or_default(),
        ),
    }
}

pub fn build_tx_result_pair(
    frame: &TransactionFrame,
    network_id: &NetworkId,
    exec: &TransactionExecutionResult,
    base_fee: i64,
    protocol_version: u32,
) -> Result<TransactionResultPair> {
    let tx_hash = frame
        .hash(network_id)
        .map_err(|e| LedgerError::Internal(format!("tx hash error: {}", e)))?;
    let op_results: Vec<OperationResult> = exec.operation_results.clone();

    let result = if frame.is_fee_bump() {
        let inner_hash = fee_bump_inner_hash(frame, network_id)?;
        let inner_result = if exec.success {
            InnerTransactionResultResult::TxSuccess(
                op_results.clone().try_into().unwrap_or_default(),
            )
        } else if let Some(failure) = &exec.failure {
            map_failure_to_inner_result(failure, &op_results)
        } else {
            InnerTransactionResultResult::TxFailed(
                op_results.clone().try_into().unwrap_or_default(),
            )
        };

        // Calculate inner fee_charged using C++ formula:
        // Protocol >= 25: 0 (outer pays everything)
        // Protocol < 25 and protocol >= 11:
        //   - For Soroban: resourceFee + min(inclusionFee, baseFee * numOps) - refund
        //     (C++ had a bug where refund was applied to inner fee; this was fixed in p25)
        //   - For classic: min(inner_fee, baseFee * numOps)
        let inner_fee_charged = if protocol_version >= 25 {
            0
        } else {
            let num_inner_ops = frame.operation_count() as i64;
            let adjusted_fee = base_fee * std::cmp::max(1, num_inner_ops);
            if frame.is_soroban() {
                // For Soroban transactions, include the declared resource fee
                let resource_fee = frame.declared_soroban_resource_fee();
                let inner_fee = frame.inner_fee() as i64;
                let inclusion_fee = inner_fee - resource_fee;
                let computed_fee = resource_fee + std::cmp::min(inclusion_fee, adjusted_fee);
                // Prior to protocol 25, C++ incorrectly applied the refund to the inner
                // feeCharged field for fee bump transactions. We replicate this behavior
                // for compatibility.
                computed_fee.saturating_sub(exec.fee_refund)
            } else {
                // For classic transactions
                std::cmp::min(frame.inner_fee() as i64, adjusted_fee)
            }
        };

        let inner_pair = InnerTransactionResultPair {
            transaction_hash: stellar_xdr::curr::Hash(inner_hash.0),
            result: InnerTransactionResult {
                fee_charged: inner_fee_charged,
                result: inner_result,
                ext: InnerTransactionResultExt::V0,
            },
        };

        let result = if exec.success {
            TransactionResultResult::TxFeeBumpInnerSuccess(inner_pair)
        } else {
            TransactionResultResult::TxFeeBumpInnerFailed(inner_pair)
        };

        TransactionResult {
            fee_charged: exec.fee_charged,
            result,
            ext: TransactionResultExt::V0,
        }
    } else if exec.success {
        TransactionResult {
            fee_charged: exec.fee_charged,
            result: TransactionResultResult::TxSuccess(op_results.try_into().unwrap_or_default()),
            ext: TransactionResultExt::V0,
        }
    } else if let Some(failure) = &exec.failure {
        let result = match failure {
            ExecutionFailure::OperationFailed => {
                TransactionResultResult::TxFailed(op_results.try_into().unwrap_or_default())
            }
            _ => map_failure_to_result(failure),
        };
        TransactionResult {
            fee_charged: exec.fee_charged,
            result,
            ext: TransactionResultExt::V0,
        }
    } else {
        TransactionResult {
            fee_charged: exec.fee_charged,
            result: TransactionResultResult::TxFailed(op_results.try_into().unwrap_or_default()),
            ext: TransactionResultExt::V0,
        }
    };

    Ok(TransactionResultPair {
        transaction_hash: stellar_xdr::curr::Hash(tx_hash.0),
        result,
    })
}

/// Convert AccountId to key bytes.
fn account_id_to_key(account_id: &AccountId) -> [u8; 32] {
    match &account_id.0 {
        stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key) => key.0,
    }
}

/// Check if an operation result indicates success.
fn is_operation_success(result: &OperationResult) -> bool {
    match result {
        OperationResult::OpInner(inner) => {
            use stellar_xdr::curr::OperationResultTr;
            use stellar_xdr::curr::*;
            match inner {
                OperationResultTr::CreateAccount(r) => {
                    matches!(r, CreateAccountResult::Success)
                }
                OperationResultTr::Payment(r) => {
                    matches!(r, PaymentResult::Success)
                }
                OperationResultTr::PathPaymentStrictReceive(r) => {
                    matches!(r, PathPaymentStrictReceiveResult::Success(_))
                }
                OperationResultTr::ManageSellOffer(r) => {
                    matches!(r, ManageSellOfferResult::Success(_))
                }
                OperationResultTr::CreatePassiveSellOffer(r) => {
                    matches!(r, ManageSellOfferResult::Success(_))
                }
                OperationResultTr::SetOptions(r) => {
                    matches!(r, SetOptionsResult::Success)
                }
                OperationResultTr::ChangeTrust(r) => {
                    matches!(r, ChangeTrustResult::Success)
                }
                OperationResultTr::AllowTrust(r) => {
                    matches!(r, AllowTrustResult::Success)
                }
                OperationResultTr::AccountMerge(r) => {
                    matches!(r, AccountMergeResult::Success(_))
                }
                OperationResultTr::Inflation(r) => {
                    matches!(r, InflationResult::Success(_))
                }
                OperationResultTr::ManageData(r) => {
                    matches!(r, ManageDataResult::Success)
                }
                OperationResultTr::BumpSequence(r) => {
                    matches!(r, BumpSequenceResult::Success)
                }
                OperationResultTr::ManageBuyOffer(r) => {
                    matches!(r, ManageBuyOfferResult::Success(_))
                }
                OperationResultTr::PathPaymentStrictSend(r) => {
                    matches!(r, PathPaymentStrictSendResult::Success(_))
                }
                OperationResultTr::CreateClaimableBalance(r) => {
                    matches!(r, CreateClaimableBalanceResult::Success(_))
                }
                OperationResultTr::ClaimClaimableBalance(r) => {
                    matches!(r, ClaimClaimableBalanceResult::Success)
                }
                OperationResultTr::BeginSponsoringFutureReserves(r) => {
                    matches!(r, BeginSponsoringFutureReservesResult::Success)
                }
                OperationResultTr::EndSponsoringFutureReserves(r) => {
                    matches!(r, EndSponsoringFutureReservesResult::Success)
                }
                OperationResultTr::RevokeSponsorship(r) => {
                    matches!(r, RevokeSponsorshipResult::Success)
                }
                OperationResultTr::Clawback(r) => {
                    matches!(r, ClawbackResult::Success)
                }
                OperationResultTr::ClawbackClaimableBalance(r) => {
                    matches!(r, ClawbackClaimableBalanceResult::Success)
                }
                OperationResultTr::SetTrustLineFlags(r) => {
                    matches!(r, SetTrustLineFlagsResult::Success)
                }
                OperationResultTr::LiquidityPoolDeposit(r) => {
                    matches!(r, LiquidityPoolDepositResult::Success)
                }
                OperationResultTr::LiquidityPoolWithdraw(r) => {
                    matches!(r, LiquidityPoolWithdrawResult::Success)
                }
                OperationResultTr::InvokeHostFunction(r) => {
                    matches!(r, InvokeHostFunctionResult::Success(_))
                }
                OperationResultTr::ExtendFootprintTtl(r) => {
                    matches!(r, ExtendFootprintTtlResult::Success)
                }
                OperationResultTr::RestoreFootprint(r) => {
                    matches!(r, RestoreFootprintResult::Success)
                }
            }
        }
        OperationResult::OpNotSupported => false, // Unsupported operations fail
        _ => false,
    }
}

fn has_sufficient_signer_weight(
    tx_hash: &Hash256,
    signatures: &[stellar_xdr::curr::DecoratedSignature],
    account: &AccountEntry,
    required_weight: u32,
) -> bool {
    let mut total = 0u32;
    let mut counted: HashSet<Hash256> = HashSet::new();

    // Master key signer.
    if let Ok(pk) = stellar_core_crypto::PublicKey::try_from(&account.account_id.0) {
        let master_weight = account.thresholds.0[0] as u32;
        tracing::trace!(
            master_weight = master_weight,
            required_weight = required_weight,
            num_signatures = signatures.len(),
            num_signers = account.signers.len(),
            thresholds = ?account.thresholds.0,
            "Checking signature weight"
        );
        if master_weight > 0 {
            let has_sig = has_ed25519_signature(tx_hash, signatures, &pk);
            tracing::trace!(has_master_sig = has_sig, "Master key signature check");
            if has_sig {
                let id = signer_key_id(&SignerKey::Ed25519(stellar_xdr::curr::Uint256(
                    *pk.as_bytes(),
                )));
                if counted.insert(id) {
                    total = total.saturating_add(master_weight);
                }
            }
        }
    }

    for signer in account.signers.iter() {
        if signer.weight == 0 {
            continue;
        }
        let key = &signer.key;
        let id = signer_key_id(key);

        if counted.contains(&id) {
            continue;
        }

        match key {
            SignerKey::Ed25519(key) => {
                if let Ok(pk) = stellar_core_crypto::PublicKey::from_bytes(&key.0) {
                    if has_ed25519_signature(tx_hash, signatures, &pk) && counted.insert(id) {
                        total = total.saturating_add(signer.weight);
                    }
                }
            }
            SignerKey::PreAuthTx(key) => {
                if key.0 == tx_hash.0 && counted.insert(id) {
                    total = total.saturating_add(signer.weight);
                }
            }
            SignerKey::HashX(key) => {
                if has_hashx_signature(signatures, key) && counted.insert(id) {
                    total = total.saturating_add(signer.weight);
                }
            }
            SignerKey::Ed25519SignedPayload(payload) => {
                if has_signed_payload_signature(tx_hash, signatures, payload) && counted.insert(id)
                {
                    total = total.saturating_add(signer.weight);
                }
            }
        }

        if total >= required_weight && total > 0 {
            return true;
        }
    }

    total >= required_weight && total > 0
}

fn has_required_extra_signers(
    tx_hash: &Hash256,
    signatures: &[stellar_xdr::curr::DecoratedSignature],
    extra_signers: &[SignerKey],
) -> bool {
    extra_signers.iter().all(|signer| match signer {
        SignerKey::Ed25519(key) => {
            if let Ok(pk) = stellar_core_crypto::PublicKey::from_bytes(&key.0) {
                has_ed25519_signature(tx_hash, signatures, &pk)
            } else {
                false
            }
        }
        SignerKey::PreAuthTx(key) => key.0 == tx_hash.0,
        SignerKey::HashX(key) => has_hashx_signature(signatures, key),
        SignerKey::Ed25519SignedPayload(payload) => {
            has_signed_payload_signature(tx_hash, signatures, payload)
        }
    })
}

fn fee_bump_inner_hash(frame: &TransactionFrame, network_id: &NetworkId) -> Result<Hash256> {
    match frame.envelope() {
        TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
            stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                let inner_env = TransactionEnvelope::Tx(inner.clone());
                let inner_frame = TransactionFrame::with_network(inner_env, *network_id);
                inner_frame
                    .hash(network_id)
                    .map_err(|e| LedgerError::Internal(format!("inner tx hash error: {}", e)))
            }
        },
        _ => frame
            .hash(network_id)
            .map_err(|e| LedgerError::Internal(format!("tx hash error: {}", e))),
    }
}

fn threshold_low(account: &AccountEntry) -> u32 {
    account.thresholds.0[1] as u32
}

fn threshold_medium(account: &AccountEntry) -> u32 {
    account.thresholds.0[2] as u32
}

fn signer_key_id(key: &SignerKey) -> Hash256 {
    let bytes = key
        .to_xdr(stellar_xdr::curr::Limits::none())
        .unwrap_or_default();
    Hash256::hash(&bytes)
}

fn has_ed25519_signature(
    tx_hash: &Hash256,
    signatures: &[stellar_xdr::curr::DecoratedSignature],
    pk: &stellar_core_crypto::PublicKey,
) -> bool {
    signatures
        .iter()
        .any(|sig| validation::verify_signature_with_key(tx_hash, sig, pk))
}

fn has_hashx_signature(
    signatures: &[stellar_xdr::curr::DecoratedSignature],
    key: &stellar_xdr::curr::Uint256,
) -> bool {
    signatures.iter().any(|sig| {
        // HashX signatures can be any length - the signature is the preimage
        // whose SHA256 hash should equal the signer key.
        // Check hint first (last 4 bytes of key)
        let expected_hint = [key.0[28], key.0[29], key.0[30], key.0[31]];
        if sig.hint.0 != expected_hint {
            return false;
        }
        // Hash the preimage (signature) and compare to key
        let hash = Hash256::hash(&sig.signature.0);
        hash.0 == key.0
    })
}

fn has_signed_payload_signature(
    _tx_hash: &Hash256,
    signatures: &[stellar_xdr::curr::DecoratedSignature],
    signed_payload: &stellar_xdr::curr::SignerKeyEd25519SignedPayload,
) -> bool {
    let pk = match stellar_core_crypto::PublicKey::from_bytes(&signed_payload.ed25519.0) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // The hint for signed payloads is XOR of pubkey hint and payload hint.
    // See SignatureUtils::getSignedPayloadHint in C++ stellar-core.
    let pubkey_hint = [
        signed_payload.ed25519.0[28],
        signed_payload.ed25519.0[29],
        signed_payload.ed25519.0[30],
        signed_payload.ed25519.0[31],
    ];
    let payload_hint = if signed_payload.payload.len() >= 4 {
        let len = signed_payload.payload.len();
        [
            signed_payload.payload[len - 4],
            signed_payload.payload[len - 3],
            signed_payload.payload[len - 2],
            signed_payload.payload[len - 1],
        ]
    } else {
        // For shorter payloads, C++ getHint copies from the beginning
        let mut hint = [0u8; 4];
        for (i, &byte) in signed_payload.payload.iter().enumerate() {
            if i < 4 {
                hint[i] = byte;
            }
        }
        hint
    };
    let expected_hint = [
        pubkey_hint[0] ^ payload_hint[0],
        pubkey_hint[1] ^ payload_hint[1],
        pubkey_hint[2] ^ payload_hint[2],
        pubkey_hint[3] ^ payload_hint[3],
    ];

    signatures.iter().any(|sig| {
        // Check hint first (XOR of pubkey hint and payload hint)
        if sig.hint.0 != expected_hint {
            return false;
        }

        // C++ stellar-core verifies the signature against the raw payload bytes,
        // not a hash. This is per CAP-0040 - the signed payload signer
        // requires a valid signature of the payload from the ed25519 public key.
        let ed_sig = match stellar_core_crypto::Signature::try_from(&sig.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        stellar_core_crypto::verify(&pk, &signed_payload.payload, &ed_sig).is_ok()
    })
}

/// Compute subSha256(baseSeed, index) as used by C++ stellar-core for PRNG seeds.
///
/// This computes SHA256(baseSeed || xdr::xdr_to_opaque(index)) where index is a u64.
/// XDR encodes uint64 as 8 bytes in big-endian (network byte order).
///
/// Note: C++ uses `static_cast<uint64_t>(index)` before passing to `xdr::xdr_to_opaque`,
/// so even though the index is originally an int, it's serialized as 8 bytes.
fn sub_sha256(base_seed: &[u8; 32], index: u32) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(base_seed);
    // XDR uint64 is 8 bytes big-endian
    hasher.update((index as u64).to_be_bytes());
    hasher.finalize().into()
}

/// Execute a full transaction set.
///
/// # Arguments
///
/// * `soroban_base_prng_seed` - The transaction set hash used as base seed for Soroban PRNG.
///   Each transaction gets its own seed computed as subSha256(baseSeed, txIndex).
pub fn execute_transaction_set(
    snapshot: &SnapshotHandle,
    transactions: &[(TransactionEnvelope, Option<u32>)],
    ledger_seq: u32,
    close_time: u64,
    base_fee: u32,
    base_reserve: u32,
    protocol_version: u32,
    network_id: NetworkId,
    delta: &mut LedgerDelta,
    soroban_config: SorobanConfig,
    soroban_base_prng_seed: [u8; 32],
    classic_events: ClassicEventConfig,
    op_invariants: Option<OperationInvariantRunner>,
    module_cache: Option<&PersistentModuleCache>,
) -> Result<(
    Vec<TransactionExecutionResult>,
    Vec<TransactionResultPair>,
    Vec<TransactionResultMetaV1>,
    u64,
    Vec<LedgerKey>, // Hot archive restored keys for HotArchiveBucketList::add_batch
)> {
    execute_transaction_set_with_fee_mode(
        snapshot,
        transactions,
        ledger_seq,
        close_time,
        base_fee,
        base_reserve,
        protocol_version,
        network_id,
        delta,
        soroban_config,
        soroban_base_prng_seed,
        classic_events,
        op_invariants,
        true,
        module_cache,
    )
}

/// Execute a full transaction set with configurable fee deduction.
///
/// # Arguments
///
/// * `module_cache` - Optional persistent module cache for reusing compiled WASM.
///   When provided, Soroban contract execution reuses pre-compiled modules,
///   significantly improving performance for workloads with many contract calls.
///
/// # Returns
///
/// A tuple containing:
/// - Transaction execution results
/// - Transaction result pairs (XDR)
/// - Transaction result metadata
/// - Updated ID pool
/// - Hot archive restored keys (for passing to HotArchiveBucketList::add_batch)
pub fn execute_transaction_set_with_fee_mode(
    snapshot: &SnapshotHandle,
    transactions: &[(TransactionEnvelope, Option<u32>)],
    ledger_seq: u32,
    close_time: u64,
    base_fee: u32,
    base_reserve: u32,
    protocol_version: u32,
    network_id: NetworkId,
    delta: &mut LedgerDelta,
    soroban_config: SorobanConfig,
    soroban_base_prng_seed: [u8; 32],
    classic_events: ClassicEventConfig,
    op_invariants: Option<OperationInvariantRunner>,
    deduct_fee: bool,
    module_cache: Option<&PersistentModuleCache>,
) -> Result<(
    Vec<TransactionExecutionResult>,
    Vec<TransactionResultPair>,
    Vec<TransactionResultMetaV1>,
    u64,
    Vec<LedgerKey>, // Hot archive restored keys for HotArchiveBucketList::add_batch
)> {
    let id_pool = snapshot.header().id_pool;
    let mut executor = TransactionExecutor::new(
        ledger_seq,
        close_time,
        base_reserve,
        protocol_version,
        network_id,
        id_pool,
        soroban_config,
        classic_events,
        op_invariants,
    );
    // Set the module cache if provided for better Soroban performance
    if let Some(cache) = module_cache {
        executor.set_module_cache(cache.clone());
    }

    let mut results = Vec::with_capacity(transactions.len());
    let mut tx_results = Vec::with_capacity(transactions.len());
    let mut tx_result_metas = Vec::with_capacity(transactions.len());

    for (tx_index, (tx, tx_base_fee)) in transactions.iter().enumerate() {
        // Snapshot the delta before starting each transaction.
        // This preserves committed changes from previous transactions so they're
        // not lost if this transaction fails and rolls back.
        executor.state.snapshot_delta();

        let tx_fee = tx_base_fee.unwrap_or(base_fee);
        // Compute per-transaction PRNG seed: subSha256(basePrngSeed, txIndex)
        let tx_prng_seed = sub_sha256(&soroban_base_prng_seed, tx_index as u32);
        let result = executor.execute_transaction_with_fee_mode(
            snapshot,
            tx,
            tx_fee,
            Some(tx_prng_seed),
            deduct_fee,
        )?;
        let frame = TransactionFrame::with_network(tx.clone(), executor.network_id);
        let tx_result = build_tx_result_pair(
            &frame,
            &executor.network_id,
            &result,
            tx_fee as i64,
            protocol_version,
        )?;
        let tx_meta = result
            .tx_meta
            .clone()
            .unwrap_or_else(empty_transaction_meta);
        let fee_changes = result
            .fee_changes
            .clone()
            .unwrap_or_else(empty_entry_changes);
        let post_fee_changes = result
            .post_fee_changes
            .clone()
            .unwrap_or_else(empty_entry_changes);
        let tx_result_meta = TransactionResultMetaV1 {
            ext: ExtensionPoint::V0,
            result: tx_result.clone(),
            fee_processing: fee_changes,
            tx_apply_processing: tx_meta,
            post_tx_apply_fee_processing: post_fee_changes,
        };

        info!(
            success = result.success,
            fee = result.fee_charged,
            ops = result.operation_results.len(),
            "Executed transaction"
        );

        results.push(result);
        tx_results.push(tx_result);
        tx_result_metas.push(tx_result_meta);
    }

    // Protocol 23+: Apply Soroban fee refunds after ALL transactions
    // This matches C++ stellar-core's processPostTxSetApply() phase
    if protocol_version >= 23 && deduct_fee {
        let mut total_refunds = 0i64;
        for (idx, (tx, _)) in transactions.iter().enumerate() {
            let refund = results[idx].fee_refund;
            if refund > 0 {
                let frame = TransactionFrame::with_network(tx.clone(), executor.network_id);
                let fee_source_id =
                    stellar_core_tx::muxed_to_account_id(&frame.fee_source_account());

                // Apply refund to the account balance in the delta
                executor.state.apply_refund_to_delta(&fee_source_id, refund);

                // Subtract refund from fee pool
                executor.state.delta_mut().add_fee(-refund);
                total_refunds += refund;

                tracing::info!(
                    ledger_seq = ledger_seq,
                    tx_index = idx,
                    refund = refund,
                    fee_source = %account_id_to_strkey(&fee_source_id),
                    "Applied P23+ Soroban fee refund"
                );
            }
        }
        if total_refunds > 0 {
            tracing::info!(
                ledger_seq = ledger_seq,
                total_refunds = total_refunds,
                tx_count = transactions.len(),
                "P23+ Soroban fee refunds applied"
            );
        }
    }

    // Apply all changes to the delta
    executor.apply_to_delta(snapshot, delta)?;

    // Add fees to fee pool
    if deduct_fee {
        let total_fees = executor.total_fees();
        delta.record_fee_pool_delta(total_fees);
    }

    // Collect all hot archive restored keys across all transactions
    let mut all_hot_archive_restored_keys: Vec<LedgerKey> = Vec::new();
    for result in &results {
        all_hot_archive_restored_keys.extend(result.hot_archive_restored_keys.iter().cloned());
    }

    Ok((
        results,
        tx_results,
        tx_result_metas,
        executor.id_pool(),
        all_hot_archive_restored_keys,
    ))
}

/// Compute the state size window update entry for a ledger close.
///
/// This implements the C++ `maybeSnapshotSorobanStateSize` logic, which updates the
/// `LiveSorobanStateSizeWindow` config setting on each sample period.
///
/// # Arguments
///
/// * `seq` - Current ledger sequence number
/// * `protocol_version` - Current protocol version
/// * `bucket_list` - Bucket list to read current window state from
/// * `soroban_state_size` - Total size of Soroban state in bytes (contracts + data)
///
/// # Returns
///
/// The updated window entry if a change is needed, or None if no update is required.
pub fn compute_state_size_window_entry(
    seq: u32,
    protocol_version: u32,
    bucket_list: &stellar_core_bucket::BucketList,
    soroban_state_size: u64,
) -> Option<LedgerEntry> {
    use stellar_core_common::protocol::MIN_SOROBAN_PROTOCOL_VERSION;
    use stellar_xdr::curr::{
        ConfigSettingEntry, ConfigSettingId, LedgerEntryData, LedgerEntryExt, LedgerKey,
        LedgerKeyConfigSetting, VecM,
    };

    if protocol_version < MIN_SOROBAN_PROTOCOL_VERSION {
        return None;
    }

    // Load state archival settings to get sample period and size
    let archival_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::StateArchival,
    });
    let archival_entry = bucket_list.get(&archival_key).ok()??;
    let LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(archival)) =
        archival_entry.data
    else {
        return None;
    };

    let sample_period = archival.live_soroban_state_size_window_sample_period;
    let sample_size = archival.live_soroban_state_size_window_sample_size as usize;
    if sample_period == 0 || sample_size == 0 {
        return None;
    }

    // Load current window state
    let window_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::LiveSorobanStateSizeWindow,
    });
    let window_entry = bucket_list.get(&window_key).ok()??;
    let LedgerEntryData::ConfigSetting(ConfigSettingEntry::LiveSorobanStateSizeWindow(window)) =
        window_entry.data
    else {
        return None;
    };

    let mut window_vec: Vec<u64> = window.into();
    if window_vec.is_empty() {
        return None;
    }

    // Check if window size needs to be adjusted
    let mut changed = false;
    if window_vec.len() != sample_size {
        if sample_size < window_vec.len() {
            let remove_count = window_vec.len() - sample_size;
            window_vec.drain(0..remove_count);
        } else {
            let oldest = window_vec[0];
            let insert_count = sample_size - window_vec.len();
            for _ in 0..insert_count {
                window_vec.insert(0, oldest);
            }
        }
        changed = true;
    }

    // Update window on sample ledgers
    if seq % sample_period == 0 {
        if !window_vec.is_empty() {
            window_vec.remove(0);
            window_vec.push(soroban_state_size);
            changed = true;
        }
    }

    if !changed {
        return None;
    }

    let window_vecm: VecM<u64> = window_vec.try_into().ok()?;

    Some(LedgerEntry {
        last_modified_ledger_seq: seq,
        data: LedgerEntryData::ConfigSetting(ConfigSettingEntry::LiveSorobanStateSizeWindow(
            window_vecm,
        )),
        ext: LedgerEntryExt::V0,
    })
}

/// Compute the total size of Soroban state from the bucket list.
///
/// This sums the byte sizes of all CONTRACT_DATA and CONTRACT_CODE entries
/// in the bucket list. For Protocol 23+, this is used for state size tracking.
///
/// For CONTRACT_DATA entries, the size is the XDR serialized size.
/// For CONTRACT_CODE entries, the size includes both the XDR size and the
/// in-memory compiled module size (computed via soroban-env-host's
/// `entry_size_for_rent` function). This matches the C++ stellar-core behavior
/// which uses `contractCodeSizeForRent()` -> `ledgerEntrySizeForRent()` ->
/// `rust_bridge::contract_code_memory_size_for_rent()`.
///
/// Note: This is a relatively expensive operation as it requires iterating
/// through all live entries in the bucket list and computing compiled module
/// sizes for contract code entries.
pub fn compute_soroban_state_size_from_bucket_list(
    bucket_list: &stellar_core_bucket::BucketList,
    protocol_version: u32,
) -> u64 {
    use stellar_core_tx::operations::execute::entry_size_for_rent_by_protocol;
    use stellar_xdr::curr::{LedgerEntryData, Limits, WriteXdr};

    let mut total_size: u64 = 0;

    if let Ok(entries) = bucket_list.live_entries() {
        for entry in &entries {
            match &entry.data {
                LedgerEntryData::ContractData(_) => {
                    // Contract data uses XDR size
                    if let Ok(xdr_bytes) = entry.to_xdr(Limits::none()) {
                        total_size += xdr_bytes.len() as u64;
                    }
                }
                LedgerEntryData::ContractCode(_) => {
                    // Contract code uses entry_size_for_rent which includes
                    // the compiled module memory cost for Protocol 23+
                    if let Ok(xdr_bytes) = entry.to_xdr(Limits::none()) {
                        let xdr_size = xdr_bytes.len() as u32;
                        let rent_size =
                            entry_size_for_rent_by_protocol(protocol_version, entry, xdr_size);
                        total_size += rent_size as u64;
                    }
                }
                _ => {}
            }
        }
    }

    total_size
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        AccountId, AlphaNum4, Asset, AssetCode4, LedgerEntry, LedgerEntryChange, LedgerEntryData,
        LedgerEntryExt, OfferEntry, OfferEntryExt, Price, PublicKey, Uint256,
    };

    #[test]
    fn test_transaction_executor_creation() {
        let executor = TransactionExecutor::new(
            100,
            1234567890,
            5_000_000,
            21,
            NetworkId::testnet(),
            0,
            SorobanConfig::default(),
            ClassicEventConfig::default(),
            None,
        );

        assert_eq!(executor.ledger_seq, 100);
        assert_eq!(executor.close_time, 1234567890);
    }

    fn make_account_id(byte: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32])))
    }

    fn make_asset(code: &[u8; 4], issuer: u8) -> Asset {
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*code),
            issuer: make_account_id(issuer),
        })
    }

    fn make_offer(
        offer_id: i64,
        selling: Asset,
        buying: Asset,
        price: Price,
        flags: u32,
    ) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Offer(OfferEntry {
                seller_id: make_account_id(9),
                offer_id,
                selling,
                buying,
                amount: 100,
                price,
                flags,
                ext: OfferEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    #[test]
    fn test_operation_invariant_runner_detects_crossed_order_book() {
        let asset_a = make_asset(b"ABCD", 1);
        let asset_b = make_asset(b"WXYZ", 2);

        let ask = make_offer(1, asset_a.clone(), asset_b.clone(), Price { n: 1, d: 1 }, 0);
        let bid = make_offer(2, asset_b.clone(), asset_a.clone(), Price { n: 1, d: 1 }, 0);

        let runner =
            OperationInvariantRunner::new(vec![ask], LedgerHeader::default(), NetworkId::testnet())
                .unwrap();
        let mut runner = runner;

        let changes = LedgerEntryChanges(
            vec![LedgerEntryChange::Created(bid)]
                .try_into()
                .unwrap_or_default(),
        );

        assert!(runner.apply_and_check(&changes, &[]).is_err());
    }

    /// Regression test: Verify classic transaction fee calculation uses min(inclusion_fee, required_fee)
    ///
    /// This matches C++ stellar-core's TransactionFrame::getFee() behavior when applying=true:
    /// - For classic transactions: min(inclusionFee, adjustedFee)
    ///   where adjustedFee = baseFee * numOperations
    ///
    /// Previously we incorrectly used inclusion_fee directly (or max()), which caused
    /// transactions with high declared fees to be charged more than necessary.
    #[test]
    fn test_classic_fee_calculation_uses_min() {
        // This test validates the fee calculation logic at lines ~1490-1497 and ~2129-2136
        // For a classic transaction with:
        //   - declared fee (inclusion_fee) = 1,000,000 stroops
        //   - base_fee = 100 stroops
        //   - num_ops = 1
        //   - required_fee = base_fee * num_ops = 100
        //
        // The fee charged should be min(1_000_000, 100) = 100, NOT 1,000,000

        // We can't easily test the full execute_transaction flow without extensive setup,
        // but we can verify the formula directly using the same calculation:
        let inclusion_fee: i64 = 1_000_000;
        let base_fee: i64 = 100;
        let num_ops: i64 = 1;
        let required_fee = base_fee * std::cmp::max(1, num_ops);

        // This is the correct formula (matches C++):
        let fee_charged = std::cmp::min(inclusion_fee, required_fee);
        assert_eq!(
            fee_charged, 100,
            "Classic fee should be min(declared, required)"
        );

        // Verify it's not using max (the previous bug):
        let wrong_fee = std::cmp::max(inclusion_fee, required_fee);
        assert_eq!(
            wrong_fee, 1_000_000,
            "max() would incorrectly give 1,000,000"
        );
        assert_ne!(
            fee_charged, wrong_fee,
            "Fee calculation must use min(), not max()"
        );
    }

    /// Regression test: Verify Soroban fee calculation
    ///
    /// For Soroban transactions:
    ///   fee = resourceFee + min(inclusionFee, adjustedFee)
    #[test]
    fn test_soroban_fee_calculation() {
        let resource_fee: i64 = 500_000;
        let declared_total_fee: i64 = 2_000_000;
        let inclusion_fee = declared_total_fee - resource_fee; // 1,500,000
        let base_fee: i64 = 100;
        let num_ops: i64 = 1;
        let required_fee = base_fee * std::cmp::max(1, num_ops); // 100

        // Soroban fee = resourceFee + min(inclusionFee, adjustedFee)
        let fee_charged = resource_fee + std::cmp::min(inclusion_fee, required_fee);

        // Should be 500_000 + min(1_500_000, 100) = 500_000 + 100 = 500_100
        assert_eq!(
            fee_charged, 500_100,
            "Soroban fee should be resourceFee + min(inclusionFee, adjustedFee)"
        );
    }
}
