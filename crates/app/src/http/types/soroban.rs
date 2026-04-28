//! Types for Soroban-related endpoints.

use serde::{Deserialize, Serialize};

/// Query parameters for /sorobaninfo endpoint.
#[derive(Deserialize)]
pub struct SorobanInfoParams {
    pub format: Option<String>,
}

/// Response for the /sorobaninfo endpoint (basic format).
#[derive(Serialize)]
pub struct SorobanInfoResponse {
    pub max_contract_size: u32,
    pub max_contract_data_key_size: u32,
    pub max_contract_data_entry_size: u32,
    pub tx: SorobanTxLimits,
    pub ledger: SorobanLedgerLimits,
    pub fee_rate_per_instructions_increment: i64,
    pub fee_read_ledger_entry: i64,
    pub fee_write_ledger_entry: i64,
    pub fee_read_1kb: i64,
    pub fee_write_1kb: i64,
    pub fee_historical_1kb: i64,
    pub fee_contract_events_size_1kb: i64,
    pub fee_transaction_size_1kb: i64,
    pub state_archival: SorobanStateArchival,
    /// Protocol 23+: maximum dependent TX clusters per parallel stage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_dependent_tx_clusters: Option<u32>,
    /// Protocol 23+: SCP timing settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scp: Option<SorobanScpSettings>,
}

/// SCP timing settings (protocol 23+), matching stellar-core's JSON field names.
#[derive(Serialize)]
pub struct SorobanScpSettings {
    pub ledger_close_time_ms: u32,
    pub nomination_timeout_ms: u32,
    pub nomination_timeout_inc_ms: u32,
    pub ballot_timeout_ms: u32,
    pub ballot_timeout_inc_ms: u32,
}

/// Soroban per-transaction resource limits.
#[derive(Serialize)]
pub struct SorobanTxLimits {
    pub max_instructions: i64,
    pub memory_limit: u32,
    pub max_read_ledger_entries: u32,
    pub max_read_bytes: u32,
    pub max_write_ledger_entries: u32,
    pub max_write_bytes: u32,
    pub max_contract_events_size_bytes: u32,
    pub max_size_bytes: u32,
}

/// Soroban per-ledger resource limits.
#[derive(Serialize)]
pub struct SorobanLedgerLimits {
    pub max_instructions: i64,
    pub max_read_ledger_entries: u32,
    pub max_read_bytes: u32,
    pub max_write_ledger_entries: u32,
    pub max_write_bytes: u32,
    pub max_tx_size_bytes: u32,
    pub max_tx_count: u32,
}

/// Soroban state archival settings.
#[derive(Serialize)]
pub struct SorobanStateArchival {
    pub max_entry_ttl: u32,
    pub min_temporary_ttl: u32,
    pub min_persistent_ttl: u32,
    pub persistent_rent_rate_denominator: i64,
    pub temp_rent_rate_denominator: i64,
    pub max_entries_to_archive: u32,
    pub bucketlist_size_window_sample_size: u32,
    pub eviction_scan_size: i64,
    pub starting_eviction_scan_level: u32,
}
