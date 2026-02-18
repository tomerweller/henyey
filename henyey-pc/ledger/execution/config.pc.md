## Pseudocode: crates/ledger/src/execution/config.rs

### load_config_setting

```
load_config_setting(snapshot, id):
  key = ConfigSetting ledger key for id
  entry = snapshot.get_entry(key)
  GUARD entry is missing or not ConfigSetting → none
  → config setting value
```

### load_soroban_config

"Load SorobanConfig from the ledger's ConfigSettingEntry entries."
"Loads cost parameters and limits required for accurate Soroban execution."

```
load_soroban_config(snapshot, protocol_version):
  --- Load cost parameters ---
  cpu_cost_params = load_config_setting(ContractCostParamsCpuInstructions)
    default: empty params
  mem_cost_params = load_config_setting(ContractCostParamsMemoryBytes)
    default: empty params
```

**Calls**: [load_config_setting](#load_config_setting)

```
  --- Load compute limits ---
  (tx_max_instructions,
   tx_max_memory_bytes,
   fee_per_instruction_increment)
    = load_config_setting(ContractComputeV0)
    default: (100_000_000, 40MB, 0)

  --- Load ledger cost settings ---
  (fee_disk_read_ledger_entry,
   fee_write_ledger_entry,
   fee_disk_read_1kb,
   soroban_state_target_size_bytes,
   rent_fee_1kb_state_size_low,
   rent_fee_1kb_state_size_high,
   soroban_state_rent_fee_growth_factor)
    = load_config_setting(ContractLedgerCostV0)
    default: all zeros

  fee_write_1kb = load_config_setting(ContractLedgerCostExtV0).fee_write1_kb
    default: 0

  fee_historical_1kb = load_config_setting(ContractHistoricalDataV0)
    default: 0

  (tx_max_contract_events_size_bytes,
   fee_contract_events_1kb)
    = load_config_setting(ContractEventsV0)
    default: (0, 0)

  fee_tx_size_1kb = load_config_setting(ContractBandwidthV0)
    default: 0

  --- Load contract size limits ---
  CONST DEFAULT_MAX_CONTRACT_SIZE = 64KB
  max_contract_size_bytes
    = load_config_setting(ContractMaxSizeBytes)
    default: 64KB
  max_contract_data_entry_size_bytes
    = load_config_setting(ContractDataEntrySizeBytes)
    default: 64KB

  --- Load state archival TTL settings ---
  (min_temp_entry_ttl,
   min_persistent_entry_ttl,
   max_entry_ttl,
   persistent_rent_rate_denominator,
   temp_rent_rate_denominator)
    = load_config_setting(StateArchival)
    default: (16, 120960, 6312000, 0, 0)

  --- Compute average state size from live window ---
  average_soroban_state_size
    = load_config_setting(LiveSorobanStateSizeWindow)
    if window not empty: sum(window) / len(window)
    default: 0

  --- Compute rent write fee ---
  rent_write_config = {
    state_target_size_bytes,
    rent_fee_1kb_state_size_low,
    rent_fee_1kb_state_size_high,
    state_size_rent_fee_growth_factor
  }
  fee_per_rent_1kb = compute_rent_write_fee_per_1kb(
    average_soroban_state_size, rent_write_config)

  --- Protocol-dependent fee selection ---
  "Matches stellar-core rustBridgeFeeConfiguration():"
  "- For protocol >= 23: use fee_write_1kb (flat rate)"
  "- For protocol < 23: use fee_per_rent_1kb (computed from state size)"
  @version(≥23):
    fee_per_write_1kb_for_config = fee_write_1kb
  @version(<23):
    fee_per_write_1kb_for_config = fee_per_rent_1kb

  fee_config = FeeConfiguration {
    fee_per_instruction_increment,
    fee_per_disk_read_entry,
    fee_per_write_entry,
    fee_per_disk_read_1kb,
    fee_per_write_1kb: fee_per_write_1kb_for_config,
    fee_per_historical_1kb,
    fee_per_contract_event_1kb,
    fee_per_transaction_size_1kb
  }

  "RentFeeConfiguration.fee_per_write_1kb must be feeFlatRateWrite1KB()"
  "to match stellar-core rustBridgeRentFeeConfiguration()."
  "This is 0 for protocol < 23 (the setting doesn't exist),"
  "which is correct because the TTL entry write fee component"
  "was introduced in protocol 23."
  "This is DIFFERENT from FeeConfiguration.fee_per_write_1kb which"
  "uses fee_per_rent_1kb for protocol < 23."
  rent_fee_config = RentFeeConfiguration {
    fee_per_write_1kb: fee_write_1kb,
    fee_per_rent_1kb,
    fee_per_write_entry,
    persistent_rent_rate_denominator,
    temporary_rent_rate_denominator
  }

  → SorobanConfig { all fields assembled above }
```

### load_soroban_network_info

"Load all configuration settings needed for the /sorobaninfo endpoint."

```
load_soroban_network_info(snapshot):
  GUARD load_config_setting(ContractComputeV0) missing → none

  info = default SorobanNetworkInfo

  --- Populate from each config setting ---
  load ContractDataKeySizeBytes → info.max_contract_data_key_size
  load ContractDataEntrySizeBytes → info.max_contract_data_entry_size
  load ContractMaxSizeBytes → info.max_contract_size

  load ContractComputeV0 → info.tx_max_instructions,
    info.ledger_max_instructions,
    info.fee_rate_per_instructions_increment,
    info.tx_memory_limit

  load ContractLedgerCostV0 → all read/write limits and fees
  load ContractLedgerCostExtV0 → info.fee_write_1kb
  load ContractHistoricalDataV0 → info.fee_historical_1kb
  load ContractEventsV0 → info.tx_max_contract_events_size_bytes,
    info.fee_contract_events_size_1kb
  load ContractBandwidthV0 → info.ledger_max_tx_size_bytes,
    info.tx_max_size_bytes, info.fee_transaction_size_1kb
  load ContractExecutionLanes → info.ledger_max_tx_count
  load StateArchival → all TTL and rent settings,
    info.max_entries_to_archive, info.eviction_scan_size, etc.
  load LiveSorobanStateSizeWindow → info.average_bucket_list_size
    (computed as sum/len if window not empty)
  load ScpTiming → info.nomination/ballot timeout settings

  → info
```

### compute_soroban_resource_fee

```
compute_soroban_resource_fee(frame, protocol_version, config, event_size_bytes):
  resources = frame.soroban_transaction_resources(
    protocol_version, event_size_bytes)
  GUARD resources missing → none
  → compute_transaction_resource_fee(resources, config.fee_config)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 454    | 120        |
| Functions     | 4      | 4          |
