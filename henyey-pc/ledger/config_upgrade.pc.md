## Pseudocode: crates/ledger/src/config_upgrade.rs

"Soroban configuration upgrade handling."
"Implements ConfigUpgradeSetFrame from stellar-core."
"Config upgrades change Soroban parameters (compute limits, fees, etc.)
through consensus. Upgrade data is stored in a temporary CONTRACT_DATA entry."

"Protocol:
 1. ConfigUpgradeSet is uploaded as CONTRACT_DATA
 2. Validators schedule upgrade referencing ConfigUpgradeSetKey
 3. At upgrade time, ConfigUpgradeSet is loaded and validated
 4. If valid, CONFIG_SETTING entries are updated in the ledger"

### ConfigUpgradeValidity (enum)

```
ENUM ConfigUpgradeValidity:
  Valid       // upgrade can be applied
  XdrInvalid  // bad hash, unsorted, or duplicates
  Invalid     // violates constraints or non-upgradeable
```

### Minimum config constants

"Match stellar-core MinimumSorobanNetworkConfig (NetworkConfig.h).
These are intentionally low floor values, NOT initial/production values."

```
CONST MAX_CONTRACT_SIZE                      = 2_000
CONST MAX_CONTRACT_DATA_KEY_SIZE_BYTES       = 200
CONST MAX_CONTRACT_DATA_ENTRY_SIZE_BYTES     = 2_000
CONST TX_MAX_SIZE_BYTES                      = 10_000
CONST TX_MAX_INSTRUCTIONS                    = 2_500_000
CONST MEMORY_LIMIT                           = 2_000_000
CONST TX_MAX_READ_LEDGER_ENTRIES             = 3
CONST TX_MAX_READ_BYTES                      = 3_200
CONST TX_MAX_WRITE_LEDGER_ENTRIES            = 2
CONST TX_MAX_WRITE_BYTES                     = 3_200
CONST TX_MAX_CONTRACT_EVENTS_SIZE_BYTES      = 200
CONST MAXIMUM_ENTRY_LIFETIME                 = 1_054_080
CONST MINIMUM_TEMP_ENTRY_LIFETIME            = 16
CONST MINIMUM_PERSISTENT_ENTRY_LIFETIME      = 10
CONST MAX_ENTRIES_TO_ARCHIVE                 = 0
CONST BUCKETLIST_SIZE_WINDOW_SAMPLE_SIZE     = 1
CONST EVICTION_SCAN_SIZE                     = 0
CONST STARTING_EVICTION_LEVEL                = 1
CONST BUCKETLIST_WINDOW_SAMPLE_PERIOD        = 1
CONST LEDGER_TARGET_CLOSE_TIME_MS_MIN        = 4_000
CONST NOMINATION_TIMEOUT_INITIAL_MS_MIN      = 750
CONST NOMINATION_TIMEOUT_INCREMENT_MS_MIN    = 750
CONST BALLOT_TIMEOUT_INITIAL_MS_MIN          = 750
CONST BALLOT_TIMEOUT_INCREMENT_MS_MIN        = 750
```

### Maximum config constants

```
CONST LEDGER_TARGET_CLOSE_TIME_MS_MAX        = 5_000
CONST NOMINATION_TIMEOUT_INITIAL_MS_MAX      = 2_500
CONST NOMINATION_TIMEOUT_INCREMENT_MS_MAX    = 2_000
CONST BALLOT_TIMEOUT_INITIAL_MS_MAX          = 2_500
CONST BALLOT_TIMEOUT_INCREMENT_MS_MAX        = 2_000
```

### ConfigUpgradeSetFrame (struct)

```
STRUCT ConfigUpgradeSetFrame:
  config_upgrade_set   // the upgrade set data
  key                  // ConfigUpgradeSetKey used to load this
  valid_xdr            // whether XDR structure is valid
  ledger_version       // protocol version when loaded
```

### <a id="make_from_key"></a>ConfigUpgradeSetFrame::make_from_key

"Load a ConfigUpgradeSet from the ledger."

```
FUNCTION make_from_key(snapshot, key):
  lk = get_ledger_key(key)

  "Load the CONTRACT_DATA entry"
  entry = snapshot.get_entry(lk)
  GUARD entry not found → None

  "Check TTL (entry must be live)"
  ttl_key = get_ttl_key(lk)
  ttl_entry = snapshot.get_entry(ttl_key)
  GUARD ttl_entry not found → None
  GUARD NOT is_live(ttl_entry, snapshot.ledger_seq) → None

  "Extract CONTRACT_DATA"
  contract_data = entry.data as ContractData
  GUARD entry.data is not ContractData → None

  "Must be TEMPORARY durability"
  GUARD contract_data.durability != TEMPORARY → None

  "Value must be SCV_BYTES"
  bytes = contract_data.val as Bytes
  GUARD contract_data.val is not Bytes → None

  "Decode the ConfigUpgradeSet"
  upgrade_set = XDR_decode(bytes)
  GUARD decode fails → None

  valid_xdr = is_valid_xdr_static(upgrade_set, key)
  → ConfigUpgradeSetFrame { upgrade_set, key, valid_xdr, ledger_version }
```

**Calls**: [get_ledger_key](#get_ledger_key) | [get_ttl_key](#get_ttl_key) | [is_live](#is_live) | [is_valid_xdr_static](#is_valid_xdr_static)

### <a id="get_ledger_key"></a>ConfigUpgradeSetFrame::get_ledger_key

"Construct the LedgerKey for a ConfigUpgradeSet.
Stored in CONTRACT_DATA with contract_id, content_hash as key, TEMPORARY durability."

```
FUNCTION get_ledger_key(upgrade_key):
  key_val = Bytes(upgrade_key.content_hash)
  → ContractDataKey {
      contract: Contract(upgrade_key.contract_id),
      key: key_val,
      durability: TEMPORARY
    }
```

### <a id="get_ttl_key"></a>Helper: get_ttl_key

```
FUNCTION get_ttl_key(data_key):
  → TtlKey { key_hash: SHA256(XDR_encode(data_key)) }
```

### <a id="is_live"></a>Helper: is_live

```
FUNCTION is_live(ttl_entry, current_ledger):
  if ttl_entry.data is Ttl:
    → ttl.live_until_ledger_seq >= current_ledger
  → false
```

### upgrade_needed

```
FUNCTION upgrade_needed(self, snapshot):
  for each entry in self.config_upgrade_set.updated_entry:
    key = ConfigSettingKey { id: entry.discriminant() }
    current = snapshot.get_entry(key)

    if current exists AND current.data is ConfigSetting:
      if current_entry != entry:
        → true
    else:
      "Entry doesn't exist, upgrade needed"
      → true

  → false
```

### <a id="is_valid_for_apply"></a>is_valid_for_apply

```
FUNCTION is_valid_for_apply(self):
  GUARD NOT self.valid_xdr → XdrInvalid

  for each entry in self.config_upgrade_set.updated_entry:
    GUARD NOT is_valid_config_setting_entry(entry, self.ledger_version)
      → Invalid
    GUARD is_non_upgradeable(entry.discriminant())
      → Invalid

  → Valid
```

**Calls**: [is_valid_config_setting_entry](#is_valid_config_setting_entry) | [is_non_upgradeable](#is_non_upgradeable)

### is_consistent_with

```
FUNCTION is_consistent_with(self, scheduled):
  if scheduled exists:
    → self.key == scheduled.key
  → false
```

### <a id="apply_to"></a>apply_to

"Apply configuration upgrades to the ledger.
Returns (state_archival_changed, memory_cost_params_changed, entry_changes)."

```
FUNCTION apply_to(self, snapshot, delta):
  state_archival_changed = false
  memory_cost_params_changed = false
  window_sample_size_changed = false
  changes = []

  for each new_entry in self.config_upgrade_set.updated_entry:
    setting_id = new_entry.discriminant()
    key = ConfigSettingKey { id: setting_id }

    "Load current entry from ledger"
    previous = snapshot.get_entry(key)
    GUARD previous not found → skip (continue)

    "Track special changes BEFORE recording the update"
    "Parity: Upgrades.cpp:1426-1437"
    if setting_id == StateArchival:
      state_archival_changed = true
      if previous.window_sample_size != new_entry.window_sample_size:
        window_sample_size_changed = true

    if setting_id == ContractCostParamsMemoryBytes:
      memory_cost_params_changed = true

    "Create the new entry"
    new_ledger_entry = LedgerEntry {
      last_modified_ledger_seq: delta.ledger_seq(),
      data: ConfigSetting(new_entry)
    }

    "Capture before/after for upgrade meta"
    changes += State(previous)
    changes += Updated(new_ledger_entry)

    "Record the update"
    delta.record_update(previous, new_ledger_entry)    REF: delta::LedgerDelta::record_update

  "Parity: Upgrades.cpp:1443-1446"
  "If state size window sample size changed, resize the window."
  "Must happen AFTER all config settings applied but BEFORE bucket list extraction."
  if window_sample_size_changed:
    maybe_update_state_size_window(snapshot, delta)

  → (state_archival_changed, memory_cost_params_changed, changes)
```

**Calls**: [maybe_update_state_size_window](#maybe_update_state_size_window)

### <a id="maybe_update_state_size_window"></a>Helper: maybe_update_state_size_window

"Resize LiveSorobanStateSizeWindow when sample size changes via config upgrade."
"Parity: NetworkConfig.cpp:2080 maybeUpdateSorobanStateSizeWindowSize"

```
FUNCTION maybe_update_state_size_window(self, snapshot, delta):
  "Get new sample size from upgrade set"
  new_sample_size = find StateArchival entry in upgrade set
    → archival.live_soroban_state_size_window_sample_size
  GUARD new_sample_size not found → return

  "Load current window from snapshot"
  window_entry = snapshot.get_entry(LiveSorobanStateSizeWindow key)
  GUARD window_entry not found → return
  GUARD window_entry.data is not LiveSorobanStateSizeWindow → return

  window_vec = window entries as list
  curr_size = window_vec.length

  if new_sample_size == curr_size:
    → return

  if new_sample_size < curr_size:
    "Shrink: remove oldest entries from front"
    remove first (curr_size - new_sample_size) elements from window_vec
  else:
    "Grow: backfill with oldest value at front"
    oldest = window_vec[0] or 0
    insert (new_sample_size - curr_size) copies of oldest at front

  new_window_entry = LedgerEntry {
    last_modified_ledger_seq: delta.ledger_seq(),
    data: ConfigSetting(LiveSorobanStateSizeWindow(window_vec))
  }

  delta.record_update(window_entry, new_window_entry)
```

### <a id="is_valid_xdr_static"></a>Helper: is_valid_xdr_static

```
FUNCTION is_valid_xdr_static(upgrade_set, key):
  "Check hash matches"
  bytes = XDR_encode(upgrade_set)
  computed_hash = SHA256(bytes)
  GUARD computed_hash != key.content_hash → false

  "Check not empty"
  GUARD upgrade_set.updated_entry is empty → false

  "Check sorted by config setting ID, no duplicates"
  for i from 1 to entries.length - 1:
    GUARD entries[i].discriminant() <= entries[i-1].discriminant()
      → false

  → true
```

### <a id="is_non_upgradeable"></a>is_non_upgradeable

```
FUNCTION is_non_upgradeable(id):
  → id is LiveSorobanStateSizeWindow OR EvictionIterator
```

### <a id="is_valid_config_setting_entry"></a>is_valid_config_setting_entry

"Validate config setting against constraints."
"Parity: stellar-core SorobanNetworkConfig::isValidConfigSettingEntry (NetworkConfig.cpp)"

```
FUNCTION is_valid_config_setting_entry(entry, ledger_version):
  case entry:
    ContractMaxSizeBytes(v):
      → v >= MAX_CONTRACT_SIZE

    ContractCostParamsCpuInstructions:
      → true   // complex validation, accepted

    ContractCostParamsMemoryBytes:
      → true   // complex validation, accepted

    ContractDataKeySizeBytes(v):
      → v >= MAX_CONTRACT_DATA_KEY_SIZE_BYTES

    ContractDataEntrySizeBytes(v):
      → v >= MAX_CONTRACT_DATA_ENTRY_SIZE_BYTES

    ContractExecutionLanes:
      → true

    ContractBandwidthV0(bw):
      → bw.fee_tx_size1_kb >= 0
        AND bw.tx_max_size_bytes >= TX_MAX_SIZE_BYTES
        AND bw.ledger_max >= bw.tx_max

    ContractComputeV0(c):
      → c.fee_rate >= 0
        AND c.tx_max_instructions >= TX_MAX_INSTRUCTIONS
        AND c.ledger_max_instructions >= c.tx_max_instructions
        AND c.tx_memory_limit >= MEMORY_LIMIT

    ContractHistoricalDataV0(h):
      → h.fee_historical1_kb >= 0

    ContractLedgerCostV0(cost):
      → cost.tx_max_read_entries >= TX_MAX_READ_LEDGER_ENTRIES
        AND cost.ledger_max_read_entries >= cost.tx_max_read_entries
        AND cost.tx_max_read_bytes >= TX_MAX_READ_BYTES
        AND cost.ledger_max_read_bytes >= cost.tx_max_read_bytes
        AND cost.tx_max_write_entries >= TX_MAX_WRITE_LEDGER_ENTRIES
        AND cost.ledger_max_write_entries >= cost.tx_max_write_entries
        AND cost.tx_max_write_bytes >= TX_MAX_WRITE_BYTES
        AND cost.ledger_max_write_bytes >= cost.tx_max_write_bytes
        AND cost.fee_read_entry >= 0
        AND cost.fee_write_entry >= 0
        AND cost.fee_read1_kb >= 0
        AND cost.state_target_size > 0
        AND cost.rent_fee_high >= 0

    ContractEventsV0(events):
      → events.tx_max_size >= TX_MAX_CONTRACT_EVENTS_SIZE_BYTES
        AND events.fee1_kb >= 0

    StateArchival(a):
      → a.max_entry_ttl >= MAXIMUM_ENTRY_LIFETIME
        AND a.min_temp_ttl >= MINIMUM_TEMP_ENTRY_LIFETIME
        AND a.min_persistent_ttl >= MINIMUM_PERSISTENT_ENTRY_LIFETIME
        AND a.persistent_rent_rate_denominator > 0
        AND a.temp_rent_rate_denominator > 0
        AND a.max_entries_to_archive >= MAX_ENTRIES_TO_ARCHIVE
        AND a.window_sample_size >= BUCKETLIST_SIZE_WINDOW_SAMPLE_SIZE
        AND a.eviction_scan_size >= EVICTION_SCAN_SIZE
        AND a.starting_eviction_level >= STARTING_EVICTION_LEVEL
        AND a.starting_eviction_level < 12   // kNumLevels
        AND a.window_sample_period >= BUCKETLIST_WINDOW_SAMPLE_PERIOD
        AND a.max_entry_ttl > a.min_persistent_ttl
        AND a.max_entry_ttl > a.min_temp_ttl

    LiveSorobanStateSizeWindow:
      → true

    EvictionIterator:
      → true

    ContractParallelComputeV0(p):
      @version(≥PARALLEL_SOROBAN_PHASE):
        → p.ledger_max_dependent_tx_clusters > 0
          AND p.ledger_max_dependent_tx_clusters < 128
      @version(<PARALLEL_SOROBAN_PHASE):
        → false

    ContractLedgerCostExtV0(ext):
      @version(≥23):
        → ext.tx_max_footprint_entries >= TX_MAX_READ_LEDGER_ENTRIES
          AND ext.fee_write1_kb >= 0
      @version(<23):
        → false

    ScpTiming(t):
      @version(≥23):
        → t.ledger_target_close_time_ms
            in [LEDGER_TARGET_CLOSE_TIME_MS_MIN, LEDGER_TARGET_CLOSE_TIME_MS_MAX]
          AND t.nomination_timeout_initial_ms
            in [NOMINATION_TIMEOUT_INITIAL_MS_MIN, NOMINATION_TIMEOUT_INITIAL_MS_MAX]
          AND t.nomination_timeout_increment_ms
            in [NOMINATION_TIMEOUT_INCREMENT_MS_MIN, NOMINATION_TIMEOUT_INCREMENT_MS_MAX]
          AND t.ballot_timeout_initial_ms
            in [BALLOT_TIMEOUT_INITIAL_MS_MIN, BALLOT_TIMEOUT_INITIAL_MS_MAX]
          AND t.ballot_timeout_increment_ms
            in [BALLOT_TIMEOUT_INCREMENT_MS_MIN, BALLOT_TIMEOUT_INCREMENT_MS_MAX]
      @version(<23):
        → false
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 710    | 225        |
| Functions     | 14     | 14         |
