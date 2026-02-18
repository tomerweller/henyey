## Pseudocode: crates/ledger/src/soroban_state.rs

"In-memory Soroban state management for fast contract data access."
"TTLs are co-located with entries (not stored separately like bucket list)."
"Pending TTLs buffer handles TTLs arriving before their entries during init."

### Data Structures

```
STRUCT TtlData:
  live_until_ledger_seq: u32
  last_modified_ledger_seq: u32

STRUCT SorobanRentConfig:
  cpu_cost_params: ContractCostParams
  mem_cost_params: ContractCostParams
  tx_max_instructions: u64
  tx_max_memory_bytes: u64

STRUCT ContractDataMapEntry:
  ledger_entry: LedgerEntry   // immutable shared ref
  ttl_data: TtlData

STRUCT ContractCodeMapEntry:
  ledger_entry: LedgerEntry   // immutable shared ref
  ttl_data: TtlData
  size_bytes: u32              // in-memory compiled module size (for rent)

STRUCT InMemorySorobanState:
  contract_data_entries: Map<[32]byte, ContractDataMapEntry>  // key = TTL key hash
  contract_code_entries: Map<[32]byte, ContractCodeMapEntry>
  config_settings: Map<i32, LedgerEntry>                      // key = ConfigSettingId
  pending_ttls: Map<[32]byte, TtlData>
  last_closed_ledger_seq: u32
  contract_data_state_size: i64   // cumulative XDR size
  contract_code_state_size: i64   // cumulative in-memory size

STRUCT SorobanStateStats:
  ledger_seq, contract_data_count, contract_code_count: ...
  config_settings_count, contract_data_size, contract_code_size: ...
  pending_ttl_count: usize
```

### Helper: config_setting_entry_id

```
function config_setting_entry_id(entry) -> i32:
  → map ConfigSettingEntry variant to ConfigSettingId integer
```

### Helper: convert_ledger_entry_to_p25

```
function convert_ledger_entry_to_p25(entry) -> optional p25::LedgerEntry:
  "XDR round-trip: our stellar-xdr → bytes → soroban-env-host P25 XDR"
  bytes = xdr_encode(entry)
  → p25::LedgerEntry.from_xdr(bytes)
```

### Helper: build_rent_budget

```
function build_rent_budget(rent_config) -> Budget:
  if rent_config is null: → default Budget
  if cost params are empty: → default Budget

  cpu = convert_contract_cost_params_to_p25(rent_config.cpu_cost_params)
  mem = convert_contract_cost_params_to_p25(rent_config.mem_cost_params)
  instruction_limit = rent_config.tx_max_instructions * 2
  memory_limit = rent_config.tx_max_memory_bytes * 2

  → Budget.try_from_configs(instruction_limit, memory_limit, cpu, mem)
```

### Key Hash Functions

```
function contract_data_key_hash(key) -> [32]byte:
  → sha256(xdr_encode(ContractDataKey(key)))

function contract_code_key_hash(key) -> [32]byte:
  → sha256(xdr_encode(ContractCodeKey(key)))

function ttl_key_to_map_key(key) -> [32]byte:
  → key.key_hash.bytes
```

### get

```
function get(state, key) -> optional LedgerEntry:
  if key is ContractData(cd):
    → state.contract_data_entries[cd_hash]?.ledger_entry
  if key is ContractCode(cc):
    → state.contract_code_entries[cc_hash]?.ledger_entry
  if key is Ttl(ttl):
    → get_ttl_entry(state, ttl)
  if key is ConfigSetting(cs):
    → state.config_settings[cs.id]
  → null
```

### get_ttl_entry

"Synthesize a TTL entry from stored TTL data."

```
function get_ttl_entry(state, ttl_key) -> optional LedgerEntry:
  key_hash = ttl_key.key_hash.bytes

  ttl_data = state.contract_data_entries[key_hash]?.ttl_data
          ?? state.contract_code_entries[key_hash]?.ttl_data
  if ttl_data is null: → null

  "Synthesize the TTL entry"
  → LedgerEntry(
      last_modified = ttl_data.last_modified_ledger_seq,
      data = TtlEntry(key_hash, ttl_data.live_until_ledger_seq)
    )
```

### create_contract_data

```
function create_contract_data(state, entry):
  GUARD entry.data is not ContractData → error("not a contract data entry")

  key_hash = contract_data_key_hash(entry.data.key)
  GUARD key_hash in state.contract_data_entries → error("already exists")

  // Adopt pending TTL if available
  ttl_data = state.pending_ttls.remove(key_hash) ?? default TtlData

  map_entry = ContractDataMapEntry(entry, ttl_data)
  state.contract_data_state_size += map_entry.xdr_size()
  state.contract_data_entries[key_hash] = map_entry
```

### update_contract_data

"Preserves existing TTL while updating data."

```
function update_contract_data(state, entry):
  GUARD entry.data is not ContractData → error("not a contract data entry")

  key_hash = contract_data_key_hash(entry.data.key)
  old_entry = state.contract_data_entries.remove(key_hash)
  GUARD old_entry is null → error("does not exist")

  new_entry = ContractDataMapEntry(entry, old_entry.ttl_data)

  state.contract_data_state_size += new_entry.xdr_size() - old_entry.xdr_size()
  state.contract_data_entries[key_hash] = new_entry
```

### delete_contract_data

```
function delete_contract_data(state, key):
  key_hash = contract_data_key_hash(key)
  old_entry = state.contract_data_entries.remove(key_hash)
  GUARD old_entry is null → error("does not exist")

  state.contract_data_state_size -= old_entry.xdr_size()
```

### create_contract_code

```
function create_contract_code(state, entry, protocol_version, rent_config):
  GUARD entry.data is not ContractCode → error("not a contract code entry")

  key_hash = contract_code_key_hash(entry.data.hash)
  GUARD key_hash in state.contract_code_entries → error("already exists")

  ttl_data = state.pending_ttls.remove(key_hash) ?? default TtlData
  size_bytes = calculate_code_size(entry, protocol_version, rent_config)

  map_entry = ContractCodeMapEntry(entry, ttl_data, size_bytes)
  state.contract_code_state_size += size_bytes
  state.contract_code_entries[key_hash] = map_entry
```

### update_contract_code

"Preserves existing TTL while updating code."

```
function update_contract_code(state, entry, protocol_version, rent_config):
  GUARD entry.data is not ContractCode → error("not a contract code entry")

  key_hash = contract_code_key_hash(entry.data.hash)
  old_entry = state.contract_code_entries.remove(key_hash)
  GUARD old_entry is null → error("does not exist")

  new_size = calculate_code_size(entry, protocol_version, rent_config)
  new_entry = ContractCodeMapEntry(entry, old_entry.ttl_data, new_size)

  state.contract_code_state_size += new_size - old_entry.size_bytes
  state.contract_code_entries[key_hash] = new_entry
```

### delete_contract_code

```
function delete_contract_code(state, key):
  key_hash = contract_code_key_hash(key.hash)
  old_entry = state.contract_code_entries.remove(key_hash)
  GUARD old_entry is null → error("does not exist")

  state.contract_code_state_size -= old_entry.size_bytes
```

### create_ttl

"If corresponding data/code entry exists, stores TTL inline. Otherwise stores as pending."

```
function create_ttl(state, ttl_key, ttl_data):
  key_hash = ttl_key.key_hash.bytes

  if key_hash in state.contract_data_entries:
    entry = state.contract_data_entries[key_hash]
    GUARD entry.ttl_data.is_initialized() → error("TTL already initialized")
    MUTATE entry.ttl_data = ttl_data
    return

  if key_hash in state.contract_code_entries:
    entry = state.contract_code_entries[key_hash]
    GUARD entry.ttl_data.is_initialized() → error("TTL already initialized")
    MUTATE entry.ttl_data = ttl_data
    return

  "No entry found, store as pending"
  GUARD key_hash in state.pending_ttls → error("pending TTL already exists")
  state.pending_ttls[key_hash] = ttl_data
```

### update_ttl

```
function update_ttl(state, ttl_key, ttl_data):
  key_hash = ttl_key.key_hash.bytes

  if key_hash in state.contract_data_entries:
    MUTATE state.contract_data_entries[key_hash].ttl_data = ttl_data
    return
  if key_hash in state.contract_code_entries:
    MUTATE state.contract_code_entries[key_hash].ttl_data = ttl_data
    return

  → error("TTL update missing contract data/code entry")
```

### calculate_code_size

```
function calculate_code_size(state, entry, protocol_version, rent_config) -> u32:
  xdr_size = length(xdr_encode(entry))

  @version(<25):
    → entry_size_for_rent_by_protocol_with_cost_params(
        protocol_version, entry, xdr_size, cost_params)

  @version(≥25):
    budget = build_rent_budget(rent_config)
    p25_entry = convert_ledger_entry_to_p25(entry)
    → entry_size_for_rent_p25(budget, p25_entry, xdr_size) ?? xdr_size
```

**Calls**: REF: henyey_tx::entry_size_for_rent_by_protocol_with_cost_params, REF: soroban_env_host_p25::entry_size_for_rent

### update_state

"Update state with entries from a ledger close."

```
function update_state(state, ledger_seq, init_entries, live_entries,
                      dead_entries, protocol_version, rent_config):
  // Validate sequence progression
  if state.last_closed_ledger_seq > 0:
    GUARD ledger_seq != state.last_closed_ledger_seq + 1
        → error(InvalidSequence)

  // Process init entries (creates)
  for each entry in init_entries:
    process_entry_create(state, entry, protocol_version, rent_config)

  // Process live entries (updates)
  for each entry in live_entries:
    process_entry_update(state, entry, protocol_version, rent_config)

  // Process dead entries (deletes)
  for each key in dead_entries:
    process_entry_delete(state, key)

  state.last_closed_ledger_seq = ledger_seq

  // Check invariant: pending_ttls should be empty after each update
  ASSERT: state.pending_ttls is empty
```

### process_entry_create

```
function process_entry_create(state, entry, protocol_version, rent_config):
  if entry.data is ContractData:   → create_contract_data(state, entry)
  if entry.data is ContractCode:   → create_contract_code(state, entry, ...)
  if entry.data is Ttl:            → process_ttl_entry_create(state, entry)
  if entry.data is ConfigSetting:
    id = config_setting_entry_id(entry.data)
    state.config_settings[id] = entry
  else: ignore non-Soroban entries
```

### process_entry_update

```
function process_entry_update(state, entry, protocol_version, rent_config):
  if entry.data is ContractData:
    key_hash = contract_data_key_hash(entry.data.key)
    if key_hash in state.contract_data_entries:
      update_contract_data(state, entry)
    else:
      create_contract_data(state, entry)
      NOTE: update-as-create for entries from INIT → LIVE moves

  if entry.data is ContractCode:
    key_hash = contract_code_key_hash(entry.data.hash)
    if key_hash in state.contract_code_entries:
      update_contract_code(state, entry, ...)
    else:
      create_contract_code(state, entry, ...)

  if entry.data is Ttl:           → process_ttl_entry_update(state, entry)
  if entry.data is ConfigSetting:
    id = config_setting_entry_id(entry.data)
    state.config_settings[id] = entry
  else: ignore
```

### process_entry_delete

```
function process_entry_delete(state, key):
  if key is ContractData(cd):
    delete_contract_data(state, cd)   // ignore error if not exists
  if key is ContractCode(cc):
    delete_contract_code(state, cc)   // ignore error if not exists
  if key is Ttl(ttl):
    "TTL deletion handled implicitly when data/code is deleted"
    state.pending_ttls.remove(ttl.key_hash)
  else: ignore
```

### recompute_contract_code_sizes

"Called after protocol upgrade or config change affecting compiled module sizing."
"Parity: InMemorySorobanState.cpp:562 recomputeContractCodeSize"

```
function recompute_contract_code_sizes(state, protocol_version, rent_config):
  total_size = 0
  budget = build_rent_budget(rent_config)

  for each entry in state.contract_code_entries.values():
    xdr_size = length(xdr_encode(entry.ledger_entry))

    @version(≥25):
      new_size = entry_size_for_rent_p25(budget, ...) ?? xdr_size
    @version(<25):
      new_size = entry_size_for_rent_by_protocol(..., xdr_size, cost_params)

    entry.size_bytes = new_size
    total_size += new_size

  state.contract_code_state_size = total_size
```

### SharedSorobanState

"Thread-safe wrapper: RwLock for concurrent reads, exclusive writes."

```
STRUCT SharedSorobanState:
  inner: RwLock<InMemorySorobanState>

function read(shared) → read_guard    // concurrent access
function write(shared) → write_guard  // exclusive access
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1126  | ~215       |
| Functions     | 38     | 22         |
