## Pseudocode: crates/tx/src/soroban/host.rs

### Data Structures

```
struct SorobanExecutionResult:
  return_value: ScVal
  storage_changes: list of StorageChange
  contract_events: list of ContractEvent
  diagnostic_events: list of DiagnosticEvent
  cpu_insns: u64
  mem_bytes: u64
  contract_events_and_return_value_size: u32
  rent_fee: i64
  live_bucket_list_restores: list of LiveBucketListRestore
  actual_restored_indices: list of u32
    NOTE: "Indices of entries ACTUALLY restored from hot archive in THIS transaction.
           Subset of envelope's archived_soroban_entries, excluding entries
           already restored by a previous transaction in the same ledger."

struct SorobanExecutionError:
  host_error: HostError
  cpu_insns_consumed: u64
  mem_bytes_consumed: u64

struct StorageChange:
  key: LedgerKey
  new_entry: LedgerEntry or null
  live_until: u32 or null
  ttl_extended: bool
  is_rent_related: bool
  is_read_only_ttl_bump: bool
    NOTE: "Read-only TTL bumps should be applied to state (bucket list)
           but NOT included in transaction meta. Matches stellar-core
           CAP-0063 behavior."

enum PersistentModuleCache:
  P24(ModuleCache)
  P25(ModuleCacheP25)

struct EncodedFootprint:
  ledger_entries: list of byte[]
  ttl_entries: list of byte[]
  actual_restored_indices: list of u32
  live_bl_restores: list of LiveBucketListRestore
```

### PersistentModuleCache.new_for_protocol

```
new_for_protocol(protocol_version):
  @version(≥25):
    → new_p25()
  @version(<25):
    → new_p24()
```

### PersistentModuleCache.add_contract

```
add_contract(code, protocol_version):
  contract_id = SHA256(code)
  cost_inputs = { wasm_bytes: length(code) }
  → cache.parse_and_cache_module(
      compilation_context, protocol_version,
      contract_id, code, cost_inputs)
```

### PersistentModuleCache.remove_contract

```
remove_contract(hash):
  contract_id = Hash(hash)
  → cache.remove_module(contract_id)
```

### LedgerSnapshotAdapter (P24)

"Adapter that provides snapshot access to our ledger state for Soroban."

#### get_archived

```
get_archived(key):
  current_key = convert_key_from_p24(key)

  "Get TTL but don't check if expired - this is for archived entries"
  live_until = get_entry_ttl(state, current_key, current_ledger)

  "No TTL check - entry might be archived with expired TTL"
  entry = state.get_entry(current_key)

  if entry exists:
    p24_entry = convert_entry_to_p24(entry)
    → (p24_entry, live_until)

  "Entry not found in live state - try hot archive bucket list"
  if hot_archive available:
    archived = hot_archive.get(current_key)
    if archived exists:
      p24_entry = convert_entry_to_p24(archived)
      "Hot archive entries have no TTL (they are archived/expired)"
      → (p24_entry, null)

  → null
```

#### get_archived_with_restore_info

```
get_archived_with_restore_info(key, current_key):
  result = get_archived(key)
  if result is null:
    → null

  (entry, live_until) = result

  "Check if this is a live BL restore: entry exists AND TTL is expired"
  live_bl_restore = null
  if live_until exists AND live_until < current_ledger:
    current_entry = state.get_entry(current_key)
    if current_entry exists:
      key_hash = compute_key_hash(current_key)
      ttl_key = LedgerKey::Ttl(key_hash)
      ttl_entry = state.get_entry(ttl_key)
      if ttl_entry exists:
        live_bl_restore = LiveBucketListRestore {
          key, entry: current_entry, ttl_key, ttl_entry
        }

  → (entry, live_until, live_bl_restore)
```

#### SnapshotSource.get (P24)

"For ContractData and ContractCode, check TTL first.
If TTL has expired, the entry is considered to be in the hot archive
and not accessible. This mimics stellar-core behavior."

```
get(key):
  current_key = convert_key_from_p24(key)
  live_until = get_entry_ttl(state, current_key, current_ledger)

  if key is ContractData or ContractCode:
    if live_until exists AND live_until < current_ledger:
      → null

  entry = state.get_entry(current_key)
  if entry exists:
    p24_entry = convert_entry_to_p24(entry)
    → (p24_entry, live_until)
  → null
```

### LedgerSnapshotAdapterP25

#### get_local

"For ContractData and ContractCode, check TTL from bucket list snapshot."

```
get_local(key):
  live_until = get_entry_ttl(state, key, current_ledger)

  if key is ContractData or ContractCode:
    if live_until exists AND live_until >= current_ledger:
      pass  // live, proceed
    else:
      → null  // expired or no TTL

  entry = state.get_entry(key)
  if entry exists:
    → (entry, live_until)
  → null
```

#### get_archived (P25)

```
get_archived(key):
  live_until = get_entry_ttl(state, key, current_ledger)
  entry = state.get_entry(key)

  if entry exists:
    → (entry, live_until)

  "Entry not found in live state - try hot archive bucket list"
  if hot_archive available:
    archived = hot_archive.get(key)
    if archived exists:
      → (archived, null)  // no TTL for hot archive entries

  → null
```

#### get_archived_with_restore_info (P25)

```
get_archived_with_restore_info(key):
  result = get_archived(key)
  if result is null:
    → null

  (entry, live_until) = result

  live_bl_restore = null
  if live_until exists AND live_until < current_ledger:
    key_hash = compute_key_hash(key)
    ttl_key = LedgerKey::Ttl(key_hash)
    ttl_entry = state.get_entry(ttl_key)
    if ttl_entry exists:
      live_bl_restore = LiveBucketListRestore {
        key, entry, ttl_key, ttl_entry
      }

  → (entry, live_until, live_bl_restore)
```

#### SnapshotSource.get (P25)

```
get(key):
  local_key = convert_key_from_p25(key)

  live_until = get_entry_ttl(state, local_key, current_ledger)

  if key is ContractData or ContractCode:
    if live_until exists AND live_until >= current_ledger:
      pass  // live
    else:
      → null  // expired or no TTL

  entry = state.get_entry(local_key)
  if entry exists:
    p25_entry = convert_entry_to_p25(entry)
    → (p25_entry, live_until)
  → null
```

### Helper: get_entry_ttl

"Returns the CURRENT TTL value (after any modifications by earlier
transactions in this ledger), not the ledger-start TTL. This matches
stellar-core behavior where the Soroban host computes rent fees based
on the current state."

"If TX 6 extends an entry's TTL from 682237 → 700457, TX 7 accessing
the same entry will see old_live_until=700457 and NOT pay rent for
the extension."

```
get_entry_ttl(state, key, current_ledger):
  if key is not ContractData and not ContractCode:
    → null

  key_hash = compute_key_hash(key)
  "Use current state TTL which includes updates from earlier TXs"
  ttl = state.get_ttl(key_hash).live_until_ledger_seq
  → ttl or null
```

### Helper: compute_key_hash

```
compute_key_hash(key):
  bytes = xdr_encode(key)
  → SHA256(bytes)
```

### compute_rent_fee_for_new_entry

"Compute rent_fee for a newly created Soroban entry."

```
compute_rent_fee_for_new_entry(
    entry_size_bytes, live_until, is_persistent,
    is_code_entry, current_ledger, soroban_config,
    protocol_version):

  rent_change = {
    is_persistent,
    is_code_entry,
    old_size_bytes: 0,      // new entry
    new_size_bytes: entry_size_bytes,
    old_live_until_ledger: 0,
    new_live_until_ledger: live_until,
  }

  @version(≥25):
    → compute_rent_fee([rent_change],
        soroban_config.rent_fee_config, current_ledger)
  @version(<25):
    p24_config = rent_fee_config_p25_to_p24(
        soroban_config.rent_fee_config)
    → compute_rent_fee([rent_change], p24_config, current_ledger)
```

**Calls** [`compute_rent_fee`](soroban-env-host) (external crate)

### execute_host_function

```
execute_host_function(host_function, auth_entries, source,
    state, context, soroban_data, soroban_config):

  → execute_host_function_with_cache(
      host_function, auth_entries, source, state,
      context, soroban_data, soroban_config,
      module_cache=null, hot_archive=null)
```

### execute_host_function_with_cache

```
execute_host_function_with_cache(
    host_function, auth_entries, source,
    state, context, soroban_data, soroban_config,
    module_cache, hot_archive):

  @version(≥25):
    ASSERT: module_cache is provided
    p25_cache = module_cache.as_p25()
    ASSERT: p25_cache is not null
    → execute_host_function_p25(
        host_function, auth_entries, source, state,
        context, soroban_data, soroban_config,
        p25_cache, hot_archive)

  @version(<25):
    ASSERT: module_cache is provided
    p24_cache = module_cache.as_p24()
    ASSERT: p24_cache is not null
    → execute_host_function_p24(
        host_function, auth_entries, source, state,
        context, soroban_data, soroban_config,
        p24_cache, hot_archive)
```

### Helper: encode_footprint_entries (P24)

"Collect and encode ledger entries from the transaction footprint.
Handles archived entry restoration for Protocol 23+."

```
encode_footprint_entries(soroban_data, snapshot, context,
    soroban_config):

  // Phase 1: Extract archived entry indices
  restored_rw_entry_indices = soroban_data.ext match:
    V1(ext) → ext.archived_soroban_entries
    V0      → empty list
  restored_indices_set = set(restored_rw_entry_indices)

  encoded_ledger_entries = []
  encoded_ttl_entries = []

  // Phase 2: Read-only footprint entries
  for each key in soroban_data.resources.footprint.read_only:
    p24_key = convert_key_to_p24(key)
    result = snapshot.get(p24_key)
    if result exists:
      (entry, live_until) = result
      add_entry(key, entry, live_until)

  // Phase 3: Read-write footprint entries (with restoration)
  live_bl_restores = []
  actual_restored_indices = []

  for each (idx, key) in soroban_data.resources
      .footprint.read_write:

    p24_key = convert_key_to_p24(key)
    is_being_restored = idx in restored_indices_set

    if is_being_restored:
      result = snapshot.get_archived_with_restore_info(
          p24_key, key)
      if result exists:
        (entry, live_until, live_bl_restore) = result

        is_actually_archived =
          live_until is null OR live_until < current_ledger

        if is_actually_archived:
          restored_live_until = current_ledger
            + soroban_config.min_persistent_entry_ttl - 1
          add_entry(key, entry, restored_live_until)
          actual_restored_indices.append(idx)
          if live_bl_restore exists:
            live_bl_restores.append(live_bl_restore)
        else:
          NOTE: "Already live (restored by earlier TX)"
          add_entry(key, entry, live_until)
    else:
      result = snapshot.get(p24_key)
      if result exists:
        (entry, live_until) = result
        add_entry(key, entry, live_until)

  → EncodedFootprint {
      encoded_ledger_entries, encoded_ttl_entries,
      actual_restored_indices, live_bl_restores
    }
```

Where `add_entry` encodes entry + TTL:

```
add_entry(key, entry, live_until):
  encoded_ledger_entries.append(xdr_encode(entry))

  needs_ttl = key is ContractData or ContractCode
  if live_until exists:
    key_hash = compute_key_hash(key)
    encoded_ttl_entries.append(xdr_encode(
      TtlEntry { key_hash, live_until }))
  else if needs_ttl:
    "For archived entries, use current_ledger as minimum valid TTL"
    key_hash = compute_key_hash(key)
    encoded_ttl_entries.append(xdr_encode(
      TtlEntry { key_hash, current_ledger }))
  else:
    encoded_ttl_entries.append(empty)
```

### execute_host_function_p24

"Execute a Soroban host function via soroban-env-host P24's e2e_invoke API."

```
execute_host_function_p24(
    host_function, auth_entries, source,
    state, context, soroban_data, soroban_config,
    existing_cache, hot_archive):

  // Phase 1: Build budget
  "stellar-core passes per-transaction instruction limit directly
   to the host. Memory limit from network config."
  instruction_limit = soroban_data.resources.instructions
  memory_limit = soroban_config.tx_max_memory_bytes

  if soroban_config.has_valid_cost_params():
    cpu_cost_params = convert_to_p24(
        soroban_config.cpu_cost_params)
    mem_cost_params = convert_to_p24(
        soroban_config.mem_cost_params)
    budget = Budget(instruction_limit, memory_limit,
        cpu_cost_params, mem_cost_params)
  else:
    budget = Budget.default()

  // Phase 2: Build ledger info
  ledger_info = {
    protocol_version, sequence_number,
    timestamp: context.close_time,
    network_id, base_reserve,
    min_temp_entry_ttl, min_persistent_entry_ttl,
    max_entry_ttl
  }

  // Phase 3: PRNG seed
  if context.soroban_prng_seed exists:
    seed = context.soroban_prng_seed
  else:
    "Fallback: deterministic but incorrect seed"
    seed = SHA256(network_id || sequence || close_time)

  // Phase 4: Encode XDR inputs
  encoded_host_fn = xdr_encode(host_function)
  encoded_resources = xdr_encode(soroban_data.resources)
  encoded_source = xdr_encode(source)
  encoded_auth = [xdr_encode(e) for e in auth_entries]

  // Phase 5: Collect footprint entries
  snapshot = LedgerSnapshotAdapter(state, context.sequence,
      hot_archive)
  footprint = encode_footprint_entries(soroban_data, snapshot,
      context, soroban_config)

  // Phase 6: Module cache
  ASSERT: existing_cache is provided
  module_cache = existing_cache

  // Phase 7: Invoke host function
  diagnostic_events = []
  result = e2e_invoke::invoke_host_function(
    budget, enable_diagnostics=true,
    encoded_host_fn, encoded_resources,
    footprint.actual_restored_indices,
    encoded_source, encoded_auth,
    ledger_info,
    footprint.ledger_entries, footprint.ttl_entries,
    seed, diagnostic_events,
    trace_hook=null, module_cache)

  if result failed:
    → error with (host_error, cpu_consumed, mem_consumed)

  // Phase 8: Parse return value
  return_value = xdr_decode(result.encoded_invoke_result)
  if decode failed:
    → error with (host_error, cpu_consumed, mem_consumed)

  // Phase 9: Parse contract events
  contract_events = []
  contract_events_size = 0
  for each buf in result.encoded_contract_events:
    contract_events_size += length(buf)
    contract_events.append(xdr_decode(buf))

  // Phase 10: Compute rent fee
  rent_changes = extract_rent_changes(result.ledger_changes)
  p24_config = rent_fee_config_p25_to_p24(
      soroban_config.rent_fee_config)
  rent_fee = compute_rent_fee(rent_changes, p24_config,
      context.sequence)

  // Phase 11: Process storage changes
  storage_changes = process_ledger_changes(
      result.ledger_changes, state)
```

**Calls** [`e2e_invoke::invoke_host_function`](soroban-env-host-p24), [`extract_rent_changes`](soroban-env-host-p24), [`compute_rent_fee`](soroban-env-host-p24)

### execute_host_function_p25

"Execute a Soroban host function via soroban-env-host P25's e2e_invoke API."

Structure is identical to P24 path but uses P25 types and inlines the
footprint collection (same logic as `encode_footprint_entries`).

```
execute_host_function_p25(
    host_function, auth_entries, source,
    state, context, soroban_data, soroban_config,
    existing_cache, hot_archive):

  // Phase 1-4: same as P24 (budget, ledger_info, seed, encode)
  instruction_limit = soroban_data.resources.instructions
  memory_limit = soroban_config.tx_max_memory_bytes

  if soroban_config.has_valid_cost_params():
    budget = Budget(instruction_limit, memory_limit,
        p25_cpu_params, p25_mem_params)
  else:
    budget = Budget.default()

  ledger_info = { ... same fields as P24 ... }
  seed = context.soroban_prng_seed or SHA256 fallback

  encoded_host_fn = xdr_encode(host_function)
  encoded_resources = xdr_encode(soroban_data.resources)
  encoded_source = xdr_encode(source)
  encoded_auth = [xdr_encode(e) for e in auth_entries]

  // Phase 5: Collect footprint entries (inlined)
  restored_rw_entry_indices = soroban_data.ext match:
    V1(ext) → ext.archived_soroban_entries
    V0      → empty list
  restored_indices_set = set(restored_rw_entry_indices)

  snapshot = LedgerSnapshotAdapterP25(state,
      context.sequence, hot_archive)

  // Read-only entries
  for each key in footprint.read_only:
    result = snapshot.get_local(key)
    if result exists:
      add_entry(key, entry, live_until)

  // Read-write entries (with archived restoration)
  live_bl_restores = []
  actual_restored_indices = []

  for each (idx, key) in footprint.read_write:
    if idx in restored_indices_set:
      result = snapshot.get_archived_with_restore_info(key)
      if result exists:
        (entry, live_until, live_bl_restore) = result
        is_actually_archived =
          live_until is null OR live_until < current_ledger

        if is_actually_archived:
          restored_ttl = current_ledger
            + min_persistent_entry_ttl - 1
          add_entry(key, entry, restored_ttl)
          actual_restored_indices.append(idx)
          if live_bl_restore:
            live_bl_restores.append(live_bl_restore)
        else:
          NOTE: "Already live (restored by earlier TX)"
          add_entry(key, entry, live_until)
    else:
      result = snapshot.get_local(key)
      if result exists:
        add_entry(key, entry, live_until)

  // Phase 6: Module cache
  ASSERT: existing_cache is provided
  module_cache = existing_cache

  // Phase 7: Invoke
  diagnostic_events = []
  result = e2e_invoke::invoke_host_function(
    budget, enable_diagnostics=true,
    encoded_host_fn, encoded_resources,
    actual_restored_indices,
    encoded_source, encoded_auth,
    ledger_info,
    encoded_ledger_entries, encoded_ttl_entries,
    seed, diagnostic_events,
    trace_hook=null, module_cache)

  if result failed:
    → error with (host_error, cpu_consumed, mem_consumed)

  // Phase 8-10: Parse results (same as P24)
  return_value = xdr_decode(result.encoded_invoke_result)
  contract_events = parse encoded_contract_events
  rent_changes = extract_rent_changes(result.ledger_changes)
  rent_fee = compute_rent_fee(rent_changes,
      soroban_config.rent_fee_config, context.sequence)

  // Phase 11: Process storage changes
  storage_changes = process_ledger_changes(
      result.ledger_changes, state)

  → SorobanExecutionResult {
      return_value, storage_changes, contract_events,
      diagnostic_events, cpu_insns, mem_bytes,
      contract_events_and_return_value_size,
      rent_fee, live_bl_restores,
      actual_restored_indices
    }
```

**Calls** [`e2e_invoke::invoke_host_function`](soroban-env-host-p25), [`extract_rent_changes`](soroban-env-host-p25), [`compute_rent_fee`](soroban-env-host-p25)

### Helper: process_ledger_changes

"Shared logic for filtering e2e_invoke ledger changes into StorageChange list."

"stellar-core behavior for transaction meta and state updates:
1. Transaction meta (setLedgerChangesFromSuccessfulOp): Includes ALL entries, including RO TTL bumps.
2. State updates (commitChangesFromSuccessfulOp): Filters RO TTL bumps to mRoTTLBumps
   and flushes them at write barriers. This is for visibility ordering."

```
process_ledger_changes(ledger_changes, state):
  storage_changes = []

  for each change in ledger_changes:
    is_deletion = not change.read_only
        AND change.new_value is null
    is_modification = change.new_value is not null

    "Determine if TTL was extended from LEDGER-START perspective"
    ttl_extended = false
    if change.ttl_change exists:
      key = xdr_decode(change.encoded_key)
      key_hash = compute_key_hash(key)
      "Compare new TTL against ledger-start TTL, not host's old"
      ledger_start_ttl =
          state.get_ttl_at_ledger_start(key_hash) or 0
      ttl_extended =
          change.ttl_change.new_live_until > ledger_start_ttl

    "A read-only TTL bump: entry is read-only, not modified, but TTL extended"
    is_read_only_ttl_bump = change.read_only
        AND not is_modification AND ttl_extended

    should_include =
        is_modification OR is_deletion OR ttl_extended

    if should_include:
      key = xdr_decode(change.encoded_key)
      new_entry = xdr_decode(change.new_value) or null
      live_until = change.ttl_change.new_live_until or null
      is_rent_related =
          change.old_entry_size_bytes_for_rent > 0

      storage_changes.append(StorageChange {
        key, new_entry, live_until,
        ttl_extended, is_rent_related,
        is_read_only_ttl_bump
      })

  → storage_changes
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1000  | ~310       |
| Functions     | 24     | 16         |

Note: XDR conversion functions (6 functions: `convert_ledger_key_to_p24`,
`convert_ledger_key_from_p24`, `convert_ledger_entry_to_p24`,
`convert_ledger_key_from_p25`, `convert_ledger_entry_to_p25`,
`convert_contract_cost_params_to_p25`, `convert_contract_cost_params_to_p24`,
`rent_fee_config_p25_to_p24`) are mechanical XDR serialization round-trips
and are omitted. The `WasmCompilationContext`/`WasmCompilationContextP25`
types are budget wrappers with 10B CPU / 1GB mem limits for pre-compilation.
