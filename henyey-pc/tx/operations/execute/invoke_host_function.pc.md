## Pseudocode: crates/tx/src/operations/execute/invoke_host_function.rs

### Helper: is_soroban_key

```
is_soroban_key(key):
  → key is ContractData or ContractCode
```

### Helper: key_already_created_in_delta

"Check if a key was already created in the delta (by a previous TX in this ledger).
Used for hot archive restoration to distinguish INIT (create) vs LIVE (update)."

```
key_already_created_in_delta(delta, key):
  for each entry in delta.created_entries():
    entry_key = derive LedgerKey from entry.data
      (ContractData or ContractCode only)
    if entry_key == key:
      → true
  → false
```

### Helper: ttl_already_created_in_delta

```
ttl_already_created_in_delta(delta, key_hash):
  for each entry in delta.created_entries():
    if entry.data is Ttl AND entry.key_hash == key_hash:
      → true
  → false
```

### Helper: validate_contract_ledger_entry

"Matches stellar-core's validateContractLedgerEntry() in TransactionUtils.cpp."

```
validate_contract_ledger_entry(key, entry_size,
    max_contract_size, max_contract_data_size):
  if key is ContractCode:
    GUARD entry_size > max_contract_size  → false
  if key is ContractData:
    GUARD entry_size > max_contract_data_size  → false
  → true
```

### execute_invoke_host_function

```
execute_invoke_host_function(op, source, state, context,
    soroban_data, soroban_config, module_cache,
    hot_archive):

  GUARD soroban_data is null  → Malformed

  → execute_contract_invocation(op, source, state,
      context, soroban_data, soroban_config,
      module_cache, hot_archive)
```

### execute_contract_invocation

```
execute_contract_invocation(op, source, state, context,
    soroban_data, soroban_config, module_cache,
    hot_archive):

  auth_entries = op.auth

  // Phase 1: Pre-invocation validation
  GUARD footprint_has_unrestored_archived_entries(
      state, soroban_data.resources.footprint,
      soroban_data.ext, context.sequence, hot_archive)
    → EntryArchived

  GUARD disk_read_bytes_exceeded(state, soroban_data,
      context.protocol_version, context.sequence)
    → ResourceLimitExceeded

  // Phase 2: Execute via soroban-env-host
  result = execute_host_function_with_cache(
      op.host_function, auth_entries, source, state,
      context, soroban_data, soroban_config,
      module_cache, hot_archive)
```

**Calls** [`execute_host_function_with_cache`](../../../soroban/host.pc.md#execute_host_function_with_cache)

```
  if result is error:
    // Phase 2a: Map error to result code
    "stellar-core checks raw resource consumption regardless of error type"
    result_code = map_host_error_to_result_code(
        exec_error,
        soroban_data.resources.instructions,
        soroban_config.tx_max_memory_bytes)
    → result_code

  // Phase 3: Post-invocation validation
  "stellar-core: event size check (done first in collectEvents)"
  GUARD soroban_config.tx_max_contract_events_size_bytes > 0
    AND result.contract_events_and_return_value_size
      > soroban_config.tx_max_contract_events_size_bytes
    → ResourceLimitExceeded

  "stellar-core: write bytes check (recordStorageChanges)"
  validation = validate_and_compute_write_bytes(
      result.storage_changes,
      soroban_config.max_contract_size_bytes,
      soroban_config.max_contract_data_entry_size_bytes)

  GUARD validation is EntrySizeExceeded
    → ResourceLimitExceeded

  GUARD validation.total_write_bytes
    > soroban_data.resources.write_bytes
    → ResourceLimitExceeded

  // Phase 4: Apply storage changes
  "Exclude live BL restores from hot archive set -
   only true hot archive restores use INIT"
  hot_archive_restored_keys =
      extract_hot_archive_restored_keys(
        soroban_data,
        result.actual_restored_indices,
        result.live_bucket_list_restores)

  apply_soroban_storage_changes(state,
      result.storage_changes,
      soroban_data.resources.footprint,
      hot_archive_restored_keys)

  // Phase 5: Build result
  result_hash = compute_success_preimage_hash(
      result.return_value, result.contract_events)

  → Success(result_hash) with soroban_meta
```

### validate_and_compute_write_bytes

"Matches stellar-core's recordStorageChanges(). TTL entries excluded
from write bytes because their fees come from refundableFee."

```
validate_and_compute_write_bytes(storage_changes,
    max_contract_size, max_contract_data_size):
  total = 0
  for each change in storage_changes:
    if change.new_entry is null:
      continue
    if change.new_entry is TTL:
      continue  // TTL write fees handled separately
    entry_size = xdr_size(change.new_entry)
    if not validate_contract_ledger_entry(
        change.key, entry_size,
        max_contract_size, max_contract_data_size):
      → EntrySizeExceeded
    total += entry_size
  → Valid { total_write_bytes: total }
```

### disk_read_bytes_exceeded

```
disk_read_bytes_exceeded(state, soroban_data,
    protocol_version, current_ledger):
  total_read_bytes = 0
  limit = soroban_data.resources.disk_read_bytes
```

```
  @version(<23):
    "Meter all footprint entries"
    for each key in footprint.read_only:
      meter_entry(key, total_read_bytes)
      GUARD total_read_bytes > limit  → true (exceeded)
    for each key in footprint.read_write:
      meter_entry(key, total_read_bytes)
      GUARD total_read_bytes > limit  → true (exceeded)
```

```
  @version(≥23):
    "Only meter non-soroban entries from footprint"
    for each key in footprint.read_only:
      if not is_soroban_key(key):
        meter_entry(key, total_read_bytes)
        GUARD total_read_bytes > limit  → true
    for each key in footprint.read_write:
      if not is_soroban_key(key):
        meter_entry(key, total_read_bytes)
        GUARD total_read_bytes > limit  → true

    "Meter archived soroban entries from ext.V1"
    if soroban_data.ext is V1:
      for each index in ext.archived_soroban_entries:
        key = footprint.read_write[index]
        if not is_soroban_key(key):
          continue
        "Only meter if still archived (not restored by earlier TX)"
        key_hash = compute_key_hash(key)
        is_still_archived = state.get_ttl(key_hash) match:
          exists AND live_until >= current_ledger → false
          otherwise → true
        if not is_still_archived:
          continue
        meter_entry(key, total_read_bytes)
        GUARD total_read_bytes > limit  → true

  → false (not exceeded)
```

Where `meter_entry` computes the XDR size of the entry and adds to total.

### compute_success_preimage_hash

```
compute_success_preimage_hash(return_value, events):
  preimage = InvokeHostFunctionSuccessPreImage {
    return_value, events
  }
  → SHA256(xdr_encode(preimage))
```

### build_soroban_operation_meta

```
build_soroban_operation_meta(result):
  events = result.contract_events

  diagnostic_events = []
  for each event in events:
    diagnostic_events.append(DiagnosticEvent {
      in_successful_contract_call: true,
      event
    })
  diagnostic_events.extend(result.diagnostic_events)

  → SorobanOperationMeta {
      events,
      diagnostic_events,
      return_value: result.return_value,
      event_size_bytes:
        result.contract_events_and_return_value_size,
      rent_fee: result.rent_fee,
      live_bucket_list_restores:
        result.live_bucket_list_restores,
      actual_restored_indices:
        result.actual_restored_indices
    }
```

### extract_hot_archive_restored_keys

"Extract keys of entries being restored from the hot archive (NOT live BL).
Per CAP-0066, hot archive restored entries → INIT (created).
Live BL restores (expired TTL but not yet evicted) → LIVE (updated)."

"Uses actual_restored_indices from execution result, NOT raw
archived_soroban_entries from envelope. Earlier TXs in same ledger
may have already restored entries."

```
extract_hot_archive_restored_keys(soroban_data,
    actual_restored_indices,
    live_bucket_list_restores):

  if actual_restored_indices is empty:
    → empty set

  live_bl_restore_keys = set of keys from
      live_bucket_list_restores

  keys = empty set
  for each index in actual_restored_indices:
    key = soroban_data.footprint.read_write[index]
    if key not in live_bl_restore_keys:
      keys.add(key)

  → keys
```

### apply_soroban_storage_changes

"stellar-core behavior: delete any read-write footprint entries that weren't
returned by the host (recordStorageChanges)."

```
apply_soroban_storage_changes(state, changes, footprint,
    hot_archive_restored_keys):

  // Phase 1: Track created/modified keys
  created_and_modified_keys = set of keys where
      change.new_entry is not null

  // Phase 2: Apply all changes from the host
  for each change in changes:
    apply_soroban_storage_change(state, change,
        hot_archive_restored_keys)

  // Phase 3: Delete unmentioned read-write entries
  "Entries NOT returned by host are considered deleted"
  for each key in footprint.read_write:
    if key in created_and_modified_keys:
      continue
    if key is ContractData:
      if entry exists in state:
        MUTATE state delete_contract_data(key)
        MUTATE state delete_ttl(compute_key_hash(key))
    if key is ContractCode:
      if entry exists in state:
        MUTATE state delete_contract_code(key)
        MUTATE state delete_ttl(compute_key_hash(key))
```

### apply_soroban_storage_change

"Apply a single storage change with hot archive restore awareness."

```
apply_soroban_storage_change(state, change,
    hot_archive_restored_keys):

  is_hot_archive_restore =
      change.key in hot_archive_restored_keys

  if change.new_entry exists:
    // === Data/Code entry handling ===
    if entry is ContractData or ContractCode:
      entry_exists = state has entry
      already_restored = is_hot_archive_restore
          AND key_already_created_in_delta(
              state.delta(), change.key)

      if is_hot_archive_restore AND not already_restored:
        "First restoration from hot archive → INIT"
        MUTATE state CREATE entry
      else if entry_exists OR already_restored:
        MUTATE state UPDATE entry
      else:
        "New entry (not restore, not existing) → CREATE"
        MUTATE state CREATE entry

    if entry is Ttl:
      if state has TTL:
        MUTATE state UPDATE ttl
      else:
        MUTATE state CREATE ttl

    "SAC (Stellar Asset Contract) can modify these"
    if entry is Account:
      MUTATE state create_or_update account
    if entry is Trustline:
      MUTATE state create_or_update trustline

    // === TTL handling for contract entries ===
    "Skip TTL emission for TTL entries themselves"
    if entry is not Ttl AND change.live_until exists
        AND change.live_until != 0:

      key_hash = compute_key_hash(change.key)
      existing_ttl = state.get_ttl(key_hash)
      ttl = TtlEntry { key_hash, live_until }

      ttl_already_restored = is_hot_archive_restore
          AND ttl_already_created_in_delta(
              state.delta(), key_hash)

      if is_hot_archive_restore AND not ttl_already_restored:
        "First restoration → create TTL"
        MUTATE state CREATE ttl
      else if is_hot_archive_restore AND ttl_already_restored:
        "Already restored by earlier TX → update"
        MUTATE state UPDATE ttl
      else if change.ttl_extended:
        "TTL extended from ledger-start perspective"
        NOTE: "Must emit even if current state already has value
               (e.g., from earlier TX in same ledger)"
        if existing_ttl exists:
          MUTATE state UPDATE ttl
        else:
          MUTATE state CREATE ttl
      else if existing_ttl is null:
        "New entry being created → emit TTL"
        MUTATE state CREATE ttl
      else:
        "TTL NOT extended and entry exists → skip"

  else if change.live_until exists AND live_until != 0:
    // === TTL-only change (no data modification) ===
    if change.ttl_extended:
      key_hash = compute_key_hash(change.key)
      existing_ttl = state.get_ttl(key_hash)
      ttl = TtlEntry { key_hash, live_until }

      if change.is_read_only_ttl_bump:
        "Record in delta for meta, defer state update
         so subsequent TXs don't see bumped value"
        MUTATE state record_ro_ttl_bump_for_meta(
            key_hash, live_until)
      else:
        if existing_ttl exists:
          MUTATE state UPDATE ttl
        else:
          MUTATE state CREATE ttl

  else:
    // === Deletion (no new_entry, no live_until) ===
    if key is ContractData:
      MUTATE state delete_contract_data(key)
      MUTATE state delete_ttl(compute_key_hash(key))
    if key is ContractCode:
      MUTATE state delete_contract_code(key)
      MUTATE state delete_ttl(compute_key_hash(key))
    if key is Ttl:
      MUTATE state delete_ttl(key.key_hash)
    "SAC can also delete Account and Trustline"
    if key is Account:
      MUTATE state delete_account(key)
    if key is Trustline:
      MUTATE state delete_trustline(key)
```

### footprint_has_unrestored_archived_entries

```
footprint_has_unrestored_archived_entries(state,
    footprint, ext, current_ledger, hot_archive):

  archived_rw = set of indices from
      ext.V1.archived_soroban_entries (if V1)

  if any key in footprint.read_only is archived:
    → true

  for each (index, key) in footprint.read_write:
    if not is_archived_contract_entry(state, key,
        current_ledger, hot_archive):
      continue
    if index not in archived_rw:
      → true  // archived but not marked for restore

  → false
```

### is_archived_contract_entry

"Parity: InvokeHostFunctionOpFrame.cpp addReads() lines 378-445"

```
is_archived_contract_entry(state, key, current_ledger,
    hot_archive):
  "Only persistent Soroban entries can be archived"
  GUARD key is not persistent ContractData
    AND key is not ContractCode  → false

  // Check live state
  entry_in_live = state has entry for key
  if entry_in_live:
    key_hash = compute_key_hash(key)
    ttl = state.get_ttl(key_hash)
    if ttl exists:
      → ttl.live_until < current_ledger
    else:
      → true  // No TTL → treat as archived

  // Not in live state → check hot archive
  if hot_archive available:
    if hot_archive.get(key) exists:
      → true

  → false
```

### map_host_error_to_result_code

"stellar-core logic (InvokeHostFunctionOpFrame.cpp lines 579-602):
Checks raw resource consumption regardless of error type."

"Note: stellar-core does NOT check the host error type - it purely
checks measured consumption against limits."

```
map_host_error_to_result_code(exec_error,
    specified_instructions, tx_memory_limit):
  if exec_error.cpu_insns_consumed > specified_instructions:
    → ResourceLimitExceeded
  if exec_error.mem_bytes_consumed > tx_memory_limit:
    → ResourceLimitExceeded
  → Trapped
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1040  | ~290       |
| Functions     | 16     | 16         |
