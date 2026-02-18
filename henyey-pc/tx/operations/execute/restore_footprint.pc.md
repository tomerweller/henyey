## Pseudocode: crates/tx/src/operations/execute/restore_footprint.rs

"RestoreFootprint operation execution."
"Restores archived Soroban contract data entries."

### Data Structures

```
struct HotArchiveRestoreEntry:
  key      // LedgerKey of the entry to restore
  entry    // LedgerEntry from the hot archive
```

### execute_restore_footprint

```
function execute_restore_footprint(op, source, state,
    context, soroban_data, min_persistent_entry_ttl,
    hot_archive_restores):

  --- Phase 1: Validate footprint ---

  GUARD soroban_data is null
    → Malformed

  footprint = soroban_data.resources.footprint

  GUARD footprint.read_only is not empty
    → Malformed

  for each key in footprint.read_write:
    GUARD not is_persistent_entry(key)
      → Malformed

  --- Phase 2: Calculate new TTL ---

  "Per stellar-core RestoreFootprintOpFrame.cpp line 115-116:
   restoredLiveUntilLedger = ledgerSeq + minPersistentTTL - 1"
  current_ledger = context.sequence
  new_ttl = current_ledger + min_persistent_entry_ttl - 1
    (saturating)

  --- Phase 3: Restore hot archive entries ---

  for each restore in hot_archive_restores:
    if restore.entry.data is ContractCode:
      state.create_contract_code(restore.entry.data)
    else if restore.entry.data is ContractData:
      state.create_contract_data(restore.entry.data)

    key_hash = compute_ledger_key_hash(restore.key)
    ttl_entry = TtlEntry {
      key_hash: key_hash,
      live_until_ledger_seq: new_ttl
    }
    state.create_ttl(ttl_entry)

  --- Phase 4: Restore live-state entries ---

  "Restore entries in read_write footprint that exist
   in live state (expired TTLs, entry still present)"
  for each key in footprint.read_write:
    if key was already restored from hot archive:
      continue

    if restore_entry(key, new_ttl, state,
        current_ledger) fails:
      → ResourceLimitExceeded

  → Success
```

**Calls:**
- [`LedgerStateManager.create_contract_code`](../../state.pc.md) — REF: state::LedgerStateManager
- [`LedgerStateManager.create_ttl`](../../state.pc.md) — REF: state::LedgerStateManager

### Helper: is_persistent_entry

```
function is_persistent_entry(key):
  if key is ContractCode:
    → true
  if key is ContractData:
    → key.durability == Persistent
  → false
```

### Helper: restore_entry

```
function restore_entry(key, new_ttl, state,
    current_ledger):

  "Only contract data and contract code can be restored"
  if key is not ContractData and not ContractCode:
    → ok  // non-contract entries don't need restoration

  key_hash = compute_ledger_key_hash(key)
  current_ttl = state.get_ttl(key_hash)
    .live_until_ledger_seq

  if current_ttl exists AND current_ttl >= current_ledger:
    "Entry is still live, no restoration needed"
    → ok

  "Entry is archived or has no TTL entry"
  if state.get_entry(key) is null:
    "Neither live nor archived entry exists; skip"
    → ok

  ttl_entry = TtlEntry {
    key_hash: key_hash,
    live_until_ledger_seq: new_ttl
  }

  if state.get_ttl(key_hash) exists:
    state.update_ttl(ttl_entry)
  else:
    state.create_ttl(ttl_entry)

  → ok
```

### Helper: compute_ledger_key_hash

```
function compute_ledger_key_hash(key):
  → SHA256(xdr_encode(key))
```

### Helper: make_result

```
function make_result(code):
  → OperationResult.RestoreFootprint(code)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 216    | 75         |
| Functions     | 5      | 5          |
