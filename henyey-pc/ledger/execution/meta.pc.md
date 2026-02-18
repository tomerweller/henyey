## Pseudocode: crates/ledger/src/execution/meta.rs

### asset_to_trustline_asset

```
asset_to_trustline_asset(asset):
  if asset is Native: → none
  if asset is CreditAlphanum4 or CreditAlphanum12:
    → corresponding TrustLineAsset variant
```

### asset_issuer_id

```
asset_issuer_id(asset):
  if asset is Native: → none
  → issuer AccountId from asset
```

### make_account_key / make_trustline_key

```
make_account_key(account_id):
  → LedgerKey::Account { account_id }

make_trustline_key(account_id, asset):
  → LedgerKey::Trustline { account_id, asset }
```

### delta_snapshot

```
delta_snapshot(state):
  "Capture current sizes of delta vectors for later slicing."
  delta = state.delta()
  → { created: len(created_entries),
      updated: len(updated_entries),
      deleted: len(deleted_keys),
      change_order: len(change_order) }
```

### delta_changes_between

```
delta_changes_between(delta, start, end):
  "Slice delta vectors between two snapshots."
  created = delta.created_entries[start.created .. end.created]
  updated = delta.updated_entries[start.updated .. end.updated]
  update_states = delta.update_states[start.updated .. end.updated]
  deleted = delta.deleted_keys[start.deleted .. end.deleted]
  delete_states = delta.delete_states[start.deleted .. end.deleted]

  "Adjust change_order indices to be relative to sliced vectors."
  change_order = for each ref in delta.change_order[start .. end]:
    convert global index to local by subtracting start offset
    filter out indices outside the slice range

  → DeltaChanges { created, updated, update_states,
      deleted, delete_states, change_order }
```

### allow_trust_asset

```
allow_trust_asset(op, issuer):
  "Reconstruct full Asset from AllowTrust asset code + issuer."
  → Asset with op.asset code and provided issuer
```

### pool_reserves

```
pool_reserves(pool):
  "Extract (asset_a, asset_b, reserve_a, reserve_b) from pool."
  → (asset_a, asset_b, reserve_a, reserve_b) from
    ConstantProduct body
```

### extract_hot_archive_restored_keys

"Extract keys of entries being restored from hot archive."
"Per CAP-0066, these emit RESTORED (not CREATED) in transaction meta."

```
extract_hot_archive_restored_keys(soroban_data, op_type,
    actual_restored_indices):
  GUARD soroban_data missing → empty set

  if op_type is RestoreFootprint:
    "Don't add keys here - detect at change-building time"
    "based on whether entries are CREATED (hot archive)"
    "or UPDATED (live BL)"
    → empty set

  GUARD actual_restored_indices is empty → empty set

  "Use actual_restored_indices instead of raw archived_soroban_entries."
  "Filtered during host invocation to only include entries ACTUALLY"
  "being restored in THIS transaction, excluding entries already"
  "restored by a previous transaction in this ledger."
  keys = empty set
  for each index in actual_restored_indices:
    key = soroban_data.resources.footprint.read_write[index]
    NOTE: Only add main entry keys (ContractData/ContractCode),
      NOT TTL keys. stellar-core HotArchiveBucketList::add_batch
      only receives main entry keys.
    add key to keys

  → keys
```

### emit_classic_events_for_operation

```
emit_classic_events_for_operation(op_event_manager, op, op_result,
    op_source, state, pre_claimable_balance, pre_pool):
  GUARD not op_event_manager.is_enabled() → return

  source_address = make_muxed_account_address(op_source)

  CreateAccount:
    emit transfer(Native, source → destination, starting_balance)

  Payment:
    emit transfer(asset, source → destination, amount)

  PathPaymentStrictSend (on success):
    emit events_for_claim_atoms(offers)
    emit transfer(dest_asset, source → destination, success.last.amount)

  PathPaymentStrictReceive (on success):
    emit events_for_claim_atoms(offers)
    emit transfer(dest_asset, source → destination, dest_amount)

  ManageSellOffer / CreatePassiveSellOffer (on success):
    emit events_for_claim_atoms(offers_claimed)

  ManageBuyOffer (on success):
    emit events_for_claim_atoms(offers_claimed)

  AccountMerge (on success):
    emit transfer(Native, source → destination, balance)

  CreateClaimableBalance (on success):
    emit transfer(asset, source → balance_address, amount)

  ClaimClaimableBalance:
    if pre_claimable_balance exists:
      emit transfer(asset, balance_address → source, amount)

  Clawback:
    emit clawback(asset, from, amount)

  ClawbackClaimableBalance:
    if pre_claimable_balance exists:
      emit clawback(asset, balance_address, amount)

  AllowTrust:
    issuer = account_id from op_source
    asset = allow_trust_asset(op, issuer)
    if trustline exists:
      authorize = (trustline.flags & AUTHORIZED_FLAG) != 0
      emit set_authorized(asset, trustor, authorize)

  SetTrustLineFlags:
    if trustline exists:
      authorize = (trustline.flags & AUTHORIZED_FLAG) != 0
      emit set_authorized(asset, trustor, authorize)

  LiquidityPoolDeposit:
    (asset_a, asset_b, pre_a, pre_b) = pool_reserves(pre_pool)
    (_, _, post_a, post_b) = pool_reserves(post_pool)
    GUARD post_a < pre_a or post_b < pre_b → return
    amount_a = post_a - pre_a
    amount_b = post_b - pre_b
    emit transfer(asset_a, source → pool, amount_a)
    emit transfer(asset_b, source → pool, amount_b)

  LiquidityPoolWithdraw:
    (asset_a, asset_b, pre_a, pre_b) = pool_reserves(pre_pool)
    (_, _, post_a, post_b) = pool_reserves(post_pool)
    GUARD pre_a < post_a or pre_b < post_b → return
    amount_a = pre_a - post_a
    amount_b = pre_b - post_b
    emit transfer(asset_a, pool → source, amount_a)
    emit transfer(asset_b, pool → source, amount_b)

  Inflation (on success):
    for each payout:
      emit mint(Native, destination, payout.amount)
```

**Calls**: [allow_trust_asset](#allow_trust_asset) | [pool_reserves](#pool_reserves)

### restore_delta_entries

"Restore delta entries after a rollback (when tx fails)."
"Restores fee/seq changes that were committed before the operation rollback."

```
restore_delta_entries(state, created, updated, deleted):
  delta = state.delta_mut()
  for each entry in created:
    delta.record_create(entry)
  for each entry in updated:
    "Use entry as both pre and post state (restore after rollback)"
    delta.record_update(entry, entry)
  for each (i, key) in deleted:
    "In practice, fee/seq changes rarely delete entries"
    if i < len(updated):
      delta.record_delete(key, updated[i])
```

### build_entry_changes_with_state

```
build_entry_changes_with_state(state, created, updated, deleted):
  → build_entry_changes_with_state_overrides(
      state, created, updated, deleted, empty_overrides)
```

**Calls**: [build_entry_changes_with_state_overrides](#build_entry_changes_with_state_overrides)

### build_entry_changes_with_state_overrides

```
build_entry_changes_with_state_overrides(state, created, updated,
    deleted, state_overrides):
  "Wrapper that calls build_entry_changes_with_hot_archive"
  "with empty change_order and restored sets."
  → build_entry_changes_with_hot_archive(
      state, { created, updated, update_states=empty,
               deleted, delete_states=empty,
               change_order=empty, state_overrides,
               restored=empty },
      footprint=none, ledger_seq=0)
```

**Calls**: [build_entry_changes_with_hot_archive](#build_entry_changes_with_hot_archive)

### build_entry_changes_with_hot_archive

"Build entry changes with support for hot archive and live BL"
"restoration tracking."
"Per CAP-0066:"
"  - Hot archive entries → RESTORED instead of CREATED"
"  - Live BL expired TTL entries → RESTORED instead of STATE+UPDATED"
"Ordering depends on context:"
"  - Soroban with footprint: change_order with Soroban creates sorted by key_hash"
"  - Classic with change_order: execution order, each update gets STATE/UPDATED pair"
"  - Fallback (no change_order): type-grouped: deleted → updated → created"

```
build_entry_changes_with_hot_archive(state, changes, footprint,
    current_ledger_seq):

  --- Build final values for each updated key ---
  final_updated = map of key_bytes → last entry for each updated key

  --- Helper: push_created_or_restored ---
  push_created_or_restored(entry, restored):
    key = entry_to_key(entry)
    if key in restored.hot_archive or restored.live_bucket_list:
      emit RESTORED(entry)
    else:
      emit CREATED(entry)
```

**Calls**: push_created_or_restored (internal helper)

```
  --- Path A: Soroban with footprint ---
  if footprint is provided:
    "Group change_order items into:"
    "  - SorobanCreates (consecutive TTL/ContractData/ContractCode)"
    "  - ClassicCreate (single non-Soroban create)"
    "  - SingleUpdate"
    "  - SingleDelete"

    for each change_ref in change_order:
      if Created and entry is Soroban type:
        accumulate into pending_soroban_creates
      else:
        flush pending_soroban_creates as group
        add as appropriate group type

    for each group:
      SorobanCreates:
        "Sort by (associated_key_hash, type_order)"
        "where TTL type_order=0 (first), Data/Code type_order=1"
        "TTL's associated_hash is key_hash field"
        "Data/Code's associated_hash is SHA256(key XDR)"
        sort entries_with_sort by (hash, type_order)
        for each entry (deduplicated by key):
          push_created_or_restored(entry)

      ClassicCreate:
        push_created_or_restored(entry) if not duplicate

      SingleUpdate:
        if key in restored sets:
          emit RESTORED(post_state)
        else:
          NOTE: "RO TTL bumps ARE included in transaction meta"
          "per stellar-core setLedgerChangesFromSuccessfulOp."
          pre_state = update_states[idx] or state_overrides
            or snapshot lookup
          if pre_state: emit STATE(pre_state)
          emit UPDATED(post_state)

      SingleDelete:
        if key in restored sets:
          pre_state from delete_states or snapshot
          if pre_state: emit RESTORED(pre_state)
          emit REMOVED(key)
        else:
          pre_state from delete_states or snapshot
          if pre_state: emit STATE(pre_state)
          emit REMOVED(key)

  --- Path B: Classic with change_order ---
  else if change_order not empty:
    "Preserve execution order. Creates deduplicated,"
    "updates NOT deduplicated — each gets STATE/UPDATED pair."
    created_keys = empty set

    for each change_ref in change_order:
      Created:
        if key not in created_keys:
          add to created_keys
          push_created_or_restored(entry)

      Updated:
        if key in restored sets:
          emit RESTORED(post_state)
        else:
          pre_state = update_states[idx] or state_overrides
            or snapshot lookup
          if pre_state: emit STATE(pre_state)
          emit UPDATED(post_state)

      Deleted:
        if key in restored sets:
          pre_state from delete_states or snapshot
          if pre_state: emit RESTORED(pre_state)
          emit REMOVED(key)
        else:
          pre_state from delete_states or snapshot
          if pre_state: emit STATE(pre_state)
          emit REMOVED(key)

  --- Path C: Fallback (no change_order) ---
  else:
    "Type-grouped order: deleted → updated → created"
    for each key in deleted:
      if key in restored sets:
        pre_state from snapshot
        if pre_state: emit RESTORED(pre_state)
        emit REMOVED(key)
      else:
        pre_state from snapshot
        if pre_state: emit STATE(pre_state)
        emit REMOVED(key)

    "Deduplicate updated entries"
    for each entry in updated (first occurrence only):
      final_entry = final_updated[key_bytes]
      if key in restored sets:
        emit RESTORED(final_entry)
      else:
        pre_state from snapshot
        if pre_state: emit STATE(pre_state)
        emit UPDATED(final_entry)

    for each entry in created:
      push_created_or_restored(entry)

  --- Post-processing: Live BL restore entries ---
  "Per stellar-core TransactionMeta.cpp:"
  "RestoreOp creates both TTL and Code/Data in hot archive case."
  "When restoring from live BL, only TTL value is modified,"
  "so manually insert RESTORED meta for Code/Data entry."
  for each (key, entry) in restored.live_bucket_list_entries:
    if key not already processed:
      emit RESTORED(entry)

  --- Post-processing: Hot archive restore entries ---
  for each (key, entry) in restored.hot_archive_entries:
    if key not already processed:
      restored_entry = copy of entry
      MUTATE restored_entry last_modified_ledger_seq = current_ledger_seq
      emit RESTORED(restored_entry)

  → LedgerEntryChanges(changes)
```

### empty_entry_changes

```
empty_entry_changes():
  → empty LedgerEntryChanges
```

### build_transaction_meta

```
build_transaction_meta(tx_changes_before, op_changes, op_events,
    tx_events, soroban_return_value, diagnostic_events,
    soroban_fee_info):

  operations = zip(op_changes, op_events) → OperationMetaV2 {
    changes, events }

  soroban_meta = none
  if soroban_return_value or diagnostic_events not empty:
    if soroban_fee_info provided:
      ext = V1 { non_refundable, refundable_consumed, rent_consumed }
    else:
      ext = V0
    soroban_meta = { ext, return_value: soroban_return_value }

  → TransactionMeta::V4 {
      tx_changes_before,
      operations,
      tx_changes_after: empty,
      soroban_meta,
      events: tx_events,
      diagnostic_events
    }
```

### empty_transaction_meta

```
empty_transaction_meta():
  → build_transaction_meta(all empty/none args)
```

**Calls**: [build_transaction_meta](#build_transaction_meta)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 1181   | 250        |
| Functions     | 14     | 14         |
