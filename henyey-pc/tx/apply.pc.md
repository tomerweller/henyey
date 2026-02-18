## Pseudocode: crates/tx/src/apply.rs

### ChangeRef (enum)

```
STATE_MACHINE: ChangeRef
  STATES: [Created(index), Updated(index), Deleted(index)]
  NOTE: Tracks insertion order for correct metadata construction
```

---

### LedgerDelta (struct)

"Accumulator for ledger state changes during transaction execution."

```
fields:
  ledger_seq       : u32
  created          : list of LedgerEntry
  updated          : list of LedgerEntry        "post-state"
  update_states    : list of LedgerEntry        "pre-state, parallel to updated"
  deleted          : list of LedgerKey
  delete_states    : list of LedgerEntry        "pre-state, parallel to deleted"
  fee_charged      : i64
  change_order     : list of ChangeRef          "preserves execution order"
```

---

### LedgerDelta::record_create

```
idx = created.len
append entry to created
append Created(idx) to change_order
```

---

### LedgerDelta::record_update

```
idx = updated.len
append pre_state to update_states
append post_state to updated
append Updated(idx) to change_order
```

---

### LedgerDelta::update_created_ttl

"Update a TTL entry created in the same transaction (avoids emitting
separate STATE+UPDATED pair)."

```
for each entry in created:
  if entry is TTL and entry.key_hash == key_hash:
    MUTATE entry.live_until_ledger_seq = ttl_entry.live_until_ledger_seq
    return
```

---

### LedgerDelta::record_delete

```
idx = deleted.len
append pre_state to delete_states
append key to deleted
append Deleted(idx) to change_order
```

---

### LedgerDelta::apply_refund_to_account

"Modifies the balance in the post-state of the most recent account update."

```
for each entry in updated (reverse order):
  if entry is Account and entry.account_id == account_id:
    MUTATE entry.balance += refund
    return
```

---

### LedgerDelta::snapshot_lengths

```
→ DeltaLengths {
    created.len, updated.len, deleted.len, change_order.len
  }
```

---

### LedgerDelta::truncate_to

"Used by savepoint rollback to undo speculative delta entries."

```
MUTATE created      truncate to lengths.created
MUTATE updated      truncate to lengths.updated
MUTATE update_states truncate to lengths.updated
MUTATE deleted      truncate to lengths.deleted
MUTATE delete_states truncate to lengths.deleted
MUTATE change_order truncate to lengths.change_order
```

---

### LedgerDelta::merge

```
created_offset = self.created.len
updated_offset = self.updated.len
deleted_offset = self.deleted.len

append other.created to self.created
append other.updated to self.updated
append other.update_states to self.update_states
append other.deleted to self.deleted
append other.delete_states to self.delete_states
MUTATE self.fee_charged += other.fee_charged

for each ref in other.change_order:
  adjust index by corresponding offset
  append adjusted ref to self.change_order
```

---

### apply_from_history

"Main entry point for catchup mode. Trust historical results and apply
state changes from transaction meta."

```
MUTATE delta.fee_charged += result.fee_charged
apply_meta_changes(meta, delta)
wrapper = TxResultWrapper from result
→ TxApplyResult { success: wrapper.is_success, fee_charged, result: wrapper }
```

**Calls:** [`apply_meta_changes`](#apply_meta_changes), [`TxResultWrapper::from_xdr`](../result.rs)

---

### apply_meta_changes

"Apply state changes from transaction meta."

```
meta version switch:
  V0:
    for each op_meta in changes:
      apply_ledger_entry_changes(op_meta.changes, delta)

  V1:
    apply_ledger_entry_changes(tx_changes, delta)
    for each op_meta in operations:
      apply_ledger_entry_changes(op_meta.changes, delta)

  V2, V3, V4:
    apply_ledger_entry_changes(tx_changes_before, delta)
    for each op_meta in operations:
      apply_ledger_entry_changes(op_meta.changes, delta)
    apply_ledger_entry_changes(tx_changes_after, delta)
```

**Calls:** [`apply_ledger_entry_changes`](#apply_ledger_entry_changes)

---

### apply_ledger_entry_changes

"Replay historical changes. STATE entries precede UPDATED/REMOVED as pre-state."

```
pending_state = nil

for each change in changes:
  change type switch:
    CREATED:
      pending_state = nil
      delta.record_create(entry)

    UPDATED:
      pre_state = pending_state or entry itself
      pending_state = nil
      delta.record_update(pre_state, entry)

    REMOVED:
      if pending_state exists:
        delta.record_delete(key, pending_state)
      pending_state = nil
      NOTE: "If no STATE preceded REMOVED, skip (invalid meta)"

    STATE:
      pending_state = entry

    RESTORED:
      pending_state = nil
      delta.record_create(entry)
```

---

### apply_fee_only

```
fee = frame.total_fee()
MUTATE delta.fee_charged += fee
```

---

### entry_to_key

```
entry data type switch:
  Account          → AccountKey(account_id)
  Trustline        → TrustlineKey(account_id, asset)
  Offer            → OfferKey(seller_id, offer_id)
  Data             → DataKey(account_id, data_name)
  ClaimableBalance → ClaimableBalanceKey(balance_id)
  LiquidityPool    → LiquidityPoolKey(pool_id)
  ContractData     → ContractDataKey(contract, key, durability)
  ContractCode     → ContractCodeKey(hash)
  ConfigSetting    → ConfigSettingKey(discriminant)
  Ttl              → TtlKey(key_hash)
```

---

### AssetKey::from_asset

```
asset type switch:
  Native          → AssetKey::Native
  CreditAlphanum4 → AssetKey::CreditAlphanum4(code[4], issuer_bytes[32])
  CreditAlphanum12→ AssetKey::CreditAlphanum12(code[12], issuer_bytes[32])
```

---

### apply_transaction_set_from_history

"Batch apply multiple transactions from history."

```
results = []
for each (frame, result, meta) in transactions:
  apply_result = apply_from_history(frame, result, meta, delta)
  append apply_result to results
→ results
```

**Calls:** [`apply_from_history`](#apply_from_history)

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~630   | ~140       |
| Functions     | 17     | 15         |
