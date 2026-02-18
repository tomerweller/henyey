## Pseudocode: crates/ledger/src/delta.rs

"Change tracking for ledger close operations."
"Tracks three types of changes: Created, Updated, Deleted."
"Changes are coalesced: Create+Update=Create, Create+Delete=NoOp, Update+Update=Update, Update+Delete=Delete."

### Data Structures

```
ENUM EntryChange:
  Created(entry)
  Updated(previous, current)
  Deleted(previous)

STRUCT LedgerDelta:
  ledger_seq: u32
  changes: Map<key_bytes, EntryChange>
  change_order: List<key_bytes>        // insertion-order for deterministic iteration
  fee_pool_delta: i64
  total_coins_delta: i64
```

### Helper: entry_to_key

"Extract the ledger key from a ledger entry."

```
function entry_to_key(entry) -> LedgerKey:
  if entry.data is Account:      → AccountKey(account_id)
  if entry.data is Trustline:    → TrustlineKey(account_id, asset)
  if entry.data is Offer:        → OfferKey(seller_id, offer_id)
  if entry.data is Data:         → DataKey(account_id, data_name)
  if entry.data is ClaimableBalance: → ClaimableBalanceKey(balance_id)
  if entry.data is LiquidityPool:    → LiquidityPoolKey(pool_id)
  if entry.data is ContractData: → ContractDataKey(contract, key, durability)
  if entry.data is ContractCode: → ContractCodeKey(hash)
  if entry.data is ConfigSetting: → ConfigSettingKey(discriminant)
  if entry.data is Ttl:          → TtlKey(key_hash)
```

### Helper: key_to_bytes

```
function key_to_bytes(key) -> bytes:
  → xdr_encode(key)
```

### record_create

"Record the creation of a new entry with coalescing."

```
function record_create(delta, entry):
  key_bytes = key_to_bytes(entry_to_key(entry))

  if key_bytes in delta.changes:
    existing = delta.changes[key_bytes]
    if existing is Created:
      "Entry was already created, update with new value"
      delta.changes[key_bytes] = Created(entry)
    if existing is Updated(previous, _):
      "Keep original previous, update current"
      delta.changes[key_bytes] = Updated(previous, entry)
    if existing is Deleted(previous):
      "Deleted then created = update (existed before ledger)"
      delta.changes[key_bytes] = Updated(previous, entry)
  else:
    delta.change_order.append(key_bytes)
    delta.changes[key_bytes] = Created(entry)
```

### record_update

```
function record_update(delta, previous, current):
  key_bytes = key_to_bytes(entry_to_key(current))

  if key_bytes in delta.changes:
    existing = delta.changes[key_bytes]
    if existing is Created(_):
      "Created then updated = Created with new value"
      delta.changes[key_bytes] = Created(current)
    if existing is Updated(orig_prev, _):
      "Keep original previous, update current"
      delta.changes[key_bytes] = Updated(orig_prev, current)
    if existing is Deleted(orig_prev):
      "Deleted then updated = entry came back (e.g. fee refund)"
      delta.changes[key_bytes] = Updated(orig_prev, current)
  else:
    delta.change_order.append(key_bytes)
    delta.changes[key_bytes] = Updated(previous, current)
```

### record_delete

"Parity: LedgerTxnTests.cpp:853 'fails for configuration'"

```
function record_delete(delta, entry):
  GUARD entry.data is ConfigSetting → error("cannot delete ConfigSetting entries")

  key_bytes = key_to_bytes(entry_to_key(entry))

  if key_bytes in delta.changes:
    existing = delta.changes[key_bytes]
    if existing is Created(_):
      "Created then deleted = remove from delta entirely (no-op)"
      delta.changes.remove(key_bytes)
      delta.change_order.remove(key_bytes)
    if existing is Updated(original_prev, _):
      "Updated then deleted = Deleted with original previous"
      delta.changes[key_bytes] = Deleted(original_prev)
    if existing is Deleted:
      "Already deleted, idempotent no-op"
      NOTE: can happen during replay when entries processed multiple times
  else:
    delta.change_order.append(key_bytes)
    delta.changes[key_bytes] = Deleted(entry)
```

### deduct_fee_from_account

"Pre-deduct a fee from an account entry in the delta."
"Used by parallel Soroban execution to pre-deduct all fees before cluster execution."

```
function deduct_fee_from_account(delta, account_id, fee,
                                  snapshot, ledger_seq)
    -> (charged_fee, fee_changes):

  key = AccountKey(account_id)
  key_bytes = key_to_bytes(key)

  // Get current entry from delta or snapshot
  if key_bytes in delta.changes:
    entry = delta.changes[key_bytes].current_entry()
    GUARD entry is null → (0, empty_changes)
    is_new = false
  else if entry = snapshot.get_entry(key):
    is_new = true
  else:
    → (0, empty_changes)

  state_entry = copy(entry)

  // Deduct fee
  balance = entry.account.balance
  charged_fee = min(balance, fee)
  MUTATE entry.account.balance -= charged_fee
  if charged_fee > 0:
    entry.last_modified_ledger_seq = ledger_seq

  // Build fee metadata: [State(before), Updated(after)]
  if charged_fee > 0:
    fee_changes = [State(state_entry), Updated(entry)]
  else:
    fee_changes = empty

  // Update delta
  if is_new:
    delta.change_order.append(key_bytes)
    delta.changes[key_bytes] = Updated(state_entry, entry)
  else:
    update current value in existing change entry
    if existing is Created:  replace entry data
    if existing is Updated:  replace current

  → (charged_fee, fee_changes)
```

**Calls**: [snapshot.get_entry](../snapshot.pc.md#get_entry)

### apply_refund_to_account

"Apply a fee refund to an account entry already in the delta."

```
function apply_refund_to_account(delta, account_id, refund):
  key_bytes = key_to_bytes(AccountKey(account_id))

  if key_bytes in delta.changes:
    change = delta.changes[key_bytes]
    if change is Created(entry):
      MUTATE entry.account.balance += refund
    if change is Updated(_, current):
      MUTATE current.account.balance += refund
    if change is Deleted:
      no-op
```

### merge

"Merge another delta into this one."

```
function merge(target, source):
  for each key_bytes in source.change_order:
    source_change = source.changes[key_bytes]

    if key_bytes in target.changes:
      target_change = target.changes[key_bytes]

      // Created in source:
      if source_change is Created(entry):
        if target_change is Deleted(prev):
          "Deleted + Created = Updated"
          target.changes[key_bytes] = Updated(prev, entry)
        if target_change is Created(_):
          "Created + Created: later value wins (hot archive re-restore)"
          target.changes[key_bytes] = Created(entry)
        if target_change is Updated:
          → error("invalid merge: create on updated entry")

      // Updated in source:
      if source_change is Updated(_, current):
        if target_change is Created(_):
          target.changes[key_bytes] = Created(current)
        if target_change is Updated(orig_prev, _):
          target.changes[key_bytes] = Updated(orig_prev, current)
        if target_change is Deleted:
          → error("invalid merge: update on deleted entry")

      // Deleted in source:
      if source_change is Deleted(prev):
        if target_change is Created(_):
          "Created + Deleted = no change"
          target.changes.remove(key_bytes)
          target.change_order.remove(key_bytes)
        if target_change is Updated(orig_prev, _):
          target.changes[key_bytes] = Deleted(orig_prev)
        if target_change is Deleted:
          → error("invalid merge: delete on deleted entry")

    else:
      target.change_order.append(key_bytes)
      target.changes[key_bytes] = source_change

  target.fee_pool_delta += source.fee_pool_delta
  target.total_coins_delta += source.total_coins_delta
```

### Accessors

```
function init_entries(delta) -> List<LedgerEntry>:
  → [change.current for change in ordered_changes if change is Created]

function live_entries(delta) -> List<LedgerEntry>:
  → [change.current for change in ordered_changes if change is Updated]

function current_entries(delta) -> List<LedgerEntry>:
  "Used to propagate prior-stage entries for parallel Soroban execution"
  → [change.current for change in ordered_changes
      if change is Created or Updated]

function dead_entries(delta) -> List<LedgerKey>:
  → [change.key for change in ordered_changes if change is Deleted]
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~752   | ~165       |
| Functions     | 25     | 12         |
