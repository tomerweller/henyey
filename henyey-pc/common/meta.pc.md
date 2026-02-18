# Pseudocode: crates/common/src/meta.rs

"Ledger metadata normalization for deterministic hashing."
"Different validators may produce metadata with changes in different orders."
"Normalizing sorts changes so the metadata hash is consistent."

## Helper: change_key

```
function change_key(change) -> LedgerKey:
  if change is State, Created, Updated, or Restored:
    -> ledger_entry_key(change.entry)    REF: asset::ledger_entry_key
  if change is Removed:
    -> change.key
```

**Calls**: [ledger_entry_key](asset.pc.md#ledger_entry_key)

## Helper: change_type_order

"Numeric order: State(0) < Created(1) < Updated(2) < Removed(3) < Restored(4)"

```
function change_type_order(change) -> u8:
  if State:    -> 0
  if Created:  -> 1
  if Updated:  -> 2
  if Removed:  -> 3
  if Restored: -> 4
```

## Helper: sort_changes

"Sort by (key_bytes, change_type, full_change_hash) for determinism."

```
function sort_changes(changes):
  entries = empty list

  for each change in changes:
    key       = change_key(change)
    key_bytes = xdr_encode(key)
    hash      = SHA256(xdr_encode(change))
    order     = change_type_order(change)
    append (key_bytes, order, hash, change) to entries

  sort entries by:
    1. key_bytes  (lexicographic)
    2. order      (ascending)
    3. hash       (lexicographic, tiebreaker)

  replace changes with sorted entries
```

**Calls**: [change_key](#helper-change_key) | [change_type_order](#helper-change_type_order) | [Hash256.hash_xdr](types.pc.md#hash_xdr)

## Helper: normalize_ops_v0

```
function normalize_ops_v0(operations):
  for each op in operations:
    sort_changes(op.changes)
```

**Calls**: [sort_changes](#helper-sort_changes)

## Helper: normalize_ops_v2

```
function normalize_ops_v2(operations):
  for each op in operations:
    sort_changes(op.changes)
```

**Calls**: [sort_changes](#helper-sort_changes)

### normalize_transaction_meta

```
function normalize_transaction_meta(meta):
  if meta is V0:
    normalize_ops_v0(meta.operations)

  if meta is V1:
    sort_changes(meta.tx_changes)
    normalize_ops_v0(meta.operations)

  if meta is V2:
    sort_changes(meta.tx_changes_before)
    sort_changes(meta.tx_changes_after)
    normalize_ops_v0(meta.operations)

  if meta is V3:
    sort_changes(meta.tx_changes_before)
    sort_changes(meta.tx_changes_after)
    normalize_ops_v0(meta.operations)

  if meta is V4:
    sort_changes(meta.tx_changes_before)
    sort_changes(meta.tx_changes_after)
    normalize_ops_v2(meta.operations)
```

**Calls**: [sort_changes](#helper-sort_changes) | [normalize_ops_v0](#helper-normalize_ops_v0) | [normalize_ops_v2](#helper-normalize_ops_v2)

### normalize_ledger_close_meta

"Normalize all tx metadata and upgrade metadata within a ledger close."

```
function normalize_ledger_close_meta(meta):
  if meta is V0:
    for each upgrade in meta.upgrades_processing:
      sort_changes(upgrade.changes)
    for each tx in meta.tx_processing:
      sort_changes(tx.fee_processing)
      normalize_transaction_meta(tx.tx_apply_processing)

  if meta is V1:
    for each upgrade in meta.upgrades_processing:
      sort_changes(upgrade.changes)
    for each tx in meta.tx_processing:
      sort_changes(tx.fee_processing)
      normalize_transaction_meta(tx.tx_apply_processing)

  if meta is V2:
    for each upgrade in meta.upgrades_processing:
      sort_changes(upgrade.changes)
    for each tx in meta.tx_processing:
      sort_changes(tx.fee_processing)
      normalize_transaction_meta(tx.tx_apply_processing)
```

**Calls**: [sort_changes](#helper-sort_changes) | [normalize_transaction_meta](#normalize_transaction_meta)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 100    | 68         |
| Functions     | 7      | 7          |
