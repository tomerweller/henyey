# EntryStore<K,V> Refactor Plan

## Status: Complete

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Implement `EntryStore<K,V>` struct | Done |
| 1 | Unit tests for `EntryStore<K,V>` (44 tests) | Done |
| 2 | Convert ClaimableBalance | Done |
| 3 | Convert LiquidityPool | Done |
| 4 | Convert ContractCode | Done |
| 5 | Convert ContractData | Done |
| 6 | Convert Data | Done |

## Problem

`LedgerStateManager` contains 9 entry types, each with 5 parallel collections
(live map, snapshots, created set, modified vec, optional deleted set) and 5+
CRUD methods following nearly identical patterns. This results in ~1,170 lines
of repetitive code across `entries.rs` and `mod.rs`.

## Solution: Generic `EntryStore<K,V>` struct

Bundle the 5 per-type parallel collections into a self-contained generic struct.
CRUD and lifecycle methods (savepoint, rollback, commit) become methods on the
store. The `LedgerStateManager` public API methods become thin wrappers that
handle shared-state bookkeeping (delta, op_snapshots, last_modified, sponsorship)
then delegate to the store.

### Scope

Convert 5 "clean" entry types whose CRUD follows the standard pattern:

1. **ClaimableBalance** -- zero unique behavior (simplest)
2. **LiquidityPool** -- minor: update/delete add to modified vec
3. **ContractCode** -- minor: deleted set for Soroban
4. **ContractData** -- minor: deleted set for Soroban
5. **Data** -- minor: LedgerKey constructed from stored entry fields

The 4 complex types (Account, Trustline, Offer, TTL) stay hand-written due to
extensive unique behaviors (offer indexes, dual-key trustline API, TTL deferred
bumps, account-specific flush methods).

### Borrow-checker approach

The store's CRUD methods operate only on store-internal data. Shared-state
operations (`delta.record_create`, `capture_op_snapshot_for_key`,
`snapshot_last_modified_key`, etc.) are called by the thin wrapper on
`LedgerStateManager` before/after the store call. This avoids borrow conflicts
since the store borrow is released between calls.

## Architecture

### New file: `crates/tx/src/state/entry_store.rs`

```rust
pub(super) struct EntryStore<K: Eq + Hash + Clone, V: Clone + PartialEq> {
    entries: HashMap<K, V>,
    snapshots: HashMap<K, Option<V>>,
    created: HashSet<K>,
    modified: Vec<K>,
    deleted: Option<HashSet<K>>,  // Some only for Soroban types
}

pub(super) struct EntryStoreSavepoint<K: Eq + Hash + Clone, V: Clone> {
    snapshots: HashMap<K, Option<V>>,
    pre_values: Vec<(K, Option<V>)>,
    created: HashSet<K>,
    modified_len: usize,
}
```

### EntryStore methods

**Storage access:**
- `get(&self, key: &K) -> Option<&V>`
- `contains(&self, key: &K) -> bool`
- `is_tracked(&self, key: &K) -> bool` (checks snapshot map)

**Snapshot management:**
- `ensure_snapshot(&mut self, key: &K)` -- for get_mut: uses `is_some_and`
- `ensure_snapshot_on_first(&mut self, key: &K)` -- for update/delete: uses `contains_key`

**CRUD (store-internal parts):**
- `insert_created(&mut self, key: K, value: V)`
- `insert_updated(&mut self, key: K, value: V, track_modified: bool)`
- `remove_deleted(&mut self, key: &K, track_deleted: bool)`
- `get_mut_tracked(&mut self, key: &K) -> Option<&mut V>`

**Lifecycle:**
- `create_savepoint(&self) -> EntryStoreSavepoint<K,V>`
- `rollback_to_savepoint(&mut self, sp: EntryStoreSavepoint<K,V>)`
- `rollback(&mut self)` -- full TX rollback
- `commit(&mut self)` -- clear all tracking

**Flush support:**
- `take_modified(&mut self) -> Vec<K>`
- `snapshot_value(&self, key: &K) -> Option<&Option<V>>`

**Deleted tracking:**
- `is_deleted(&self, key: &K) -> bool`
- `mark_deleted(&mut self, key: K)`

### Thin wrapper pattern

Each `LedgerStateManager` method becomes a thin wrapper:

```rust
pub fn create_claimable_balance(&mut self, entry: ClaimableBalanceEntry) {
    let key = claimable_balance_id_to_bytes(&entry.balance_id);
    let ledger_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
        balance_id: entry.balance_id.clone(),
    });
    // Shared bookkeeping
    self.snapshot_last_modified_key(&ledger_key);
    self.set_last_modified_key(ledger_key.clone(), self.ledger_seq);
    let ledger_entry = self.claimable_balance_to_ledger_entry(&entry);
    self.delta.record_create(ledger_entry);
    // Store-internal bookkeeping
    self.claimable_balances.insert_created(key, entry);
}
```

### Flush modes

The 5 types use 3 different flush modes for `flush_modified_entries`:

| Mode | Description | Types |
|------|-------------|-------|
| OpSnapshotWithGate | Check `op_snapshots_active && op_entry_snapshots.contains_key` | Data |
| OpSnapshotNoGate | Check `op_entry_snapshots.contains_key` only | ClaimableBalance, LiquidityPool |
| ChangeOnly | No op_snapshot check; flush only if value changed | ContractData, ContractCode |

The flush logic stays in `LedgerStateManager::flush_modified_entries` but uses
`store.take_modified()` and `store.snapshot_value()` to simplify each block.

## Testing Strategy

### Layer 1: EntryStore unit tests (43 tests)

Test the generic store in isolation with synthetic types (`EntryStore<u32, String>`).
Cover every method and edge case including snapshot behavior, rollback, savepoint,
commit, flush support, deleted tracking.

### Layer 2: Integration regression tests per converted type

After each conversion, verify the type behaves identically:
- Create/update/delete record correct delta entries
- Rollback/savepoint-rollback restore correct state
- Flush produces correct STATE/UPDATED pairs

### Layer 3: Existing test suite (844 henyey-tx + 253 henyey-ledger)

All existing tests must pass after each phase. This is the primary regression net.

### Layer 4: Clippy + build verification

`cargo clippy -p henyey-tx -p henyey-ledger` clean after each phase.

## Conversion order rationale

1. **ClaimableBalance first** -- zero unique behaviors, validates the pattern
2. **LiquidityPool** -- adds modified-in-update flag, validates the `track_modified` parameter
3. **ContractCode** -- adds deleted set, validates Soroban tracking
4. **ContractData** -- same as ContractCode but also has `mark_entry_deleted` and `take_soroban_state`
5. **Data last** -- has the LedgerKey-from-stored-entry wrinkle, most complex of the 5
