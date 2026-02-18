## Pseudocode: crates/tx/src/state/ttl.rs

### get_ttl

```
get_ttl(key_hash):
    → ttl_entries[key_hash] if present
```

### get_ttl_at_ledger_start

"Returns the TTL value from the bucket list snapshot captured at the"
"start of the ledger, before any transactions modified it. Used by"
"Soroban execution to match stellar-core behavior where transactions"
"see bucket list state at ledger start, not changes from previous txs."

```
get_ttl_at_ledger_start(key_hash):
    → ttl_bucket_list_snapshot[key_hash] if present
```

### capture_ttl_bucket_list_snapshot

"Called once at the start of each ledger, after loading state from the"
"bucket list but before executing any transactions."

```
capture_ttl_bucket_list_snapshot():
    ttl_bucket_list_snapshot.clear()
    for each (key_hash, ttl) in ttl_entries:
        ttl_bucket_list_snapshot[key_hash] = ttl.live_until_ledger_seq
```

### get_ttl_mut

```
get_ttl_mut(key_hash):
    GUARD key_hash not in ttl_entries → return none

    "Save snapshot if not already saved or if it's None (for newly created entries)."
    "For newly created entries, we update the snapshot to the current value so"
    "subsequent operations can track changes with STATE/UPDATED pairs."
    "Rollback correctness is ensured by the created_ttl set."
    if ttl_snapshots[key_hash] is absent or none:
        ttl_snapshots[key_hash] = ttl_entries[key_hash]

    capture_op_snapshot_for_key(ttl_ledger_key)     REF: state/mod::capture_op_snapshot_for_key
    snapshot_last_modified_key(ttl_ledger_key)       REF: state/mod::snapshot_last_modified_key

    if key_hash not in modified_ttl:
        modified_ttl.add(key_hash)

    → mutable reference to ttl_entries[key_hash]
```

### create_ttl

```
create_ttl(entry):
    key = entry.key_hash

    "Save snapshot (None because it didn't exist)"
    ttl_snapshots[key] = none (only if not already present)
    snapshot_last_modified_key(ttl_ledger_key)
    MUTATE last_modified[ttl_ledger_key] = ledger_seq

    "Record in delta"
    ledger_entry = ttl_to_ledger_entry(entry)
    delta.record_create(ledger_entry)

    "Insert into state"
    ttl_entries[key] = entry

    "Track that this entry was created in this transaction (for rollback)"
    created_ttl.insert(key)

    if key not in modified_ttl:
        modified_ttl.add(key)
```

**Calls**: [ttl_to_ledger_entry](mod.pc.md#ttl_to_ledger_entry)

### update_ttl

"Only records a delta update if the TTL value actually changes."
"This is critical for correct bucket list behavior: when multiple"
"transactions in the same ledger access the same entry, later"
"transactions may call update_ttl with a value that earlier"
"transactions already set. Recording a no-op update would cause"
"bucket list divergence from stellar-core."

```
update_ttl(entry):
    key = entry.key_hash

    "Check if the TTL value is actually changing"
    if ttl_entries[key].live_until_ledger_seq == entry.live_until_ledger_seq:
        → return (skip — value unchanged)

    "Save snapshot if not already saved (preserves original for rollback)"
    if key not in ttl_snapshots:
        ttl_snapshots[key] = ttl_entries[key]
    capture_op_snapshot_for_key(ttl_ledger_key)
    snapshot_last_modified_key(ttl_ledger_key)

    MUTATE last_modified[ttl_ledger_key] = ledger_seq

    "Update state — delta recording deferred to flush_modified_entries()"
    ttl_entries[key] = entry

    if key not in modified_ttl:
        modified_ttl.add(key)
```

### update_ttl_no_delta

"Used for TTL-only auto-bump changes where the data entry wasn't modified"
"but the TTL was extended. stellar-core does NOT include these TTL updates"
"in transaction meta, so we update state without creating delta entries."
"State update is still needed for correct bucket list computation."

```
update_ttl_no_delta(entry):
    key = entry.key_hash

    if ttl_entries[key].live_until_ledger_seq == entry.live_until_ledger_seq:
        → return (no change)

    MUTATE last_modified[ttl_ledger_key] = ledger_seq

    "Update state only (no delta recording)"
    ttl_entries[key] = entry

    "Update snapshot to prevent flush_modified_entries from recording this"
    ttl_snapshots[key] = entry

    if key not in modified_ttl:
        modified_ttl.add(key)
```

### record_ro_ttl_bump_for_meta

"Per stellar-core behavior:"
"- Transaction meta includes all TTL changes (including RO bumps)"
"- RO TTL bumps are deferred for state visibility (subsequent TXs don't see them)"
"- At end of ledger, deferred bumps are flushed to state for bucket list"

```
record_ro_ttl_bump_for_meta(key_hash, live_until_ledger_seq):
    key = key_hash

    "Get pre-state (current value, NOT including deferred bumps)"
    pre_state = ttl_to_ledger_entry(ttl_entries[key])
    GUARD pre_state is none → return (entry not found)

    "Check if TTL is actually changing"
    if ttl_entries[key].live_until_ledger_seq == live_until_ledger_seq:
        → return (no change)

    capture_op_snapshot_for_key(ttl_ledger_key)
    NOTE: "Do NOT call snapshot_last_modified_key or set_last_modified_key here
           because RO TTL bumps should NOT affect visible state for subsequent TXs"

    "Build post-state with CURRENT ledger as lastModifiedLedgerSeq"
    post_state = LedgerEntry {
        last_modified = ledger_seq,
        data = TtlEntry(key_hash, live_until_ledger_seq),
        ext = ledger_entry_ext_for(ttl_ledger_key)
    }

    "Record in delta (for transaction meta): pre_state → post_state"
    delta.record_update(pre_state, post_state)

    "Store for later flushing — only keep the highest TTL bump per key"
    if live_until_ledger_seq > deferred_ro_ttl_bumps[key]:
        deferred_ro_ttl_bumps[key] = live_until_ledger_seq
```

### defer_ro_ttl_bump

"Read-only TTL bumps must NOT appear in transaction meta, but MUST be written"
"to the bucket list. Matches stellar-core's mRoTTLBumps behavior."

```
defer_ro_ttl_bump(key_hash, live_until_ledger_seq):
    key = key_hash
    "Only keep the highest TTL bump for each key"
    if live_until_ledger_seq > deferred_ro_ttl_bumps[key]:
        deferred_ro_ttl_bumps[key] = live_until_ledger_seq
```

### flush_ro_ttl_bumps_for_write_footprint

"Matches stellar-core's flushRoTTLBumpsInTxWriteFootprint:"
"before each TX in a cluster executes, any accumulated RO TTL bumps"
"for Soroban entries in the TX's read-write footprint are flushed"
"to ttl_entries. This ensures write TXs see bumped TTL values from"
"earlier TXs' read-only bumps, producing correct rent fee calculations."

```
flush_ro_ttl_bumps_for_write_footprint(write_keys):
    for each key in write_keys:
        "Only flush for Soroban entry keys"
        if key is not ContractData and not ContractCode:
            continue

        key_hash = SHA256(XDR-encode(key))

        if deferred_ro_ttl_bumps has key_hash:
            bumped_live_until = deferred_ro_ttl_bumps.remove(key_hash)
            if bumped_live_until > ttl_entries[key_hash].live_until_ledger_seq:
                update_ttl_no_delta(TtlEntry(key_hash, bumped_live_until))
```

**Calls**: [update_ttl_no_delta](#update_ttl_no_delta)

### flush_deferred_ro_ttl_bumps

"Called at end of cluster processing after all transactions executed."
"Remaining deferred RO TTL bumps (not already flushed by"
"flush_ro_ttl_bumps_for_write_footprint) are applied to ttl_entries"
"so the bucket list sees the final values."

```
flush_deferred_ro_ttl_bumps():
    bumps = take(deferred_ro_ttl_bumps)  "drain map"
    for each (key, live_until) in bumps:
        if key in ttl_entries:
            if live_until > ttl_entries[key].live_until_ledger_seq:
                update_ttl_no_delta(TtlEntry(key, live_until))
```

**Calls**: [update_ttl_no_delta](#update_ttl_no_delta)

### extend_ttl

```
extend_ttl(key_hash, live_until_ledger_seq):
    ttl_entry = ttl_entries[key_hash]
    GUARD ttl_entry not found → return

    GUARD live_until_ledger_seq <= ttl_entry.live_until_ledger_seq:
        → return (no extension needed)

    if key_hash in created_ttl:
        "Entry was created in this transaction — do NOT emit STATE+UPDATED pair."
        "The CREATED entry should reflect the final value."
        updated = TtlEntry(key_hash, live_until_ledger_seq)
        delta.update_created_ttl(key_hash, updated)
        ttl_entries[key_hash] = updated
    else:
        "Save snapshot if not already saved"
        ttl_snapshots[key_hash] (preserve original for rollback)
        capture_op_snapshot_for_key(ttl_ledger_key)
        snapshot_last_modified_key(ttl_ledger_key)
        MUTATE last_modified[ttl_ledger_key] = ledger_seq

        updated = TtlEntry(key_hash, live_until_ledger_seq)
        "Update state — delta recording deferred to flush_modified_entries()"
        ttl_entries[key_hash] = updated

        if key_hash not in modified_ttl:
            modified_ttl.add(key_hash)
```

### delete_ttl

```
delete_ttl(key_hash):
    key = key_hash

    "Save snapshot if not already saved"
    if key not in ttl_snapshots:
        ttl_snapshots[key] = ttl_entries[key]
    capture_op_snapshot_for_key(ttl_ledger_key)
    snapshot_last_modified_key(ttl_ledger_key)

    "Get pre-state BEFORE deletion"
    pre_state = ttl_to_ledger_entry(ttl_entries[key])

    if pre_state exists:
        delta.record_delete(ttl_ledger_key, pre_state)

    clear_entry_sponsorship_metadata(ttl_ledger_key)   REF: state/sponsorship::clear_entry_sponsorship_metadata
    ttl_entries.remove(key)
    remove_last_modified_key(ttl_ledger_key)
    "Track deletion to prevent reloading from bucket list"
    deleted_ttl.insert(key)
```

### is_entry_live

```
is_entry_live(key_hash):
    ttl = get_ttl(key_hash)
    → ttl exists AND ttl.live_until_ledger_seq >= ledger_seq
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 504    | ~190       |
| Functions     | 14     | 14         |
