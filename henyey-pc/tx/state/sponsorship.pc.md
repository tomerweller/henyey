## Pseudocode: crates/tx/src/state/sponsorship.rs

### clear_sponsorship_stack

```
clear_sponsorship_stack():
    sponsorship_stack.clear()
```

### has_pending_sponsorship

```
has_pending_sponsorship():
    → sponsorship_stack is not empty
```

### active_sponsor_for

```
active_sponsor_for(sponsored):
    "search stack from top (most recent) to bottom"
    for each ctx in sponsorship_stack (reverse):
        if ctx.sponsored == sponsored:
            → ctx.sponsoring
    → none
```

### is_sponsored

```
is_sponsored(account_id):
    → any entry in sponsorship_stack where ctx.sponsored == account_id
```

### is_sponsoring

```
is_sponsoring(account_id):
    → any entry in sponsorship_stack where ctx.sponsoring == account_id
```

### push_sponsorship

```
push_sponsorship(sponsoring, sponsored):
    sponsorship_stack.push({sponsoring, sponsored})
```

### pop_sponsorship

```
pop_sponsorship():
    → sponsorship_stack.pop()
```

### remove_sponsorship_for

```
remove_sponsorship_for(sponsored):
    pos = last index where ctx.sponsored == sponsored
    if found:
        → sponsorship_stack.remove_at(pos)
    → none
```

### entry_sponsor

```
entry_sponsor(key):
    → entry_sponsorships[key] if present
```

### Helper: snapshot_entry_sponsorship_ext

```
snapshot_entry_sponsorship_ext(key):
    if key not in entry_sponsorship_ext_snapshots:
        entry_sponsorship_ext_snapshots[key] = (key in entry_sponsorship_ext)
```

### Helper: snapshot_entry_sponsorship_metadata

```
snapshot_entry_sponsorship_metadata(key):
    if key not in entry_sponsorship_snapshots:
        entry_sponsorship_snapshots[key] = entry_sponsorships[key] (or none)
    snapshot_entry_sponsorship_ext(key)
```

### clear_entry_sponsorship_metadata

```
clear_entry_sponsorship_metadata(key):
    snapshot_entry_sponsorship_metadata(key)
    entry_sponsorships.remove(key)
    entry_sponsorship_ext.remove(key)
```

### set_entry_sponsor

```
set_entry_sponsor(key, sponsor):
    snapshot_entry_sponsorship_metadata(key)
    capture_op_snapshot_for_key(key)       REF: state/mod::capture_op_snapshot_for_key
    entry_sponsorships[key] = sponsor
    entry_sponsorship_ext.insert(key)
```

### remove_entry_sponsor

```
remove_entry_sponsor(key):
    snapshot_entry_sponsorship_metadata(key)
    capture_op_snapshot_for_key(key)       REF: state/mod::capture_op_snapshot_for_key
    entry_sponsorship_ext.insert(key)
    → entry_sponsorships.remove(key)
```

### apply_entry_sponsorship

"Apply sponsorship to a newly created ledger entry owned by sponsored"

```
apply_entry_sponsorship(key, sponsored, multiplier):
    sponsor = active_sponsor_for(sponsored)
    GUARD sponsor is none → return none

    apply_entry_sponsorship_with_sponsor(key, sponsor, sponsored, multiplier)
    → sponsor
```

**Calls**: [active_sponsor_for](#active_sponsor_for) | [apply_entry_sponsorship_with_sponsor](#apply_entry_sponsorship_with_sponsor)

### apply_entry_sponsorship_with_sponsor

```
apply_entry_sponsorship_with_sponsor(key, sponsor, sponsored, multiplier):
    GUARD multiplier < 0 → error "negative sponsorship multiplier"

    set_entry_sponsor(key, sponsor)
    MUTATE sponsor num_sponsoring += multiplier
    if sponsored is present:
        MUTATE sponsored num_sponsored += multiplier
```

**Calls**: [set_entry_sponsor](#set_entry_sponsor) | [update_num_sponsoring](#update_num_sponsoring) | [update_num_sponsored](#update_num_sponsored)

### apply_account_entry_sponsorship

"Apply sponsorship to a newly created account entry (account not yet in state)"

```
apply_account_entry_sponsorship(account, sponsor, multiplier):
    GUARD multiplier < 0 → error "negative sponsorship multiplier"

    ext = ensure_account_ext_v2(account)
    updated = ext.num_sponsored + multiplier
    GUARD updated < 0 OR updated > MAX_U32 → error "num_sponsored out of range"
    MUTATE ext num_sponsored = updated

    MUTATE sponsor num_sponsoring += multiplier
```

**Calls**: [update_num_sponsoring](#update_num_sponsoring)

### remove_entry_sponsorship_and_update_counts

```
remove_entry_sponsorship_and_update_counts(key, sponsored, multiplier):
    sponsor = remove_entry_sponsor(key)
    GUARD sponsor is none → return none

    GUARD multiplier < 0 → error "negative sponsorship multiplier"

    MUTATE sponsor num_sponsoring -= multiplier
    MUTATE sponsored num_sponsored -= multiplier
    → sponsor
```

**Calls**: [remove_entry_sponsor](#remove_entry_sponsor) | [update_num_sponsoring](#update_num_sponsoring) | [update_num_sponsored](#update_num_sponsored)

### remove_entry_sponsorship_with_sponsor_counts

```
remove_entry_sponsorship_with_sponsor_counts(key, sponsored, multiplier):
    sponsor = remove_entry_sponsor(key)
    GUARD sponsor is none → return none

    GUARD multiplier < 0 → error "negative sponsorship multiplier"

    MUTATE sponsor num_sponsoring -= multiplier
    if sponsored is present:
        MUTATE sponsored num_sponsored -= multiplier
    → sponsor
```

**Calls**: [remove_entry_sponsor](#remove_entry_sponsor) | [update_num_sponsoring](#update_num_sponsoring) | [update_num_sponsored](#update_num_sponsored)

### update_num_sponsoring

"Lazily loads the account from the bucket list if not already in state."
"Necessary because sponsored entries may reference a sponsor account that"
"hasn't been loaded yet (e.g., during offer crossing when a sponsored offer"
"is fully consumed and deleted)."

```
update_num_sponsoring(account_id, delta):
    ensure_account_loaded(account_id)      REF: state/mod::ensure_account_loaded
    account = get_account_mut(account_id)
    GUARD account not found → error

    ext = ensure_account_ext_v2(account)
    updated = ext.num_sponsoring + delta
    GUARD updated < 0 OR updated > MAX_U32 → error "num_sponsoring out of range"
    MUTATE ext num_sponsoring = updated
```

### update_num_sponsored

"Lazily loads the account from the bucket list if not already in state."

```
update_num_sponsored(account_id, delta):
    ensure_account_loaded(account_id)      REF: state/mod::ensure_account_loaded
    account = get_account_mut(account_id)
    GUARD account not found → error

    ext = ensure_account_ext_v2(account)
    updated = ext.num_sponsored + delta
    GUARD updated < 0 OR updated > MAX_U32 → error "num_sponsored out of range"
    MUTATE ext num_sponsored = updated
```

### sponsorship_counts_for_account

```
sponsorship_counts_for_account(account_id):
    → (num_sponsoring, num_sponsored) from account if found
```

### remove_one_time_signers_from_all_sources

"Pre-auth TX signers are automatically consumed when a transaction they"
"authorized is applied."

```
remove_one_time_signers_from_all_sources(tx_hash, source_accounts, protocol_version):
    "Protocol 7 bypass (matches stellar-core behavior)"
    @version(==7):
        → return (no-op)

    signer_key = PreAuthTx(tx_hash)

    for each account_id in source_accounts:
        remove_account_signer(account_id, signer_key)
```

**Calls**: [remove_account_signer](#remove_account_signer)

### remove_account_signer

```
remove_account_signer(account_id, signer_key):
    account = get_account_mut(account_id)
    GUARD account not found → return false
        NOTE: "Account may have been removed (e.g., by merge)"

    idx = find signer_key in account.signers
    GUARD idx not found → return false

    account.signers.remove_at(idx)

    if account.num_sub_entries > 0:
        MUTATE account num_sub_entries -= 1

    remove_signer_sponsorship(account_id, idx)
    → true
```

**Calls**: [remove_signer_sponsorship](#remove_signer_sponsorship)

### Helper: remove_signer_sponsorship

"When a signer is sponsored, the sponsoring account's ID is stored in"
"the account's signer_sponsoring_ids vector (in AccountEntryExtensionV2)."
"Removing a signer requires cleaning up this sponsorship relationship."

```
remove_signer_sponsorship(account_id, signer_index):
    account = get_account(account_id)
    GUARD account not found → return

    "Check if the account has extension v2 with signer sponsorships"
    sponsor_id = account.ext.v1.ext.v2.signer_sponsoring_ids[signer_index]
        (none if no v2 ext or index out of bounds)

    if sponsor_id is present:
        MUTATE sponsor num_sponsoring -= 1
        MUTATE account num_sponsored -= 1

        "Remove the sponsorship entry from signer_sponsoring_ids"
        account.ext.v1.ext.v2.signer_sponsoring_ids.remove_at(signer_index)
```

**Calls**: [update_num_sponsoring](#update_num_sponsoring) | [update_num_sponsored](#update_num_sponsored)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 388    | ~170       |
| Functions     | 21     | 21         |
