## Pseudocode: crates/tx/src/state/entries.rs

This file implements typed CRUD operations for every ledger entry kind.
All entry types follow the same pattern (documented once in detail for
accounts, then shown in abbreviated form for other types).

---

### Helper: aa_index_insert

"Insert an offer into the (account, asset) secondary index"

```
aa_index_insert(offer):
    seller = bytes(offer.seller_id)
    account_asset_offers[(seller, offer.selling)].insert(offer.offer_id)
    account_asset_offers[(seller, offer.buying)].insert(offer.offer_id)
```

### Helper: aa_index_remove

```
aa_index_remove(offer):
    seller = bytes(offer.seller_id)
    account_asset_offers[(seller, offer.selling)].remove(offer.offer_id)
    account_asset_offers[(seller, offer.buying)].remove(offer.offer_id)
```

### Helper: last_modified_for_key

```
last_modified_for_key(key):
    → entry_last_modified[key] or ledger_seq
```

### Helper: snapshot_last_modified_key

```
snapshot_last_modified_key(key):
    if key not in entry_last_modified_snapshots:
        entry_last_modified_snapshots[key] = entry_last_modified[key]
```

### Helper: capture_op_snapshot_for_key

```
capture_op_snapshot_for_key(key):
    GUARD not op_snapshots_active OR key already in op_entry_snapshots → return
    entry = get_entry(key)
    if entry exists:
        op_entry_snapshots[key] = entry
```

### Helper: ledger_entry_ext_for

```
ledger_entry_ext_for(key):
    sponsor = entry_sponsorships[key]
    if entry_sponsorship_ext contains key OR sponsor exists:
        → V1 extension with sponsoring_id = sponsor
    → V0 (no extension)
```

### Helper: ledger_entry_ext_for_snapshot

"Uses snapshot values instead of current values — for pre-state in delta"

```
ledger_entry_ext_for_snapshot(key):
    ext_present = entry_sponsorship_ext_snapshots[key]
        (fall back to entry_sponsorship_ext)
    sponsor = entry_sponsorship_snapshots[key]
        (fall back to entry_sponsorships[key])
    if ext_present OR sponsor exists:
        → V1 extension with sponsoring_id = sponsor
    → V0
```

### Helper: record_entry_metadata

"Shared by load_entry and load_entry_without_snapshot"

```
record_entry_metadata(ledger_key, last_modified, has_sponsorship_ext, sponsor):
    entry_last_modified[ledger_key] = last_modified
    if has_sponsorship_ext:
        entry_sponsorship_ext.insert(ledger_key)
    if sponsor present:
        entry_sponsorships[ledger_key] = sponsor
```

### Helper: build_ledger_entry

"Shared by all *_to_ledger_entry methods"

```
build_ledger_entry(ledger_key, data):
    → LedgerEntry {
        last_modified = last_modified_for_key(ledger_key),
        data = data,
        ext = ledger_entry_ext_for(ledger_key)
    }
```

---

## Load Operations

### load_from_reader

```
load_from_reader(reader, keys):
    for each key in keys:
        entry = reader.get_entry(key)
        if entry exists:
            load_entry(entry)
```

### load_entry

```
load_entry(entry):
    sponsor = sponsorship_from_entry_ext(entry)
    has_sponsorship_ext = entry.ext is V1
    last_modified = entry.last_modified_ledger_seq

    dispatch on entry.data type:
        Account:
            accounts[bytes(account_id)] = entry
        Trustline:
            trustlines[(account_bytes, asset_key)] = entry
        Offer:
            offer_index.add_offer(entry)
            aa_index_insert(entry)
            offers[OfferKey(seller, offer_id)] = entry
        Data:
            data_entries[(account_bytes, name_string)] = entry
        ContractData:
            contract_data[ContractDataKey] = entry
        ContractCode:
            contract_code[hash] = entry
        Ttl:
            "Only capture if not already present — keep original bucket list value"
            ttl_bucket_list_snapshot[key] or= entry.live_until_ledger_seq
            ttl_entries[key] = entry
        ClaimableBalance:
            claimable_balances[balance_id_bytes] = entry
        LiquidityPool:
            liquidity_pools[pool_id_bytes] = entry

    record_entry_metadata(ledger_key, last_modified, has_sponsorship_ext, sponsor)
```

**Calls**: [aa_index_insert](#helper-aa_index_insert) | [record_entry_metadata](#helper-record_entry_metadata)

### load_entry_without_snapshot

"Matches stellar-core's loadWithoutRecord() behavior."
"Entries loaded this way will NOT appear in transaction meta changes"
"unless subsequently accessed via get_*_mut() or record_*_access()."

```
load_entry_without_snapshot(entry):
    if entry is Account:
        "Insert account but do NOT save snapshot or mark as modified"
        accounts[bytes(account_id)] = entry
        record_entry_metadata(...)
    else:
        "For other entry types, delegate to regular load_entry"
        load_entry(entry)
```

---

## CRUD Pattern (documented once for Accounts)

All entry types follow an identical pattern. The pattern is documented
in full for accounts, then shown in abbreviated form for other types.

### get_account

```
get_account(account_id):
    → accounts[bytes(account_id)]
```

### get_account_mut

```
get_account_mut(account_id):
    key = bytes(account_id)
    GUARD key not in accounts → return none

    "Save snapshot if not already saved or if None (for newly created entries)."
    "For newly created entries, update snapshot to current value so"
    "subsequent operations can track changes with STATE/UPDATED pairs."
    "Rollback correctness is ensured by created_accounts set."
    if account_snapshots[key] is absent or none:
        account_snapshots[key] = accounts[key]

    capture_op_snapshot_for_key(ledger_key)
    snapshot_last_modified_key(ledger_key)

    if key not in modified_accounts:
        modified_accounts.add(key)

    → mutable ref to accounts[key]
```

### record_account_access

"Captures op snapshot so account appears in delta even if only read."
"Matches stellar-core load() vs loadWithoutRecord() distinction."

```
record_account_access(account_id):
    key = bytes(account_id)
    GUARD key not in accounts → return

    if account_snapshots[key] is absent or none:
        account_snapshots[key] = accounts[key]

    capture_op_snapshot_for_key(ledger_key)
    snapshot_last_modified_key(ledger_key)

    if key not in modified_accounts:
        modified_accounts.add(key)
```

### create_account

```
create_account(entry):
    key = bytes(entry.account_id)

    "Save snapshot (None because it didn't exist)"
    account_snapshots[key] or= none
    snapshot_last_modified_key(ledger_key)
    MUTATE last_modified[ledger_key] = ledger_seq

    delta.record_create(account_to_ledger_entry(entry))

    accounts[key] = entry
    created_accounts.insert(key)

    if key not in modified_accounts:
        modified_accounts.add(key)
```

### update_account

```
update_account(entry):
    key = bytes(entry.account_id)

    "Save snapshot if not already saved (preserves original state from start of tx)"
    if key not in account_snapshots:
        account_snapshots[key] = accounts[key]
    capture_op_snapshot_for_key(ledger_key)
    snapshot_last_modified_key(ledger_key)

    pre_state = account_to_ledger_entry(accounts[key])
    MUTATE last_modified[ledger_key] = ledger_seq

    post_state = account_to_ledger_entry(entry)
    delta.record_update(pre_state, post_state)

    accounts[key] = entry
    "Update snapshot to current value so flush_modified_entries doesn't record a duplicate"
    account_snapshots[key] = entry
```

### delete_account

```
delete_account(account_id):
    key = bytes(account_id)

    if key not in account_snapshots:
        account_snapshots[key] = accounts[key]
    capture_op_snapshot_for_key(ledger_key)
    snapshot_last_modified_key(ledger_key)

    pre_state = account_to_ledger_entry(accounts[key])
    delta.record_delete(ledger_key, pre_state)

    clear_entry_sponsorship_metadata(ledger_key)    REF: state/sponsorship::clear_entry_sponsorship_metadata
    accounts.remove(key)
    remove_last_modified_key(ledger_key)
```

### set_account_no_tracking / put_account

"Used during verification to sync state with CDP without affecting delta"

```
set_account_no_tracking(entry):
    accounts[bytes(entry.account_id)] = entry
```

---

## Trustlines

Same CRUD pattern as accounts. Key = `(account_bytes, asset_key)`.

### get_trustline / get_trustline_by_trustline_asset

```
get_trustline(account_id, asset):
    → trustlines[(account_bytes, asset_key)]
```

### is_trustline_tracked

```
is_trustline_tracked(account_id, asset):
    → key in trustline_snapshots
```

### get_trustline_mut / get_trustline_by_trustline_asset_mut

Same snapshot + track pattern as get_account_mut.

### create_trustline

Same create pattern. Records in delta, tracks in created_trustlines.

### update_trustline

Same update pattern. Records pre/post in delta.
NOTE: "Do NOT add to modified_trustlines since update already recorded.
Prevents flush_modified_entries from recording a duplicate."

### delete_trustline / delete_trustline_by_trustline_asset

Same delete pattern. Records pre-state, removes from state + sponsorship.

---

## Offers

Key = `OfferKey(seller_bytes, offer_id)`.
Additional indexes: `offer_index` (price-sorted) and `aa_index` (account+asset).

### get_offer / is_offer_tracked / get_offer_mut

Same pattern as accounts.

### get_offers_by_account_and_asset

"Uses state's own account_asset_offers secondary index"

```
get_offers_by_account_and_asset(account_id, asset):
    offer_ids = account_asset_offers[(account_bytes, asset_key)]
    → offers matching those IDs
```

### create_offer

```
create_offer(entry):
    ... standard create pattern ...
    offer_index.add_offer(entry)
    aa_index_insert(entry)
```

**Calls**: [add_offer](offer_index.pc.md#add_offer) | [aa_index_insert](#helper-aa_index_insert)

### update_offer

```
update_offer(entry):
    ... standard snapshot/pre-state/post-state pattern ...
    offer_index.update_offer(entry)
    aa_index_remove(old_offer)
    aa_index_insert(entry)
    NOTE: "Do NOT track in modified_offers — update already recorded"
```

**Calls**: [update_offer](offer_index.pc.md#update_offer) | [aa_index_remove](#helper-aa_index_remove) | [aa_index_insert](#helper-aa_index_insert)

### delete_offer

```
delete_offer(seller_id, offer_id):
    ... standard snapshot/pre-state/delta pattern ...
    offer_index.remove_offer(seller_id, offer_id)
    aa_index_remove(offer)
    clear_entry_sponsorship_metadata(ledger_key)
    offers.remove(key)
```

**Calls**: [remove_offer](offer_index.pc.md#remove_offer) | [aa_index_remove](#helper-aa_index_remove)

### best_offer / best_offer_filtered

```
best_offer(buying, selling):
    key = offer_index.best_offer_key(buying, selling)
    → offers[key]

best_offer_filtered(buying, selling, filter_fn):
    for each offer_key in offer_index.offers_for_pair(buying, selling):
        offer = offers[offer_key]
        if filter_fn(offer):
            → offer
```

### remove_offers_by_account_and_asset

"Used when revoking authorization on a trustline."
"Mirrors stellar-core removeOffersByAccountAndAsset which queries SQL for ALL matching offers."

```
remove_offers_by_account_and_asset(account_id, asset):
    "Phase 1: Load from authoritative source"
    if offers_by_account_asset_loader is available:
        entries = loader(account_id, asset)
        for each entry in entries:
            if entry is Offer:
                "Skip offers already deleted in this ledger"
                if delta.deleted_keys contains offer_ledger_key:
                    continue
                "Only load offers not already tracked in state"
                if offer not in offers:
                    load_entry(entry)

    "Phase 2: Remove from secondary index"
    offer_ids = account_asset_offers[(account_bytes, asset_key)]

    "Phase 3: Verify and collect matching offers"
    offers_to_remove = offers where (buying == asset OR selling == asset)

    "Phase 4: Delete each offer"
    for each offer in offers_to_remove:
        delete_offer(offer.seller_id, offer.offer_id)

    → offers_to_remove
```

**Calls**: [load_entry](#load_entry) | [delete_offer](#delete_offer)

---

## Data Entries

Key = `(account_bytes, name_string)`. Same CRUD pattern.

### get_data / is_data_tracked / get_data_mut

Same pattern as accounts.

### create_data / update_data / delete_data

Same CRUD pattern. `update_data` updates snapshot to prevent duplicate flush.

---

## Contract Data

Key = `ContractDataKey(contract, key, durability)`. Same CRUD pattern.
Deletion also tracks in `deleted_contract_data` to prevent bucket list reload.

---

## Contract Code

Key = `hash.0` (32-byte hash). Same CRUD pattern.
Deletion also tracks in `deleted_contract_code` to prevent bucket list reload.

---

## Claimable Balances

Key = `claimable_balance_id_to_bytes(balance_id)`. Same CRUD pattern.

### is_claimable_balance_tracked

"Returns true if entry exists in snapshots, meaning it was loaded"
"(even if subsequently deleted). Prevents reloading deleted entries."

---

## Liquidity Pools

Key = `pool_id_to_bytes(pool_id)`. Same CRUD pattern.

---

## No-Tracking Operations

### apply_entry_no_tracking

"Used during verification to sync state with CDP without affecting delta"

```
apply_entry_no_tracking(entry):
    dispatch on entry.data type:
        insert into appropriate map by key
        (Ttl entries also capture bucket list snapshot)
        ConfigSetting: no-op
```

### delete_entry_no_tracking

```
delete_entry_no_tracking(key):
    dispatch on key type:
        remove from appropriate map
        ConfigSetting: no-op
    entry_sponsorships.remove(key)
    entry_sponsorship_ext.remove(key)
    entry_last_modified.remove(key)
```

---

## Generic Entry Lookup

### get_entry

```
get_entry(key):
    dispatch on key type:
        Account     → account_to_ledger_entry(accounts[...])
        Trustline   → trustline_to_ledger_entry(trustlines[...])
        Offer       → offer_to_ledger_entry(offers[...])
        Data        → data_to_ledger_entry(data_entries[...])
        ContractData→ contract_data_to_ledger_entry(contract_data[...])
        ContractCode→ contract_code_to_ledger_entry(contract_code[...])
        Ttl         → ttl_to_ledger_entry(ttl_entries[...])
        ClaimableBalance → claimable_balance_to_ledger_entry(...)
        LiquidityPool    → liquidity_pool_to_ledger_entry(...)
```

### is_entry_deleted

"Used to prevent reloading deleted entries from the bucket list."
"In stellar-core, deleted entries are tracked in mThreadEntryMap as nullopt."

```
is_entry_deleted(key):
    dispatch on key type:
        ContractData → key in deleted_contract_data
        ContractCode → key in deleted_contract_code
        Ttl          → key in deleted_ttl
        other        → false
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 2094   | ~310       |
| Functions     | 65     | 65         |

NOTE: The file is highly repetitive — 9 entry types × ~7 methods each
(get, get_mut, create, update, delete, to_ledger_entry, is_tracked) plus
shared helpers and offer-specific index methods.
