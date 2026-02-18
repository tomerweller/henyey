## Pseudocode: crates/tx/src/state/mod.rs

This module manages all ledger entry state during transaction execution.
It tracks accounts, trustlines, offers, data entries, contract data/code,
TTL entries, claimable balances, and liquidity pools with full snapshot,
rollback, savepoint, and delta-recording support.

The production logic spans four files:
- `mod.rs` — data structures, rollback, savepoint, commit, flush, helpers
- `entries.rs` — CRUD for every entry type, loading, conversion
- `sponsorship.rs` — sponsorship stack, entry sponsor management
- `ttl.rs` — TTL entry operations, deferred RO TTL bumps

---

### Data Structures

```
enum AssetKey:
  Native
  CreditAlphanum4(code_4bytes, issuer_32bytes)
  CreditAlphanum12(code_12bytes, issuer_32bytes)
  PoolShare(pool_id_32bytes)

struct ContractDataKey:
  contract: ScAddress
  key: ScVal
  durability: Temporary | Persistent

struct SponsorshipContext:
  sponsoring: AccountId
  sponsored: AccountId
```

### LedgerStateManager

"Ledger state manager for transaction execution."
"Provides read/write access to ledger entries during transaction
execution, tracking all changes for later persistence."

```
struct LedgerStateManager:
  STATE:
    ledger_seq: u32
    base_reserve: i64
    id_pool: u64

  ENTRY_MAPS (keyed by typed lookup keys):
    accounts:           Map<[u8;32], AccountEntry>
    trustlines:         Map<(acct_bytes, AssetKey), TrustLineEntry>
    offers:             Map<OfferKey, OfferEntry>
    data_entries:       Map<(acct_bytes, String), DataEntry>
    contract_data:      Map<ContractDataKey, ContractDataEntry>
    contract_code:      Map<[u8;32], ContractCodeEntry>
    ttl_entries:        Map<[u8;32], TtlEntry>
    claimable_balances: Map<[u8;32], ClaimableBalanceEntry>
    liquidity_pools:    Map<[u8;32], LiquidityPoolEntry>

  METADATA:
    entry_sponsorships:    Map<LedgerKey, AccountId>
    entry_sponsorship_ext: Set<LedgerKey>
    entry_last_modified:   Map<LedgerKey, u32>

  "TTL values at ledger start (for Soroban execution).
  Captured at start of each ledger, remains read-only during execution.
  Soroban uses these instead of ttl_entries to match stellar-core
  where transactions see bucket list state at ledger start."
  ttl_bucket_list_snapshot: Map<[u8;32], u32>

  OPERATION SNAPSHOTS:
    op_entry_snapshots: Map<LedgerKey, LedgerEntry>
    op_snapshots_active: bool
    multi_op_mode: bool

  TRANSACTION SNAPSHOTS (per entry type):
    *_snapshots: Map<K, nullable<V>>
    NOTE: "snapshot value = pre-TX entry state; null = entry didn't exist"
    created_*: Set<K>
    NOTE: "tracks entries created in this TX for correct rollback"

  MODIFICATION TRACKING:
    modified_*: Vec<K>

  "Deferred read-only TTL bumps. TTL updates for read-only entries
  where only the TTL changed. Per stellar-core behavior:
  - Should NOT appear in transaction meta
  - Should be flushed to delta at end of ledger (for bucket list)"
  deferred_ro_ttl_bumps: Map<[u8;32], u32>
  deferred_ro_ttl_bumps_snapshot: nullable<Map<[u8;32], u32>>

  "Track Soroban entries deleted in this ledger.
  Prevents reloading deleted entries from bucket list during
  footprint loading. In stellar-core, deleted entries are tracked
  in mThreadEntryMap as nullopt."
  deleted_contract_data: Set<ContractDataKey>
  deleted_contract_code: Set<[u8;32]>
  deleted_ttl: Set<[u8;32]>

  INDEXES:
    offer_index: OfferIndex
    account_asset_offers: Map<(acct_bytes, AssetKey), Set<offer_id>>
    NOTE: "Each offer indexed under both (seller, selling) and (seller, buying)"

  LOADERS (optional callbacks):
    entry_loader: nullable<fn(LedgerKey) -> nullable<LedgerEntry>>
    batch_entry_loader: nullable<fn([LedgerKey]) -> [LedgerEntry]>
    offers_by_account_asset_loader: nullable<fn(AccountId, Asset) -> [LedgerEntry]>

  "Per-source-account maximum sequence number across all TXs in
  current tx set. Used by AccountMerge to prevent seq num reuse."
  max_seq_num_to_apply: Map<[u8;32], i64>

  DELTA:
    delta: LedgerDelta
    delta_snapshot: nullable<LedgerDelta>
    id_pool_snapshot: nullable<u64>

  SPONSORSHIP:
    sponsorship_stack: Vec<SponsorshipContext>
```

---

### Helper: rollback_new_snapshots

"Restore entries from snapshots created after the savepoint."
"For each key present in current_snapshots but not in savepoint_snapshots,
the snapshot value is applied to live_map."

```
function rollback_new_snapshots(live_map, current_snapshots, savepoint_snapshots):
  for each (key, snapshot) in current_snapshots:
    if key NOT in savepoint_snapshots:
      if snapshot is present:
        live_map[key] = snapshot
      else:
        remove live_map[key]
```

### Helper: apply_pre_values

"Restore pre-savepoint values for entries modified before the savepoint."

```
function apply_pre_values(live_map, pre_values):
  for each (key, value) in pre_values:
    if value is present:
      live_map[key] = value
    else:
      remove live_map[key]
```

### Helper: rollback_entries

"For each snapshotted key: if created, remove from live map.
Otherwise restore pre-TX value from snapshot."

```
function rollback_entries(live_map, snapshots, created):
  for each (key, snapshot) in snapshots.drain():
    if key in created:
      remove live_map[key]
    else if snapshot is present:
      live_map[key] = snapshot
  created.clear()
```

---

### new

```
function new(base_reserve, ledger_seq):
  → LedgerStateManager with all maps empty,
    delta = LedgerDelta.new(ledger_seq),
    id_pool = 0,
    all flags = false
```

### starting_sequence_number

"Compute the starting sequence number for new accounts."

```
function starting_sequence_number():
  GUARD ledger_seq > i32.MAX  → error "overflowed"
  → (ledger_seq as i64) << 32
```

### minimum_balance_for_account

```
function minimum_balance_for_account(account, protocol_version, additional_subentries):
  num_sub_entries = account.num_sub_entries + additional_subentries
  GUARD num_sub_entries < 0  → error "negative subentry count"
  (num_sponsoring, num_sponsored) = sponsorship_counts(account)
  → minimum_balance_with_counts(protocol_version, num_sub_entries,
      num_sponsoring, num_sponsored)
```

### minimum_balance_for_account_with_deltas

```
function minimum_balance_for_account_with_deltas(account, protocol_version,
    additional_subentries, delta_sponsoring, delta_sponsored):
  num_sub_entries = account.num_sub_entries + additional_subentries
  GUARD num_sub_entries < 0  → error "negative subentry count"
  (num_sponsoring, num_sponsored) = sponsorship_counts(account)
  num_sponsoring += delta_sponsoring
  num_sponsored += delta_sponsored
  GUARD num_sponsoring < 0 OR num_sponsored < 0
    → error "negative sponsorship count"
  → minimum_balance_with_counts(protocol_version, num_sub_entries,
      num_sponsoring, num_sponsored)
```

### minimum_balance_with_counts

```
function minimum_balance_with_counts(protocol_version, num_sub_entries,
    num_sponsoring, num_sponsored):
  effective_entries = 2 + num_sub_entries + num_sponsoring - num_sponsored
  GUARD effective_entries < 0
    → error "unexpected account state"
  → effective_entries * base_reserve
```

### next_id

"Generate the next ID from the pool."

```
function next_id():
  NOTE: "First call snapshots id_pool for rollback on failed TX"
  if id_pool_snapshot is null:
    id_pool_snapshot = id_pool
  id_pool += 1
  ASSERT: id_pool did not overflow
  → id_pool as i64
```

---

## Lazy Loading

### ensure_offer_entries_loaded

"Batch-load all entries needed to cross an offer (seller account + trustlines).
Single pass through bucket list instead of 2-3 separate passes."

```
function ensure_offer_entries_loaded(seller, selling, buying):
  seller_bytes = account_id_to_bytes(seller)
  needed_keys = []

  if seller_bytes NOT in accounts:
    needed_keys.add(AccountKey(seller))
  if selling is NOT Native:
    if (seller_bytes, AssetKey(selling)) NOT in trustlines:
      needed_keys.add(TrustlineKey(seller, selling))
  if buying is NOT Native:
    if (seller_bytes, AssetKey(buying)) NOT in trustlines:
      needed_keys.add(TrustlineKey(seller, buying))

  if needed_keys is empty:
    → return

  if batch_entry_loader is available:
    entries = batch_entry_loader(needed_keys)
    for each entry in entries:
      load_entry(entry)                    REF: entries::load_entry
  else if entry_loader is available:
    for each key in needed_keys:
      entry = entry_loader(key)
      if entry is present:
        load_entry(entry)                  REF: entries::load_entry
```

### ensure_account_loaded

```
function ensure_account_loaded(account_id):
  key_bytes = account_id_to_bytes(account_id)
  if key_bytes in accounts:
    → true
  if entry_loader is available:
    entry = entry_loader(AccountKey(account_id))
    if entry is present:
      load_entry(entry)                    REF: entries::load_entry
      → true
  → false
```

### ensure_trustline_loaded

```
function ensure_trustline_loaded(account_id, asset):
  if (account_bytes, asset_key) in trustlines:
    → true
  if entry_loader is available:
    entry = entry_loader(TrustlineKey(account_id, asset))
    if entry is present:
      load_entry(entry)                    REF: entries::load_entry
      → true
  → false
```

---

## Soroban State Extraction

### take_soroban_state / restore_soroban_state

"Path payment operations clone state for speculative orderbook exchange.
By extracting Soroban collections (never accessed during exchange),
the clone becomes much cheaper."

```
function take_soroban_state():
  → extract contract_data, contract_code, ttl_entries,
    ttl_bucket_list_snapshot from self

function restore_soroban_state(soroban):
  self.contract_data = soroban.contract_data
  self.contract_code = soroban.contract_code
  self.ttl_entries = soroban.ttl_entries
  self.ttl_bucket_list_snapshot = soroban.ttl_bucket_list_snapshot
```

---

## Delta & Snapshot Management

### snapshot_delta

"Preserves committed changes from previous TXs so they're not lost
if current TX fails and rolls back."

```
function snapshot_delta():
  delta_snapshot = delta.copy()
  deferred_ro_ttl_bumps_snapshot = deferred_ro_ttl_bumps.copy()
```

### clear_cached_entries_inner

```
function clear_cached_entries_inner(preserve_offers):
  clear accounts, trustlines, data_entries
  clear contract_data, contract_code, ttl_entries, ttl_bucket_list_snapshot
  clear claimable_balances, liquidity_pools

  if NOT preserve_offers:
    clear offers, offer_index, account_asset_offers

  if preserve_offers:
    "Retain sponsorship/last_modified entries for Offer keys only"
    entry_sponsorships.retain(Offer keys only)
    entry_sponsorship_ext.retain(Offer keys only)
    entry_last_modified.retain(Offer keys only)
  else:
    clear entry_sponsorships, entry_sponsorship_ext, entry_last_modified

  clear entry_loader, offers_by_account_asset_loader
  clear all TX-level state (op_entry_snapshots, sponsorship_stack,
    delta, all modified_*, all *_snapshots, all created_*)

  if NOT preserve_offers:
    clear created_offers
```

### begin_op_snapshot / end_op_snapshot

```
function begin_op_snapshot():
  op_entry_snapshots.clear()
  op_snapshots_active = true

function end_op_snapshot():
  op_snapshots_active = false
  → take op_entry_snapshots
```

---

## Savepoint Support

### create_savepoint

"Captures current state for potential rollback. Used for:
1. Per-operation rollback (failed ops undo changes)
2. Path payment speculation (orderbook vs pool comparison)"

```
function create_savepoint():
  sp = new Savepoint

  "Clone all snapshot maps (small: only entries modified in current TX)"
  sp.*_snapshots = copy of self.*_snapshots (for all 9 entry types)

  "Save current values of entries in snapshot maps (pre-savepoint values)"
  for each entry type:
    sp.*_pre_values = [(key, live_map[key]) for key in *_snapshots.keys()]

  "Created entry sets"
  sp.created_* = copy of self.created_* (for all 9 entry types)

  "Delta and modified vec lengths"
  sp.delta_lengths = delta.snapshot_lengths()
  sp.modified_*_len = len(self.modified_*) (for all 9 entry types)

  "Entry metadata"
  sp.entry_last_modified_snapshots = copy
  sp.entry_last_modified_pre_values = current values for snapshot'd keys
  sp.entry_sponsorship_snapshots = copy
  sp.entry_sponsorship_ext_snapshots = copy
  sp.entry_sponsorship_pre_values = current values for snapshot'd keys
  sp.entry_sponsorship_ext_pre_values = current presence for snapshot'd keys

  sp.op_entry_snapshot_keys = current op_entry_snapshots.keys()
  sp.id_pool = self.id_pool

  → sp
```

### rollback_to_savepoint

"Undoes all modifications since savepoint. O(k) where k = entries
modified during speculation (typically < 50)."

```
function rollback_to_savepoint(sp):
  "Phase 1: Restore entries newly snapshot'd since savepoint"
  NOTE: "These entries have snapshots added after savepoint, so their
  snapshot values ARE their pre-savepoint (= pre-TX) values."
  rollback_offer_snapshots(sp)
  for each non-offer entry type:
    rollback_new_snapshots(live_map, current_snapshots, sp.snapshots)

  "Phase 2: Restore pre-savepoint values for already-snapshot'd entries"
  apply_offer_pre_values(sp.offer_pre_values)
  for each non-offer entry type:
    apply_pre_values(live_map, sp.pre_values)

  "Phase 3: Restore snapshot maps and created sets"
  self.*_snapshots = sp.*_snapshots
  self.created_* = sp.created_*

  "Phase 4: Truncate delta"
  delta.truncate_to(sp.delta_lengths)

  "Phase 5: Truncate modified tracking vecs"
  self.modified_*.truncate(sp.modified_*_len)

  "Phase 6: Restore entry metadata"
  rollback_new_snapshots for entry_last_modified, entry_sponsorships
  apply_pre_values for entry_last_modified, entry_sponsorships

  for entry_sponsorship_ext (bool-based, not nullable):
    for each key in current_ext_snapshots NOT in sp.ext_snapshots:
      if was_present: insert into ext set
      else: remove from ext set
    for each (key, was_present) in sp.ext_pre_values:
      if was_present: insert
      else: remove

  "Phase 7: Restore op entry snapshots and id_pool"
  op_entry_snapshots.retain(keys in sp.op_entry_snapshot_keys)
  id_pool = sp.id_pool
```

### Helper: rollback_offer_snapshots

"Offers need special handling for aa_index and offer_index."

```
function rollback_offer_snapshots(sp):
  new_offer_keys = offer_snapshots.keys NOT in sp.offer_snapshots
  for each (key, snapshot) in new offers since savepoint:
    if current offer exists at key:
      aa_index_remove(current offer)
    if snapshot is present:
      aa_index_insert(snapshot)
      offer_index.update_offer(snapshot)
      offers[key] = snapshot
    else:
      offer_index.remove_by_key(key)
      remove offers[key]
```

### Helper: apply_offer_pre_values

```
function apply_offer_pre_values(pre_values):
  for each (key, value) in pre_values:
    if current offer exists at key:
      aa_index_remove(current offer)
    if value is present:
      aa_index_insert(value)
      offer_index.update_offer(value)
      offers[key] = value
    else:
      offer_index.remove_by_key(key)
      remove offers[key]
```

---

## Rollback

### rollback

"Rollback all changes since the state manager was created."

```
function rollback():
  "Restore id_pool snapshot if present"
  if id_pool_snapshot is present:
    id_pool = id_pool_snapshot
    id_pool_snapshot = null

  "Rollback basic entry types"
  rollback_entries(accounts, account_snapshots, created_accounts)
  rollback_entries(trustlines, trustline_snapshots, created_trustlines)

  "Offers need special handling for aa_index and offer_index"
  for each (key, snapshot) in offer_snapshots.drain():
    if key in created_offers:
      if current offer exists:
        aa_index_remove(current)
      offer_index.remove_by_key(key)
      remove offers[key]
    else if snapshot is present:
      if current offer exists:
        aa_index_remove(current)
      aa_index_insert(snapshot)
      offer_index.update_offer(snapshot)
      offers[key] = snapshot
  created_offers.clear()

  rollback_entries(data_entries, data_snapshots, created_data)
  rollback_entries(contract_data, contract_data_snapshots, created_contract_data)
  rollback_entries(contract_code, contract_code_snapshots, created_contract_code)
  rollback_entries(ttl_entries, ttl_snapshots, created_ttl)

  "Restore deferred RO TTL bumps to pre-transaction state"
  NOTE: "In stellar-core, commitChangesFromSuccessfulOp is only called for
  successful TXs. Failed TXs do not commit RO TTL bumps."
  if deferred_ro_ttl_bumps_snapshot is present:
    deferred_ro_ttl_bumps = deferred_ro_ttl_bumps_snapshot
  else:
    deferred_ro_ttl_bumps.clear()

  rollback_entries(claimable_balances, cb_snapshots, created_cbs)
  rollback_entries(liquidity_pools, lp_snapshots, created_lps)

  "Restore entry sponsorship snapshots"
  for each (key, snapshot) in entry_sponsorship_snapshots.drain():
    if snapshot is present: entry_sponsorships[key] = snapshot
    else: remove entry_sponsorships[key]
  for each (key, was_present) in entry_sponsorship_ext_snapshots.drain():
    if was_present: insert key into entry_sponsorship_ext
    else: remove key from entry_sponsorship_ext
  for each (key, snapshot) in entry_last_modified_snapshots.drain():
    if snapshot is present: entry_last_modified[key] = snapshot
    else: remove entry_last_modified[key]

  "Clear all modification tracking"
  clear all modified_* vecs

  "Restore delta from snapshot"
  NOTE: "Preserves committed changes from previous TXs in this ledger.
  Fee for current TX was already added during fee deduction phase
  and is restored via restore_delta_entries() in execution.rs."
  if delta_snapshot is present:
    delta = delta_snapshot
  else:
    fee_charged = delta.fee_charged()
    delta = LedgerDelta.new(ledger_seq)
    if fee_charged != 0:
      delta.add_fee(fee_charged)
```

### commit

"Commit changes by clearing snapshots (changes become permanent)."

```
function commit():
  id_pool_snapshot = null
  NOTE: "Do NOT clear delta_snapshot here. It preserves committed
  changes from PREVIOUS TXs and is only set/cleared at TX boundaries."
  clear all *_snapshots
  clear all modified_* vecs
  clear all created_* sets
```

---

## Flushing Modified Entries

### flush_all_accounts_except

"Flush pending account changes to delta, excluding a specific account."

```
function flush_all_accounts_except(exclude):
  exclude_key = account_id_to_key(exclude)
  for each key in modified_accounts:
    if key == exclude_key:
      keep in remaining list
      continue

    snapshot_entry = account_snapshots[key]
    if snapshot_entry is null: continue
    entry = accounts[key]
    if entry is null: continue

    ledger_key = AccountKey(entry.account_id)
    accessed_in_op = op_snapshots_active AND
                     ledger_key in op_entry_snapshots
    should_record = accessed_in_op OR multi_op_mode OR
                    entry != snapshot_entry

    if should_record:
      if op_snapshots_active:
        pre_state = op_entry_snapshots[ledger_key]
          or else account_to_ledger_entry(snapshot_entry)
      else:
        pre_state = account_to_ledger_entry(snapshot_entry)

      set_last_modified_key(ledger_key, ledger_seq)
      post_state = account_to_ledger_entry(entry)
      delta.record_update(pre_state, post_state)
      NOTE: "Do NOT update account_snapshots. Original pre-tx
      snapshot must be preserved for transaction-level rollback."
```

### flush_account

"Flush a specific account's changes to delta."

```
function flush_account(account_id):
  key = account_id_to_key(account_id)
  pos = find key in modified_accounts
  if not found: → false

  remove from modified_accounts at pos
  snapshot_entry = account_snapshots[key]
  entry = accounts[key]

  "For single-op TXs: only record if entry actually changed.
  For multi-op TXs: record every access (even if no change)."
  should_record = multi_op_mode OR entry != snapshot_entry

  if should_record:
    pre_state = account_to_ledger_entry(snapshot_entry)
    set_last_modified_key(ledger_key, ledger_seq)
    post_state = account_to_ledger_entry(entry)
    delta.record_update(pre_state, post_state)
    → true
  → false
```

### flush_modified_entries

"Record updates for mutated entries into delta and clear modification tracking."
"For per-operation STATE values, uses op_entry_snapshots (captured at access time)
rather than TX-level snapshots."

```
function flush_modified_entries():
  for each entry type in [accounts, trustlines, offers, data,
      contract_data, contract_code, ttl, claimable_balances,
      liquidity_pools]:

    for each key in modified_<type>:
      snapshot_entry = <type>_snapshots[key]
      if snapshot_entry is null: continue
      entry = <type>_map[key]
      if entry is null: continue

      ledger_key = build_ledger_key(entry)

      "Determine if change should be recorded"
      accessed_in_op = op_snapshots_active AND
                       ledger_key in op_entry_snapshots
      NOTE: "contract_data, contract_code, ttl skip op_snapshot check,
      only record if entry != snapshot_entry"

      if accessed_in_op OR entry != snapshot_entry:
        fallback = <type>_to_ledger_entry(snapshot_entry)
        post = <type>_to_ledger_entry(entry)
        record_flush_update(ledger_key, fallback, post)

    SPECIAL for TTL:
      "Skip entries created in this TX (already have CREATED recorded)"
      if key in created_ttl: continue
```

### Helper: record_flush_update

"Resolve pre-state, set last_modified, record delta."

```
function record_flush_update(ledger_key, fallback_pre, post_state):
  pre_state = op_entry_snapshots[ledger_key] or else fallback_pre
  set_last_modified_key(ledger_key, ledger_seq)
  "Stamp post_state with current ledger sequence, matching
  stellar-core's maybeUpdateLastModified"
  post_state.last_modified_ledger_seq = ledger_seq
  delta.record_update(pre_state, post_state)
```

### apply_refund_to_delta

"Fee refunds are NOT separate meta changes - incorporated into
the final account balance of the existing update."

```
function apply_refund_to_delta(account_id, refund):
  delta.apply_refund_to_account(account_id, refund)
  MUTATE accounts[account_id] balance += refund
```

---

## snapshot_entry

"Get the pre-modification entry snapshot by LedgerKey."

```
function snapshot_entry(key):
  last_modified = last_modified_snapshot_for_key(key)
    or else last_modified_for_key(key)
  ext = ledger_entry_ext_for_snapshot(key)

  for each entry type matching key:
    snapshot = <type>_snapshots[typed_key]
    if snapshot is present:
      → LedgerEntry(last_modified, data=snapshot, ext)
  → null
```

---

## Entry Operations (entries.rs)

All entry types follow the same pattern. Shown once for accounts,
then summarized for other types.

### load_entry

"Load a single entry into state manager."

```
function load_entry(entry):
  sponsor = sponsorship_from_entry_ext(entry)
  has_ext = entry.ext is V1
  last_modified = entry.last_modified_ledger_seq

  dispatch on entry type:
    Account:
      key = account_id_to_bytes(account.account_id)
      accounts[key] = account
      record_entry_metadata(ledger_key, last_modified, has_ext, sponsor)

    Offer:
      offer_index.add_offer(offer)
      aa_index_insert(offer)
      offers[offer_key] = offer
      record_entry_metadata(...)

    Ttl:
      NOTE: "Capture bucket list TTL value for Soroban.
      Only capture if not already present - keeps original value
      even if entry is reloaded later."
      ttl_bucket_list_snapshot.entry(key).or_insert(ttl.live_until)
      ttl_entries[key] = ttl
      record_entry_metadata(...)

    [similar for Trustline, Data, ContractData, ContractCode,
     ClaimableBalance, LiquidityPool]
```

### load_entry_without_snapshot

"Load entry WITHOUT setting up change tracking.
Matches stellar-core's loadWithoutRecord() behavior.
Entries loaded this way will NOT appear in transaction meta
unless subsequently accessed via get_*_mut()."

```
function load_entry_without_snapshot(entry):
  for Account:
    accounts[key] = account
    record_entry_metadata(...)
    NOTE: "No snapshot, no modified tracking"
  for all other types:
    → delegate to load_entry(entry)
```

### get_<type>_mut (generic pattern)

"Get mutable reference. Automatically tracks modification for delta."

```
function get_<type>_mut(lookup_args):
  if key NOT in <type>_map:
    → null

  "Save snapshot if not already saved or if null (for newly created).
  For newly created entries, update snapshot to current value so
  subsequent operations can track STATE/UPDATED pairs.
  Rollback correctness ensured by created_<type> set."
  if <type>_snapshots[key] is missing or null:
    <type>_snapshots[key] = current entry value

  capture_op_snapshot_for_key(ledger_key)
  snapshot_last_modified_key(ledger_key)

  if key NOT in modified_<type>:
    modified_<type>.add(key)

  → mutable ref to <type>_map[key]
```

### record_account_access

"Record that an account was accessed during operation execution.
Captures op snapshot so it appears in delta even if only read.
Matches stellar-core load() vs loadWithoutRecord()."

```
function record_account_access(account_id):
  GUARD account NOT in accounts → return
  if account_snapshots[key] is missing or null:
    account_snapshots[key] = current value
  capture_op_snapshot_for_key(ledger_key)
  snapshot_last_modified_key(ledger_key)
  if key NOT in modified_accounts:
    modified_accounts.add(key)
```

### create_<type> (generic pattern)

```
function create_<type>(entry):
  <type>_snapshots[key].or_insert(null)
  snapshot_last_modified_key(ledger_key)
  set_last_modified_key(ledger_key, ledger_seq)

  ledger_entry = <type>_to_ledger_entry(entry)
  delta.record_create(ledger_entry)

  <type>_map[key] = entry
  created_<type>.insert(key)

  if key NOT in modified_<type>:
    modified_<type>.add(key)

  NOTE for Offer: also adds to offer_index and aa_index
```

### update_<type> (generic pattern)

```
function update_<type>(entry):
  if key NOT in <type>_snapshots:
    <type>_snapshots[key] = current value
  capture_op_snapshot_for_key(ledger_key)
  snapshot_last_modified_key(ledger_key)

  pre_state = <type>_to_ledger_entry(current_entry)
  set_last_modified_key(ledger_key, ledger_seq)
  post_state = <type>_to_ledger_entry(entry)
  delta.record_update(pre_state, post_state)

  <type>_map[key] = entry
  <type>_snapshots[key] = entry
  NOTE: "Update snapshot to prevent flush_modified_entries duplicate"

  NOTE for Offer: also updates offer_index, aa_index_remove/insert
  NOTE for Offer: does NOT add to modified_offers (already recorded)
```

### delete_<type> (generic pattern)

```
function delete_<type>(lookup_args):
  if key NOT in <type>_snapshots:
    <type>_snapshots[key] = current value
  capture_op_snapshot_for_key(ledger_key)
  snapshot_last_modified_key(ledger_key)

  pre_state = <type>_to_ledger_entry(current_entry)
  delta.record_delete(ledger_key, pre_state)

  clear_entry_sponsorship_metadata(ledger_key)
  remove <type>_map[key]
  remove_last_modified_key(ledger_key)

  NOTE for Offer: also removes from offer_index and aa_index
  NOTE for ContractData/Code/TTL: also inserts into deleted_* set
```

### remove_offers_by_account_and_asset

"Remove all offers owned by account buying or selling specific asset.
Used when revoking authorization on a trustline."
"Mirrors stellar-core removeOffersByAccountAndAsset which calls
loadOffersByAccountAndAsset to query SQL for ALL matching offers."

```
function remove_offers_by_account_and_asset(account_id, asset):
  "Load all matching offers from authoritative source"
  if offers_by_account_asset_loader is available:
    entries = loader(account_id, asset)
    for each offer_entry in entries:
      "Skip offers already deleted in this ledger"
      if offer's ledger_key in delta.deleted_keys():
        continue
      "Only load offers not already tracked in state"
      if offer_key NOT in offers:
        load_entry(entry)

  "Look up offer IDs from secondary index"
  offer_ids = account_asset_offers[(account_bytes, asset_key)]

  "Collect matching offers (verify they still match)"
  offers_to_remove = [offer for offer_id in offer_ids
    where offer.buying == asset OR offer.selling == asset]

  "Remove each offer"
  for each offer in offers_to_remove:
    delete_offer(offer.seller_id, offer.offer_id)

  → offers_to_remove
```

### best_offer

"Get best offer for buying/selling pair (lowest price, then offer ID).
Uses offer index for O(log n) lookup."

```
function best_offer(buying, selling):
  key = offer_index.best_offer_key(buying, selling)
  if key is present:
    → offers[key]
  → null
```

### best_offer_filtered

```
function best_offer_filtered(buying, selling, keep_fn):
  for each offer_key in offer_index.offers_for_pair(buying, selling):
    offer = offers[offer_key]
    if keep_fn(offer):
      → offer
  → null
```

### get_entry

"Get entry by LedgerKey (read-only). Dispatches to typed getter
and wraps result as LedgerEntry with metadata."

```
function get_entry(key):
  dispatch on key type:
    → <type>_to_ledger_entry(get_<type>(...))
```

### is_entry_deleted

"Check if Soroban entry was deleted during this ledger.
Prevents reloading from bucket list."

```
function is_entry_deleted(key):
  dispatch on key type:
    ContractData → key in deleted_contract_data
    ContractCode → key in deleted_contract_code
    Ttl          → key in deleted_ttl
    otherwise    → false
```

### build_ledger_entry

```
function build_ledger_entry(ledger_key, data):
  → LedgerEntry(
      last_modified = last_modified_for_key(ledger_key),
      data = data,
      ext = ledger_entry_ext_for(ledger_key))
```

---

## Entry Metadata Helpers (entries.rs)

### aa_index_insert / aa_index_remove

```
function aa_index_insert(offer):
  seller = account_id_to_bytes(offer.seller_id)
  account_asset_offers[(seller, selling_key)].add(offer.offer_id)
  account_asset_offers[(seller, buying_key)].add(offer.offer_id)

function aa_index_remove(offer):
  seller = account_id_to_bytes(offer.seller_id)
  account_asset_offers[(seller, selling_key)].remove(offer.offer_id)
  account_asset_offers[(seller, buying_key)].remove(offer.offer_id)
```

### capture_op_snapshot_for_key

```
function capture_op_snapshot_for_key(key):
  if NOT op_snapshots_active: return
  if key already in op_entry_snapshots: return
  entry = get_entry(key)
  if entry is present:
    op_entry_snapshots[key] = entry
```

### ledger_entry_ext_for / ledger_entry_ext_for_snapshot

```
function ledger_entry_ext_for(key):
  sponsor = entry_sponsorships[key]
  if key in entry_sponsorship_ext OR sponsor exists:
    → V1(sponsoring_id = sponsor)
  → V0

function ledger_entry_ext_for_snapshot(key):
  ext_present = entry_sponsorship_ext_snapshots[key]
    or else (key in entry_sponsorship_ext)
  sponsor = entry_sponsorship_snapshots[key]
    or else entry_sponsorships[key]
  if ext_present OR sponsor exists:
    → V1(sponsoring_id = sponsor)
  → V0
```

### record_entry_metadata

```
function record_entry_metadata(ledger_key, last_modified, has_ext, sponsor):
  entry_last_modified[ledger_key] = last_modified
  if has_ext:
    entry_sponsorship_ext.insert(ledger_key)
  if sponsor is present:
    entry_sponsorships[ledger_key] = sponsor
```

---

## Sponsorship (sponsorship.rs)

### Sponsorship Stack

```
function clear_sponsorship_stack():
  sponsorship_stack.clear()

function has_pending_sponsorship():
  → sponsorship_stack is not empty

function active_sponsor_for(sponsored):
  "Search stack from top (most recent first)"
  → first ctx where ctx.sponsored == sponsored
    return ctx.sponsoring

function is_sponsored(account_id):
  → any ctx in stack where ctx.sponsored == account_id

function is_sponsoring(account_id):
  → any ctx in stack where ctx.sponsoring == account_id

function push_sponsorship(sponsoring, sponsored):
  sponsorship_stack.push(SponsorshipContext(sponsoring, sponsored))

function pop_sponsorship():
  → sponsorship_stack.pop()

function remove_sponsorship_for(sponsored):
  pos = last position where ctx.sponsored == sponsored
  → remove and return sponsorship_stack[pos]
```

### Entry Sponsorship

```
function entry_sponsor(key):
  → entry_sponsorships[key]

function set_entry_sponsor(key, sponsor):
  snapshot_entry_sponsorship_metadata(key)
  capture_op_snapshot_for_key(key)
  entry_sponsorships[key] = sponsor
  entry_sponsorship_ext.insert(key)

function remove_entry_sponsor(key):
  snapshot_entry_sponsorship_metadata(key)
  capture_op_snapshot_for_key(key)
  entry_sponsorship_ext.insert(key)
  → entry_sponsorships.remove(key)
```

### apply_entry_sponsorship

"Apply sponsorship to a newly created ledger entry owned by sponsored."

```
function apply_entry_sponsorship(key, sponsored, multiplier):
  sponsor = active_sponsor_for(sponsored)
  if no sponsor: → null
  apply_entry_sponsorship_with_sponsor(key, sponsor, sponsored, multiplier)
  → sponsor
```

### apply_entry_sponsorship_with_sponsor

```
function apply_entry_sponsorship_with_sponsor(key, sponsor,
    sponsored, multiplier):
  GUARD multiplier < 0 → error "negative multiplier"
  set_entry_sponsor(key, sponsor)
  update_num_sponsoring(sponsor, multiplier)
  if sponsored is present:
    update_num_sponsored(sponsored, multiplier)
```

### apply_account_entry_sponsorship

"Apply sponsorship to a newly created account (not yet in state)."

```
function apply_account_entry_sponsorship(account, sponsor, multiplier):
  GUARD multiplier < 0 → error "negative multiplier"
  ext_v2 = ensure_account_ext_v2(account)
  updated = ext_v2.num_sponsored + multiplier
  GUARD updated < 0 OR updated > u32.MAX → error "out of range"
  ext_v2.num_sponsored = updated
  update_num_sponsoring(sponsor, multiplier)
```

### remove_entry_sponsorship_and_update_counts

```
function remove_entry_sponsorship_and_update_counts(key, sponsored, multiplier):
  sponsor = remove_entry_sponsor(key)
  if no sponsor: → null
  GUARD multiplier < 0 → error "negative multiplier"
  update_num_sponsoring(sponsor, -multiplier)
  update_num_sponsored(sponsored, -multiplier)
  → sponsor
```

### update_num_sponsoring / update_num_sponsored

"Lazily loads account from bucket list if not already in state."

```
function update_num_sponsoring(account_id, delta):
  ensure_account_loaded(account_id)
  account = get_account_mut(account_id)
  GUARD account is null → error SourceAccountNotFound
  ext_v2 = ensure_account_ext_v2(account)
  updated = ext_v2.num_sponsoring + delta
  GUARD updated < 0 OR updated > u32.MAX → error "out of range"
  ext_v2.num_sponsoring = updated

function update_num_sponsored(account_id, delta):
  ensure_account_loaded(account_id)
  account = get_account_mut(account_id)
  GUARD account is null → error SourceAccountNotFound
  ext_v2 = ensure_account_ext_v2(account)
  updated = ext_v2.num_sponsored + delta
  GUARD updated < 0 OR updated > u32.MAX → error "out of range"
  ext_v2.num_sponsored = updated
```

### remove_one_time_signers_from_all_sources

"Pre-auth TX signers are automatically consumed when authorized TX is applied."

```
function remove_one_time_signers_from_all_sources(tx_hash,
    source_accounts, protocol_version):
  @version(==7):
    → return (no-op)
  signer_key = PreAuthTx(tx_hash)
  for each account_id in source_accounts:
    remove_account_signer(account_id, signer_key)
```

### remove_account_signer

```
function remove_account_signer(account_id, signer_key):
  account = get_account_mut(account_id)
  GUARD account is null → false

  idx = find signer_key in account.signers
  GUARD idx not found → false

  remove account.signers[idx]
  MUTATE account num_sub_entries -= 1

  remove_signer_sponsorship(account_id, idx)
  → true
```

### Helper: remove_signer_sponsorship

```
function remove_signer_sponsorship(account_id, signer_index):
  account = get_account(account_id)
  if no account: return

  sponsor_id = account.ext.v1.ext.v2.signer_sponsoring_ids[signer_index]
  if no sponsor: return

  update_num_sponsoring(sponsor, -1)
  update_num_sponsored(account_id, -1)

  "Remove sponsorship entry from signer_sponsoring_ids vector"
  account = get_account_mut(account_id)
  remove signer_sponsoring_ids[signer_index]
```

---

## TTL Operations (ttl.rs)

### get_ttl_at_ledger_start

"Returns TTL value from bucket list snapshot captured at ledger start.
Used by Soroban execution to match stellar-core behavior."

```
function get_ttl_at_ledger_start(key_hash):
  → ttl_bucket_list_snapshot[key_hash]
```

### capture_ttl_bucket_list_snapshot

```
function capture_ttl_bucket_list_snapshot():
  ttl_bucket_list_snapshot.clear()
  for each (key_hash, ttl) in ttl_entries:
    ttl_bucket_list_snapshot[key_hash] = ttl.live_until_ledger_seq
```

### update_ttl

"Only records delta update if TTL value actually changes.
Critical for correct bucket list behavior: when multiple TXs in same
ledger access same entry, later TXs may set same value."

```
function update_ttl(entry):
  if existing.live_until == entry.live_until:
    NOTE: "TTL value unchanged - skip. Recording no-op would
    cause bucket list divergence."
    → return

  save snapshot if not already saved
  capture_op_snapshot_for_key(ledger_key)
  snapshot_last_modified_key(ledger_key)
  set_last_modified_key(ledger_key, ledger_seq)

  "Delta recording deferred to flush_modified_entries()"
  ttl_entries[key] = entry

  track modification
```

### update_ttl_no_delta

"Update TTL without recording in delta.
Used for TTL-only auto-bump changes where data entry wasn't modified.
stellar-core does NOT include these in transaction meta."

```
function update_ttl_no_delta(entry):
  if existing.live_until == entry.live_until:
    → return
  set_last_modified_key(ledger_key, ledger_seq)
  ttl_entries[key] = entry
  "Update snapshot to prevent flush_modified_entries from recording"
  ttl_snapshots[key] = entry
  track modification
```

### extend_ttl

```
function extend_ttl(key_hash, live_until_ledger_seq):
  ttl_entry = ttl_entries[key]
  if live_until_ledger_seq <= ttl_entry.live_until:
    → return

  if key in created_ttl:
    NOTE: "Entry created in this TX - do NOT emit STATE+UPDATED pair.
    Update CREATED entry in delta to reflect final value."
    delta.update_created_ttl(key_hash, updated)
    ttl_entries[key] = updated
  else:
    save snapshot (preserves original for rollback)
    capture_op_snapshot, snapshot_last_modified
    set_last_modified_key(ledger_key, ledger_seq)
    "Delta recording deferred to flush_modified_entries()"
    ttl_entries[key] = updated
    track modification
```

### record_ro_ttl_bump_for_meta

"Record RO TTL bump in delta for transaction meta, then defer state update."
"Per stellar-core: TX meta includes all TTL changes (including RO bumps).
RO bumps are deferred for state visibility. At end of ledger, flushed to state."

```
function record_ro_ttl_bump_for_meta(key_hash, live_until_ledger_seq):
  pre_state = ttl_to_ledger_entry(ttl_entries[key])
  GUARD pre_state is null → warn and return

  if existing.live_until == live_until_ledger_seq:
    → return (no change)

  capture_op_snapshot_for_key(ledger_key)
  NOTE: "Do NOT call snapshot_last_modified_key or set_last_modified_key.
  RO TTL bumps should NOT affect visible state for subsequent TXs."

  "Build post-state with CURRENT ledger as lastModified"
  post_state = LedgerEntry(
    last_modified = ledger_seq,
    data = TtlEntry(key_hash, live_until_ledger_seq),
    ext = ledger_entry_ext_for(ledger_key))

  delta.record_update(pre_state, post_state)

  "Store for later flushing (keep highest TTL per key)"
  deferred_ro_ttl_bumps[key] = max(current, live_until_ledger_seq)
```

### flush_ro_ttl_bumps_for_write_footprint

"Before each TX in cluster, flush accumulated RO TTL bumps for
entries in TX's read-write footprint. Ensures write TXs see bumped
values for correct rent fee calculations."

```
function flush_ro_ttl_bumps_for_write_footprint(write_keys):
  for each key in write_keys:
    if key is NOT ContractData or ContractCode: continue
    key_hash = SHA256(xdr_encode(key))
    if deferred_ro_ttl_bumps[key_hash] is present:
      bumped_live_until = deferred_ro_ttl_bumps.remove(key_hash)
      if bumped_live_until > existing_ttl.live_until:
        update_ttl_no_delta(TtlEntry(key_hash, bumped_live_until))
```

### flush_deferred_ro_ttl_bumps

"Flush remaining deferred RO TTL bumps at end of cluster processing."

```
function flush_deferred_ro_ttl_bumps():
  bumps = take deferred_ro_ttl_bumps
  for each (key, live_until) in bumps:
    if ttl_entries[key] exists AND live_until > existing.live_until:
      update_ttl_no_delta(TtlEntry(key, live_until))
```

### is_entry_live

```
function is_entry_live(key_hash):
  ttl = get_ttl(key_hash)
  → ttl exists AND ttl.live_until >= ledger_seq
```

---

## Free Functions (mod.rs)

### sponsorship_counts

```
function sponsorship_counts(account):
  if account.ext is V0: → (0, 0)
  if account.ext.v1.ext is V0: → (0, 0)
  → (v2.num_sponsoring, v2.num_sponsored)
```

### ensure_account_ext_v2

"Ensure account has extension V2 (with sponsorship fields).
Creates extension chain V0→V1→V2 if missing."

```
function ensure_account_ext_v2(account):
  if ext is V0:
    create V1 with zero liabilities, V2 with zero counts,
    signer_sponsoring_ids sized to signer count

  if ext is V1 with V0 inner:
    preserve existing liabilities, create V2 with zero counts,
    signer_sponsoring_ids sized to signer count

  ensure_signer_sponsoring_ids(v2, signer_count)
  → mutable ref to V2
```

### update_account_seq_info

"Update sequence metadata when account's sequence number changes."

```
function update_account_seq_info(account, ledger_seq, close_time):
  ext_v2 = ensure_account_ext_v2(account)
  if ext_v2.ext is V0:
    ext_v2.ext = V3(seq_ledger = ledger_seq, seq_time = close_time)
  else if ext_v2.ext is V3:
    MUTATE v3 seq_ledger = ledger_seq
    MUTATE v3 seq_time = close_time
```

### get_account_seq_time / get_account_seq_ledger

```
function get_account_seq_time(account):
  → account.ext.v1.ext.v2.ext.v3.seq_time or 0

function get_account_seq_ledger(account):
  → account.ext.v1.ext.v2.ext.v3.seq_ledger or 0
```

### ensure_signer_sponsoring_ids

```
function ensure_signer_sponsoring_ids(v2, signer_count):
  if ids.len < signer_count:
    extend with null sponsors
  if ids.len > signer_count:
    truncate to signer_count
```

---

## Summary

| Metric        | Source             | Pseudocode |
|---------------|--------------------|------------|
| Lines (logic) | ~4240 (4 files)    | ~540       |
| Functions     | ~95                | ~55        |

NOTE: Many CRUD functions are repetitive across 9 entry types.
Pseudocode uses generic patterns to avoid redundancy while preserving
the exact semantics (snapshot-before-mutation, delta recording order,
offer index maintenance, created-set tracking).
