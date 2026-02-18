## Pseudocode: crates/history/src/replay.rs

"Ledger replay for history catchup and verification."
"Two approaches: re-execution replay (default) and metadata replay."
"During replay, we verify tx_set_hash, tx_result_hash, and bucket_list_hash."

CONST FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION = 23

---

### Data: LedgerReplayResult

```
LedgerReplayResult:
  sequence            : u32
  protocol_version    : u32
  ledger_hash         : Hash256
  tx_count            : u32
  op_count            : u32
  fee_pool_delta      : i64
  total_coins_delta   : i64
  init_entries        : list of LedgerEntry   // INITENTRY (created)
  live_entries        : list of LedgerEntry   // LIVEENTRY (updated)
  dead_entries        : list of LedgerKey     // DEADENTRY (deleted)
  changes             : list of EntryChange
  eviction_iterator   : optional EvictionIterator
  soroban_state_size_delta : i64
```

### Data: ReplayConfig

```
ReplayConfig:
  verify_results                  : bool  // default false
  verify_bucket_list              : bool  // default true
  emit_classic_events             : bool  // default false
  backfill_stellar_asset_events   : bool  // default false
  run_eviction                    : bool  // default true
  eviction_settings               : StateArchivalSettings
```

NOTE: `verify_results` is false by default because re-execution may produce
different result codes than stellar-core, especially for Soroban.

### Data: ReplayedLedgerState

```
ReplayedLedgerState:
  sequence, ledger_hash, bucket_list_hash,
  close_time, protocol_version, base_fee, base_reserve
```

---

### Helper: load_state_archival_settings

```
load_state_archival_settings(snapshot):
  key = ConfigSetting(StateArchival)
  entry = snapshot.get_entry(key)
  GUARD entry is missing or wrong type → null
  → StateArchivalSettings from entry
```

### Helper: soroban_entry_size

"Compute the size of a Soroban entry for state size tracking."

```
soroban_entry_size(entry, protocol_version, cost_params):
  if entry is ContractData:
    → XDR-encoded byte length of entry
  if entry is ContractCode:
    xdr_size = XDR-encoded byte length of entry
    → entry_size_for_rent_by_protocol(
        protocol_version, entry, xdr_size, cost_params)
  → 0
```

**Calls:** [`entry_size_for_rent_by_protocol_with_cost_params`](../tx/operations/execute.pc.md)

### Helper: compute_soroban_state_size_delta

"Compute the net change in Soroban state size from entry changes."

```
compute_soroban_state_size_delta(changes, protocol_version, cost_params):
  delta = 0
  for each change in changes:
    if change is Created(entry):
      delta += soroban_entry_size(entry, ...)
    if change is Updated(previous, current):
      delta += soroban_entry_size(current, ...)
             - soroban_entry_size(previous, ...)
    if change is Deleted(previous):
      delta -= soroban_entry_size(previous, ...)
  → delta
```

### Helper: compute_soroban_state_size_window_entry

"The window tracks Soroban state size samples over time for resource limiting."

```
compute_soroban_state_size_window_entry(seq, bucket_list,
                                        soroban_state_size,
                                        archival_override):
  archival = archival_override or load from bucket_list
  GUARD archival is missing           → null
  sample_period = archival.live_soroban_state_size_window_sample_period
  sample_size   = archival.live_soroban_state_size_window_sample_size
  GUARD sample_period == 0 or sample_size == 0  → null

  window = load LiveSorobanStateSizeWindow from bucket_list
  GUARD window is empty               → null

  changed = false

  // Phase: Resize window if sample size changed
  if len(window) != sample_size:
    if sample_size < len(window):
      remove (len(window) - sample_size) oldest entries
    else:
      prepend copies of oldest entry
    changed = true

  // Phase: Sample at period boundary
  if seq % sample_period == 0 and window not empty:
    remove oldest entry
    append soroban_state_size
    changed = true

  GUARD not changed                   → null
  → LedgerEntry(ConfigSetting::LiveSorobanStateSizeWindow, window)
```

### Helper: combined_bucket_list_hash

```
combined_bucket_list_hash(live_bucket_list,
                          hot_archive_bucket_list,
                          protocol_version):
  live_hash = live_bucket_list.hash()

  @version(≥23):
    hot_hash = hot_archive_bucket_list.hash()
    → SHA256(live_hash || hot_hash)

  @version(<23):
    → live_hash
```

### Helper: count_operations

```
count_operations(tx_set):
  count = 0
  for each tx_envelope in tx_set.transactions():
    count += number of operations in tx_envelope
    NOTE: FeeBump wraps an inner transaction
  → count
```

### Helper: extract_ledger_changes

"Extract ledger entry changes from transaction metadata."

```
extract_ledger_changes(tx_metas):
  init_entries = []
  live_entries = []
  dead_entries = []

  for each meta in tx_metas:
    if meta is V0:
      for each op_meta in meta.operations:
        for each change in op_meta.changes:
          process_ledger_entry_change(change, ...)
    if meta is V1:
      process changes from meta.tx_changes
      then process changes from meta.operations
    if meta is V2, V3, or V4:
      process tx_changes_before
      then operation changes
      then tx_changes_after

  → (init_entries, live_entries, dead_entries)
```

### Helper: process_ledger_entry_change

```
process_ledger_entry_change(change, init, live, dead):
  if change is Created:  append to init
  if change is Updated:  append to live
  if change is Removed:  append key to dead
  if change is State:    skip (pre-change snapshot)
  if change is Restored: append to live
```

---

### replay_ledger

"Applies TransactionMeta directly from archives (metadata replay)."

```
replay_ledger(header, tx_set, tx_results, tx_metas, config):

  // Phase: Verification (optional)
  if config.verify_results:
    verify_tx_set(header, tx_set)
    result_set = build TransactionResultSet from tx_results
    xdr = encode result_set
    verify_tx_result_set(header, xdr)

  // Phase: Extract changes from metadata
  (init_entries, live_entries, dead_entries) =
      extract_ledger_changes(tx_metas)

  tx_count = tx_set.num_transactions()
  op_count = count_operations(tx_set)
  ledger_hash = compute_header_hash(header)

  // Phase: Soroban state size (approximation for meta replay)
  NOTE: "This is an approximation since we don't have
  pre-update/pre-delete states."
  soroban_state_size_delta = 0
  for each entry in init_entries:
    soroban_state_size_delta +=
        soroban_entry_size(entry, header.ledger_version, null)

  → LedgerReplayResult {
      sequence, protocol_version, ledger_hash,
      tx_count, op_count,
      fee_pool_delta = 0,
      total_coins_delta = 0,
      init_entries, live_entries, dead_entries,
      changes = [],
      eviction_iterator = null,
      soroban_state_size_delta
    }
```

**Calls:** [`verify_tx_set`](../history/verify.pc.md), [`verify_tx_result_set`](../history/verify.pc.md), [`compute_header_hash`](../history/verify.pc.md)

---

### replay_ledger_with_execution

"Re-executes transactions against the current bucket list state."

```
replay_ledger_with_execution(
    header, tx_set,
    bucket_list, hot_archive_bucket_list,
    network_id, config,
    expected_tx_results, eviction_iterator,
    module_cache, soroban_state_size,
    prev_id_pool, offer_entries):

  // Phase: Optional tx set verification
  if config.verify_results:
    verify_tx_set(header, tx_set)

  // Phase: Build snapshot for execution
  bucket_list.resolve_all_pending_merges()
  snapshot = LedgerSnapshot(header.ledger_seq)
  snapshot.set_id_pool(prev_id_pool)
  NOTE: "id_pool from previous ledger is critical for
  correct offer ID assignment"

  lookup_fn = closure(key):
    first try live bucket_list
    then try hot_archive_bucket_list
  snapshot = SnapshotHandle.with_lookup(snapshot, lookup_fn)

  if offer_entries provided:
    snapshot.set_entries_lookup(offers)
    NOTE: "Without this, offer matching fails because
    the executor starts with an empty order book"

  // Phase: Execute transactions
  delta = LedgerDelta(header.ledger_seq)
  transactions = tx_set.transactions_with_base_fee()
  soroban_config = load_soroban_config(snapshot, header.ledger_version)
  save cpu_cost_params, mem_cost_params for later
  eviction_settings = load_state_archival_settings(snapshot)
                      or config.eviction_settings
  soroban_base_prng_seed = tx_set.hash()

  tx_set_result = execute_transaction_set(
      snapshot, transactions, ledger_context, delta,
      SorobanContext { soroban_config, base_prng_seed,
                       classic_events, module_cache,
                       hot_archive, ... })
```

**Calls:** [`execute_transaction_set`](../ledger/execution.pc.md), [`load_soroban_config`](../ledger/execution.pc.md)

```
  // Phase: Add fee events (matching online mode)
  if classic_events enabled for this protocol version:
    for each (transaction, meta) in zip(transactions, tx_set_result.metas):
      prepend_fee_event(meta, fee_source, fee_charged, ...)
```

**Calls:** [`prepend_fee_event`](../ledger/fee_event.pc.md)

```
  // Phase: Verify results (optional)
  if config.verify_results:
    result_set = build TransactionResultSet
    xdr = encode result_set
    if verify_tx_result_set(header, xdr) fails:
      if expected_tx_results available:
        log_tx_result_mismatch(...)
      → error

  // Phase: Compute fee pool delta
  NOTE: "Use historical fee_charged values when available because
  our re-execution may calculate fees differently"
  if expected_tx_results available:
    fee_pool_delta = sum of expected fee_charged values
  else:
    fee_pool_delta = delta.fee_pool_delta()
  total_coins_delta = delta.total_coins_delta()
  changes = delta.changes()

  // Phase: INIT→LIVE reclassification
  NOTE: "Entries already in live bucket list should be LIVEENTRY,
  not INITENTRY, to avoid bucket list hash divergence during merges."
  NOTE: "ONLY check ContractCode and ContractData entries."
  init_entries = []
  live_entries = delta.live_entries()
  for each entry in delta.init_entries():
    key = entry_to_key(entry)
    should_check = entry is ContractCode or ContractData
    if should_check and bucket_list.get(key) exists:
      move entry to live_entries     // INIT → LIVE
    else:
      keep entry in init_entries

  // Phase: Handle hot archive restored entries
  for each key in tx_set_result.hot_archive_restored_keys:
    if key already in init_entries: skip
    if bucket_list has entry for key:
      set entry.last_modified = header.ledger_seq
      append entry to live_entries

  // Phase: Remove restored entries from dead_entries
  if hot_archive_restored_keys not empty:
    dead_entries.remove_all(keys in restored_keys)

  // Phase: Incremental eviction scan (protocol 23+)
  evicted_keys = []
  archived_entries = []
  updated_eviction_iterator = eviction_iterator
```

```
  @version(≥23):
    if config.run_eviction:
      iter = eviction_iterator or
             EvictionIterator(eviction_settings.starting_level)
      eviction_result = bucket_list.scan_for_eviction_incremental(
          iter, header.ledger_seq, eviction_settings)

      // Resolution phase: TTL filtering + max_entries limit
      "Matches stellar-core resolveBackgroundEvictionScan"
      modified_ttl_keys = collect TTL keys from init + live entries
      resolved = eviction_result.resolve(
          max_entries_to_archive, modified_ttl_keys)
      evicted_keys = resolved.evicted_keys
      archived_entries = resolved.archived_entries
      updated_eviction_iterator = resolved.end_iterator
```

**Calls:** [`scan_for_eviction_incremental`](../bucket/eviction.pc.md)

```
  // Phase: Combine entries for bucket list update
  all_dead = dead_entries + evicted_keys
  all_live = live_entries

  // Add EvictionIterator config entry if eviction ran
  "stellar-core updates EvictionIterator EVERY ledger during scan"
  if eviction actually ran:
    all_live.append(
      ConfigSetting::EvictionIterator(updated_eviction_iterator))

  // Phase: Update LiveSorobanStateSizeWindow
  "stellar-core calls snapshotSorobanStateSizeWindow() at end of close"
  if no window entry already in all_live:
    if soroban_state_size available:
      window_entry = compute_soroban_state_size_window_entry(
          header.ledger_seq, bucket_list, soroban_state_size)
      if window_entry: all_live.append(window_entry)

  // Phase: Update hot archive FIRST
  "Must happen before live bucket list update — matches stellar-core order:
  addHotArchiveBatch before addLiveBatch"
  "Must always call add_batch for protocol 23+ even with empty entries,
  because hot archive needs spill logic at same boundaries as live"
  hot_archive_bucket_list.add_batch(
      header.ledger_seq, header.ledger_version,
      archived_entries,
      tx_set_result.hot_archive_restored_keys)

  // Phase: Update live bucket list SECOND
  bucket_list.add_batch(
      header.ledger_seq, header.ledger_version,
      BucketListType::Live,
      init_entries, all_live, all_dead)
```

**Calls:** [`BucketList::add_batch`](../bucket/bucket_list.pc.md), [`HotArchiveBucketList::add_batch`](../bucket/hot_archive.pc.md)

```
  // Phase: Verify bucket list hash (at checkpoints only)
  if config.verify_bucket_list:
    is_checkpoint = (header.ledger_seq % 64 == 63)
    eviction_running = config.run_eviction and
                       eviction_iterator was provided

    @version(≥23):
      can_verify = is_checkpoint and eviction_running
    @version(<23):
      can_verify = is_checkpoint

    if can_verify:
      expected = header.bucket_list_hash
      actual = combined_bucket_list_hash(
          bucket_list, hot_archive_bucket_list,
          header.ledger_version)
      GUARD actual != expected →
        error "bucket list hash mismatch"

  // Phase: Build result
  tx_count = count of tx_set_result.results
  op_count = sum of operation_results per result
  ledger_hash = compute_header_hash(header)
  soroban_state_size_delta =
      compute_soroban_state_size_delta(
          changes, header.ledger_version,
          (cpu_cost_params, mem_cost_params))

  → LedgerReplayResult { ... }
```

---

### replay_ledgers

```
replay_ledgers(ledgers, config, progress_callback):
  results = []
  for each (i, (header, tx_set, tx_results, tx_metas)) in ledgers:
    result = replay_ledger(header, tx_set, tx_results,
                           tx_metas, config)
    results.append(result)
    if progress_callback: callback(i + 1, total)
  → results
```

### verify_replay_consistency

```
verify_replay_consistency(final_header, computed_bucket_list_hash):
  → verify_ledger_hash(final_header, computed_bucket_list_hash)
```

### apply_replay_to_bucket_list

```
apply_replay_to_bucket_list(bucket_list, replay_result):
  bucket_list.add_batch(
      replay_result.sequence,
      replay_result.protocol_version,
      BucketListType::Live,
      replay_result.init_entries,
      replay_result.live_entries,
      replay_result.dead_entries)
```

### ReplayedLedgerState::from_header

```
from_header(header, ledger_hash):
  → ReplayedLedgerState {
      sequence = header.ledger_seq,
      ledger_hash,
      bucket_list_hash = header.bucket_list_hash,
      close_time = header.scp_value.close_time,
      protocol_version = header.ledger_version,
      base_fee = header.base_fee,
      base_reserve = header.base_reserve
    }
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1418  | ~260       |
| Functions     | 16     | 16         |
