## Pseudocode: crates/app/src/app/ledger_close.rs

### Helper: extract_tx_metas

```
function extract_tx_metas(meta):
  if meta is V0:
    → empty list
  if meta is V1 or V2:
    → [processing.tx_apply_processing for each processing in meta.tx_processing]
```

---

### persist_ledger_close

```
function persist_ledger_close(header, tx_set_variant, tx_results, tx_metas):
  header_xdr = serialize(header)
  network_id = NetworkId.from_passphrase(config.network.passphrase)
  ordered_txs = tx_set_variant.transactions_with_base_fee()
                  → extract envelopes only
  tx_count = min(ordered_txs.length, tx_results.length)
  meta_count = tx_metas.length if present, else 0

  "Build SCP quorum sets for history"
  scp_envelopes = herder.get_scp_envelopes(header.ledger_seq)
  scp_quorum_sets = []
  for each envelope in scp_envelopes:
    hash = scp_quorum_set_hash(envelope.statement)
    if hash exists:
      qset = herder.get_quorum_set_by_hash(hash)
      if qset found:
        append (hash, qset) to scp_quorum_sets

  "Build HAS from current bucket list state for restart recovery."
  "This captures pending merge outputs so a restarted node can"
  "reconstruct the bucket list without re-downloading from archives."
  bucket_list = ledger_manager.bucket_list()
  hot_archive = ledger_manager.hot_archive_bucket_list()

  "Ensure hot archive buckets are persisted to disk for restart recovery."
  "Hot archive merges are all in-memory, so after each close the curr/snap"
  "buckets may have no backing file."
  if hot_archive exists:
    bucket_dir = config.database.path.parent / "buckets"
    for each level in hot_archive.levels():
      for each bucket in [level.curr, level.snap]:
        if bucket has no backing file AND bucket.hash is not zero:
          permanent = bucket_dir / "{hash}.bucket.xdr"
          if not permanent.exists():
            bucket.save_to_xdr_file(permanent)
```

**Calls:** [`build_history_archive_state`](../history/mod.pc.md#build_history_archive_state)

```
  has = build_history_archive_state(
    header.ledger_seq, bucket_list, hot_archive, passphrase
  )
  has_json = has.to_json()

  "Persist everything in a single DB transaction"
  DB_TRANSACTION:
    store_ledger_header(header, header_xdr)
    store_tx_history_entry(header.ledger_seq, tx_history_entry)
    store_tx_result_entry(header.ledger_seq, tx_result_entry)

    if is_checkpoint_ledger(header.ledger_seq):
      store_bucket_list(header.ledger_seq, bucket_list_levels)
      if is_validator:
        enqueue_publish(header.ledger_seq)

    for index in 0..tx_count:
      tx = ordered_txs[index]
      tx_result = tx_results[index]
      tx_meta = tx_metas[index] if present
      tx_hash = TransactionFrame.hash(tx, network_id)
      store_transaction(header.ledger_seq, index, tx_hash, tx_body_xdr,
                        tx_result_xdr, tx_meta_xdr)

    store_scp_history(header.ledger_seq, scp_envelopes)
    for each (hash, qset) in scp_quorum_sets:
      store_scp_quorum_set(hash, header.ledger_seq, qset)

    "Persist HAS and LCL for restart recovery"
    set_state(HISTORY_ARCHIVE_STATE, has_json)
    set_last_closed_ledger(header.ledger_seq)
```

---

### load_last_known_ledger

"Attempt to restore node state from persisted DB and on-disk bucket files."
"This is the Rust equivalent of stellar-core's loadLastKnownLedger."

```
async function load_last_known_ledger():
  "Step 1: Read LCL sequence from DB"
  lcl_seq = db.get_last_closed_ledger()
  GUARD lcl_seq is null       → false
  GUARD lcl_seq == 0          → false

  "Step 2: Read HAS JSON from DB"
  has_json = db.get_state(HISTORY_ARCHIVE_STATE)
  GUARD has_json is null       → false
  has = HistoryArchiveState.from_json(has_json)

  "Step 3: Verify consistency between LCL and HAS"
  GUARD has.current_ledger != lcl_seq → false

  "Step 4: Load ledger header from DB"
  header = db.get_ledger_header(lcl_seq)
  ASSERT: header exists
  header_hash = compute_header_hash(header)

  "Step 5: Verify essential bucket files exist on disk."
  "We only require curr/snap hashes — pending merge outputs (next.output)"
  "are optional; if missing we'll discard the pending merge state."
  essential_hashes = []
  for each (curr, snap) in has.bucket_hash_pairs():
    if not curr.is_zero(): append curr
    if not snap.is_zero(): append snap
  for each (curr, snap) in has.hot_archive_bucket_hash_pairs():
    if not curr.is_zero(): append curr
    if not snap.is_zero(): append snap

  missing = bucket_manager.verify_buckets_exist(essential_hashes)
  GUARD missing is not empty  → false

  "Step 5b: Check which pending merge outputs are available."
  "If a next.output hash is missing on disk, downgrade that level's"
  "merge state so restore_from_has doesn't try to load it."
  for each level in has.current_buckets:
    if level.next.state == 1:          // FB_HASH_OUTPUT
      output_hash = parse_hex(level.next.output)
      if not output_hash.is_zero() AND not bucket_manager.bucket_exists(output_hash):
        level.next.state = 0
        level.next.output = null
```

**Calls:** [`reconstruct_bucket_lists`](#reconstruct_bucket_lists)

```
  "Step 6: Reconstruct bucket lists from HAS using shared helper"
  (bucket_list, hot_archive) = reconstruct_bucket_lists(has, header, lcl_seq)

  "Step 7: Initialize LedgerManager"
  if ledger_manager.is_initialized():
    ledger_manager.reset()
  ledger_manager.initialize(bucket_list, hot_archive, header, header_hash)

  → true
```

---

### reconstruct_bucket_lists

"Reconstruct both live and hot archive bucket lists from a parsed HAS,"
"including restarting any pending merges from saved input/output hashes."
"Shared helper used by both load_last_known_ledger (startup restore)"
"and rebuild_bucket_lists_from_has (Case 1 replay)."

```
async function reconstruct_bucket_lists(has, header, lcl_seq):
  live_hash_pairs = has.bucket_hash_pairs()
  live_next_states = has.live_next_states()
```

**Calls:** [`BucketList::restore_from_has`](../../bucket/bucket_list.pc.md#restore_from_has), [`BucketList::restart_merges_from_has`](../../bucket/bucket_list.pc.md#restart_merges_from_has)

```
  bucket_list = BucketList.restore_from_has(
    live_hash_pairs, live_next_states, load_bucket_fn
  )
  bucket_list.set_bucket_dir(bucket_dir)
  bucket_list.set_ledger_seq(lcl_seq)

  "Restart pending merges from HAS state."
  "This matches stellar-core loadLastKnownLedgerInternal() which calls"
  "AssumeStateWork -> assumeState() -> restartMerges()."
  bucket_list.restart_merges_from_has(
    lcl_seq, header.ledger_version, live_next_states,
    load_bucket_for_merge_fn, true
  )

  "Reconstruct hot archive BucketList (or create empty)"
  if has has hot_archive_bucket_hash_pairs:
    hot_hash_pairs = has.hot_archive_bucket_hash_pairs()
    hot_next_states = has.hot_archive_next_states()
    hot_bl = HotArchiveBucketList.restore_from_has(
      hot_hash_pairs, hot_next_states, load_hot_fn
    )
    hot_bl.restart_merges_from_has(
      lcl_seq, header.ledger_version, hot_next_states,
      load_hot_for_merge_fn, true
    )
  else:
    hot_bl = HotArchiveBucketList.default()

  → (bucket_list, hot_bl)
```

---

### rebuild_bucket_lists_from_has

"Rebuild bucket lists from the persisted HAS in the database."
"This matches stellar-core's approach for Case 1 catchup."

```
async function rebuild_bucket_lists_from_has():
  has_json = db.get_state(HISTORY_ARCHIVE_STATE)
  ASSERT: has_json exists
  has = HistoryArchiveState.from_json(has_json)
  lcl_seq = has.current_ledger
  header = db.get_ledger_header(lcl_seq)
  ASSERT: header exists
```

**Calls:** [`reconstruct_bucket_lists`](#reconstruct_bucket_lists)

```
  (bucket_list, hot_archive) = reconstruct_bucket_lists(has, header, lcl_seq)
  network_id = NetworkId(self.network_id())

  → ExistingBucketState {
      bucket_list,
      hot_archive_bucket_list: hot_archive,
      header,
      network_id
    }
```

---

### try_close_slot_directly

"Try to close a specific slot directly when we receive its tx set."
"This feeds the buffered ledger pipeline and attempts sequential apply."

```
async function try_close_slot_directly(slot):
  close_info = herder.check_ledger_close(slot)
  GUARD close_info is null  → return
  update_buffered_tx_set(slot, close_info.tx_set)
  try_apply_buffered_ledgers()
```

---

### process_externalized_slots

"Process any externalized slots that need ledger close."

```
async function process_externalized_slots():
  latest_externalized = herder.latest_externalized_slot()
  GUARD latest_externalized is null → return

  last_processed = self.last_processed_slot
  has_new_slots = latest_externalized > last_processed

  if has_new_slots:
    prev_latest = self.last_externalized_slot.swap(latest_externalized)
    if latest_externalized != prev_latest:
      self.last_externalized_at = now()

    missing_tx_set = false
    buffered_count = 0
    advance_to = last_processed

    current_ledger = self.current_ledger

    "Only iterate slots that peers are likely to still have tx_sets for."
    "Exception: when the first replay ledger falls in an unpublished"
    "checkpoint AND we have its EXTERNALIZE, process ALL slots so the"
    "node can close ledgers from cached SCP messages."
    first_replay = current_ledger + 1
    replay_checkpoint = checkpoint_containing(first_replay)
    checkpoint_unpublished = replay_checkpoint > latest_externalized
    have_next_externalize = herder.get_externalized(first_replay) exists

    if checkpoint_unpublished AND have_next_externalize:
      iter_start = last_processed + 1
    else if (latest_externalized - last_processed) > TX_SET_REQUEST_WINDOW:
      skip_to = latest_externalized - TX_SET_REQUEST_WINDOW
      advance_to = skip_to
      iter_start = skip_to + 1
    else:
      iter_start = last_processed + 1

    for slot in iter_start..=latest_externalized:
      "Skip slots that have already been closed."
      if slot <= current_ledger:
        skipped_stale += 1
        if slot == advance_to + 1:
          advance_to = slot
        continue

      if info = herder.check_ledger_close(slot):
        has_tx_set = info.tx_set is not null
        if buffer already has entry for info.slot:
          "Update existing entry's tx_set if it was missing"
          if existing.tx_set is null AND info.tx_set is not null:
            existing.tx_set = info.tx_set
          if existing.tx_set is null:
            missing_tx_set = true
        else:
          if not has_tx_set:
            missing_tx_set = true
          insert info into buffer
        buffered_count += 1
        if slot == advance_to + 1:
          advance_to = slot

    self.last_processed_slot = advance_to

    if missing_tx_set:
      request_pending_tx_sets()

    "Trigger externalized catchup if gap is too large"
    gap = latest_externalized - current_ledger
    if buffered_count == 0 OR gap > TX_SET_REQUEST_WINDOW:
      set_phase(11)   // externalized_catchup
      maybe_start_externalized_catchup(latest_externalized)

  "Always try to apply buffered ledgers and check for catchup"
  set_phase(12)   // try_apply_buffered
  try_apply_buffered_ledgers()
  set_phase(13)   // maybe_buffered_catchup
  maybe_start_buffered_catchup()
```

---

### Helper: first_ledger_in_checkpoint

```
function first_ledger_in_checkpoint(ledger):
  → (ledger / CHECKPOINT_FREQUENCY) * CHECKPOINT_FREQUENCY
```

### Helper: is_first_ledger_in_checkpoint

```
function is_first_ledger_in_checkpoint(ledger):
  → ledger % CHECKPOINT_FREQUENCY == 0
```

---

### trim_syncing_ledgers

```
function trim_syncing_ledgers(buffer, current_ledger):
  CONST MAX_BUFFER_SIZE = 100

  "Step 1: Remove entries already closed"
  min_keep = current_ledger + 1
  buffer.retain(seq >= min_keep)
  GUARD buffer is empty → return

  "Step 2: Trim to checkpoint boundary ONLY when the buffer's first"
  "entry is far ahead of current_ledger (gap >= CHECKPOINT_FREQUENCY)."
  first_buffered = buffer.first_key()
  last_buffered = buffer.last_key()
  gap = first_buffered - current_ledger
  if gap >= CHECKPOINT_FREQUENCY:
    if is_first_ledger_in_checkpoint(last_buffered):
      GUARD last_buffered == 0 → return
      trim_before = first_ledger_in_checkpoint(last_buffered - 1)
    else:
      trim_before = first_ledger_in_checkpoint(last_buffered)
    buffer.retain(seq >= trim_before)

  "Step 3: Hard limit to prevent unbounded memory growth"
  if buffer.length > MAX_BUFFER_SIZE:
    remove oldest (buffer.length - MAX_BUFFER_SIZE) entries
```

---

### update_buffered_tx_set

```
async function update_buffered_tx_set(slot, tx_set):
  GUARD tx_set is null → return
  entry = buffer.get(slot)
  if entry exists:
    GUARD tx_set.hash != entry.tx_set_hash → return  // hash mismatch
    entry.tx_set = tx_set
  else:
    NOTE: "Received tx set for unbuffered slot — ignored"
```

---

### attach_tx_set_by_hash

```
async function attach_tx_set_by_hash(tx_set):
  for each (slot, entry) in syncing_ledgers:
    if entry.tx_set is null AND entry.tx_set_hash == tx_set.hash:
      entry.tx_set = tx_set
      → true
  → false
```

---

### buffer_externalized_tx_set

```
async function buffer_externalized_tx_set(tx_set):
  slot = herder.find_externalized_slot_by_tx_set_hash(tx_set.hash)
  GUARD slot is null → false
  info = herder.check_ledger_close(slot)
  GUARD info is null → false
  insert info into syncing_ledgers if not present
  update_buffered_tx_set(slot, tx_set)
  → true
```

---

### drain_buffered_ledgers_sync

"Drain all sequential buffered ledgers synchronously."
"Called at the end of catchup to match stellar-core's ApplyBufferedLedgersWork."

```
async function drain_buffered_ledgers_sync():
  drained = 0
  loop:
    pending = try_start_ledger_close()
    GUARD pending is null → break
    join_result = await pending.handle
    success = handle_close_complete(pending, join_result)
    if not success: break
    drained += 1
  → drained
```

---

### try_apply_buffered_ledgers

"Apply a single buffered ledger. If a background close is already"
"in progress, returns immediately."

```
async function try_apply_buffered_ledgers():
  GUARD is_applying_ledger() → return

  pending = try_start_ledger_close()
  GUARD pending is null → return
  join_result = await pending.handle
  success = handle_close_complete(pending, join_result)

  "After closing, reset stall-detection timestamps"
  if success:
    if is_validator:
      try_trigger_consensus()
    self.last_externalized_at = now()
    self.tx_set_all_peers_exhausted = false
    clear tx_set_dont_have, tx_set_last_request, tx_set_exhausted_warned
    self.consensus_stuck_state = null
```

---

### try_start_ledger_close

"Start a background ledger close if the next buffered ledger is ready."

```
async function try_start_ledger_close():
  GUARD is_applying_ledger()                → null
  GUARD catchup_in_progress                 → null

  current_ledger = get_current_ledger()
  next_seq = current_ledger + 1

  trim_syncing_ledgers(buffer, current_ledger)

  close_info = buffer.get(next_seq)
  GUARD close_info is null                  → null
  GUARD close_info.tx_set is null           → null  // waiting for tx_set

  tx_set = close_info.tx_set

  "Validate pre-close hash matches network"
  our_header_hash = ledger_manager.current_header_hash()
  if our_header_hash != tx_set.previous_ledger_hash:
    "FATAL: pre-close hash mismatch — our ledger state has diverged"
    exit(1)

  GUARD tx_set.hash != close_info.tx_set_hash → null  // buffered hash mismatch

  "Build LedgerCloseData"
  tx_set_variant = build_tx_set_variant(tx_set)
  decoded_upgrades = decode_upgrades(close_info.upgrades)
  close_data = LedgerCloseData.new(next_seq, tx_set_variant, close_time, prev_hash)
  if decoded_upgrades not empty:
    close_data.with_upgrades(decoded_upgrades)
  if scp_history_entry = build_scp_history_entry(next_seq):
    close_data.with_scp_history([scp_history_entry])

  "Remove from buffer before spawning (optimistic)"
  buffer.remove(next_seq)

  "Spawn blocking close"
  set_applying_ledger(true)
```

**Calls:** [`LedgerManager::close_ledger`](../../ledger/ledger_manager.pc.md#close_ledger)

```
  handle = spawn_blocking(|| ledger_manager.close_ledger(close_data))

  → PendingLedgerClose { handle, ledger_seq, tx_set, tx_set_variant, close_time }
```

---

### handle_close_complete

"Handle completion of a background ledger close."
"Performs all post-close work: meta emission, DB persistence,"
"herder notification, and state updates."

```
async function handle_close_complete(pending, join_result):
  set_applying_ledger(false)

  "Phase 1: Extract result"
  if join_result is task panic:
    → false
  if join_result is error:
    if error contains "hash mismatch":
      clear all syncing_ledgers
    → false
  result = join_result.value

  "Phase 2: Emit LedgerCloseMeta to stream"
  if result.meta exists:
    stream = meta_stream
    if stream exists:
      stream.maybe_rotate_debug_stream(pending.ledger_seq)
      status = stream.emit_meta(result.meta)
      if status is MainStreamWrite error:
        abort()                    // fatal
      if status is DebugStreamWrite error:
        NOTE: "non-fatal, warn only"

  "Phase 3: Persist ledger close data to DB"
  tx_metas = extract_tx_metas(result.meta) if present
  persist_ledger_close(result.header, pending.tx_set_variant,
                       result.tx_results, tx_metas)

  "Phase 4: Classify transactions as applied or failed"
  applied_hashes = []
  failed_hashes = []
  for each (tx, tx_result) in zip(pending.tx_set.transactions, result.tx_results):
    hash = tx_hash(tx)
    if tx_result is TxSuccess or TxFeeBumpInnerSuccess:
      append hash to applied_hashes
    else:
      append hash to failed_hashes

  "Phase 5: Post-close notifications"
  herder.ledger_closed(pending.ledger_seq, applied_hashes)

  "Clear per-ledger overlay state (flood gate, etc.)"
  if overlay exists:
    overlay.clear_ledgers_below(pending.ledger_seq, pending.ledger_seq)

  "Notify peers if max tx size increased due to protocol upgrade"
  new_max = compute_max_tx_size(result.header.ledger_version, soroban_tx_max)
  old_max = self.max_tx_size_bytes
  diff = new_max - old_max
  MUTATE self max_tx_size_bytes = new_max
  if diff > 0 AND overlay exists:
    overlay.handle_max_tx_size_increase(diff)

  "Clean up old survey rate limiter entries"
  survey_limiter.clear_old_ledgers(pending.ledger_seq)

  if failed_hashes not empty:
    herder.tx_queue().ban(failed_hashes)

  "Record externalized close time for drift tracking"
  drift_tracker.record_externalized_close_time(pending.ledger_seq, pending.close_time)

  "Phase 6: Update herder tx queue context"
  herder.tx_queue().update_validation_context(
    pending.ledger_seq, result.header.close_time,
    result.header.ledger_version, result.header.base_fee
  )
  herder.tx_queue().shift()

  "Phase 7: State bookkeeping"
  MUTATE self current_ledger = pending.ledger_seq
  MUTATE self last_processed_slot = pending.ledger_seq
  clear_tx_advert_history(pending.ledger_seq)
  herder.cleanup_old_pending_tx_sets(pending.ledger_seq + 1)
  sync_recovery_heartbeat()

  if pending.ledger_seq % 100 == 0:
    cleanup_stale_bucket_files_background()

  MUTATE self tx_set_all_peers_exhausted = false

  → true
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~850   | ~350       |
| Functions     | 14     | 14         |
