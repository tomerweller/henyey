## Pseudocode: crates/history/src/catchup.rs

"Catchup manager for synchronizing from history archives."
"Orchestrates downloading, verifying, and replaying historical data."

STATE_MACHINE: CatchupStatus
  STATES: [Pending, DownloadingHAS, DownloadingBuckets, ApplyingBuckets,
           DownloadingLedgers, Verifying, Replaying, Completed, Failed]
  TRANSITIONS:
    Pending → DownloadingHAS: catchup starts
    DownloadingHAS → DownloadingBuckets: HAS downloaded and verified
    DownloadingBuckets → ApplyingBuckets: all buckets downloaded
    ApplyingBuckets → DownloadingLedgers: bucket list built
    DownloadingLedgers → Verifying: ledger data downloaded
    Verifying → Replaying: chain verified
    Replaying → Completed: all ledgers replayed
    (any) → Failed: error

---

### Data: CatchupProgress

```
CatchupProgress:
  status              : CatchupStatus  // default Pending
  current_step        : u32            // 1-based, 7 total
  total_steps         : u32            // 7
  buckets_downloaded  : u32
  buckets_total       : u32
  current_ledger      : u32
  target_ledger       : u32
  message             : string
```

### Data: CheckpointData

```
CheckpointData:
  has          : HistoryArchiveState
  bucket_dir   : path
  headers      : list of LedgerHeaderHistoryEntry
  transactions : list of TransactionHistoryEntry
  tx_results   : list of TransactionHistoryResultEntry
  scp_history  : list of ScpHistoryEntry
```

### Data: ExistingBucketState

```
ExistingBucketState:
  bucket_list              : BucketList
  hot_archive_bucket_list  : HotArchiveBucketList
  header                   : LedgerHeader
  network_id               : NetworkId
```

### Data: LedgerData

```
LedgerData:
  header            : LedgerHeader
  tx_set            : TransactionSetVariant
  tx_results        : list of TransactionResultPair
  tx_history_entry  : optional TransactionHistoryEntry
  tx_result_entry   : optional TransactionHistoryResultEntry
```

### Data: CatchupOptions

```
CatchupOptions:
  verify_buckets  : bool  // default true
  verify_headers  : bool  // default true
```

### Data: CatchupManager

```
CatchupManager:
  archives        : list of HistoryArchive  // tried in order
  bucket_manager  : BucketManager
  db              : Database
  progress        : CatchupProgress
  replay_config   : ReplayConfig
```

---

### CatchupManager::new

```
new(archives, bucket_manager, db):
  → CatchupManager {
      archives, bucket_manager, db,
      progress = default,
      replay_config = default
    }
```

### CatchupManager::catchup_to_ledger

"Main entry point: full catchup from scratch."

```
catchup_to_ledger(target, ledger_manager):

  // Step 1: Find checkpoint
  checkpoint_seq = latest_checkpoint_before_or_at(target)
  GUARD checkpoint_seq is null →
    error "target before first checkpoint"
```

**Calls:** [`latest_checkpoint_before_or_at`](../history/checkpoint.pc.md)

```
  // Step 2: Download HAS
  status → DownloadingHAS (step 1)
  has = download_has(checkpoint_seq)
  verify_has_structure(has)
  verify_has_checkpoint(has, checkpoint_seq)
  scp_history = download_scp_history(checkpoint_seq)
  if scp_history not empty:
    verify_scp_history_entries(scp_history)
    persist_scp_history_entries(scp_history)
```

**Calls:** [`verify_has_structure`](../history/verify.pc.md), [`verify_has_checkpoint`](../history/verify.pc.md)

```
  // Step 3: Download buckets
  status → DownloadingBuckets (step 2)
  bucket_hashes = has.unique_bucket_hashes()
  buckets = download_buckets(bucket_hashes)

  // Step 4: Apply buckets
  status → ApplyingBuckets (step 3)
  (bucket_list, hot_archive_bucket_list,
   live_next_states, hot_next_states) =
      apply_buckets(has, buckets)
  restart_merges(bucket_list, hot_archive_bucket_list,
                 checkpoint_seq, live_next_states, hot_next_states)
  persist_bucket_list_snapshot(checkpoint_seq, bucket_list)

  // Initialize LedgerManager at checkpoint state
  (checkpoint_header, checkpoint_hash) =
      download_checkpoint_header(checkpoint_seq)
  if ledger_manager.is_initialized(): reset it
  ledger_manager.initialize(
      bucket_list, hot_archive_bucket_list,
      checkpoint_header, checkpoint_hash)
```

**Calls:** [`LedgerManager::initialize`](../ledger/manager.pc.md)

```
  // Step 5: Download ledger data
  status → DownloadingLedgers (step 4)
  ledger_data = download_ledger_data(checkpoint_seq, target)

  // Step 6: Verify chain
  status → Verifying (step 5)
  verify_downloaded_data(ledger_data)
  network_id = has.network_passphrase or testnet default

  // Step 7: Replay ledgers
  status → Replaying (step 6)
  if ledger_data is empty:
    final_header = checkpoint_header
    final_hash = checkpoint_hash
    ledgers_applied = 0
  else:
    ledgers_applied = target - checkpoint_seq
    replay_via_close_ledger(ledger_manager, ledger_data)
    final_header = ledger_manager.current_header()
    final_hash = ledger_manager.current_header_hash()

  persist_ledger_history(ledger_data, network_id)
  if ledger_data empty: persist_header_only(final_header)

  status → Completed (step 7)
  → CatchupOutput { ledger_seq, ledger_hash,
                     ledgers_applied, buckets_downloaded }
```

---

### CatchupManager::catchup_to_ledger_with_mode

"Catchup with configurable mode (Minimal, Complete, Recent(N))."

```
catchup_to_ledger_with_mode(target, mode, lcl,
                            existing_state, ledger_manager):

  // Phase: Calculate catchup range
  range = CatchupRange.calculate(lcl, target, mode)
```

**Calls:** [`CatchupRange::calculate`](../history/catchup_range.pc.md)

```
  // Phase: Apply buckets (if needed)
  if range.apply_buckets():
    bucket_apply_at = range.bucket_apply_ledger()

    // Same download/verify/apply sequence as catchup_to_ledger
    has = download_has(bucket_apply_at)
    verify_has_structure(has)
    verify_has_checkpoint(has, bucket_apply_at)

    scp_history = download_scp_history(bucket_apply_at)
    if scp_history not empty:
      verify, persist

    bucket_hashes = has.unique_bucket_hashes()
    buckets = download_buckets(bucket_hashes)

    (bucket_list, hot_archive_bucket_list,
     live_next_states, hot_next_states) =
        apply_buckets(has, buckets)
    restart_merges(...)
    persist_bucket_list_snapshot(bucket_apply_at, bucket_list)

    (checkpoint_header, checkpoint_hash) =
        download_checkpoint_header(bucket_apply_at)
    if ledger_manager.is_initialized(): reset
    ledger_manager.initialize(
        bucket_list, hot_archive_bucket_list,
        checkpoint_header, checkpoint_hash)

    checkpoint_seq = bucket_apply_at

  else:
    // Case 1: replay from current state (no bucket download)
    if not ledger_manager.is_initialized():
      if existing_state provided:
        (header, hash) = download_checkpoint_header(lcl)
        ledger_manager.initialize(
            existing_state.bucket_list,
            existing_state.hot_archive_bucket_list,
            header, hash)
      else:
        GUARD → error "requires existing bucket lists
                or initialized ledger manager"
    checkpoint_seq = lcl

  // Phase: Replay
  replay_first = range.replay_first()
  replay_count = range.replay_count()

  if replay_count == 0:
    (final_header, final_hash) =
        download_checkpoint_header(checkpoint_seq)
    ledgers_applied = 0
  else:
    download_from = replay_first - 1
    ledger_data = download_ledger_data(download_from, target)
    verify_downloaded_data(ledger_data)
    replay_via_close_ledger(ledger_manager, ledger_data)
    persist_ledger_history(ledger_data, network_id)
    final_header = ledger_manager.current_header()
    final_hash = ledger_manager.current_header_hash()
    ledgers_applied = replay_count

  if replay_count == 0:
    persist_header_only(final_header)

  status → Completed
  → CatchupOutput { ... }
```

---

### CatchupManager::catchup_to_ledger_with_checkpoint_data

"Catchup using pre-downloaded checkpoint data."

```
catchup_to_ledger_with_checkpoint_data(target, data, ledger_manager):

  checkpoint_seq = latest_checkpoint_before_or_at(target)
  GUARD data.has.current_ledger != checkpoint_seq →
    error "checkpoint data ledger mismatch"

  // Verify HAS
  verify_has_structure(data.has)
  verify_has_checkpoint(data.has, checkpoint_seq)

  // Verify bucket files exist on disk
  bucket_hashes = data.has.unique_bucket_hashes()
  empty_bucket_hash = SHA256([])
  for each hash in bucket_hashes:
    if not zero and not empty_bucket_hash:
      GUARD bucket file not at data.bucket_dir →
        error BucketNotFound

  // Copy bucket files to bucket manager dir if different
  if data.bucket_dir != bucket_manager.bucket_dir():
    for each hash in bucket_hashes:
      copy src → dst if src exists and dst doesn't

  // Verify SCP history
  if data.scp_history not empty:
    verify_scp_history_entries(data.scp_history)
    persist_scp_history_entries(data.scp_history)

  // Apply buckets
  (bucket_list, hot_archive_bucket_list,
   live_next_states, hot_next_states) =
      apply_buckets(data.has, [])
  restart_merges(...)
  persist_bucket_list_snapshot(checkpoint_seq, bucket_list)

  // Initialize LedgerManager
  (checkpoint_header, checkpoint_hash) =
      checkpoint_header_from_headers(checkpoint_seq, data.headers)
  if ledger_manager.is_initialized(): reset
  ledger_manager.initialize(
      bucket_list, hot_archive_bucket_list,
      checkpoint_header, checkpoint_hash)

  // Build ledger data from checkpoint files
  // Verify tx result sets for each ledger in range
  for each result_entry in data.tx_results:
    if entry.ledger_seq in (checkpoint_seq..target]:
      xdr = encode entry.tx_result_set
      verify_tx_result_set(header, xdr)

  // Download remaining ledger data if target > checkpoint
  ledger_data = if target == checkpoint_seq:
    []
  else:
    download_ledger_data(checkpoint_seq, target)

  verify_downloaded_data(ledger_data)

  // Replay
  if ledger_data empty:
    final = (checkpoint_header, checkpoint_hash, 0)
  else:
    replay_via_close_ledger(ledger_manager, ledger_data)
    final = (ledger_manager.current_header(), ...)

  persist_ledger_history(ledger_data, network_id)
  if ledger_data empty: persist_header_only(...)

  status → Completed
  → CatchupOutput { ... }
```

---

### Helper: restart_merges

```
restart_merges(bucket_list, hot_archive_bucket_list,
               checkpoint_seq, live_next_states, hot_next_states):

  bucket_dir = bucket_manager.bucket_dir()
  load_fn = load_disk_backed_bucket_closure(bucket_dir)

  // Live merges: run in parallel (all levels concurrently)
  bucket_list.restart_merges_from_has(
      checkpoint_seq, protocol_version=25,
      live_next_states, load_fn, parallel=true)

  // Hot archive merges: run synchronously (small)
  load_hot_fn = load_disk_backed_hot_archive_bucket_closure(bucket_dir)
  hot_archive_bucket_list.restart_merges_from_has(
      checkpoint_seq, protocol_version=25,
      hot_next_states, load_hot_fn, parallel=true)
```

**Calls:** [`BucketList::restart_merges_from_has`](../bucket/bucket_list.pc.md)

### Helper: select_archive

```
select_archive(attempt):
  "Uses attempt % archives.len() for round-robin failover"
  → archives[attempt % len(archives)]
```

### Helper: download_has

```
download_has(checkpoint_seq):
  for attempt in 0..num_archives:
    archive = select_archive(attempt)
    result = archive.get_checkpoint_has(checkpoint_seq)
    if success: → result
  → error "failed from any archive"
```

### Helper: download_scp_history

```
download_scp_history(checkpoint_seq):
  for each archive:
    result = archive.get_scp_history(checkpoint_seq)
    if success: → result
    if not found: continue
  → []   // SCP history is optional
```

### Helper: download_buckets

"Pre-downloads buckets to disk in parallel (16 concurrent)."

```
download_buckets(hashes):
  empty_bucket_hash = SHA256([])
  to_download = filter hashes where:
    not zero, not empty_bucket_hash,
    not already on disk

  if to_download empty:
    → []   // all cached

  // Parallel download (buffer_unordered = 16)
  for each hash in to_download (parallel, max 16):
    for each archive:
      data = archive.get_bucket(hash)
      GUARD data.len > MAX_HISTORY_ARCHIVE_BUCKET_SIZE →
        skip to next archive
      save data to disk at bucket_dir/<hash>.bucket.xdr
      break on success
    if no archive succeeded:
      → error BucketNotFound(hash)

  → []   // buckets are on disk, not in memory
```

### Helper: apply_buckets

"Builds bucket lists from HAS using disk-backed storage."
"Memory: O(index_size) instead of O(entries)."

```
apply_buckets(has, preloaded_buckets):

  bucket_cache = {}     // avoids re-loading same bucket
  empty_bucket_hash = SHA256([])

  // Helper: load_bucket(hash)
  //   zero hash → empty bucket
  //   check cache → return if found
  //   check disk → from_xdr_file_disk_backed
  //   check preloaded → save to disk, then load
  //   else download → save to disk, drop from memory,
  //                    load as disk-backed
  //   verify hash matches
  //   cache result

  // Phase: Restore live bucket list
  live_hash_pairs = has.bucket_hash_pairs()
  live_next_states = has.live_next_states()
  bucket_list = BucketList.restore_from_has(
      live_hash_pairs, live_next_states, load_bucket)
  bucket_list.set_bucket_dir(bucket_dir)
```

**Calls:** [`BucketList::restore_from_has`](../bucket/bucket_list.pc.md)

```
  // Phase: Restore hot archive bucket list (protocol 23+)
  hot_next_states = has.hot_archive_next_states()
  if has.has_hot_archive_buckets():
    hot_hash_pairs = has.hot_archive_bucket_hash_pairs()

    // Helper: load_hot_archive_bucket(hash)
    //   similar to load_bucket but uses
    //   HotArchiveBucket.from_xdr_file_disk_backed

    hot_archive_bucket_list =
        HotArchiveBucketList.restore_from_has(
            hot_hash_pairs, hot_next_states,
            load_hot_archive_bucket)
  else:
    hot_archive_bucket_list = HotArchiveBucketList.new()

  → (bucket_list, hot_archive_bucket_list,
     live_next_states, hot_next_states)
```

**Calls:** [`HotArchiveBucketList::restore_from_has`](../bucket/hot_archive.pc.md)

### Helper: download_ledger_data

```
download_ledger_data(from_checkpoint, to_ledger):
  start = from_checkpoint + 1
  GUARD start > to_ledger → []

  checkpoint_cache = {}

  for each seq in start..=to_ledger:
    checkpoint = checkpoint_containing(seq)
    if checkpoint not in cache:
      cache[checkpoint] = download_checkpoint_ledger_data(checkpoint)

    header = find header for seq in cache
    GUARD header not found → error

    tx_set = find tx history entry for seq
    if not found:
      if protocol >= 20:
        create empty GeneralizedTransactionSet
        NOTE: "Phase 0: empty classic, Phase 1: empty soroban"
      else:
        create empty classic TransactionSet

    tx_results = find result entry for seq or []

    append LedgerData { header, tx_set, tx_results, ... }

  → data
```

**Calls:** [`checkpoint_containing`](../history/checkpoint.pc.md)

### Helper: download_checkpoint_ledger_data

```
download_checkpoint_ledger_data(checkpoint):
  for each archive:
    headers = archive.get_ledger_headers(checkpoint)
    tx_entries = archive.get_transactions(checkpoint)
    result_entries = archive.get_results(checkpoint)
    → CheckpointLedgerData { headers, tx_entries, result_entries }
  → error "failed from any archive"
```

### Helper: verify_downloaded_data

```
verify_downloaded_data(ledger_data):
  GUARD empty → ok

  headers = extract headers from ledger_data
  verify_header_chain(headers)

  for each data in ledger_data:
    if tx_history_entry present:
      verify_tx_set(data.header, tx_set)
    if tx_result_entry present:
      xdr = encode tx_result_set
      verify_tx_result_set(data.header, xdr)
```

**Calls:** [`verify_header_chain`](../history/verify.pc.md)

### Helper: replay_via_close_ledger

"Replays ledgers using LedgerManager::close_ledger for each."
"Uses same code path as live ledger close."

```
replay_via_close_ledger(ledger_manager, ledger_data):
  GUARD ledger_data empty → error "no data"

  for each (i, data) in ledger_data:
    progress.current_ledger = data.header.ledger_seq

    upgrades = decode_upgrades_from_header(data.header)
    close_data = LedgerCloseData.new(
        data.header.ledger_seq,
        data.tx_set,
        data.header.scp_value.close_time,
        ledger_manager.current_header_hash())
      .with_stellar_value_ext(...)
      .with_upgrades(upgrades)

    result = ledger_manager.close_ledger(close_data, null)
```

**Calls:** [`LedgerManager::close_ledger`](../ledger/manager.pc.md)

```
    // Verify header hash matches archive
    if replay_config.verify_bucket_list:
      expected_hash = compute_header_hash(data.header)
      GUARD result.header_hash != expected_hash →
        error "header hash mismatch"
```

### Helper: persist_ledger_history

```
persist_ledger_history(ledger_data, network_id):
  GUARD empty → ok
  in database transaction:
    for each data in ledger_data:
      store_ledger_header(data.header)
      store_tx_history_entry(...)
      store_tx_result_entry(...)
      for each transaction (up to min(tx_count, result_count)):
        compute tx_hash
        store_transaction(ledger_seq, index, tx_id,
                          tx_body, tx_result_xdr)
```

### Helper: persist_scp_history_entries

```
persist_scp_history_entries(entries):
  GUARD empty → ok
  in database transaction:
    for each entry (V0):
      store_scp_history(ledger_seq, envelopes)
      for each quorum_set:
        hash = hash_xdr(qset)
        store_scp_quorum_set(hash, ledger_seq, qset)
```

### Helper: persist_bucket_list_snapshot

```
persist_bucket_list_snapshot(ledger_seq, bucket_list):
  levels = for each level: (curr.hash(), snap.hash())
  store_bucket_list(ledger_seq, levels)
```

### Helper: download_checkpoint_header

```
download_checkpoint_header(ledger_seq):
  for each archive:
    (header, hash) = archive.get_ledger_header_with_hash(ledger_seq)
    if success: → (header, hash)
  → error "failed from any archive"
```

---

### checkpoint_header_from_headers

```
checkpoint_header_from_headers(checkpoint_seq, headers):
  for each entry in headers:
    if entry.header.ledger_seq == checkpoint_seq:
      → (entry.header, Hash256 from entry.hash)
  → error "checkpoint header not found"
```

### decode_upgrades_from_header

```
decode_upgrades_from_header(header):
  upgrades = []
  for each upgrade in header.scp_value.upgrades:
    decoded = LedgerUpgrade.from_xdr(upgrade.bytes)
    if success: append to upgrades
    else: skip with warning
  → upgrades
```

### load_disk_backed_bucket_closure

"Streaming I/O: O(index_size) memory instead of O(file_size)."
"Critical for mainnet where buckets can be tens of GB."

```
load_disk_backed_bucket_closure(bucket_dir):
  → closure(hash):
    if hash is zero: → empty bucket
    path = bucket_dir / "<hash>.bucket.xdr"
    GUARD path not found → error
    → Bucket.from_xdr_file_disk_backed(path)
```

### load_disk_backed_hot_archive_bucket_closure

```
load_disk_backed_hot_archive_bucket_closure(bucket_dir):
  → closure(hash):
    if hash is zero: → empty hot archive bucket
    path = bucket_dir / "<hash>.bucket.xdr"
    GUARD path not found → error
    → HotArchiveBucket.from_xdr_file_disk_backed(path)
```

---

### CatchupManagerBuilder

```
CatchupManagerBuilder:
  archives       : list of HistoryArchive
  bucket_manager : optional BucketManager
  db             : optional Database
  options        : CatchupOptions

  add_archive(archive)       → self
  bucket_manager(mgr)        → self
  database(db)               → self
  options(opts)               → self

  build():
    GUARD bucket_manager missing  → error
    GUARD db missing              → error
    GUARD archives empty          → error
    manager = CatchupManager.new(archives, bucket_manager, db)
    manager.replay_config = ReplayConfig from options
    → manager
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~2230  | ~330       |
| Functions     | 27     | 27         |
