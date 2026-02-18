## Pseudocode: crates/history/src/publish.rs

"History archive publishing for validators."
"When a validator closes a checkpoint (every 64 ledgers), it can publish:"
"- Ledger headers, Transaction sets, Transaction results"
"- Bucket files, SCP messages, HAS file"

### Data Structures

```
PublishConfig:
  local_path: path
  network_passphrase: string or null
  publish_remote: bool
  remote_urls: list of string
  max_parallel_uploads: int

  defaults:
    local_path = "history"
    publish_remote = false
    remote_urls = []
    max_parallel_uploads = 4

PublishState:
  checkpoint_ledger: u32
  status: PublishStatus
  files_written: u32
  files_total: u32
```

```
STATE_MACHINE: PublishStatus
  STATES: [Queued, Publishing, Completed, Failed]
  TRANSITIONS:
    Queued → Publishing: publish begins
    Publishing → Completed: all files written
    Publishing → Failed: error during publish
```

### build_history_archive_state

"Build a history archive state from a bucket list snapshot."
"Captures the full bucket list state including any pending merges."
"Pending merges are recorded matching stellar-core FutureBucket serialization:"
"- state=1 (output hash known) for completed merges"
"- state=2 (input hashes known) for in-progress async merges"
"- state=0 (clear) for levels with no pending merge"

```
function build_history_archive_state(ledger_seq, bucket_list,
    hot_archive_bucket_list, network_passphrase):

  current_buckets = []
  for each level in bucket_list.levels():
    if level has pending merge with output hash:
      next = { state: 1, output: hash.to_hex() }
    else if level has pending merge with inputs (curr, snap):
      next = { state: 2, curr: curr.to_hex(),
               snap: snap.to_hex() }
    else:
      next = default (state: 0)

    append { curr: level.curr.hash.to_hex(),
             snap: level.snap.hash.to_hex(),
             next } to current_buckets

  hot_archive_buckets = null
  if hot_archive_bucket_list is not null:
    hot_archive_buckets = []
    for each level in hot_archive_bucket_list.levels():
      if level has pending merge output hash:
        next = { state: 1, output: hash.to_hex() }
      else:
        next = default (state: 0)
      append { curr: level.curr.hash.to_hex(),
               snap: level.snap.hash.to_hex(),
               next } to hot_archive_buckets

  → HistoryArchiveState {
      version: 2,
      server: "rs-stellar-core",
      current_ledger: ledger_seq,
      network_passphrase,
      current_buckets,
      hot_archive_buckets
    }
```

### PublishManager::publish_checkpoint

"Publish a checkpoint to history archives."
"Writes ledger headers, transaction sets, transaction results,"
"bucket files, and History Archive State (HAS) file."

```
async function publish_checkpoint(checkpoint_ledger,
    headers, tx_entries, tx_results, bucket_list):

  GUARD not is_checkpoint_ledger(checkpoint_ledger)
    → NotCheckpointLedger error
```

**Calls** [verify_header_chain](#verify_header_chain) — REF: verify::verify_header_chain

```
  header_chain = extract headers from entries
  verify_header_chain(header_chain)

  "Phase 1: Verify all tx sets and result sets"
  tx_entry_map = index tx_entries by ledger_seq
  tx_result_map = index tx_results by ledger_seq

  for each header in header_chain:
    entry = tx_entry_map[header.ledger_seq]
    GUARD entry missing → VerificationFailed
    tx_set = extract transaction set from entry
    verify_tx_set(header, tx_set)

    result_entry = tx_result_map[header.ledger_seq]
    GUARD result_entry missing → VerificationFailed
    xdr = serialize result_entry.tx_result_set
    verify_tx_result_set(header, xdr)
```

**Calls** [verify_tx_set](#verify_tx_set), [verify_tx_result_set](#verify_tx_result_set) — REF: verify::verify_tx_set, verify::verify_tx_result_set

```
  "Phase 2: Write files"
  state = PublishState(checkpoint_ledger, Publishing, 0, 0)

  ensure_directories(checkpoint_ledger)

  write_xdr_gz(ledger_path, headers, "ledger headers")
  state.files_written += 1

  write_xdr_gz(txset_path, tx_entries, "transaction entries")
  state.files_written += 1

  write_xdr_gz(results_path, tx_results, "result sets")
  state.files_written += 1

  for each level in bucket_list.levels():
    if level.curr is not empty:
      write_bucket_from_entries(bucket_path(level.curr.hash), level.curr)
      state.files_written += 1
    if level.snap is not empty:
      write_bucket_from_entries(bucket_path(level.snap.hash), level.snap)
      state.files_written += 1

  "Phase 3: Write HAS"
  has = create_has(checkpoint_ledger, headers, bucket_list)
  known_hashes = set of has.all_bucket_hashes()
  has.contains_valid_buckets(known_hashes)

  write_has(has_path, has)
  state.files_written += 1

  state.status = Completed
  state.files_total = state.files_written
  → state
```

### Helper: ensure_directories

```
function ensure_directories(checkpoint_ledger):
  for each category in [ledger, transactions, results,
                        history, scp]:
    path = base / checkpoint_file_path(checkpoint_ledger, category)
    create parent directory recursively

  bucket_base = base / "bucket"
  for i in 0..255:
    create bucket_base / hex(i) directory
```

### Helper: write_xdr_gz

```
function write_xdr_gz(path, items, label):
  file = create path.xdr.gz
  encoder = new GzEncoder(file)
  for each item in items:
    xdr = item.to_xdr()
    encoder.write(xdr)
  encoder.finish()
```

### Helper: write_bucket_from_entries

"Use iter() instead of entries() to support disk-backed buckets"

```
function write_bucket_from_entries(path, bucket):
  gz_path = path.xdr.gz
  GUARD gz_path already exists → return (skip)

  file = create gz_path
  encoder = new GzEncoder(file)
  for each entry in bucket.iter():
    xdr_entry = entry.to_xdr_entry()
    xdr = xdr_entry.to_xdr()
    encoder.write(xdr)
  encoder.finish()
```

### Helper: write_has

```
function write_has(path, has):
  json = serialize has to pretty JSON
  write json to path
```

### Helper: create_has

```
function create_has(checkpoint_ledger, headers, bucket_list):
  → build_history_archive_state(
      checkpoint_ledger, bucket_list,
      null, config.network_passphrase)
```

### is_published

```
function is_published(checkpoint_ledger):
  → has_path(checkpoint_ledger) exists
```

### latest_published_checkpoint

```
function latest_published_checkpoint():
  has_dir = base / "history"
  GUARD has_dir does not exist → null

  latest = null
  scan_dir(has_dir, latest)
  → latest

  function scan_dir(path, latest):
    for each entry in read_dir(path):
      if entry is directory:
        scan_dir(entry, latest)
      else if filename matches "history-{HEX}.json":
        seq = parse HEX as u32
        if is_checkpoint_ledger(seq):
          latest = max(latest, seq)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~460   | ~145       |
| Functions     | 11     | 11         |
