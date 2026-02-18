## Pseudocode: crates/henyey/src/main.rs

CLI entry point for rs-stellar-core. Parses arguments, loads configuration,
dispatches to subcommands covering node operation, history archive interaction,
offline verification, and debugging utilities.

### CLI Structure

```
CLI "rs-stellar-core":
  global flags:
    --config FILE       "Path to configuration file"
    --verbose / --trace "Logging verbosity"
    --log-format        "text (default) or json"
    --testnet / --mainnet
    --metadata-output-stream STREAM

  subcommands:
    run, catchup, new-db, upgrade-db, new-keypair,
    info, verify-history, publish-history,
    check-quorum-intersection, sample-config,
    http-command, bucket-info, verify-execution,
    debug-bucket-entry, dump-ledger, self-check,
    verify-checkpoints
```

### main

```
parse CLI arguments
init_logging(cli)
config = load_config(cli)

dispatch on subcommand:
  run        → cmd_run(config, validator, watcher, force_catchup)
  catchup    → cmd_catchup(config, target, mode, verify, parallelism)
  new-db     → cmd_new_db(config, path, force)
  upgrade-db → cmd_upgrade_db(config)
  new-keypair → cmd_new_keypair()
  info       → cmd_info(config)
  verify-history → cmd_verify_history(config, from, to)
  publish-history → cmd_publish_history(config, force)
  check-quorum-intersection → cmd_check_quorum_intersection(path)
  sample-config → cmd_sample_config()
  http-command → cmd_http_command(command, port)
  bucket-info → bucket_info(path)
  verify-execution → cmd_verify_execution(config, opts)
  debug-bucket-entry → cmd_debug_bucket_entry(config, checkpoint, account)
  dump-ledger → cmd_dump_ledger(config, output, entry_type, limit, lm_count)
  self-check → cmd_self_check(config)
  verify-checkpoints → cmd_verify_checkpoints(config, output, from, to)
```

**Calls**: [init_logging](#init_logging) | [load_config](#load_config) | [cmd_run](#cmd_run) | [cmd_catchup](#cmd_catchup) | [cmd_new_db](#cmd_new_db) | [cmd_verify_history](#cmd_verify_history) | [cmd_publish_history](#cmd_publish_history) | [cmd_verify_execution](#cmd_verify_execution) | [cmd_self_check](#cmd_self_check) | [cmd_verify_checkpoints](#cmd_verify_checkpoints)

---

### init_logging

```
if trace flag set:
  level = "trace"
else if verbose flag set:
  level = "debug"
else:
  level = "info"

config = LogConfig with level
if log_format is json:
  config.format = Json
  config.ansi_colors = false

logging.init(config)
```

**Calls**: [logging::init](henyey_app#logging_init)

---

### load_config

```
if config file provided:
  config = AppConfig.from_file_with_env(config_path)
else if --mainnet:
  config = AppConfig.mainnet()
  config.apply_env_overrides()
else:
  "Using testnet configuration (default)"
  config = AppConfig.testnet()
  config.apply_env_overrides()

if --metadata-output-stream provided:
  config.metadata.output_stream = stream value

→ config
```

---

### Helper: first_archive

```
find first archive in config where get_enabled = true
create HistoryArchive from its URL
GUARD no enabled archive found → error "No history archives available"
→ archive
```

### Helper: all_archives

```
for each archive in config where get_enabled = true:
  try create HistoryArchive from URL
  on failure: warn and skip
GUARD result is empty → error "No history archives available"
→ list of archives
```

---

### cmd_run

```
GUARD validator AND watcher both set → error "Cannot run as both"

mode = Validator if --validator
      | Watcher  if --watcher
      | Full     otherwise

options = { mode, force_catchup }
run_node(config, options)
```

**Calls**: [run_node](henyey_app#run_node)

---

### cmd_catchup

```
mode = parse mode string ("minimal", "complete", "recent:N")
options = { target, mode, verify = !no_verify, parallelism }
result = run_catchup(config, options)
print result
```

**Calls**: [run_catchup](henyey_app#run_catchup)

---

### cmd_new_db

```
if path override provided:
  config.database.path = path

if database file exists:
  if --force:
    remove existing file
  else:
    → error "Database already exists"

ensure parent directory exists
db = Database.open(db_path)
print success
```

---

### cmd_upgrade_db

```
db = Database.open(config.database.path)
"Database initialization already applies the latest schema"
print "up to date"
```

---

### cmd_new_keypair

```
keypair = SecretKey.generate()
print public key (strkey)
print secret seed (strkey)
print warning about secure storage
```

---

### cmd_info

```
try:
  app = App.new(config)
  print app.info()
on failure:
  print basic info: version, network, db path, validator flag
  if db does not exist:
    print "Run 'new-db' to create it"
```

---

### cmd_verify_history

"Verifies history archives by downloading and checking checkpoint data"

```
archives = all_archives(config)
root_has = archive[0].get_root_has()
start = from or 1
end = to or current_ledger

start_cp = checkpoint_containing(start)
end_cp = checkpoint_containing(end)
verified_count = 0
error_count = 0

for each checkpoint from start_cp to end_cp:
  --- Phase 1: HAS verification ---
  has = archive.get_checkpoint_has(checkpoint)
  verify_has_structure(has)
  verify_has_checkpoint(has, checkpoint)

  --- Phase 2: Header chain verification ---
  headers = archive.get_ledger_headers(checkpoint)
  verify_header_chain(headers)

  --- Phase 3: TX set and result verification ---
  tx_entries = archive.get_transactions(checkpoint)
  tx_results = archive.get_results(checkpoint)

  build maps: tx_map[ledger_seq], result_map[ledger_seq]

  for each header:
    GUARD missing tx entry → error, continue
    GUARD missing result entry → error, continue

    tx_set = extract from tx_entry (Generalized or Classic)
    verify_tx_set(header, tx_set)

    result_xdr = serialize result_entry.tx_result_set
    verify_tx_result_set(header, result_xdr)

  --- Phase 4: SCP history verification ---
  scp_entries = archive.get_scp_history(checkpoint)
  verify_scp_history_entries(scp_entries)

  checkpoint = next_checkpoint(checkpoint)

GUARD error_count > 0 → error with count
```

**Calls**: [all_archives](#helper-all_archives) | [verify_has_structure](henyey_history#verify_has_structure) | [verify_header_chain](henyey_history#verify_header_chain) | [verify_tx_set](henyey_history#verify_tx_set) | [verify_tx_result_set](henyey_history#verify_tx_result_set)

---

### cmd_publish_history

"Publishes checkpoint data to writable history archives (local or remote via commands)"

```
GUARD not validator → error "Only validators can publish"

writable_archives = archives where put_enabled = true
GUARD none writable → error

classify targets:
  local_targets:   archives with file:// URLs
  command_targets:  archives with put/mkdir shell commands

db = Database.open(config.database.path)
current_ledger = db.get_latest_ledger_seq()
latest_checkpoint = latest_checkpoint_before_or_at(current_ledger)

"Check what's already published across local archives"
published_ledger = min(latest_checkpoint, each archive's root HAS ledger)

if up to date AND not --force AND no queued checkpoints:
  → return "Archive is up to date"

determine checkpoints_to_publish:
  if queued AND not --force:
    use queued checkpoints
  else:
    range from (published_ledger + 1 checkpoint) to latest_checkpoint

for each checkpoint to publish:
  --- Load data from DB ---
  for seq in [start_ledger..checkpoint]:
    header = db.get_ledger_header(seq)
    tx_entry = db.get_tx_history_entry(seq)
    tx_result = db.get_tx_result_entry(seq)

  scp_entries = build_scp_history_entries(db, start_ledger, checkpoint)

  --- Verify integrity before publishing ---
  for each header/tx pair:
    verify tx_set_hash matches header
    verify tx_result_hash matches header

  --- Verify bucket list hash ---
  levels = db.load_bucket_list(checkpoint)
  restore bucket_list from levels
  ASSERT: bucket_list.hash() == header.bucket_list_hash

  --- Publish to command targets (via temp dir) ---
  if command_targets not empty:
    write checkpoint data to temp publish_dir
    write HAS to root path
    for each command_target:
      upload_publish_directory(target, publish_dir)

  --- Publish to local targets ---
  for each (url, path) in local_targets:
    if not --force AND already published: skip
    publish_checkpoint(checkpoint, headers, tx_entries, tx_results, bucket_list)
    write_scp_history_file(path, checkpoint, scp_entries)
    write HAS to root path

  remove from publish queue
```

**Calls**: [build_scp_history_entries](#helper-build_scp_history_entries) | [upload_publish_directory](#helper-upload_publish_directory) | [write_scp_history_file](#helper-write_scp_history_file) | [publish_checkpoint](henyey_history#publish_checkpoint)

---

### Helper: build_scp_history_entries

```
entries = []
for seq in [start_ledger..checkpoint]:
  envelopes = db.load_scp_history(seq)
  if empty: continue

  collect unique quorum set hashes from envelopes
  sort hashes
  load each quorum set from db

  entry = ScpHistoryEntry { quorum_sets, ledger_messages: { seq, envelopes } }
  entries.append(entry)

→ entries
```

### Helper: write_scp_history_file

```
path = base_dir / checkpoint_path("scp", checkpoint, "xdr.gz")
ensure parent dir exists
open gzip encoder
for each entry:
  write entry as XDR
finish compression
```

### Helper: scp_quorum_set_hash

"Extracts quorum set hash from SCP statement based on pledge type"

```
Nominate     → nom.quorum_set_hash
Prepare      → prep.quorum_set_hash
Confirm      → conf.quorum_set_hash
Externalize  → ext.commit_quorum_set_hash
```

### Helper: upload_publish_directory

"Uploads local publish directory to remote archive via shell commands"

```
files = collect_files(publish_dir), sorted

created_dirs = set()
for each file:
  rel = file relative to publish_dir

  if mkdir command configured AND parent not yet created:
    cmd = render_mkdir_command(template, remote_dir)
    run_shell_command(cmd)
    mark dir as created

  cmd = render_put_command(template, local_file, remote_path)
  run_shell_command(cmd)
```

### Helper: collect_files

```
files = []
stack = [root]
while stack not empty:
  dir = stack.pop()
  for each entry in dir:
    if directory: push to stack
    if file: append to files
→ files
```

### Helper: render_put_command

```
→ template with {0} = local_path, {1} = remote_path
```

### Helper: render_mkdir_command

```
→ template with {0} = remote_dir
```

### Helper: run_shell_command

```
status = sh -c cmd
GUARD not success → error with exit code
```

---

### download_buckets_parallel

"Downloads and loads bucket files concurrently from a history archive"

```
CONST MAX_CONCURRENT_DOWNLOADS = 16
CONST MAX_CONCURRENT_LOADS = 4

unique_hashes = deduplicate non-zero hashes
to_download = filter out hashes already present (bucket_exists check)
cached_count = total - to_download.count

if to_download not empty:
  for each hash (up to MAX_CONCURRENT_DOWNLOADS concurrently):
    bucket_data = archive.get_bucket(hash)
    bucket_manager.import_bucket(bucket_data)
    report progress every 5 downloads

"Parallel loading: load all unique buckets into cache"
"Builds in-memory index (SHA256 hash + offset index)"
for each unique hash (up to MAX_CONCURRENT_LOADS concurrently):
  bucket_manager.load_bucket(hash)   "via blocking thread"

→ (cached_count, download_count)
```

---

### cmd_verify_execution

"Re-executes transactions via close_ledger and compares against CDP metadata"

```
--- Initialization ---
determine network (testnet vs mainnet) from passphrase
set CDP URL and date defaults per network
set cache directory (or temp if --no-cache)

archive = first_archive(config)
root_has = archive.get_root_has()
end_ledger = to or latest checkpoint
start_ledger = from or (end checkpoint - 4 * CHECKPOINT_FREQUENCY)
init_checkpoint = latest checkpoint before start_ledger

--- CDP and bucket manager setup ---
cdp = CachedCdpDataLake.new(cdp_url, cdp_date, cache_path, network)
bucket_manager = BucketManager.with_persist_index(bucket_path, true)

--- Download and restore initial state ---
init_has = archive.get_checkpoint_has(init_checkpoint)
bucket_hashes = extract (curr, snap) per level from HAS
live_next_states = extract merge-in-progress state from HAS
hot_archive_hashes = extract hot archive bucket hashes (protocol 23+)

collect all hashes to download
download_buckets_parallel(archive, bucket_manager, all_hashes)

bucket_list = BucketList.restore_from_has(bucket_hashes, live_next_states)
hot_archive_bucket_list = HotArchiveBucketList.restore_from_has(...)

"Enable structure-based merge restarts to match stellar-core online mode"
"stellar-core online mode uses mLevels[i-1].getSnap() (old snap from HAS)"
bucket_list.restart_merges_from_has(
    init_checkpoint, protocol_version, next_states,
    restart_structure_based = true
)
hot_archive_bucket_list.restart_merges_from_has(..., true)

--- Initialize LedgerManager ---
ledger_manager = LedgerManager.new(passphrase, config)
ledger_manager.initialize(bucket_list, hot_archive_bucket_list,
                          init_header, init_header_hash)

--- Verification loop ---
prev_hash = init_header_hash
tracking: verified, matched, mismatched, perf accumulators

for each checkpoint from init to end:
  headers = archive.get_ledger_headers(current_cp)

  for each header_entry:
    seq = header.ledger_seq
    if seq <= init_checkpoint or seq > end_ledger: skip

    lcm = cdp.get_ledger_close_meta(seq)
    cdp_header = extract_ledger_header(lcm)

    GUARD close_time mismatch → "EPOCH MISMATCH", skip

    close_data = extract_ledger_close_data(lcm, prev_hash)
    result = ledger_manager.close_ledger(close_data)

    if seq in [start_ledger..end_ledger]:
      compare header_hash: result vs archive
      compare tx_result_hash: result vs CDP
      compare meta (if present)

      if all match:
        matched += 1
        print "." progress
      else:
        mismatched += 1
        print detailed field-by-field diff:
          header fields, bucket list levels,
          tx results (XDR comparison per TX),
          eviction/entry state comparison

        if --stop-on-error: abort

      collect performance metrics (timing, cache, memory)

    prev_hash = result.header_hash

--- Print summary ---
print verification counts, timing, performance stats
print top 10 slowest transactions
GUARD mismatches > 0 → error
```

**Calls**: [first_archive](#helper-first_archive) | [download_buckets_parallel](#download_buckets_parallel) | [BucketList.restore_from_has](henyey_bucket#restore_from_has) | [LedgerManager.close_ledger](henyey_ledger#close_ledger) | [extract_ledger_close_data](henyey_history#extract_ledger_close_data)

---

### cmd_debug_bucket_entry

"Inspects all occurrences of an account in the bucket list at a checkpoint"

```
account_bytes = hex_decode(account_hex)
GUARD length != 32 → error
account_key = LedgerKey.Account(account_id)

GUARD not a valid checkpoint ledger → error

archive = first_archive(config)
has = archive.get_checkpoint_has(checkpoint)
bucket_hashes = flatten (curr, snap) per level

download_buckets_parallel(archive, bucket_manager, non-zero hashes)

bucket_list = BucketList.restore_from_hashes(bucket_hashes)
bucket_list.restart_merges(checkpoint, protocol=25)

--- Normal lookup ---
entry = bucket_list.get(account_key)
if found: print balance, sequence, last_modified, thresholds, signers
else: print "NOT FOUND"

--- Full scan across all buckets ---
occurrences = bucket_list.find_all_occurrences(account_key)
for each (level, bucket_type, entry):
  if Live/Init: print balance, sequence, last_modified, signers
  if Dead: print "deleted"
```

**Calls**: [first_archive](#helper-first_archive) | [download_buckets_parallel](#download_buckets_parallel) | [BucketList.restore_from_hashes](henyey_bucket#restore_from_hashes)

---

### cmd_check_quorum_intersection

```
enjoys = check_quorum_intersection_from_json(path)
if enjoys: print "network enjoys quorum intersection"
else: → error "quorum sets do not have intersection"
```

**Calls**: [check_quorum_intersection_from_json](quorum_intersection.pc.md#check_quorum_intersection_from_json)

---

### cmd_dump_ledger

"Dumps live ledger entries from bucket list to JSON, with optional filters"

```
type_filter = parse entry_type string to LedgerEntryType
  "account, trustline, offer, data, claimable_balance,
   liquidity_pool, contract_data, contract_code, config_setting, ttl"

db = Database.open(config.database.path)
current_ledger = db.get_latest_ledger_seq()
min_last_modified = current_ledger - last_modified_ledger_count (if set)
checkpoint = latest_checkpoint_before_or_at(current_ledger)
levels = db.load_bucket_list(checkpoint)

entry_count = 0
for each level in levels:
  for hash in [curr_hash, snap_hash]:
    bucket = bucket_manager.load_bucket(hash)
    for each entry in bucket:
      skip Dead and Metadata entries
      if type_filter set AND entry type doesn't match: skip
      if min_last_modified set AND entry too old: skip

      write JSON-serialized entry to output file
      entry_count += 1
      GUARD entry_count >= limit → stop

      report progress every 10000 entries
```

---

### cmd_self_check

"Comprehensive offline diagnostic: header chain, bucket hashes, crypto benchmark"

```
--- Phase 1: Header chain verification ---
db = Database.open(config.database.path)
latest_seq = db.get_latest_ledger_seq()
GUARD no data → return

depth = min(latest_seq, 100)
for current_seq from latest down, up to depth:
  current = db.get_ledger_header(current_seq)
  prev = db.get_ledger_header(current_seq - 1)
  prev_hash = compute_header_hash(prev)

  if current.previous_ledger_hash != prev_hash:
    print "Header chain broken at ledger current_seq"
    all_ok = false
    break

--- Phase 2: Bucket hash verification ---
checkpoint = latest_checkpoint_before_or_at(latest_seq)
levels = db.load_bucket_list(checkpoint)
unique_hashes = deduplicate non-zero hashes from levels

for each hash:
  bucket = bucket_manager.load_bucket(hash)
  if bucket.hash() != expected_hash:
    print mismatch error
    all_ok = false

--- Phase 3: Crypto benchmarking ---
CONST BENCHMARK_OPS = 10000
keypair = SecretKey.generate()

benchmark signing: BENCHMARK_OPS sign operations
benchmark verification: BENCHMARK_OPS verify operations
print ops/sec for each

GUARD not all_ok → exit(1)
```

---

### cmd_verify_checkpoints

"Downloads, verifies, and writes checkpoint header hashes to JSON"

```
archives = all_archives(config)
root_has = archive[0].get_root_has()
start = from or 63   "first checkpoint"
end = to or current_ledger
start_cp = checkpoint_containing(start)
end_cp = checkpoint_containing(end)

prev_header = none
verified_checkpoints = []

for each checkpoint from start_cp to end_cp:
  headers = archive.get_ledger_headers(checkpoint)
  GUARD empty → error, continue

  verify_header_chain(headers)

  if prev_header exists:
    GUARD first header.previous_hash != hash(prev_header)
      → "cross-checkpoint link broken", continue

  checkpoint_hash = compute_header_hash(last header)
  append { ledger: checkpoint, hash } to verified_checkpoints
  prev_header = last header

  checkpoint = next_checkpoint(checkpoint)

write JSON: { network_passphrase, checkpoints: [...] } to output
GUARD errors > 0 → exit(1)
```

**Calls**: [all_archives](#helper-all_archives) | [verify_header_chain](henyey_history#verify_header_chain) | [compute_header_hash](henyey_ledger#compute_header_hash)

---

### cmd_http_command

"Sends HTTP GET to a running node's command interface"

```
build URL path from command string
  URL-encode query parameters after '?'

url = "http://127.0.0.1:{port}/{path}"
response = HTTP GET url

if success: print body
if connection refused: error "Is stellar-core running?"
if other failure: error with status code
```

---

### bucket_info

```
GUARD path does not exist → error

if path is directory:
  for each file in directory:
    print filename and size
  print total count and size
else:
  print file path and size
  "Bucket content parsing not yet implemented"
```

---

### cmd_sample_config

```
print AppConfig.sample_config()
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~3000  | ~370       |
| Functions     | 27     | 27         |
