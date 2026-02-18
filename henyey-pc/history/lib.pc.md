## Pseudocode: crates/history/src/lib.rs

"History archive access and catchup for rs-stellar-core."
"Handles archive access, catchup, replay, publishing, and verification."

### Module Structure

```
Modules:
  archive          — archive access and data retrieval
  archive_state    — HAS parsing
  download         — download configuration
  paths            — file path utilities
  catchup          — catchup orchestration
  catchup_range    — catchup mode/range types
  checkpoint       — checkpoint utilities
  replay           — ledger replay
  verify           — cryptographic verification
  cdp              — Checkpoint Data Pipeline
  checkpoint_builder — crash-safe checkpoint building
  publish          — history publishing
  publish_queue    — publish queue management
  remote_archive   — remote archive access
  error            — error types
```

### Data Structures

```
ArchiveConfig:
  url: URL
  get_enabled: bool
  put_enabled: bool

CatchupResult:
  ledger_seq: u32
  ledger_hash: Hash256
  ledgers_applied: u32
  buckets_downloaded: u32

CatchupOutput:
  result: CatchupResult

ArchiveEntry:
  name: string
  archive: HistoryArchive or null
  remote: RemoteArchive or null
```

### HistoryManager

"Manager for multiple history archives with failover support."
"If one archive fails, tries the next until success or all exhausted."

```
HistoryManager:
  archives: list of HistoryArchive
```

### HistoryManager::from_urls

```
function from_urls(urls):
  archives = for each url: HistoryArchive.new(url)
  → HistoryManager { archives }
```

### HistoryManager::get_root_has

"Tries each archive in sequence until one succeeds."

```
async function get_root_has():
  for each archive in archives:
    result = archive.get_root_has()
    if result is success:
      → result
    else:
      continue
  → NoArchiveAvailable error
```

### HistoryManager::get_checkpoint_has

```
async function get_checkpoint_has(ledger):
  for each archive in archives:
    result = archive.get_checkpoint_has(ledger)
    if result is success:
      → result
    else:
      continue
  → CheckpointNotFound error
```

### HistoryManager::get_bucket

```
async function get_bucket(hash):
  for each archive in archives:
    result = archive.get_bucket(hash)
    if result is success:
      → result
    else:
      continue
  → BucketNotFound error
```

### HistoryManager::get_ledger_headers

```
async function get_ledger_headers(checkpoint):
  for each archive in archives:
    result = archive.get_ledger_headers(checkpoint)
    if result is success:
      → result
    else:
      continue
  → CheckpointNotFound error
```

### HistoryManager::get_transactions

```
async function get_transactions(checkpoint):
  for each archive in archives:
    result = archive.get_transactions(checkpoint)
    if result is success:
      → result
    else:
      continue
  → CheckpointNotFound error
```

### HistoryManager::get_results

```
async function get_results(checkpoint):
  for each archive in archives:
    result = archive.get_results(checkpoint)
    if result is success:
      → result
    else:
      continue
  → CheckpointNotFound error
```

### ArchiveEntry constructors

```
function ArchiveEntry.read_only(name, archive):
  → { name, archive, remote: null }

function ArchiveEntry.write_only(name, remote):
  → { name, archive: null, remote }

function ArchiveEntry.can_read():
  → archive is not null
     or (remote is not null and remote.can_read())

function ArchiveEntry.can_write():
  → remote is not null and remote.can_write()

function ArchiveEntry.is_fully_configured():
  → can_read() and can_write()
```

### HistoryArchiveManager

"Rust equivalent of stellar-core HistoryArchiveManager."
"Manages multiple archives, detects writable archives, validates config."

```
HistoryArchiveManager:
  archives: list of ArchiveEntry
  network_passphrase: string
```

### HistoryArchiveManager::get_archive

```
function get_archive(name):
  → find first archive where archive.name == name
  GUARD not found → ArchiveNotFound error
```

### HistoryArchiveManager::publish_enabled

"Returns true if any archive has both read and write capabilities."

```
function publish_enabled():
  → any archive where is_fully_configured()
```

### HistoryArchiveManager::get_writable_archives

```
function get_writable_archives():
  → filter archives where is_fully_configured()
```

### HistoryArchiveManager::get_readable_archives

```
function get_readable_archives():
  → filter archives where can_read()
```

### HistoryArchiveManager::check_sensible_config

"Validates archive configuration, logs warnings for problems."

```
function check_sensible_config():
  sensible = true

  for each entry in archives:
    if not entry.can_read() and not entry.can_write():
      warn "archive is inert (neither get nor put)"
      sensible = false
    else if entry.can_write() and not entry.can_read():
      warn "archive has put but no get (cannot verify)"

  if get_readable_archives() is empty:
    error "no readable archives — catchup will fail"
    sensible = false

  if get_writable_archives() is empty:
    info "no writable archives — publishing disabled"

  → sensible
```

### HistoryArchiveManager::initialize_history_archive

"Create a new archive by writing empty HAS to"
".well-known/stellar-history.json."

```
async function initialize_history_archive(name):
  entry = get_archive(name)

  "Check if already initialized"
  if entry.archive is not null:
    if archive.get_root_has() succeeds:
      → ArchiveAlreadyInitialized error

  remote = entry.remote
  GUARD remote is null → ArchiveNotWritable error
  GUARD not remote.can_write() → ArchiveNotWritable error

  "Create empty HAS with 11 levels, all zeroed"
  has = HistoryArchiveState {
    version: 2,
    server: "rs-stellar-core",
    current_ledger: 0,
    network_passphrase: self.network_passphrase,
    current_buckets: [11 empty levels, all state 0],
    hot_archive_buckets: null
  }

  json = serialize has to pretty JSON
  write json to temp file
  remote.put_file_with_mkdir(temp_file,
    ".well-known/stellar-history.json")
```

### HistoryArchiveManager::get_root_has

"Tries each readable archive in sequence."

```
async function get_root_has():
  for each entry in archives:
    if entry.archive is not null:
      result = archive.get_root_has()
      if result is success:
        → result
      else:
        continue
  → NoArchiveAvailable error
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~730   | ~165       |
| Functions     | 22     | 22         |
