## Pseudocode: crates/history/src/checkpoint_builder.rs

"Crash-safe checkpoint building for history archives."
"Writes checkpoint data to .dirty temporary files first,"
"then atomically renames them to final paths on commit."

"Crash Safety:"
"1. Write to dirty files: All data is first written to .dirty files"
"2. Fsync after writes: Data is fsynced to disk before proceeding"
"3. Atomic rename on commit: Dirty files renamed to final paths"
"4. Recovery on startup: cleanup() recovers from crashes"

"Recovery Scenarios (on startup, cleanup(lcl)):"
"- Both dirty and final exist: Delete dirty (leftover)"
"- Only dirty exists: Delete it (will be rebuilt)"
"- Only final exists: Normal, nothing to do"
"- Neither exists: First run or publish was disabled"

### Constants and Data Structures

```
CONST FILE_CATEGORIES = ["ledger", "transactions", "results"]

XdrStreamWriter:
  encoder: gzip encoder (buffered)
  dirty_path: path
  final_path: path
  entry_count: u32
  last_ledger: u32

CheckpointBuilder:
  publish_dir: path
  current_checkpoint: u32 or null
  headers_writer: XdrStreamWriter or null
  transactions_writer: XdrStreamWriter or null
  results_writer: XdrStreamWriter or null
  startup_validated: bool
```

### XdrStreamWriter::new

```
function XdrStreamWriter_new(dirty_path, final_path):
  create parent directories of dirty_path if needed
  file = open dirty_path (write, create, truncate)
  encoder = new GzEncoder(buffered(file))
  → XdrStreamWriter {
      encoder, dirty_path, final_path,
      entry_count: 0, last_ledger: 0
    }
```

### XdrStreamWriter::write_xdr

"RFC 5531 record marking: 4-byte length prefix (big-endian,"
"high bit set for last fragment). Each entry is a complete record."

```
function write_xdr(entry, ledger_seq):
  xdr_bytes = entry.to_xdr()

  len = length of xdr_bytes
  marked_len = len | 0x80000000
  NOTE: high bit set = "last fragment" per RFC 5531
  encoder.write(marked_len as big-endian 4 bytes)
  encoder.write(xdr_bytes)

  "Pad to 4-byte boundary"
  padding = (4 - (len % 4)) % 4
  if padding > 0:
    encoder.write(padding zero bytes)

  entry_count += 1
  last_ledger = ledger_seq
```

### XdrStreamWriter::finish

```
function finish():
  buf_writer = encoder.finish()
  file = buf_writer.flush_inner()
  file.sync_all()
  → (dirty_path, final_path, last_ledger)
```

### CheckpointBuilder::new

```
function CheckpointBuilder_new(publish_dir):
  → CheckpointBuilder {
      publish_dir,
      current_checkpoint: null,
      headers_writer: null,
      transactions_writer: null,
      results_writer: null,
      startup_validated: false
    }
```

### CheckpointBuilder::ensure_open

```
function ensure_open(checkpoint):
  if current_checkpoint is not null:
    GUARD current_checkpoint != checkpoint
      → "checkpoint mismatch" error
    → return (already open for this checkpoint)

  "Open new writers for all three categories"
  headers_writer = XdrStreamWriter_new(
    publish_dir / checkpoint_path_dirty("ledger", checkpoint),
    publish_dir / checkpoint_path("ledger", checkpoint))

  transactions_writer = XdrStreamWriter_new(
    publish_dir / checkpoint_path_dirty("transactions", checkpoint),
    publish_dir / checkpoint_path("transactions", checkpoint))

  results_writer = XdrStreamWriter_new(
    publish_dir / checkpoint_path_dirty("results", checkpoint),
    publish_dir / checkpoint_path("results", checkpoint))

  current_checkpoint = checkpoint
```

### append_ledger_header

```
function append_ledger_header(header, checkpoint):
  ensure_open(checkpoint)
  ledger_seq = header.header.ledger_seq
  headers_writer.write_xdr(header, ledger_seq)
```

### append_transaction_set

```
function append_transaction_set(tx_entry, result_entry, checkpoint):
  ensure_open(checkpoint)
  ledger_seq = tx_entry.ledger_seq
  transactions_writer.write_xdr(tx_entry, ledger_seq)
  results_writer.write_xdr(result_entry, ledger_seq)
```

### checkpoint_complete

"Complete a checkpoint by atomically renaming dirty files to final paths."

```
function checkpoint_complete(checkpoint):
  GUARD current_checkpoint != checkpoint
    → "checkpoint mismatch" error

  "Take ownership of all writers"
  headers = take headers_writer
  transactions = take transactions_writer
  results = take results_writer

  "Finish all writers and collect (dirty, final) paths"
  files_to_rename = []
  for each writer in [headers, transactions, results]:
    if writer is not null:
      (dirty, final_path, _) = writer.finish()
      append (dirty, final_path) to files_to_rename

  "Atomically rename all dirty files to final paths"
  for each (dirty, final_path) in files_to_rename:
    create parent directories of final_path if needed
    rename(dirty → final_path)

  current_checkpoint = null
```

### cleanup

"Clean up and recover state on startup."
"Called on startup with last committed ledger (LCL)."

```
function cleanup(lcl):
  for each category in FILE_CATEGORIES:
    cleanup_category(category, lcl)
  startup_validated = true
```

### Helper: cleanup_category

```
function cleanup_category(category, lcl):
  category_dir = publish_dir / category
  GUARD category_dir does not exist → return
  scan_for_dirty_files(category_dir, lcl)
```

### Helper: scan_for_dirty_files

```
function scan_for_dirty_files(dir, lcl):
  GUARD dir is not a directory → return
  for each entry in read_dir(dir):
    if entry is directory:
      scan_for_dirty_files(entry, lcl)
    else if is_dirty_path(entry):
      handle_dirty_file(entry, lcl)
```

### Helper: handle_dirty_file

```
function handle_dirty_file(dirty_path, lcl):
  final_path = dirty_to_final_path(dirty_path)
  GUARD final_path is null → return

  dirty_exists = dirty_path exists
  final_exists = final_path exists

  if dirty_exists and final_exists:
    "Both exist — delete dirty (leftover from completed checkpoint)"
    delete dirty_path

  else if dirty_exists and not final_exists:
    "Only dirty exists — partial checkpoint, delete and rebuild"
    delete dirty_path

  else if not dirty_exists and final_exists:
    "Only final exists — normal, nothing to do"

  else:
    "Neither exists — nothing to do"
```

### is_validated

```
function is_validated():
  → startup_validated
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~440   | ~130       |
| Functions     | 14     | 14         |
