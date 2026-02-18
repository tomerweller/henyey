## Pseudocode: crates/app/src/meta_stream.rs

"Metadata stream manager for emitting LedgerCloseMeta to external consumers."

"Two independent streams are managed:"
"- Main stream: writes to configured output_stream; errors are FATAL"
"- Debug stream: writes to <bucket_dir>/meta-debug/ with gzip rotation; errors are non-fatal"

### Constants

```
CONST DEBUG_SEGMENT_SIZE = 256   // rotate debug segment every 256 ledgers
```

### new

```
constructor(config, bucket_dir):
  if config.output_stream is set:
    main_stream = open_stream(config.output_stream)
  else:
    main_stream = none

  if config.debug_ledgers > 0:
    debug_dir = bucket_dir / "meta-debug"
    create directory debug_dir
  else:
    debug_dir = none

  → MetaStreamManager {
      main_stream, debug_stream: none,
      debug_dir, debug_ledgers,
      debug_current_path: none,
      bytes_written: 0, writes_count: 0
    }
```

**Calls**: [open_stream](#helper-open_stream)

### emit_meta

"Write LedgerCloseMeta frame to main and debug streams."

```
emit_meta(meta):
  "Write to main stream (fatal on error)"
  if main_stream exists:
    n = main_stream.write_one(meta)
    GUARD write fails → FATAL MainStreamWrite error
    bytes_written += n
    writes_count += 1

  "Write to debug stream (non-fatal on error)"
  if debug_stream exists:
    debug_stream.write_one(meta)
    GUARD write fails → non-fatal DebugStreamWrite warning

  if elapsed > 100ms:
    warn "metadata stream write took >100ms"
```

### maybe_rotate_debug_stream

"At every 256-ledger boundary, close/gzip current segment, open new one."

```
maybe_rotate_debug_stream(ledger_seq):
  GUARD debug_dir is none OR debug_ledgers == 0 → return

  at_boundary = (ledger_seq % DEBUG_SEGMENT_SIZE == 0)
  need_new = debug_stream is none OR at_boundary
  GUARD not need_new → return

  "Close and compress current segment"
  if debug_stream exists:
    close debug_stream
    gzip_file(debug_current_path)

  "Open new segment"
  filename = "meta-debug-{ledger_seq:08x}-{random:08x}.xdr"
  path = debug_dir / filename
  debug_stream = XdrOutputStream.open(path)
  debug_current_path = path

  "Trim old segments"
  trim_debug_segments(debug_dir)
```

**Calls**: [gzip_file](#helper-gzip_file) | [trim_debug_segments](#helper-trim_debug_segments)

### is_streaming

```
→ main_stream is some
```

### metrics

```
→ (bytes_written, writes_count)
```

### Helper: open_stream

"Open stream from destination string: fd:N (Unix) or file path."

```
open_stream(dest):
  if dest starts with "fd:":
    parse fd number
    → XdrOutputStream.from_fd(fd)   // Unix only
  else:
    → XdrOutputStream.open(dest)
```

### Helper: gzip_file

```
gzip_file(path):
  data = read file at path
  gz_path = path with extension ".xdr.gz"
  encoder = GzEncoder(create gz_path, default compression)
  write data to encoder
  finish encoder
  delete original file at path
```

### Helper: trim_debug_segments

```
trim_debug_segments(debug_dir):
  max_segments = (debug_ledgers / DEBUG_SEGMENT_SIZE) + 2

  entries = list files in debug_dir matching "meta-debug-*"
  GUARD entries.len <= max_segments → return

  "Sort by name (embeds ledger sequence as hex)"
  sort entries by filename

  to_remove = entries.len - max_segments
  remove first to_remove entries
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 246    | 74         |
| Functions     | 7      | 7          |
