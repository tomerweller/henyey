## Pseudocode: crates/history/src/download.rs

"Download utilities for history archive files.
 Includes retry logic, gzip decompression, and XDR stream parsing."

"History archives use a special XDR format where each record is prefixed
 with a 4-byte big-endian length. This allows streaming parsing without
 knowing the total number of records upfront."

```
CONST DEFAULT_TIMEOUT       = 60 seconds
CONST DEFAULT_RETRIES       = 3
CONST DEFAULT_RETRY_DELAY   = 1 second
```

### DownloadConfig (struct)

```
STRUCT DownloadConfig:
  timeout     : duration   // default: DEFAULT_TIMEOUT
  retries     : integer    // default: DEFAULT_RETRIES
  retry_delay : duration   // default: DEFAULT_RETRY_DELAY
```

---

### create_client

"We disable automatic gzip decompression because we handle it
 manually in decompress_gzip() for downloaded bucket files."

```
function create_client(timeout):
  → build HTTP client with:
      timeout = timeout
      gzip = false    // manual decompression for control
```

### download_with_retries

```
async function download_with_retries(client, url, config):
  last_error = nil

  for attempt in 0..=config.retries:
    if attempt > 0:
      sleep(config.retry_delay)

    result = download_once(client, url)
    if result is ok:
      → result.bytes
    else:
      last_error = result.error

  → error DownloadFailed(url)
```

### Helper: download_once

```
async function download_once(client, url):
  response = client.get(url).send()

  GUARD response.status != success:
    if status == 404:
      → error NotFound(url)
    → error HttpStatus { url, status }

  → response.bytes
```

### decompress_gzip

```
function decompress_gzip(compressed):
  decoder = new GzDecoder(compressed)
  decompressed = decoder.read_to_end()
  → decompressed
```

### parse_xdr_stream

"Parse a raw XDR stream by reading entries until EOF."

```
function parse_xdr_stream<T>(data):
  entries = []
  cursor = new Cursor(data)

  loop:
    entry = T.read_xdr(cursor)
    if entry is ok:
      entries.append(entry)
    else if error is UnexpectedEof:
      break   // "Normal end of stream"
    else:
      → error Xdr(...)

  → entries
```

### parse_length_prefixed_xdr_stream

"Each entry is preceded by a 4-byte big-endian length."

```
function parse_length_prefixed_xdr_stream<T>(data):
  entries = []
  offset = 0

  while offset + 4 <= length(data):
    len = read_u32_be(data, offset)
    offset += 4

    GUARD offset + len > length(data)
      → error XdrParsing("length exceeds remaining data")

    entry = T.from_xdr(data[offset .. offset + len])
    entries.append(entry)
    offset += len

    // "XDR padding to 4-byte boundary"
    padding = (4 - (len % 4)) % 4
    offset += padding

  → entries
```

### parse_record_marked_xdr_stream

"XDR Record Marking Standard (RFC 5531).
 4-byte record marks: high bit = last fragment flag,
 lower 31 bits = record length."

```
function parse_record_marked_xdr_stream<T>(data):
  entries = []
  offset = 0

  while offset + 4 <= length(data):
    record_mark = read_u32_be(data, offset)
    offset += 4

    last_fragment = (record_mark AND 0x80000000) != 0
    record_len    = record_mark AND 0x7FFFFFFF

    if record_len == 0:
      continue   // "Empty record, skip"

    GUARD offset + record_len > length(data)
      → error XdrParsing("record length exceeds remaining data")

    entry = T.from_xdr(data[offset .. offset + record_len])
    entries.append(entry)
    offset += record_len

  → entries
```

### parse_xdr_stream_auto

"Auto-detect format by checking if high bit is set in
 the first 4 bytes (indicates record marking)."

```
function parse_xdr_stream_auto<T>(data):
  GUARD data is empty  → []

  uses_record_marks = length(data) >= 4
                      AND (data[0] AND 0x80) != 0

  if uses_record_marks:
    → parse_record_marked_xdr_stream(data)
  else:
    → parse_xdr_stream(data)
```

### download_and_decompress

```
async function download_and_decompress(client, url, config):
  compressed = download_with_retries(client, url, config)
  → decompress_gzip(compressed)
```

### download_and_parse_xdr

```
async function download_and_parse_xdr<T>(client, url, config):
  data = download_and_decompress(client, url, config)
  → parse_xdr_stream(data)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 401    | 106        |
| Functions     | 10     | 10         |
