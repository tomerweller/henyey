# Pseudocode: crates/common/src/xdr_stream.rs

"XDR output/input stream for size-prefixed binary frames."
"Wire format matches stellar-core's XDROutputFileStream / XDRInputFileStream."
"Each frame: [4-byte BE size with bit 31 set] [XDR payload]"
"See RFC 1832 / RFC 4506 (XDR record marking standard)."

## Data

```
STRUCT XdrOutputStream:
  writer : buffered writer

STRUCT XdrInputStream:
  reader : buffered reader
```

### XdrOutputStream.open

```
function XdrOutputStream.open(path) -> XdrOutputStream:
  file = open_file(path, write, create, truncate)
  -> XdrOutputStream { writer: buffered(file) }
```

### XdrOutputStream.from_fd (unix only)

```
function XdrOutputStream.from_fd(fd) -> XdrOutputStream:
  file = file_from_raw_fd(fd)
  -> XdrOutputStream { writer: buffered(file) }
```

### XdrOutputStream.from_writer

```
function XdrOutputStream.from_writer(writer) -> XdrOutputStream:
  -> XdrOutputStream { writer: buffered(writer) }
```

### XdrOutputStream.write_one

"Serialize value to XDR, write as size-prefixed frame."

```
function write_one(self, value) -> bytes_written:
  payload = xdr_serialize(value)
  sz = len(payload)

  ASSERT: sz < 0x80000000
    "XDR payload size exceeds maximum (2 GiB)"

  "Write 4-byte header with continuation bit (bit 31) set"
  header[0] = ((sz >> 24) & 0xFF) | 0x80
  header[1] = (sz >> 16) & 0xFF
  header[2] = (sz >> 8) & 0xFF
  header[3] = sz & 0xFF

  write_all(header)
  write_all(payload)
  flush()

  -> 4 + len(payload)
```

### XdrOutputStream.flush

```
function flush(self):
  flush underlying writer
```

### XdrInputStream.open

```
function XdrInputStream.open(path) -> XdrInputStream:
  file = open_file(path, read)
  -> XdrInputStream { reader: buffered(file) }
```

### XdrInputStream.from_reader

```
function XdrInputStream.from_reader(reader) -> XdrInputStream:
  -> XdrInputStream { reader: buffered(reader) }
```

### XdrInputStream.read_one

"Read one XDR value from stream. Returns none at EOF."

```
function read_one(self) -> optional<T>:
  "Read 4-byte size header"
  header = read_exact(4 bytes)
  if EOF during header read:
    -> none

  "Extract size (strip continuation bit from high byte)"
  sz = ((header[0] & 0x7F) << 24)
     | (header[1] << 16)
     | (header[2] << 8)
     | header[3]

  "Read payload"
  payload = read_exact(sz bytes)

  "Deserialize XDR"
  value = xdr_deserialize(payload)
  -> value
```

### XdrInputStream.read_all

```
function read_all(self) -> list<T>:
  entries = []
  while entry = read_one():
    append entry to entries
  -> entries
```

**Calls**: [read_one](#xdrinputstreamread_one)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 85     | 60         |
| Functions     | 9      | 9          |
