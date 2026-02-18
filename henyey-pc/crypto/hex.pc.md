## Pseudocode: crypto/hex.rs

"Hex encoding and decoding utilities."
"Compatible with stellar-core Hex.h/.cpp implementation."

### bin_to_hex

```
function bin_to_hex(data: bytes) -> string:
  "Encode bytes as lowercase hex string."
  -> hex_encode(data)
```

### hex_abbrev

```
function hex_abbrev(data: bytes) -> string:
  "Get a 6-character hex prefix (for logging)."
  prefix_len = min(data.length, 3)
  -> bin_to_hex(data[0..prefix_len])
```

**Calls**: [bin_to_hex](#bin_to_hex)

### hex_to_bin

```
function hex_to_bin(hex_str: string) -> bytes:
  "Decode hex string to bytes. Case-insensitive."
  decoded = hex_decode(hex_str)
  GUARD decode fails → InvalidHex
  -> decoded
```

### hex_to_bin_256

```
function hex_to_bin_256(hex_str: string) -> byte_array[32]:
  "Decode hex string to exactly 32 bytes."
  bytes = hex_to_bin(hex_str)
  GUARD bytes.length != 32
      → InvalidLength(expected=32, got=bytes.length)
  -> bytes as fixed array[32]
```

**Calls**: [hex_to_bin](#hex_to_bin)

### hex_to_hash256

```
function hex_to_hash256(hex_str: string) -> Hash256:
  "Decode hex string to a Hash256 type."
  bytes = hex_to_bin_256(hex_str)
  -> Hash256 from bytes
```

**Calls**: [hex_to_bin_256](#hex_to_bin_256)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 28     | 20         |
| Functions     | 5      | 5          |
