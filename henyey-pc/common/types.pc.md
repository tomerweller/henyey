# Pseudocode: crates/common/src/types.rs

"Fundamental types used throughout the codebase, particularly Hash256."

## Data

```
STRUCT Hash256:
  bytes : byte[32]

CONST ZERO = Hash256([0x00; 32])  // sentinel / placeholder value
```

### hash

```
function hash(data) -> Hash256:
  -> Hash256(SHA256(data))
```

### hash_xdr

"Serialize value to XDR, then hash the bytes."

```
function hash_xdr(value) -> Hash256:
  xdr_bytes = serialize_to_xdr(value)
  -> hash(xdr_bytes)
```

### as_bytes

```
function as_bytes(self) -> byte[32]:
  -> self.bytes
```

### from_bytes

```
function from_bytes(bytes) -> Hash256:
  -> Hash256(bytes)
```

### from_hex

```
function from_hex(hex_string) -> Hash256:
  GUARD len(hex_string) != 64   -> error(InvalidStringLength)
  decoded = hex_decode(hex_string)
  -> Hash256(decoded)
```

### to_hex

```
function to_hex(self) -> string:
  -> lowercase_hex_encode(self.bytes)
```

### is_zero

```
function is_zero(self) -> bool:
  -> self.bytes == [0x00; 32]
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 40     | 28         |
| Functions     | 7      | 7          |
