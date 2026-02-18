## Pseudocode: crypto/random.rs

"Cryptographically secure random number generation."
"Uses the OS cryptographic RNG for all operations."

### random_bytes

```
function random_bytes<N>() -> byte_array[N]:
  buffer = zero-filled array of N bytes
  fill buffer from OS CSPRNG
  -> buffer
```

### random_bytes_32

```
function random_bytes_32() -> byte_array[32]:
  -> random_bytes<32>()
```

**Calls**: [random_bytes](#random_bytes)

### random_bytes_64

```
function random_bytes_64() -> byte_array[64]:
  -> random_bytes<64>()
```

**Calls**: [random_bytes](#random_bytes)

### random_u64

```
function random_u64() -> u64:
  -> next random 64-bit integer from OS CSPRNG
```

### random_u32

```
function random_u32() -> u32:
  -> next random 32-bit integer from OS CSPRNG
```

### fill_random

```
function fill_random(dest: mutable byte_slice):
  fill dest from OS CSPRNG
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 16     | 14         |
| Functions     | 6      | 6          |
