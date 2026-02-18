## Pseudocode: crates/bucket/src/bloom_filter.rs

"Binary Fuse Filter for fast negative lookups in bucket indexes."
"False positive rate: ~1/65536 (~0.0015%)"
"Space efficiency: ~18 bits per entry, O(1) lookup time"
"Keys are hashed using SipHash-2-4 for consistency with stellar-core."

### Constants

```
CONST HASH_KEY_BYTES = 16  // SipHash key size (128 bits)
```

### BucketBloomFilter (struct)

```
STRUCT BucketBloomFilter:
  filter: BinaryFuseFilter16
  seed: HashSeed  // [byte; 16]
```

### from_hashes

```
function from_hashes(key_hashes, seed):
  GUARD len(key_hashes) < 2
    → error "requires at least 2 elements"

  "Construction can fail with hash collisions."
  "Retry with modified seeds up to 10 times."
  modified_seed = copy of seed
  for attempt in 0..10:
    try:
      filter = construct BinaryFuse16 from key_hashes
      → BucketBloomFilter(filter, modified_seed)
    on failure:
      if attempt < 9:
        modified_seed[0] = modified_seed[0] + 1 (wrapping)
      else:
        → error "failed after 10 attempts"
```

### empty

```
function empty():
  "Used when bucket has too few entries for a filter."
  "Returns nothing — callers should skip bloom check."
  → nothing
```

### hash_key

"Matches stellar-core hash computation for bloom filter keys."

```
function hash_key(key, seed):
  key_bytes = serialize key to XDR
  → hash_bytes(key_bytes, seed)
```

**Calls**: [hash_bytes](#hash_bytes)

### hash_bytes

```
function hash_bytes(bytes, seed):
  hasher = new SipHash-2-4 with seed
  hasher.write(bytes)
  → hasher.finish()
```

### may_contain

```
function may_contain(key, seed):
  "Returns false if key is definitely NOT in set."
  "Returns true if key might be in set (possible false positive)."
  hash = hash_key(key, seed)
  → may_contain_hash(hash)
```

**Calls**: [hash_key](#hash_key) | [may_contain_hash](#may_contain_hash)

### may_contain_hash

```
function may_contain_hash(hash):
  → filter.contains(hash)
```

### size_bytes

```
function size_bytes():
  "BinaryFuse16 uses ~18 bits per element"
  → filter.len() * size_of(uint16)
```

### len / is_empty / seed / inner_filter / from_parts

```
function len():       → filter.len()
function is_empty():  → filter.len() == 0
function seed():      → self.seed
function inner_filter(): → self.filter
function from_parts(filter, seed):
  → BucketBloomFilter(filter, seed)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 236    | 55         |
| Functions     | 10     | 10         |
