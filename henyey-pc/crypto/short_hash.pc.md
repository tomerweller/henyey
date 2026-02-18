## Pseudocode: crypto/short_hash.rs

"SipHash-2-4 short hashing for deterministic ordering."
"Process-global key, initialized once. Cannot be reseeded after hashing begins."

CONST KEY_BYTES = 16  // 128-bit SipHash key

### KeyState (internal)

```
STRUCT KeyState:
  key:           byte_array[KEY_BYTES]
  have_hashed:   boolean
  explicit_seed: u32

function KeyState.new() -> KeyState:
  -> KeyState {
    key = random_bytes<16>(),
    have_hashed = false,
    explicit_seed = 0
  }
```

**Calls**: [random_bytes](random.pc.md#random_bytes)

### key_state (internal)

```
function key_state() -> global mutex-protected KeyState:
  "Returns reference to the process-global key state."
  "Lazily initialized on first access."
  -> global singleton Mutex<KeyState>
```

### initialize

```
function initialize():
  lock state = key_state()
  state.key = random_bytes<16>()
```

**Calls**: [random_bytes](random.pc.md#random_bytes)

### Helper: expand_seed_to_key

```
function expand_seed_to_key(seed: u32) -> byte_array[KEY_BYTES]:
  "Expands a 32-bit seed to 128-bit key by repeating byte pattern."
  key = zero-filled array[KEY_BYTES]
  for i in 0..KEY_BYTES:
    shift = i mod 4
    key[i] = (seed >> shift) as byte
  -> key
```

### seed

```
function seed(seed: u32) -> ok/error:
  lock state = key_state()
  GUARD state.have_hashed AND state.explicit_seed != seed
      → ShortHashSeedConflict(state.explicit_seed, seed)
  state.explicit_seed = seed
  state.key = expand_seed_to_key(seed)
  -> ok
```

**Calls**: [expand_seed_to_key](#helper-expand_seed_to_key)

### compute_hash

```
function compute_hash(bytes: byte_slice) -> u64:
  lock state = key_state()
  MUTATE state have_hashed = true
  hasher = SipHasher24 with state.key
  hasher.write(bytes)
  -> hasher.finish()
```

### xdr_compute_hash

```
function xdr_compute_hash<T: XDR-writable>(value: T) -> u64:
  bytes = serialize value to XDR (no limits)
  -> compute_hash(bytes)
```

**Calls**: [compute_hash](#compute_hash)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 60     | 40         |
| Functions     | 6      | 6          |
