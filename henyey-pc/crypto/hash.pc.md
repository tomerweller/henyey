## Pseudocode: crypto/hash.rs

"SHA-256 and BLAKE2 hashing utilities."
"Single-shot, streaming, multi-chunk, HMAC, HKDF, and XDR hashing."

### Helper: hash256_from_digest (internal)

```
function hash256_from_digest(output: byte_ref) -> Hash256:
  bytes = copy first 32 bytes from output
  -> Hash256(bytes)
```

---

## Phase 1: SHA-256

### sha256

```
function sha256(data: bytes) -> Hash256:
  -> Hash256.hash(data)
```

### sha256_multi

```
function sha256_multi(chunks: list of byte_slices) -> Hash256:
  "Equivalent to concatenating all chunks and hashing."
  hasher = new SHA-256
  for each chunk in chunks:
    hasher.update(chunk)
  -> hash256_from_digest(hasher.finalize())
```

### sub_sha256

```
function sub_sha256(seed: bytes, counter: u64) -> Hash256:
  "Per-transaction PRNG sub-seeding for Soroban."
  "Formula: SHA256(seed || counter_be)"
  hasher = new SHA-256
  hasher.update(seed)
  hasher.update(counter as 8-byte big-endian)
  -> hash256_from_digest(hasher.finalize())
```

### Sha256Hasher (streaming)

```
STRUCT Sha256Hasher:
  inner: SHA-256 state

function Sha256Hasher.new() -> Sha256Hasher:
  -> Sha256Hasher with fresh SHA-256 state

function Sha256Hasher.reset(self):
  self.inner = fresh SHA-256 state

function Sha256Hasher.update(self, data: bytes):
  feed data into self.inner

function Sha256Hasher.finalize(self) -> Hash256:
  -> hash256_from_digest(self.inner.finalize())
```

---

## Phase 2: BLAKE2

### blake2

```
function blake2(data: bytes) -> Hash256:
  hasher = new BLAKE2b-256
  hasher.update(data)
  -> hash256_from_digest(hasher.finalize())
```

### blake2_multi

```
function blake2_multi(chunks: list of byte_slices) -> Hash256:
  "Equivalent to concatenating all chunks and hashing."
  hasher = new BLAKE2b-256
  for each chunk in chunks:
    hasher.update(chunk)
  -> hash256_from_digest(hasher.finalize())
```

### Blake2Hasher (streaming)

```
STRUCT Blake2Hasher:
  inner: BLAKE2b-256 state

function Blake2Hasher.new() -> Blake2Hasher:
  -> Blake2Hasher with fresh BLAKE2b-256 state

function Blake2Hasher.reset(self):
  self.inner = fresh BLAKE2b-256 state

function Blake2Hasher.update(self, data: bytes):
  feed data into self.inner

function Blake2Hasher.finalize(self) -> Hash256:
  -> hash256_from_digest(self.inner.finalize())
```

---

## Phase 3: HMAC-SHA256

### hmac_sha256

```
function hmac_sha256(key: byte_array[32], data: bytes)
    -> byte_array[32]:
  mac = HMAC-SHA256 initialized with key
  mac.update(data)
  -> mac.finalize()
```

### hmac_sha256_multi

```
function hmac_sha256_multi(key: byte_array[32],
    chunks: list of byte_slices) -> byte_array[32]:
  mac = HMAC-SHA256 initialized with key
  for each chunk in chunks:
    mac.update(chunk)
  -> mac.finalize()
```

### hmac_sha256_verify

```
function hmac_sha256_verify(mac: byte_array[32],
    key: byte_array[32], data: bytes) -> boolean:
  "Performs timing-safe comparison to prevent timing attacks."
  verifier = HMAC-SHA256 initialized with key
  verifier.update(data)
  -> verifier.verify_constant_time(mac)
```

---

## Phase 4: HKDF Key Derivation (RFC 5869)

### hkdf_extract

```
function hkdf_extract(ikm: bytes) -> byte_array[32]:
  "HKDF-Extract with all-zero salt."
  "PRK = HMAC-SHA256(salt=all_zeros, IKM=input)"
  zero_salt = [0; 32]
  -> hmac_sha256(zero_salt, ikm)
```

**Calls**: [hmac_sha256](#hmac_sha256)

### hkdf_extract_with_salt

```
function hkdf_extract_with_salt(salt: byte_array[32],
    ikm: bytes) -> byte_array[32]:
  -> hmac_sha256(salt, ikm)
```

**Calls**: [hmac_sha256](#hmac_sha256)

### hkdf_expand

```
function hkdf_expand(prk: byte_array[32], info: bytes)
    -> byte_array[32]:
  "Single-step HKDF-Expand (RFC 5869)."
  "OKM = HMAC-SHA256(PRK, info || 0x01)"
  mac = HMAC-SHA256 initialized with prk
  mac.update(info)
  mac.update([0x01])  "Counter byte for first block"
  -> mac.finalize()
```

### hkdf

```
function hkdf(ikm: bytes, info: bytes) -> byte_array[32]:
  "Full HKDF: extract + expand."
  prk = hkdf_extract(ikm)
  -> hkdf_expand(prk, info)
```

**Calls**: [hkdf_extract](#hkdf_extract) | [hkdf_expand](#hkdf_expand)

---

## Phase 5: XDR Hashing

### xdr_sha256

```
function xdr_sha256<T: XDR-writable>(value: T) -> Hash256:
  bytes = serialize value to XDR (no limits)
  -> sha256(bytes)
```

**Calls**: [sha256](#sha256)

### xdr_blake2

```
function xdr_blake2<T: XDR-writable>(value: T) -> Hash256:
  bytes = serialize value to XDR (no limits)
  -> blake2(bytes)
```

**Calls**: [blake2](#blake2)

### XdrSha256Hasher (streaming XDR)

```
STRUCT XdrSha256Hasher:
  hasher: Sha256Hasher

function XdrSha256Hasher.new() -> XdrSha256Hasher:
  -> XdrSha256Hasher with new Sha256Hasher

function XdrSha256Hasher.hash_bytes(self, bytes):
  self.hasher.update(bytes)

function XdrSha256Hasher.finalize(self) -> Hash256:
  -> self.hasher.finalize()
```

### XdrBlake2Hasher (streaming XDR)

```
STRUCT XdrBlake2Hasher:
  hasher: Blake2Hasher

function XdrBlake2Hasher.new() -> XdrBlake2Hasher:
  -> XdrBlake2Hasher with new Blake2Hasher

function XdrBlake2Hasher.hash_bytes(self, bytes):
  self.hasher.update(bytes)

function XdrBlake2Hasher.finalize(self) -> Hash256:
  -> self.hasher.finalize()
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 180    | 120        |
| Functions     | 22     | 22         |
