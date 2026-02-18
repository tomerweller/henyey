## Pseudocode: crypto/keys.rs

"Ed25519 key types and management."
"PublicKey (G...) for verification, SecretKey (S...) for signing."
"All keys support Stellar StrKey encoding."

### PublicKey (struct)

```
STRUCT PublicKey:
  inner: Ed25519 verifying key (32 bytes)
```

### PublicKey.from_bytes

```
function PublicKey.from_bytes(bytes: byte_array[32])
    -> PublicKey or error:
  GUARD bytes not on Ed25519 curve → InvalidPublicKey
  -> PublicKey wrapping verified key
```

### PublicKey.as_bytes

```
function PublicKey.as_bytes(self) -> reference to byte_array[32]:
  -> reference to inner key bytes
```

### PublicKey.verify

```
function PublicKey.verify(self, message: bytes,
    signature: Signature) -> ok/error:
  sig = Ed25519 signature from signature.bytes
  GUARD verification fails → InvalidSignature
  -> ok
```

### PublicKey.to_strkey

```
function PublicKey.to_strkey(self) -> string:
  "Encodes as Stellar account ID (G...)."
  -> strkey_encode(ED25519_PUBLIC, self.bytes)
```

### PublicKey.from_strkey

```
function PublicKey.from_strkey(s: string) -> PublicKey or error:
  "Parses from Stellar account ID (G...)."
  GUARD invalid strkey format → InvalidStrKey(detail)
  bytes = strkey_decode(s)
  -> PublicKey.from_bytes(bytes)
```

### PublicKey.to_curve25519_bytes

```
function PublicKey.to_curve25519_bytes(self) -> byte_array[32]:
  "Converts Ed25519 point to Curve25519 (Montgomery form)."
  "Used for sealed box encryption (X25519 key exchange)."
  -> self.inner.to_montgomery().to_bytes()
```

### XDR conversions (PublicKey)

```
"xdr::PublicKey (Ed25519 variant) -> PublicKey: extract bytes, from_bytes"
"PublicKey -> xdr::PublicKey: wrap bytes in Ed25519 variant"
"PublicKey -> xdr::AccountId: wrap xdr::PublicKey in AccountId"
```

### SecretKey (struct)

```
STRUCT SecretKey:
  inner: Ed25519 signing key (32-byte seed, zeroized on drop)
```

### SecretKey.generate

```
function SecretKey.generate() -> SecretKey:
  signing_key = generate Ed25519 key from OS CSPRNG
  -> SecretKey wrapping signing_key
```

### SecretKey.from_seed

```
function SecretKey.from_seed(seed: byte_array[32]) -> SecretKey:
  "Deterministic: same seed always produces same key."
  -> SecretKey wrapping SigningKey from seed
```

### SecretKey.sign

```
function SecretKey.sign(self, message: bytes) -> Signature:
  sig = Ed25519 sign(self.inner, message)
  -> Signature from sig bytes
```

### SecretKey.public_key

```
function SecretKey.public_key(self) -> PublicKey:
  "Deterministic derivation of public key from secret."
  -> PublicKey wrapping self.inner.verifying_key()
```

### SecretKey.to_strkey

```
function SecretKey.to_strkey(self) -> string:
  "Encodes as Stellar seed (S...)."
  -> strkey_encode(ED25519_PRIVATE, self.bytes)
```

### SecretKey.from_strkey

```
function SecretKey.from_strkey(s: string) -> SecretKey or error:
  "Parses from Stellar seed (S...)."
  GUARD invalid strkey format → InvalidStrKey(detail)
  bytes = strkey_decode(s)
  -> SecretKey.from_seed(bytes)
```

### SecretKey.to_curve25519_bytes

```
function SecretKey.to_curve25519_bytes(self) -> byte_array[32]:
  "Converts Ed25519 scalar to Curve25519 for sealed box decryption."
  -> self.inner.to_scalar_bytes()
```

### SecretKey.as_bytes

```
function SecretKey.as_bytes(self) -> reference to byte_array[32]:
  -> reference to inner seed bytes
```

### account_id_to_strkey

```
function account_id_to_strkey(account_id: xdr::AccountId) -> string:
  "Convenience function: XDR AccountId -> G... strkey."
  bytes = account_id.0.ed25519_bytes
  -> strkey_encode(ED25519_PUBLIC, bytes)
```

### Signature (struct)

```
STRUCT Signature:
  bytes: byte_array[64]  "64-byte Ed25519 signature"
```

### Signature.as_bytes

```
function Signature.as_bytes(self) -> reference to byte_array[64]:
  -> reference to self.bytes
```

### Signature.from_bytes

```
function Signature.from_bytes(bytes: byte_array[64]) -> Signature:
  "No validation; use PublicKey.verify to check validity."
  -> Signature wrapping bytes
```

### XDR conversions (Signature)

```
"Signature -> xdr::Signature: wrap 64 bytes in BytesM<64>"
"xdr::Signature -> Signature:"
  GUARD length != 64 → InvalidLength(expected=64, got=actual)
  "extract bytes from BytesM<64>"
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 118    | 82         |
| Functions     | 16     | 16         |
