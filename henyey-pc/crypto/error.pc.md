## Pseudocode: crypto/error.rs

"Cryptographic error types."

### CryptoError

```
ENUM CryptoError:
  InvalidPublicKey
    "The provided bytes do not represent a valid Ed25519 public key."

  InvalidSecretKey
    "The provided bytes do not represent a valid Ed25519 secret key."

  InvalidSignature
    "Signature verification failed."

  InvalidStrKey(detail: string)
    "StrKey encoding or decoding failed."

  InvalidHex
    "Hexadecimal decoding failed."

  InvalidLength(expected: int, got: int)
    "Data length does not match the expected size."

  EncryptionFailed
    "Sealed box encryption failed."

  DecryptionFailed
    "Sealed box decryption failed."

  Xdr(inner: xdr_error)
    "XDR serialization or deserialization failed."

  ShortHashSeedConflict(existing: u32, requested: u32)
    "Short hash already seeded; cannot reseed with different value."
    "The short hash key can only be seeded once per process."
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 30     | 28         |
| Functions     | 0      | 0          |
