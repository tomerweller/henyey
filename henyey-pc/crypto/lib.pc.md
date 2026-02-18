## Pseudocode: crypto/lib.rs

"Pure Rust cryptographic primitives for rs-stellar-core."
"No C/C++ dependencies (no libsodium)."

This is the crate root module. It declares submodules and re-exports their public API.

### Module declarations

```
modules:
  curve25519    "Curve25519 ECDH key exchange"
  error         "Error types"
  hash          "SHA-256, BLAKE2, HMAC, HKDF, XDR hashing"
  hex           "Hex encoding/decoding (public module)"
  keys          "Ed25519 public/secret key types"
  random        "CSPRNG utilities"
  sealed_box    "Sealed box encryption"
  short_hash    "SipHash-2-4 for deterministic ordering"
  signature     "Ed25519 signature type"
  signer_key    "Signer key abstraction"
```

### Re-exports

```
re-export all public items from:
  curve25519, hash, keys, random,
  sealed_box, short_hash, signature, signer_key

re-export CryptoError from error
re-export hex module (as public submodule)
re-export stellar_strkey (external crate)
re-export Hash256 from henyey_common
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 14     | 12         |
| Functions     | 0      | 0          |
