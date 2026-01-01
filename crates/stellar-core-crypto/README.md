# stellar-core-crypto

Pure Rust cryptographic primitives for rs-stellar-core.

## Overview

This crate provides all cryptographic operations needed by Stellar Core:

- **Ed25519 signatures** - Key generation, signing, and verification
- **SHA-256 hashing** - Hash computation
- **Short hashing (SipHash-2-4)** - Deterministic short hashes for XDR data
- **Stellar key encoding** - StrKey format (G..., S..., etc.)
- **Random number generation** - Cryptographically secure RNG
- **Sealed box encryption** - Survey payload encryption/decryption (Curve25519)

All implementations are pure Rust with no C/C++ dependencies.

## Features

- Pure Rust implementation (no libsodium dependency)
- Ed25519 keys compatible with Stellar network
- StrKey encoding/decoding for human-readable keys
- Thread-safe random number generation

## Key Types

### PublicKey

Ed25519 public key for verifying signatures:

```rust
use stellar_core_crypto::PublicKey;

// Parse from StrKey format
let pk = PublicKey::from_strkey("GDKXE2OZMJIPOSLNA6N6F2BVCI3O777I2OOC4BV7VOYUEHYX7RTRYA7Y")?;

// Convert to StrKey
let strkey = pk.to_strkey();

// Get raw bytes
let bytes: &[u8; 32] = pk.as_bytes();
```

### SecretKey

Ed25519 secret key for signing:

```rust
use stellar_core_crypto::SecretKey;

// Generate a new random key
let sk = SecretKey::generate();

// Parse from StrKey format
let sk = SecretKey::from_strkey("SBKGC.....")?;

// Get the corresponding public key
let pk = sk.public_key();

// Sign data
let signature = sk.sign(b"message to sign");
```

### Signature

Ed25519 signature:

```rust
use stellar_core_crypto::{SecretKey, verify_signature};

let sk = SecretKey::generate();
let pk = sk.public_key();

// Sign
let signature = sk.sign(b"message");

// Verify
assert!(verify_signature(&pk, b"message", &signature));
```

## StrKey Encoding

Stellar uses StrKey encoding for human-readable keys:

| Prefix | Type | Example |
|--------|------|---------|
| `G` | Account ID (public key) | `GDKXE2OZM...` |
| `S` | Secret seed | `SBKGCM...` |
| `M` | Muxed account | `MDKXE2OZM...` |
| `P` | Pre-auth transaction | `PBKGCM...` |
| `X` | SHA256 hash | `XBKGCM...` |

```rust
use stellar_core_crypto::{encode_account_id, decode_account_id};

// Encode public key bytes to G... format
let strkey = encode_account_id(&public_key_bytes);

// Decode G... format to bytes
let bytes = decode_account_id("GDKXE2OZM...")?;
```

## Hashing

```rust
use stellar_core_crypto::sha256;

// Compute SHA-256 hash
let hash = sha256(b"data to hash");
```

## Short Hashing

```rust
use stellar_core_crypto::{compute_hash, initialize, xdr_compute_hash};
use stellar_xdr::curr::LedgerEntry;

initialize();
let short = compute_hash(b"payload");

let entry = LedgerEntry::default();
let short_xdr = xdr_compute_hash(&entry)?;
```

## Random Generation

```rust
use stellar_core_crypto::generate_random_bytes;

// Generate 32 random bytes
let bytes: [u8; 32] = generate_random_bytes();
```

## Dependencies

- `ed25519-dalek` - Ed25519 implementation
- `sha2` - SHA-256 implementation
- `rand` - Random number generation

## License

Apache 2.0
