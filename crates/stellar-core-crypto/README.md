# stellar-core-crypto

Pure Rust cryptographic primitives for rs-stellar-core.

## Overview

This crate provides all cryptographic operations needed by Stellar Core, implemented entirely in Rust with no C/C++ dependencies (no libsodium). It is designed to produce deterministic, bit-compatible results with the C++ stellar-core implementation.

## Features

- **Ed25519 Signatures**: Key generation, signing, and verification
- **SHA-256 Hashing**: Single-shot and streaming hash computation
- **StrKey Encoding**: Stellar's base32 key format (G..., S..., T..., X..., M...)
- **Short Hashing**: SipHash-2-4 for deterministic ordering in bucket lists
- **Sealed Boxes**: Curve25519-based anonymous encryption for survey payloads
- **Secure Random**: Cryptographically secure random number generation

## Key Types

| Type | Description |
|------|-------------|
| `PublicKey` | Ed25519 public key (32 bytes), encodes to account ID (G...) |
| `SecretKey` | Ed25519 secret key (32 bytes), encodes to seed (S...), zeroized on drop |
| `Signature` | Ed25519 signature (64 bytes) |
| `Hash256` | SHA-256 hash (32 bytes), re-exported from `stellar-core-common` |
| `SignedMessage` | Message bundled with signature and signer hint |
| `CryptoError` | Error type for all cryptographic operations |

## Usage

### Key Generation and Signing

```rust
use stellar_core_crypto::{SecretKey, PublicKey};

// Generate a new keypair
let secret = SecretKey::generate();
let public = secret.public_key();

// Sign a message
let message = b"hello stellar";
let signature = secret.sign(message);

// Verify the signature
assert!(public.verify(message, &signature).is_ok());

// Convert to StrKey format
let account_id = public.to_strkey();  // G...
let seed = secret.to_strkey();         // S...
```

### Hashing

```rust
use stellar_core_crypto::{sha256, sha256_multi, Sha256Hasher};

// Single-shot hashing
let hash = sha256(b"hello world");

// Multi-chunk hashing (avoids concatenation)
let hash = sha256_multi(&[b"hello ", b"world"]);

// Streaming hashing
let mut hasher = Sha256Hasher::new();
hasher.update(b"hello ");
hasher.update(b"world");
let hash = hasher.finalize();
```

### StrKey Encoding

```rust
use stellar_core_crypto::{encode_account_id, decode_account_id};

let key = [0u8; 32];
let strkey = encode_account_id(&key);  // GAAAAAA...
let decoded = decode_account_id(&strkey).unwrap();
assert_eq!(decoded, key);
```

### Short Hashing (SipHash)

```rust
use stellar_core_crypto::{compute_hash, seed};

// Seed for deterministic tests (optional)
seed(12345).unwrap();

// Compute short hash
let hash = compute_hash(b"some data");
```

### Sealed Box Encryption

```rust
use stellar_core_crypto::{SecretKey, seal_to_public_key, open_from_secret_key};

let recipient_secret = SecretKey::generate();
let recipient_public = recipient_secret.public_key();

// Encrypt
let plaintext = b"secret message";
let ciphertext = seal_to_public_key(&recipient_public, plaintext).unwrap();

// Decrypt
let decrypted = open_from_secret_key(&recipient_secret, &ciphertext).unwrap();
assert_eq!(decrypted, plaintext);
```

## Module Structure

```
src/
├── lib.rs          # Crate root, re-exports
├── error.rs        # CryptoError type
├── hash.rs         # SHA-256 hashing
├── keys.rs         # PublicKey, SecretKey, Signature
├── random.rs       # Secure random generation
├── sealed_box.rs   # Curve25519 sealed box encryption
├── short_hash.rs   # SipHash-2-4 for deterministic ordering
├── signature.rs    # Signing utilities, SignedMessage
└── strkey.rs       # StrKey encode/decode
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `ed25519-dalek` | Ed25519 signatures |
| `sha2` | SHA-256 hashing |
| `siphasher` | SipHash-2-4 |
| `crypto_box` | Sealed box encryption (X25519 + XSalsa20-Poly1305) |
| `rand` | Random number generation |
| `base32` | StrKey encoding |

## Security Notes

- **Key Zeroization**: `SecretKey` is zeroized on drop to minimize key material exposure
- **Debug Safety**: `SecretKey::Debug` shows `[REDACTED]` instead of key material
- **Deterministic Ordering**: Short hashes use a process-global key that cannot be changed after first use
- **No Libsodium**: Pure Rust implementation ensures reproducible builds and auditable code

## Compatibility

This crate is designed to be bit-compatible with stellar-core. Test vectors from the C++ implementation should produce identical results.

## C++ Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed C++ parity analysis.
