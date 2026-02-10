# henyey-crypto

Pure Rust cryptographic primitives for henyey.

## Overview

This crate provides all cryptographic operations needed by Stellar Core, implemented entirely in Rust with no C dependencies (no libsodium). It is designed to produce deterministic, bit-compatible results with the stellar-core implementation.

## Features

- **Ed25519 Signatures**: Key generation, signing, and verification
- **SHA-256 Hashing**: Single-shot and streaming hash computation
- **BLAKE2 Hashing**: Single-shot and streaming BLAKE2b-256 hash computation
- **HMAC-SHA256**: Message authentication with constant-time verification
- **HKDF**: Key derivation (extract, expand, and combined)
- **XDR Hashing**: SHA-256 and BLAKE2 hashing of XDR-encoded values
- **StrKey Encoding**: Stellar's base32 key format (G..., S..., T..., X..., M..., P..., C...)
- **Short Hashing**: SipHash-2-4 for deterministic ordering in bucket lists
- **Sealed Boxes**: Curve25519-based anonymous encryption for survey payloads
- **Curve25519 ECDH**: Key exchange for P2P overlay authentication
- **Hex Encoding**: Hex encode/decode utilities matching stellar-core `Hex.h`
- **SignerKey Utilities**: Construction and inspection of transaction authorization signer keys
- **Secure Random**: Cryptographically secure random number generation

## Key Types

| Type | Description |
|------|-------------|
| `PublicKey` | Ed25519 public key (32 bytes), encodes to account ID (G...) |
| `SecretKey` | Ed25519 secret key (32 bytes), encodes to seed (S...), zeroized on drop |
| `Signature` | Ed25519 signature (64 bytes) |
| `Curve25519Secret` | X25519 secret scalar for ECDH key exchange, zeroized on drop |
| `Curve25519Public` | X25519 public point for ECDH key exchange |
| `Hash256` | SHA-256 hash (32 bytes), re-exported from `henyey-common` |
| `SignedMessage` | Message bundled with signature and signer hint |
| `CryptoError` | Error type for all cryptographic operations |

## Usage

### Key Generation and Signing

```rust
use henyey_crypto::{SecretKey, PublicKey};

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
use henyey_crypto::{sha256, sha256_multi, Sha256Hasher};

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
use henyey_crypto::{encode_account_id, decode_account_id};

let key = [0u8; 32];
let strkey = encode_account_id(&key);  // GAAAAAA...
let decoded = decode_account_id(&strkey).unwrap();
assert_eq!(decoded, key);
```

### Short Hashing (SipHash)

```rust
use henyey_crypto::{compute_hash, seed};

// Seed for deterministic tests (optional)
seed(12345).unwrap();

// Compute short hash
let hash = compute_hash(b"some data");
```

### Sealed Box Encryption

```rust
use henyey_crypto::{SecretKey, seal_to_public_key, open_from_secret_key};

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
├── curve25519.rs   # Curve25519 ECDH key exchange for P2P overlay
├── error.rs        # CryptoError type
├── hash.rs         # SHA-256, BLAKE2, HMAC-SHA256, HKDF, XDR hashing
├── hex.rs          # Hex encoding/decoding utilities
├── keys.rs         # PublicKey, SecretKey, Signature
├── random.rs       # Secure random generation
├── sealed_box.rs   # Curve25519 sealed box encryption
├── short_hash.rs   # SipHash-2-4 for deterministic ordering
├── signature.rs    # Signing utilities, SignedMessage
├── signer_key.rs   # SignerKey construction and inspection
└── strkey.rs       # StrKey encode/decode
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `ed25519-dalek` | Ed25519 signatures |
| `x25519-dalek` | X25519 ECDH key exchange |
| `sha2` | SHA-256 hashing |
| `blake2` | BLAKE2b hashing |
| `hmac` | HMAC-SHA256 message authentication |
| `hkdf` | HKDF key derivation |
| `siphasher` | SipHash-2-4 |
| `crypto_box` | Sealed box encryption (X25519 + XSalsa20-Poly1305) |
| `rand` | Random number generation |
| `base32` | StrKey encoding |
| `hex` | Hex encoding/decoding |
| `zeroize` | Secure memory clearing for key material |
| `thiserror` | Error type derivation |

## Security Notes

- **Key Zeroization**: `SecretKey` and `Curve25519Secret` are zeroized on drop to minimize key material exposure
- **Debug Safety**: `SecretKey` and `Curve25519Secret` show `[REDACTED]` instead of key material in debug output
- **Constant-Time HMAC Verification**: `hmac_sha256_verify` uses constant-time comparison to prevent timing attacks
- **Deterministic Ordering**: Short hashes use a process-global key that cannot be changed after first use
- **No Libsodium**: Pure Rust implementation ensures reproducible builds and auditable code

## Compatibility

This crate is designed to be bit-compatible with stellar-core. Test vectors from the stellar-core implementation should produce identical results.

## stellar-core Parity Status

See [PARITY_STATUS.md](PARITY_STATUS.md) for detailed stellar-core parity analysis.
