# C++ Parity Status

This document tracks the parity between the Rust `stellar-core-crypto` crate and the upstream C++ `stellar-core/src/crypto/` implementation (v25.x / p25).

## Summary

| Category | Parity Status |
|----------|---------------|
| Ed25519 Keys & Signatures | High |
| SHA-256 Hashing | High |
| BLAKE2 Hashing | High |
| HMAC-SHA256 / HKDF | High |
| StrKey Encoding | High |
| Short Hash (SipHash) | High |
| Sealed Box Encryption | High |
| Random Generation | High |
| Curve25519 (P2P ECDH) | Low |
| Signature Cache | Not Implemented |
| Key Utilities | Partial |
| Hex Encoding | Partial |

## Implemented Features

### Ed25519 Keys and Signatures (SecretKey.h/cpp)

| C++ Function | Rust Equivalent | Status |
|--------------|-----------------|--------|
| `SecretKey::SecretKey()` | `SecretKey::from_seed()` | Implemented |
| `SecretKey::~SecretKey()` | `Drop for SecretKey` | Implemented (zeroization via ed25519-dalek) |
| `SecretKey::random()` | `SecretKey::generate()` | Implemented |
| `SecretKey::fromSeed()` | `SecretKey::from_seed()` | Implemented |
| `SecretKey::fromStrKeySeed()` | `SecretKey::from_strkey()` | Implemented |
| `SecretKey::getStrKeySeed()` | `SecretKey::to_strkey()` | Implemented |
| `SecretKey::getStrKeyPublic()` | `PublicKey::to_strkey()` | Implemented |
| `SecretKey::getPublicKey()` | `SecretKey::public_key()` | Implemented |
| `SecretKey::sign()` | `SecretKey::sign()` | Implemented |
| `SecretKey::isZero()` | Manual comparison | Partially (no dedicated method) |
| `PubKeyUtils::verifySig()` | `PublicKey::verify()` | Implemented (without cache) |
| `PublicKey` XDR conversions | `TryFrom`/`From` impls | Implemented |

### SHA-256 Hashing (SHA.h/cpp)

| C++ Function | Rust Equivalent | Status |
|--------------|-----------------|--------|
| `sha256()` | `sha256()` | Implemented |
| `subSha256()` | `sub_sha256()` | Implemented |
| `SHA256` class | `Sha256Hasher` | Implemented |
| `SHA256::reset()` | `Sha256Hasher::reset()` | Implemented |
| `SHA256::add()` | `Sha256Hasher::update()` | Implemented |
| `SHA256::finish()` | `Sha256Hasher::finalize()` | Implemented |
| `xdrSha256()` | `xdr_sha256()` | Implemented |
| `XDRSHA256` (zero-alloc) | `XdrSha256Hasher` | Partial (allocates XDR bytes) |
| `hmacSha256()` | `hmac_sha256()` | Implemented |
| `hmacSha256Verify()` | `hmac_sha256_verify()` | Implemented (constant-time) |
| `hkdfExtract()` | `hkdf_extract()` | Implemented |
| `hkdfExpand()` | `hkdf_expand()` | Implemented |

### BLAKE2 Hashing (BLAKE2.h/cpp)

| C++ Function | Rust Equivalent | Status |
|--------------|-----------------|--------|
| `blake2()` | `blake2()` | Implemented |
| `BLAKE2` class | `Blake2Hasher` | Implemented |
| `BLAKE2::reset()` | `Blake2Hasher::reset()` | Implemented |
| `BLAKE2::add()` | `Blake2Hasher::update()` | Implemented |
| `BLAKE2::finish()` | `Blake2Hasher::finalize()` | Implemented |
| `xdrBlake2()` | `xdr_blake2()` | Implemented |
| `XDRBLAKE2` (zero-alloc) | `XdrBlake2Hasher` | Partial (allocates XDR bytes) |

### StrKey Encoding (StrKey.h/cpp)

| C++ Feature | Rust Equivalent | Status |
|-------------|-----------------|--------|
| `toStrKey()` | `encode_*` functions | Implemented |
| `fromStrKey()` | `decode_*` functions | Implemented |
| Account ID (G...) | `encode/decode_account_id()` | Implemented |
| Secret Seed (S...) | `encode/decode_secret_seed()` | Implemented |
| Pre-Auth TX (T...) | `encode/decode_pre_auth_tx()` | Implemented |
| SHA256 Hash (X...) | `encode/decode_sha256_hash()` | Implemented |
| Muxed Account (M...) | `encode/decode_muxed_account()` | Implemented |
| CRC16-XModem | `crc16_xmodem()` (internal) | Implemented |
| `getStrKeySize()` | Not exposed | Not Implemented |

### Short Hash (ShortHash.h/cpp)

| C++ Function | Rust Equivalent | Status |
|--------------|-----------------|--------|
| `shortHash::initialize()` | `initialize()` | Implemented |
| `shortHash::seed()` | `seed()` | Implemented |
| `shortHash::computeHash()` | `compute_hash()` | Implemented |
| `shortHash::xdrComputeHash()` | `xdr_compute_hash()` | Implemented |
| `getShortHashInitKey()` | Not exposed | Not Implemented |
| `XDRShortHasher` (zero-alloc) | N/A | Not Implemented (uses allocation) |
| Thread-safe global key | `OnceLock<Mutex<KeyState>>` | Implemented |
| Seed conflict detection | `ShortHashSeedConflict` error | Implemented |

### Random (Random.h/cpp)

| C++ Function | Rust Equivalent | Status |
|--------------|-----------------|--------|
| `randomBytes(size_t)` | `random_bytes::<N>()` | Implemented (compile-time size) |
| N/A | `random_bytes_32()` | Implemented |
| N/A | `random_bytes_64()` | Implemented |
| N/A | `random_u32()` | Implemented |
| N/A | `random_u64()` | Implemented |
| N/A | `fill_random()` | Implemented |

### Curve25519 / Sealed Box (Curve25519.h/cpp)

| C++ Function | Rust Equivalent | Status |
|--------------|-----------------|--------|
| `curve25519Encrypt<N>()` | `seal_to_public_key()` | Implemented |
| `curve25519Decrypt()` | `open_from_secret_key()` | Implemented |
| Ed25519 to Curve25519 | `PublicKey::to_curve25519_bytes()` | Implemented |
| Ed25519 to Curve25519 | `SecretKey::to_curve25519_bytes()` | Implemented |
| N/A | `seal_to_curve25519_public_key()` | Implemented |
| N/A | `open_from_curve25519_secret_key()` | Implemented |

### Signature Utilities (signature.rs)

| Feature | Rust Implementation | Status |
|---------|---------------------|--------|
| Signature hints | `signature_hint()` | Implemented |
| Sign hash | `sign_hash()` | Implemented |
| Verify hash | `verify_hash()` | Implemented |
| Signed message bundle | `SignedMessage` | Implemented |

## Not Yet Implemented (Gaps)

### Signature Verification Cache (SecretKey.h/cpp)

The C++ implementation includes a process-wide signature verification cache (`RandomEvictionCache<Hash, bool>`) that caches verification results keyed by BLAKE2 hash.

| C++ Feature | Status | Priority |
|-------------|--------|----------|
| `PubKeyUtils::clearVerifySigCache()` | Not Implemented | Low |
| `PubKeyUtils::seedVerifySigCache()` | Not Implemented | Low |
| `PubKeyUtils::flushVerifySigCacheCounts()` | Not Implemented | Low |
| `VerifySigCacheLookupResult` enum | Not Implemented | Low |
| `VerifySigResult` struct | Not Implemented | Low |
| BLAKE2-based cache key computation | Not Implemented | Low |

**Note**: This is a performance optimization, not a correctness issue. The Rust implementation performs signature verification on every call.

### Curve25519 P2P Key Exchange (Curve25519.h/cpp)

| C++ Function | Status | Priority |
|--------------|--------|----------|
| `curve25519RandomSecret()` | Not Implemented | Medium |
| `curve25519DerivePublic()` | Not Implemented | Medium |
| `clearCurve25519Keys()` | Not Implemented | Medium |
| `curve25519DeriveSharedKey()` | Not Implemented | Medium |
| `Curve25519Public` / `Curve25519Secret` XDR types | Not Implemented | Medium |

**Note**: These functions are used for P2P overlay authentication (ephemeral ECDH handshake). The sealed box implementation covers survey encryption but not P2P handshake.

### SignerKey Utilities (SignerKey.h/cpp, SignerKeyUtils.h/cpp)

| C++ Feature | Status | Priority |
|-------------|--------|----------|
| `KeyFunctions<SignerKey>` template | Not Implemented | Medium |
| `SignerKeyUtils::preAuthTxKey()` | Not Implemented | Medium |
| `SignerKeyUtils::hashXKey()` | Not Implemented | Medium |
| `SignerKeyUtils::ed25519PayloadKey()` | Not Implemented | Medium |
| Signed Payload StrKey (P...) | Not Implemented | Medium |
| Contract StrKey (C...) | Not Implemented | Medium |

### Key Utilities (KeyUtils.h/cpp)

| C++ Feature | Status | Priority |
|-------------|--------|----------|
| `KeyUtils::toStrKey<T>()` template | Not Implemented | Low |
| `KeyUtils::fromStrKey<T>()` template | Not Implemented | Low |
| `KeyUtils::toShortString()` | Not Implemented | Low |
| `KeyUtils::getKeyVersionSize()` | Not Implemented | Low |
| `KeyUtils::canConvert()` | Not Implemented | Low |
| `KeyUtils::convertKey()` | Not Implemented | Low |

### Hex Encoding (Hex.h/cpp)

| C++ Function | Rust Status | Priority |
|--------------|-------------|----------|
| `binToHex()` | `Hash256::to_hex()` (partial) | Low |
| `hexAbbrev()` | Not Implemented | Low |
| `hexToBin()` | Not Implemented | Low |
| `hexToBin256()` | Not Implemented | Low |

**Note**: Hex encoding is available via the `hex` crate dependency and `Hash256::to_hex()`.

### XDRHasher CRTP Pattern (XDRHasher.h)

| C++ Feature | Status | Priority |
|-------------|--------|----------|
| `XDRHasher<T>` CRTP base | Not Implemented | Low |
| Buffered hashing (256-byte buffer) | Not Implemented | Low |
| Zero-allocation XDR hashing | Not Implemented | Low |

**Note**: Rust serializes XDR to bytes first, which allocates but is simpler. The CRTP pattern is a C++ optimization.

### Testing and Benchmarking (SecretKey.h/cpp)

| C++ Feature | Status | Priority |
|-------------|--------|----------|
| `SecretKey::benchmarkOpsPerSecond()` | Not Implemented | Low |
| `SecretKey::pseudoRandomForTesting()` | Not Implemented | Low |
| `SecretKey::pseudoRandomForTestingFromSeed()` | Not Implemented | Low |
| `PubKeyUtils::pseudoRandomForTesting()` | Not Implemented | Low |
| `PubKeyUtils::random()` | Not Implemented | Low |
| `HashUtils::random()` | Not Implemented | Low |
| `HashUtils::pseudoRandomForTesting()` | Not Implemented | Low |

### Logging Utilities

| C++ Feature | Status | Priority |
|-------------|--------|----------|
| `StrKeyUtils::logKey()` | Not Implemented | Low |

### ByteSlice (ByteSlice.h)

| C++ Feature | Rust Equivalent | Status |
|-------------|-----------------|--------|
| `ByteSlice` adaptor class | `&[u8]` native slices | N/A (Rust idiom) |

**Note**: Rust naturally handles byte slices with `&[u8]` and trait bounds, making a separate adaptor unnecessary.

## Architectural Differences

### 1. No libsodium Dependency

The Rust implementation uses pure Rust crates instead of libsodium:

| Functionality | C++ (libsodium) | Rust Crate |
|---------------|-----------------|------------|
| Ed25519 signatures | `crypto_sign_*` | `ed25519-dalek` |
| SHA-256 | `crypto_hash_sha256_*` | `sha2` |
| BLAKE2b | `crypto_generichash_*` | `blake2` |
| SipHash-2-4 | `crypto_shorthash_*` | `siphasher` |
| HMAC-SHA256 | `crypto_auth_hmacsha256_*` | `hmac` |
| X25519 / Sealed Box | `crypto_box_seal*` | `crypto_box` |
| Random bytes | `randombytes_buf` | `rand::rngs::OsRng` |

Benefits:
- Reproducible builds without C dependencies
- Easier auditing and verification
- No FFI overhead
- Memory safety guarantees

### 2. Memory Management

- **Zeroization**: `SecretKey` uses `ed25519-dalek`'s built-in zeroization on drop
- **No explicit clear functions**: Rust's ownership system and drop semantics handle cleanup

### 3. XDR Hashing

- **C++**: Uses `XDRHasher<T>` CRTP pattern for zero-allocation streaming XDR hashing
- **Rust**: Serializes XDR to `Vec<u8>` first via `stellar_xdr` crate, then hashes

The Rust approach is simpler but allocates. This is acceptable for most use cases.

### 4. Error Handling

- **C++**: Throws exceptions or returns bool
- **Rust**: Returns `Result<T, CryptoError>` with typed error variants

### 5. Thread Safety

- **Short hash key**: Protected by `Mutex<KeyState>` with `OnceLock` initialization
- **All other operations**: Pure functions with no shared state

## Priority Assessment

### High Priority (Needed for Core Consensus/Ledger)
All high priority items are **implemented**:
- SHA-256 hashing and `xdrSha256()`
- BLAKE2 hashing and `xdrBlake2()`
- HMAC-SHA256 and HKDF
- Ed25519 signing and verification
- StrKey encoding/decoding
- Short hash (SipHash-2-4)

### Medium Priority (Needed for Full Network Participation)
- Curve25519 P2P ECDH key exchange
- SignerKey utilities for transaction validation
- Contract address (C...) StrKey support
- Signed payload (P...) StrKey support

### Low Priority (Optimizations and Testing)
- Signature verification cache
- Zero-allocation XDR hashing (CRTP pattern)
- Benchmarking utilities
- Pseudo-random test key generation
- Logging utilities
- Hex encoding utilities beyond `Hash256::to_hex()`

## Test Coverage

The Rust implementation includes unit tests for:
- Key generation and round-trip encoding
- Signing and verification
- SHA-256 and BLAKE2 hashing
- HMAC-SHA256 computation and verification
- HKDF key derivation
- StrKey encoding/decoding (all implemented types)
- Short hash computation with seed management
- Sealed box encryption/decryption

Tests are located in each module file under `#[cfg(test)]` sections.
