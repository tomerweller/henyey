## C++ Parity Status

This section documents the parity between this Rust crate and the upstream C++ `stellar-core/src/crypto/` implementation.

### Implemented

#### Ed25519 Keys and Signatures (SecretKey.h/cpp)
- [x] `SecretKey` class with seed-based key generation
- [x] `SecretKey::random()` - random key generation
- [x] `SecretKey::fromSeed()` - key from raw seed bytes
- [x] `SecretKey::fromStrKeySeed()` - key from StrKey seed (S...)
- [x] `SecretKey::getStrKeySeed()` - export as StrKey seed
- [x] `SecretKey::getStrKeyPublic()` - export public key as StrKey
- [x] `SecretKey::getPublicKey()` - derive public key
- [x] `SecretKey::sign()` - Ed25519 signing
- [x] `SecretKey::isZero()` - check if key is all zeros (implicit via comparison)
- [x] Secret key zeroization on drop
- [x] `PublicKey` type with StrKey encoding
- [x] `PubKeyUtils::verifySig()` - signature verification (basic functionality)
- [x] XDR conversions for PublicKey/AccountId

#### SHA-256 Hashing (SHA.h/cpp)
- [x] `sha256()` - single-shot hashing
- [x] `SHA256` class - streaming/incremental hashing
- [x] `reset()`, `add()`, `finish()` methods

#### StrKey Encoding (StrKey.h/cpp)
- [x] `toStrKey()` - encode with version byte and CRC16
- [x] `fromStrKey()` - decode and validate checksum
- [x] Account ID encoding/decoding (G... prefix)
- [x] Secret seed encoding/decoding (S... prefix)
- [x] Pre-auth TX hash encoding/decoding (T... prefix)
- [x] SHA256 hash encoding/decoding (X... prefix)
- [x] Muxed account encoding/decoding (M... prefix)
- [x] CRC16-XModem checksum implementation

#### Short Hash (ShortHash.h/cpp)
- [x] `shortHash::initialize()` - initialize with random key
- [x] `shortHash::seed()` - seed with deterministic value (for tests)
- [x] `shortHash::computeHash()` - compute SipHash-2-4
- [x] `xdrComputeHash()` - hash XDR-encoded values
- [x] Thread-safe global key management
- [x] Seed conflict detection after hashing has begun

#### Random (Random.h/cpp)
- [x] `randomBytes()` - generate random byte vectors
- [x] Fixed-size random byte generation
- [x] Random u32/u64 generation

#### Curve25519 / Sealed Box (Curve25519.h/cpp)
- [x] Sealed box encryption (`crypto_box_seal` equivalent)
- [x] Sealed box decryption (`crypto_box_seal_open` equivalent)
- [x] Ed25519 to Curve25519 key conversion

#### Hex Encoding (partial, via Hash256)
- [x] `to_hex()` on Hash256 (equivalent to `binToHex`)

### Not Yet Implemented (Gaps)

#### Ed25519 / Signature Infrastructure
- [ ] `SecretKey::benchmarkOpsPerSecond()` - performance benchmarking
- [ ] `SecretKey::pseudoRandomForTesting()` - deterministic test key generation (BUILD_TESTS)
- [ ] `SecretKey::pseudoRandomForTestingFromSeed()` - seeded test key generation (BUILD_TESTS)
- [ ] `PubKeyUtils::clearVerifySigCache()` - signature verification cache management
- [ ] `PubKeyUtils::seedVerifySigCache()` - cache seeding for tests
- [ ] `PubKeyUtils::flushVerifySigCacheCounts()` - cache statistics
- [ ] `PubKeyUtils::enableRustDalekVerify()` - protocol upgrade flag (N/A for Rust)
- [ ] `PubKeyUtils::random()` - generate random (invalid) public key bytes
- [ ] `PubKeyUtils::pseudoRandomForTesting()` - test random public keys
- [ ] Signature verification result caching (RandomEvictionCache)
- [ ] BLAKE2-based cache key computation for signature cache

#### BLAKE2 Hashing (BLAKE2.h/cpp)
- [ ] `blake2()` - single-shot BLAKE2b hashing
- [ ] `BLAKE2` class - streaming/incremental BLAKE2b
- [ ] `xdrBlake2()` - hash XDR-encoded values with BLAKE2

#### SHA-256 Extensions (SHA.h/cpp)
- [ ] `subSha256()` - sub-seeding for per-transaction PRNGs
- [ ] `hmacSha256()` - HMAC-SHA256
- [ ] `hmacSha256Verify()` - timing-safe HMAC verification
- [ ] `hkdfExtract()` - HKDF extract step
- [ ] `hkdfExpand()` - HKDF expand step
- [ ] `xdrSha256()` - hash XDR-encoded values without allocation (XDRSHA256 helper)

#### Curve25519 / Key Exchange (Curve25519.h/cpp)
- [ ] `curve25519RandomSecret()` - generate random Curve25519 secret
- [ ] `curve25519DerivePublic()` - derive public from secret
- [ ] `clearCurve25519Keys()` - secure key clearing
- [ ] `curve25519DeriveSharedKey()` - ECDH shared key derivation
- [ ] `Curve25519Public` / `Curve25519Secret` XDR types
- [ ] P2P overlay key exchange functions

#### Hex Encoding (Hex.h/cpp)
- [ ] `binToHex()` - general purpose hex encoding
- [ ] `hexAbbrev()` - 6-character hex prefix for logging
- [ ] `hexToBin()` - hex decoding to vector
- [ ] `hexToBin256()` - hex decoding to fixed 32 bytes

#### SignerKey Utilities (SignerKey.h/cpp, SignerKeyUtils.h/cpp)
- [ ] `KeyFunctions<SignerKey>` template specialization
- [ ] `SignerKeyUtils::preAuthTxKey()` - create pre-auth TX signer key
- [ ] `SignerKeyUtils::hashXKey()` - create hash-X signer key
- [ ] `SignerKeyUtils::ed25519PayloadKey()` - create signed payload key
- [ ] Signed payload StrKey support (P... prefix)
- [ ] Contract StrKey support (C... prefix)

#### Key Utilities (KeyUtils.h/cpp)
- [ ] `KeyUtils::toStrKey()` template - generic StrKey encoding
- [ ] `KeyUtils::fromStrKey()` template - generic StrKey decoding
- [ ] `KeyUtils::toShortString()` - 5-character key prefix
- [ ] `KeyUtils::getKeyVersionSize()` - version-specific key sizes
- [ ] `KeyUtils::canConvert()` / `convertKey()` - key type conversions

#### StrKey Extensions
- [ ] `getStrKeySize()` - calculate encoded size from data size
- [ ] Contract address encoding (C... prefix)

#### Logging Utilities (SecretKey.cpp)
- [ ] `StrKeyUtils::logKey()` - log key in multiple formats

#### Hash Utilities (SecretKey.cpp)
- [ ] `HashUtils::random()` - generate random hash
- [ ] `HashUtils::pseudoRandomForTesting()` - test random hashes

#### ByteSlice (ByteSlice.h)
- [ ] `ByteSlice` adaptor type (Rust uses native slices instead)

#### XDRHasher (XDRHasher.h)
- [ ] `XDRHasher<T>` CRTP base class for XDR hashing
- [ ] Buffered hashing with automatic batching

### Implementation Notes

#### Architectural Differences

1. **No libsodium dependency**: The Rust implementation uses pure Rust crates (`ed25519-dalek`, `sha2`, `crypto_box`) instead of libsodium. This provides:
   - Reproducible builds without C dependencies
   - Easier auditing and verification
   - No FFI overhead

2. **Signature Verification Cache**: The C++ implementation includes a process-wide signature verification cache (`RandomEvictionCache<Hash, bool>`) that caches signature verification results keyed by BLAKE2 hash. The Rust implementation does not currently have this optimization. This is a performance optimization, not a correctness issue.

3. **ByteSlice vs Native Slices**: C++ uses a `ByteSlice` adaptor class to unify different byte container types. Rust naturally handles this with `&[u8]` slices and trait bounds.

4. **XDR Hashing**: C++ has `XDRHasher<T>` CRTP template for zero-allocation XDR hashing. The Rust implementation serializes to XDR bytes first (via `stellar_xdr` crate), which does allocate but is simpler.

5. **Test-only Functions**: Several C++ functions are `#ifdef BUILD_TESTS` guarded (pseudo-random key generation, cache seeding). These may not be needed in Rust if tests use different patterns.

6. **Curve25519 for P2P**: The C++ `Curve25519.h` functions are primarily for P2P overlay authentication (ephemeral ECDH). The Rust sealed box implementation covers the survey encryption use case but not the P2P handshake key exchange.

7. **Key Type Extensibility**: C++ uses `KeyFunctions<T>` template specializations for generic key handling. Rust could use traits but currently has concrete implementations for Ed25519 only.

#### Priority Gaps for Core Functionality

**High Priority** (needed for core consensus/ledger):
- BLAKE2 hashing (used in signature cache keys)
- HMAC-SHA256 and HKDF (used in various protocols)
- `xdrSha256()` for zero-allocation XDR hashing

**Medium Priority** (needed for full network participation):
- Curve25519 ECDH for P2P overlay
- SignerKey utilities for transaction validation
- Contract address (C...) StrKey support

**Low Priority** (optimizations and testing):
- Signature verification cache
- Benchmarking utilities
- Pseudo-random test key generation
- Logging utilities
