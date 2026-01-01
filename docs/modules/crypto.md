# Crypto Module Specification

**Crate**: `stellar-core-crypto`
**stellar-core mapping**: `src/crypto/`

## 1. Overview

The crypto module provides cryptographic primitives used throughout rs-stellar-core:
- Hashing (SHA-256)
- Digital signatures (Ed25519)
- Key management (Stellar key encoding/decoding)
- Random number generation
- Hex encoding utilities
- Short hashing (SipHash-2-4)

## 2. stellar-core Reference

In stellar-core, the crypto module (`src/crypto/`) contains:
- `ByteSlice.h/cpp` - Byte array utilities
- `Curve25519.h/cpp` - Curve25519 primitives (for auth)
- `Hex.h/cpp` - Hex encoding/decoding
- `KeyUtils.h/cpp` - Key encoding utilities
- `Random.h/cpp` - Random number generation
- `SHA.h/cpp` - SHA-256 hashing
- `SecretKey.h/cpp` - Secret key management
- `ShortHash.h/cpp` - Fast non-cryptographic hashing
- `SignerKey.h/cpp` - Signer key types

## 3. Rust Implementation

### 3.1 Dependencies

**Important**: All dependencies must be pure Rust - no C/C++ bindings.

```toml
[dependencies]
# Ed25519 - pure Rust implementation (no "asm" or "simd" features that might pull in C)
ed25519-dalek = { version = "2", default-features = false, features = ["std", "rand_core", "zeroize"] }

# SHA-256 - pure Rust (RustCrypto)
sha2 = { version = "0.10", default-features = false, features = ["std"] }

# Random number generation - pure Rust
rand = { version = "0.8", default-features = false, features = ["std", "std_rng"] }
rand_chacha = "0.3"
getrandom = { version = "0.2", default-features = false, features = ["std"] }

# Encoding - pure Rust
hex = "0.4"
base32 = "0.4"

# Utilities - pure Rust
thiserror = "1"
zeroize = { version = "1", features = ["derive"] }

# Curve25519 for authentication keys - pure Rust
x25519-dalek = { version = "2", default-features = false, features = ["std", "zeroize"] }

# SipHash-2-4 short hashing - pure Rust
siphasher = "0.3"
```

**Note on Pure Rust Requirements**:
- `ed25519-dalek` and `x25519-dalek` are pure Rust by default
- Avoid features like `asm`, `simd`, or `u64_backend` that may use assembly
- The `sha2` crate from RustCrypto is pure Rust
- All encoding crates (`hex`, `base32`) are pure Rust

### 3.2 Module Structure

```
stellar-core-crypto/
├── src/
│   ├── lib.rs
│   ├── hash.rs          # SHA-256 hashing
│   ├── signature.rs     # Ed25519 signatures
│   ├── keys.rs          # Key types and management
│   ├── strkey.rs        # Stellar key encoding (G..., S..., etc.)
│   ├── random.rs        # Secure random generation
│   ├── hex.rs           # Hex utilities
│   ├── short_hash.rs    # SipHash-2-4 short hashing
│   └── error.rs         # Error types
└── tests/
    └── *.rs
```

### 3.3 Core Types

#### Hash

```rust
use sha2::{Sha256, Digest};

/// 32-byte SHA-256 hash
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub const ZERO: Self = Self([0u8; 32]);

    /// Hash arbitrary data
    pub fn hash(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Hash XDR-encoded data
    pub fn hash_xdr<T: stellar_xdr::WriteXdr>(value: &T) -> Result<Self, CryptoError> {
        let bytes = value.to_xdr(stellar_xdr::Limits::none())?;
        Ok(Self::hash(&bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
```

#### PublicKey

```rust
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

/// Ed25519 public key
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let key = VerifyingKey::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(Self(key))
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature64) -> Result<(), CryptoError> {
        let sig = Signature::from_bytes(&signature.0);
        self.0.verify(message, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Convert to Stellar account ID string (G...)
    pub fn to_strkey(&self) -> String {
        strkey::encode_account_id(self.as_bytes())
    }
}
```

#### SecretKey

```rust
use ed25519_dalek::{SigningKey, Signer};
use zeroize::Zeroize;

/// Ed25519 secret key (zeroized on drop)
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(SigningKey);

impl SecretKey {
    /// Generate a new random secret key
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self(signing_key)
    }

    /// Create from seed bytes
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self(signing_key)
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature64 {
        let signature = self.0.sign(message);
        Signature64(signature.to_bytes())
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Convert to Stellar secret seed string (S...)
    pub fn to_strkey(&self) -> String {
        strkey::encode_secret_seed(self.0.as_bytes())
    }

    /// Parse from Stellar secret seed string (S...)
    pub fn from_strkey(s: &str) -> Result<Self, CryptoError> {
        let bytes = strkey::decode_secret_seed(s)?;
        Ok(Self::from_seed(&bytes))
    }
}
```

#### Signature64

```rust
/// 64-byte Ed25519 signature
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature64(pub [u8; 64]);

impl Signature64 {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}
```

### 3.4 StrKey Encoding (Stellar Key Format)

Stellar uses a base32 encoding with version bytes:

| Type | Version Byte | Prefix |
|------|--------------|--------|
| Account ID | 0x30 (48) | G |
| Secret Seed | 0x90 (144) | S |
| Pre-Auth Tx | 0xC8 (200) | T |
| SHA256 Hash | 0xB8 (184) | X |
| Muxed Account | 0x60 (96) | M |
| Signed Payload | 0x78 (120) | P |

```rust
pub mod strkey {
    const VERSION_ACCOUNT_ID: u8 = 6 << 3;      // 'G' prefix
    const VERSION_SEED: u8 = 18 << 3;           // 'S' prefix
    const VERSION_PRE_AUTH_TX: u8 = 19 << 3;    // 'T' prefix
    const VERSION_SHA256_HASH: u8 = 23 << 3;    // 'X' prefix
    const VERSION_MUXED: u8 = 12 << 3;          // 'M' prefix

    /// Encode an account ID (G...)
    pub fn encode_account_id(key: &[u8; 32]) -> String {
        encode_check(VERSION_ACCOUNT_ID, key)
    }

    /// Decode an account ID (G...)
    pub fn decode_account_id(s: &str) -> Result<[u8; 32], CryptoError> {
        decode_check(VERSION_ACCOUNT_ID, s)
    }

    /// Encode a secret seed (S...)
    pub fn encode_secret_seed(seed: &[u8; 32]) -> String {
        encode_check(VERSION_SEED, seed)
    }

    /// Decode a secret seed (S...)
    pub fn decode_secret_seed(s: &str) -> Result<[u8; 32], CryptoError> {
        decode_check(VERSION_SEED, s)
    }

    fn encode_check(version: u8, data: &[u8]) -> String {
        let mut payload = vec![version];
        payload.extend_from_slice(data);

        // CRC16-XModem checksum
        let checksum = crc16_xmodem(&payload);
        payload.extend_from_slice(&checksum.to_le_bytes());

        base32::encode(base32::Alphabet::RFC4648 { padding: false }, &payload)
    }

    fn decode_check(expected_version: u8, s: &str) -> Result<[u8; 32], CryptoError> {
        let decoded = base32::decode(base32::Alphabet::RFC4648 { padding: false }, s)
            .ok_or(CryptoError::InvalidStrKey)?;

        if decoded.len() != 35 {
            return Err(CryptoError::InvalidStrKey);
        }

        let version = decoded[0];
        if version != expected_version {
            return Err(CryptoError::InvalidStrKey);
        }

        // Verify checksum
        let checksum = u16::from_le_bytes([decoded[33], decoded[34]]);
        let computed = crc16_xmodem(&decoded[..33]);
        if checksum != computed {
            return Err(CryptoError::InvalidStrKey);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded[1..33]);
        Ok(key)
    }

    fn crc16_xmodem(data: &[u8]) -> u16 {
        let mut crc: u16 = 0;
        for byte in data {
            crc ^= (*byte as u16) << 8;
            for _ in 0..8 {
                if crc & 0x8000 != 0 {
                    crc = (crc << 1) ^ 0x1021;
                } else {
                    crc <<= 1;
                }
            }
        }
        crc
    }
}
```

### 3.5 Error Types

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid strkey encoding")]
    InvalidStrKey,

    #[error("invalid hex encoding")]
    InvalidHex,

    #[error("XDR encoding error: {0}")]
    XdrError(#[from] stellar_xdr::Error),
}
```

### 3.6 Integration with stellar-xdr

```rust
use stellar_xdr::curr::{
    PublicKey as XdrPublicKey,
    SignerKey as XdrSignerKey,
    Signature as XdrSignature,
    Hash as XdrHash,
    Uint256,
};

impl From<&PublicKey> for XdrPublicKey {
    fn from(pk: &PublicKey) -> Self {
        XdrPublicKey::PublicKeyTypeEd25519(Uint256(*pk.as_bytes()))
    }
}

impl TryFrom<&XdrPublicKey> for PublicKey {
    type Error = CryptoError;

    fn try_from(xdr: &XdrPublicKey) -> Result<Self, Self::Error> {
        match xdr {
            XdrPublicKey::PublicKeyTypeEd25519(Uint256(bytes)) => {
                PublicKey::from_bytes(bytes)
            }
        }
    }
}

impl From<Hash256> for XdrHash {
    fn from(hash: Hash256) -> Self {
        XdrHash(hash.0)
    }
}

impl From<XdrHash> for Hash256 {
    fn from(hash: XdrHash) -> Self {
        Hash256(hash.0)
    }
}
```

## 4. Tests to Port from stellar-core

From `src/crypto/test/`:
- Key generation and serialization
- Signature creation and verification
- StrKey encoding/decoding round-trips
- Hash computation verification
- Edge cases (invalid keys, signatures)

## 5. Security Considerations

1. **Zeroization**: Secret keys are zeroized on drop
2. **Constant-time operations**: Use ed25519-dalek which provides constant-time signature verification
3. **Secure RNG**: Use system CSPRNG for key generation
4. **No key logging**: Never log secret keys

## 6. Performance Considerations

1. Batch signature verification when processing multiple transactions
2. Cache public key derivation from secret keys
3. Use SIMD-optimized SHA-256 implementation (sha2 crate auto-detects)
