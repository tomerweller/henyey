# crypto

Pure Rust cryptographic primitives for rs-stellar-core. This crate provides SHA-256 and BLAKE2 hashing, Ed25519 key management and signing, Curve25519 ECDH key exchange, sealed box encryption, SipHash-2-4 for deterministic ordering, hex encoding, CSPRNG utilities, and signer key abstractions for transaction authorization.

## Key Files

- [keys.pc.md](keys.pc.md) -- Ed25519 public/secret key types with StrKey encoding and signing
- [hash.pc.md](hash.pc.md) -- SHA-256 and BLAKE2 hashing with HMAC, HKDF, and XDR support
- [signature.pc.md](signature.pc.md) -- Signature creation, verification, and hint-based signer matching
- [curve25519.pc.md](curve25519.pc.md) -- Curve25519 ECDH key exchange for P2P overlay authentication
- [signer_key.pc.md](signer_key.pc.md) -- SignerKey types: Ed25519, pre-auth tx, hash(x), signed payload

## Architecture

The crate is split into low-level primitives and higher-level key abstractions. `hash` provides SHA-256, BLAKE2, HMAC, and HKDF operations, while `short_hash` supplies SipHash-2-4 with a process-global random key for deterministic ordering. `keys` defines Ed25519 PublicKey/SecretKey types with StrKey encoding per SEP-0023, and `signature` wraps signing/verification with hint-based signer identification. `curve25519` handles ECDH key exchange for P2P handshakes, and `sealed_box` provides anonymous encrypted payloads via X25519 + XSalsa20-Poly1305. `signer_key` abstracts the multiple authorization mechanisms (Ed25519, pre-auth tx, hash(x), signed payload). `hex` and `random` provide binary-to-text conversion and CSPRNG utilities respectively.

## All Files

| File | Description |
|------|-------------|
| [curve25519.pc.md](curve25519.pc.md) | Curve25519 ECDH key exchange for P2P overlay authentication |
| [error.pc.md](error.pc.md) | Cryptographic error types: invalid keys, signatures, encoding |
| [hash.pc.md](hash.pc.md) | SHA-256 and BLAKE2 hashing with HMAC, HKDF, and streaming support |
| [hex.pc.md](hex.pc.md) | Hex encoding/decoding between binary byte slices and strings |
| [keys.pc.md](keys.pc.md) | Ed25519 public/secret key types with StrKey encoding and signing |
| [lib.pc.md](lib.pc.md) | Crate root with module declarations and re-exports |
| [random.pc.md](random.pc.md) | Cryptographically secure random byte generation via OS CSPRNG |
| [sealed_box.pc.md](sealed_box.pc.md) | Anonymous sealed box encryption via X25519 + XSalsa20-Poly1305 |
| [short_hash.pc.md](short_hash.pc.md) | SipHash-2-4 with process-global key for deterministic ordering |
| [signature.pc.md](signature.pc.md) | Signature creation, verification, and hint-based signer matching |
| [signer_key.pc.md](signer_key.pc.md) | SignerKey factories for pre-auth tx, hash(x), and signed payloads |
