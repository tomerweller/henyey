## Pseudocode: crypto/sealed_box.rs

"Sealed box encryption for anonymous encrypted payloads."
"Uses X25519 key exchange + XSalsa20-Poly1305 authenticated encryption."
"An ephemeral keypair is generated per encryption; the ephemeral public key"
"is prepended to the ciphertext."

### seal_to_public_key

```
function seal_to_public_key(recipient: PublicKey, plaintext: bytes) -> bytes:
  "Encrypts to a recipient's Ed25519 public key."
  curve_pk = convert recipient to Curve25519 public key
  ciphertext = curve_pk.seal(OS_RNG, plaintext)
  -> ciphertext
```

**Calls**: [PublicKey.to_curve25519_bytes](keys.pc.md#to_curve25519_bytes)

### seal_to_curve25519_public_key

```
function seal_to_curve25519_public_key(
    recipient: byte_array[32], plaintext: bytes) -> bytes:
  "Encrypts to a Curve25519 public key directly."
  curve_pk = Curve25519PublicKey from recipient bytes
  ciphertext = curve_pk.seal(OS_RNG, plaintext)
  -> ciphertext
```

### open_from_secret_key

```
function open_from_secret_key(recipient: SecretKey, ciphertext: bytes) -> bytes:
  "Decrypts a sealed payload using the recipient's Ed25519 secret key."
  curve_sk = convert recipient to Curve25519 secret key
  plaintext = curve_sk.unseal(ciphertext)
  -> plaintext
```

**Calls**: [SecretKey.to_curve25519_bytes](keys.pc.md#to_curve25519_bytes_secret)

### open_from_curve25519_secret_key

```
function open_from_curve25519_secret_key(
    recipient: byte_array[32], ciphertext: bytes) -> bytes:
  "Decrypts a sealed payload using a Curve25519 secret key directly."
  curve_sk = Curve25519SecretKey from recipient bytes
  plaintext = curve_sk.unseal(ciphertext)
  -> plaintext
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 24     | 18         |
| Functions     | 4      | 4          |
