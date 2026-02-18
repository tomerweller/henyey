## Pseudocode: crypto/signature.rs

"Signature utilities and helpers."
"Stellar uses signature hints (last 4 bytes of public key) to identify signers."

### sign

```
function sign(secret_key: SecretKey, data: bytes) -> Signature:
  -> secret_key.sign(data)
```

**Calls**: [SecretKey.sign](keys.pc.md#sign)

### verify

```
function verify(public_key: PublicKey, data: bytes,
                signature: Signature) -> ok/error:
  -> public_key.verify(data, signature)
```

**Calls**: [PublicKey.verify](keys.pc.md#verify)

### SignedMessage

```
STRUCT SignedMessage:
  message:   bytes
  signature: Signature
  hint:      byte_array[4]
```

### SignedMessage.new

```
function SignedMessage.new(secret_key: SecretKey,
                           message: bytes) -> SignedMessage:
  signature = secret_key.sign(message)
  public_key = secret_key.public_key()
  hint = signature_hint(public_key)
  -> SignedMessage { message, signature, hint }
```

**Calls**: [SecretKey.sign](keys.pc.md#sign) | [SecretKey.public_key](keys.pc.md#public_key) | [signature_hint](#signature_hint)

### SignedMessage.verify

```
function SignedMessage.verify(self, public_key: PublicKey) -> ok/error:
  "Check hint matches before doing expensive signature verification"
  GUARD self.hint != signature_hint(public_key)
      → InvalidSignature
  -> public_key.verify(self.message, self.signature)
```

**Calls**: [signature_hint](#signature_hint) | [PublicKey.verify](keys.pc.md#verify)

### signature_hint

```
function signature_hint(public_key: PublicKey) -> byte_array[4]:
  "The hint is the last 4 bytes of the 32-byte public key."
  key_bytes = public_key.as_bytes()
  -> key_bytes[28..32]
```

### sign_hash

```
function sign_hash(secret_key: SecretKey, hash: Hash256) -> Signature:
  "Signs the raw 32 bytes of the hash."
  -> secret_key.sign(hash.as_bytes())
```

**Calls**: [SecretKey.sign](keys.pc.md#sign)

### verify_hash

```
function verify_hash(public_key: PublicKey, hash: Hash256,
                     signature: Signature) -> ok/error:
  -> public_key.verify(hash.as_bytes(), signature)
```

**Calls**: [PublicKey.verify](keys.pc.md#verify)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 50     | 36         |
| Functions     | 7      | 7          |
