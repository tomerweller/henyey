## Pseudocode: crypto/signer_key.rs

"SignerKey utilities for transaction authorization."
"SignerKeys allow accounts to authorize via: Ed25519 keys, pre-auth tx,"
"hash(x) preimage reveal, or Ed25519 signed payloads."

### pre_auth_tx_key

```
function pre_auth_tx_key(tx_hash: Hash256) -> SignerKey:
  "Creates a pre-authorized transaction signer from a tx hash."
  -> SignerKey::PreAuthTx(tx_hash)
```

### hash_x_key

```
function hash_x_key(preimage: bytes) -> SignerKey:
  "Creates a hash(x) signer. Authorization requires revealing the preimage."
  -> SignerKey::HashX(sha256(preimage))
```

**Calls**: [sha256](hash.pc.md#sha256)

### hash_x_key_from_hash

```
function hash_x_key_from_hash(hash: Hash256) -> SignerKey:
  "Creates a hash(x) signer from an already-computed hash."
  -> SignerKey::HashX(hash)
```

### ed25519_payload_key

```
function ed25519_payload_key(ed25519_pubkey: byte_array[32],
                              payload: bytes) -> SignerKey:
  "Requires both an Ed25519 signature AND a matching payload."
  ASSERT: payload.length <= 64
  -> SignerKey::Ed25519SignedPayload {
    ed25519: ed25519_pubkey,
    payload: payload
  }
```

### ed25519_key

```
function ed25519_key(ed25519_pubkey: byte_array[32]) -> SignerKey:
  "Most common signer type: standard Ed25519 signature."
  -> SignerKey::Ed25519(ed25519_pubkey)
```

### get_ed25519_from_signer_key

```
function get_ed25519_from_signer_key(
    signer_key: SignerKey) -> byte_array[32] or none:
  "Extracts Ed25519 public key if the signer type contains one."
  if signer_key is Ed25519(key):
    -> key
  if signer_key is Ed25519SignedPayload(payload):
    -> payload.ed25519
  if signer_key is PreAuthTx or HashX:
    -> none
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 42     | 30         |
| Functions     | 6      | 6          |
