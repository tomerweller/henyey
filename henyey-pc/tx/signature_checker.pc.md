## Pseudocode: crates/tx/src/signature_checker.rs

"Signature weight checking for multi-signature transactions."
"Processes signers in a specific order:"
"1. Pre-auth TX signers (compared against transaction hash)"
"2. Hash-X signers (preimage verification)"
"3. Ed25519 signers (cryptographic signature verification)"
"4. Ed25519 signed payload signers"

### SignatureChecker (struct)

```
SignatureChecker:
  contents_hash        // transaction hash that signatures verify against
  signatures[]         // decorated signatures from the transaction
  used_signatures[]    // parallel bool array tracking which sigs are consumed
```

### new

```
function new(contents_hash, signatures):
  used_signatures = array of false, length = len(signatures)
  → SignatureChecker { contents_hash, signatures, used_signatures }
```

### check_signature

"Processes signers in order: PRE_AUTH_TX → HASH_X → ED25519 → ED25519_SIGNED_PAYLOAD."
"Accumulates weights and marks signatures as used."

```
function check_signature(signers, needed_weight) → bool:
  signers_by_type = split_signers_by_type(signers)
  total_weight = 0

  "1. Check PRE_AUTH_TX signers first (direct hash comparison)"
  for each signer in signers_by_type[PRE_AUTH_TX]:
    if signer.key.hash == self.contents_hash:
      weight = cap_weight(signer.weight)
      total_weight += weight
      if total_weight >= needed_weight:
        → true

  "2. Check HASH_X signers"
  if verify_all_of_type(signers_by_type[HASH_X],
      needed_weight, total_weight, verify_hash_x):
    → true

  "3. Check ED25519 signers"
  if verify_all_of_type(signers_by_type[ED25519],
      needed_weight, total_weight, verify_ed25519):
    → true

  "4. Check ED25519_SIGNED_PAYLOAD signers"
  if verify_all_of_type(signers_by_type[ED25519_SIGNED_PAYLOAD],
      needed_weight, total_weight, verify_ed25519_signed_payload):
    → true

  → false
```

**Calls**: [split_signers_by_type](#helper-split_signers_by_type) | [cap_weight](#helper-cap_weight) | [verify_all_of_type](#verify_all_of_type) | [verify_hash_x](#helper-verify_hash_x) | [verify_ed25519](#helper-verify_ed25519) | [verify_ed25519_signed_payload](#helper-verify_ed25519_signed_payload)

### verify_all_of_type

"Each matching signature's signer weight is accumulated. When a match is found,"
"the signature is marked as used and the signer is removed (each signer used once)."

```
function verify_all_of_type(signers, needed_weight,
    total_weight, verify_fn) → bool:
  for each (sig_idx, sig) in self.signatures:
    if used_signatures[sig_idx]:
      continue

    found_signer_idx = null
    for each (signer_idx, signer) in signers:
      if verify_fn(sig, signer):
        found_signer_idx = signer_idx
        break

    if found_signer_idx != null:
      MUTATE used_signatures[sig_idx] = true
      weight = cap_weight(signers[found_signer_idx].weight)
      total_weight += weight

      if total_weight >= needed_weight:
        → true

      "Remove the signer so it can't be used again"
      remove signers[found_signer_idx]

  → false
```

**Calls**: [cap_weight](#helper-cap_weight)

### check_all_signatures_used

```
function check_all_signatures_used() → bool:
  → all entries in used_signatures are true
```

### Helper: cap_weight

"Signer weights are capped at 255 to prevent overflow issues."

```
function cap_weight(weight) → int:
  CONST MAX_WEIGHT = 255  // u8 max
  if weight > MAX_WEIGHT:
    → MAX_WEIGHT
  → weight
```

### Helper: split_signers_by_type

```
function split_signers_by_type(signers) → map:
  result = empty map of { signer_key_type → list of signers }
  for each signer in signers:
    key_type = type_of(signer.key)
      // one of: ED25519, PRE_AUTH_TX, HASH_X, ED25519_SIGNED_PAYLOAD
    append signer to result[key_type]
  → result
```

### Helper: verify_hash_x

"The signature should be a 32-byte preimage whose SHA-256 hash equals"
"the signer key's hash."

```
function verify_hash_x(sig, signer) → bool:
  GUARD signer.key is HASH_X type       → false

  "HashX signature must be exactly 32 bytes (the preimage)"
  GUARD len(sig.signature) != 32         → false

  "Check hint matches last 4 bytes of expected hash"
  expected_hint = signer.key.hash[28..32]
  GUARD sig.hint != expected_hint        → false

  "Hash the preimage and compare"
  hash = SHA256(sig.signature)
  → hash == signer.key.hash
```

### Helper: verify_ed25519

```
function verify_ed25519(sig, signer, contents_hash) → bool:
  GUARD signer.key is ED25519 type       → false

  "Check hint matches last 4 bytes of public key"
  expected_hint = signer.key.bytes[28..32]
  GUARD sig.hint != expected_hint        → false

  public_key = parse_public_key(signer.key.bytes)
  GUARD public_key is invalid            → false

  signature = parse_signature(sig.signature)
  GUARD signature is invalid             → false

  "Verify the cryptographic signature"
  → verify_hash(public_key, contents_hash, signature)
```

REF: henyey_crypto::verify_hash

### Helper: verify_ed25519_signed_payload

"Per CAP-0040, the signature is verified against the raw payload bytes."
"The hint is XOR of pubkey hint and payload hint."

```
function verify_ed25519_signed_payload(sig, signer) → bool:
  GUARD signer.key is ED25519_SIGNED_PAYLOAD type → false

  payload = signer.key.payload

  "See SignatureUtils::getSignedPayloadHint in stellar-core."
  pubkey_hint = signer.key.ed25519[28..32]

  if len(payload) >= 4:
    payload_hint = payload[len-4 .. len]
  else:
    "For shorter payloads, copy from the beginning"
    payload_hint = [0, 0, 0, 0]
    copy payload bytes into payload_hint[0..len(payload)]

  expected_hint = pubkey_hint XOR payload_hint
  GUARD sig.hint != expected_hint        → false

  public_key = parse_public_key(signer.key.ed25519)
  GUARD public_key is invalid            → false

  ed_sig = parse_signature(sig.signature)
  GUARD ed_sig is invalid                → false

  "stellar-core verifies the signature against the raw payload bytes,"
  "not a hash. This is per CAP-0040."
  → verify(public_key, payload, ed_sig)
```

REF: henyey_crypto::verify

### collect_signers_for_account

"Creates a signer list from the account's explicit signers plus the master"
"key (using the account's master weight from thresholds[0])."

```
function collect_signers_for_account(account) → list:
  signers = copy of account.signers

  "Add the master key as a signer with weight from thresholds[0]"
  master_weight = account.thresholds[0]
  if master_weight > 0:
    key_bytes = account.account_id.ed25519_key
    append Signer { key: ED25519(key_bytes), weight: master_weight }
      to signers

  → signers
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 360    | ~140       |
| Functions     | 9      | 9          |
