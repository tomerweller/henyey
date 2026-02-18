## Pseudocode: crates/ledger/src/execution/signatures.rs

### account_id_to_key

```
account_id_to_key(account_id):
  → 32-byte Ed25519 public key bytes from account_id
```

### is_operation_success

```
is_operation_success(result):
  "Check if an operation result indicates success."
  if result is OpInner:
    → true if inner variant is the Success case
      for the specific operation type
  → false
```

### has_sufficient_signer_weight

```
has_sufficient_signer_weight(tx_hash, signatures, account, required_weight):
  total = 0
  counted = empty set of signer key IDs

  --- Check master key ---
  pk = public key from account.account_id
  master_weight = account.thresholds[0]
  if master_weight > 0:
    if has_ed25519_signature(tx_hash, signatures, pk):
      id = signer_key_id(Ed25519(pk))
      if id not in counted:
        add id to counted
        total += master_weight
```

**Calls**: [has_ed25519_signature](#has_ed25519_signature) | [signer_key_id](#signer_key_id) | [has_hashx_signature](#has_hashx_signature) | [has_signed_payload_signature](#has_signed_payload_signature)

```
  --- Check additional signers ---
  for each signer in account.signers:
    if signer.weight == 0: skip
    id = signer_key_id(signer.key)
    if id in counted: skip

    if signer.key is Ed25519:
      if has_ed25519_signature(tx_hash, signatures, pk):
        add id to counted
        total += signer.weight
    else if signer.key is PreAuthTx:
      if key bytes == tx_hash:
        add id to counted
        total += signer.weight
    else if signer.key is HashX:
      if has_hashx_signature(signatures, key):
        add id to counted
        total += signer.weight
    else if signer.key is Ed25519SignedPayload:
      if has_signed_payload_signature(tx_hash, signatures, payload):
        add id to counted
        total += signer.weight

    if total >= required_weight and total > 0:
      → true

  → total >= required_weight and total > 0
```

### has_required_extra_signers

```
has_required_extra_signers(tx_hash, signatures, extra_signers):
  "Every extra signer must be matched by at least one signature."
  for each signer in extra_signers:
    if signer is Ed25519:
      GUARD not has_ed25519_signature(tx_hash, signatures, pk) → false
    else if signer is PreAuthTx:
      GUARD key bytes != tx_hash → false
    else if signer is HashX:
      GUARD not has_hashx_signature(signatures, key) → false
    else if signer is Ed25519SignedPayload:
      GUARD not has_signed_payload_signature(tx_hash, signatures, payload)
        → false
  → true
```

### fee_bump_inner_hash

```
fee_bump_inner_hash(frame, network_id):
  if frame is FeeBump envelope:
    extract inner transaction envelope
    inner_frame = new TransactionFrame(inner_env, network_id)
    → inner_frame.hash(network_id)
  else:
    → frame.hash(network_id)
```

### threshold_low / threshold_medium / threshold_high

```
threshold_low(account):   → account.thresholds[1]
threshold_medium(account): → account.thresholds[2]
threshold_high(account):   → account.thresholds[3]
```

### get_threshold_for_op

"Determine the threshold level required for an operation type."
"Matches stellar-core's per-OperationFrame getThresholdLevel() overrides."

```
get_threshold_for_op(op):
  --- LOW threshold operations ---
  BumpSequence, ClaimClaimableBalance, ExtendFootprintTtl,
  Inflation, RestoreFootprint,
  AllowTrust, SetTrustLineFlags    → Low

  --- HIGH threshold operations ---
  AccountMerge                      → High
  SetOptions:
    if modifying master_weight, low/med/high_threshold, or signer:
      → High
    else:
      → Medium

  --- All other operations ---
  → Medium
```

### get_needed_threshold

```
get_needed_threshold(account, level):
  Low    → threshold_low(account)
  Medium → threshold_medium(account)
  High   → threshold_high(account)
```

### has_signed_payload_match

```
has_signed_payload_match(sig, signed_payload):
  pk = public key from signed_payload.ed25519

  --- Compute expected hint ---
  pubkey_hint = last 4 bytes of signed_payload.ed25519
  if payload length >= 4:
    payload_hint = last 4 bytes of payload
  else:
    payload_hint = payload bytes zero-padded to 4
  expected_hint = pubkey_hint XOR payload_hint

  GUARD sig.hint != expected_hint → false

  ed_sig = parse signature from sig.signature
  → verify(pk, signed_payload.payload, ed_sig) succeeds
```

### check_extra_signers_with_tracker

"Mirrors stellar-core's TransactionFrame::checkExtraSigners()."

```
check_extra_signers_with_tracker(tracker, extra_signers):
  GUARD extra_signers is empty → true
  "Build a signer list where each extra signer has weight 1,"
  "and the needed weight is the total number of extra signers."
  signers = [(key, weight=1) for each key in extra_signers]
  needed_weight = len(extra_signers)
  → tracker.check_signature_from_signers(signers, needed_weight)
```

### check_operation_signatures

"Mirrors stellar-core's processSignatures() + checkOperationSignatures()."
"Returns none if all checks pass (proceed to execution),"
"or (op_results, failure) if checks fail."

```
check_operation_signatures(frame, state, tx_hash, signatures, inner_source_id):
  tracker = new SignatureTracker(tx_hash, signatures)

  --- Step 1: TX-level source account signatures ---
  source_account = state.get_account(inner_source_id)
  GUARD source_account missing → none (let existing checks handle)
  tx_threshold = threshold_low(source_account)
  if not tracker.check_signature(source_account, tx_threshold):
    → none
```

**Calls**: [threshold_low](#threshold_low) | [check_extra_signers_with_tracker](#check_extra_signers_with_tracker) | [get_threshold_for_op](#get_threshold_for_op) | [get_needed_threshold](#get_needed_threshold) | [default_success_op_result](#default_success_op_result)

```
  --- Step 2: Extra signers with tracking ---
  if frame has V2 preconditions with extra_signers:
    check_extra_signers_with_tracker(tracker, extra_signers)
    "Extra signer failures already caught by earlier check,"
    "but we need to run this for used-signature tracking."

  --- Step 3: Per-operation signature checks ---
  all_ops_valid = true
  op_results = array of none, size = num_ops

  for each (i, op) in frame.operations():
    op_source_id = op.source_account if set, else inner_source_id

    if state has account for op_source_id:
      threshold_level = get_threshold_for_op(op)
      needed = get_needed_threshold(account, threshold_level)
      if not tracker.check_signature(account, needed):
        op_results[i] = OpBadAuth
        all_ops_valid = false
    else:
      if op has no explicit source_account:
        op_results[i] = OpNoAccount
        all_ops_valid = false
      else:
        "checkSignatureNoAccount: synthetic signer, weight=1, needed=0"
        if not tracker.check_signature_no_account(op_source_id):
          op_results[i] = OpBadAuth
          all_ops_valid = false

  if not all_ops_valid:
    final_results = for each (i, op):
      if op_results[i] has value: use it
      else: default_success_op_result(op)
    → (final_results, OperationFailed)

  --- Step 4: Check all signatures used ---
  if not tracker.check_all_signatures_used():
    → (empty, BadAuthExtra)

  → none  (all checks pass)
```

### default_success_op_result

```
default_success_op_result(op):
  "Create a default success operation result for an operation."
  "When per-op signature checking succeeds for an op but another op fails,"
  "the passing op keeps its default-initialized result."
  → OpInner with Success variant for the given operation type
    (with zero/empty values for any associated data)
```

### signer_key_id

```
signer_key_id(key):
  bytes = XDR-serialize(key)
  → SHA256(bytes)
```

### has_ed25519_signature

```
has_ed25519_signature(tx_hash, signatures, pk):
  → any signature in signatures where
    verify_signature_with_key(tx_hash, sig, pk) succeeds
```

### has_hashx_signature

```
has_hashx_signature(signatures, key):
  "HashX signatures: the signature is the preimage"
  "whose SHA256 hash should equal the signer key."
  for each sig in signatures:
    expected_hint = last 4 bytes of key
    GUARD sig.hint != expected_hint → skip
    hash = SHA256(sig.signature)
    if hash == key: → true
  → false
```

### has_signed_payload_signature

"See CAP-0040 - the signed payload signer requires a valid signature"
"of the payload from the ed25519 public key."

```
has_signed_payload_signature(tx_hash, signatures, signed_payload):
  pk = public key from signed_payload.ed25519

  --- Compute expected hint ---
  "See SignatureUtils::getSignedPayloadHint in stellar-core."
  pubkey_hint = last 4 bytes of signed_payload.ed25519
  if payload length >= 4:
    payload_hint = last 4 bytes of payload
  else:
    "For shorter payloads, stellar-core getHint copies from beginning"
    payload_hint = payload bytes zero-padded to 4
  expected_hint = pubkey_hint XOR payload_hint

  for each sig in signatures:
    GUARD sig.hint != expected_hint → skip
    ed_sig = parse signature from sig.signature
    "stellar-core verifies against the raw payload bytes, not a hash."
    if verify(pk, signed_payload.payload, ed_sig) succeeds:
      → true
  → false
```

### sub_sha256

"Compute subSha256(baseSeed, index) as used by stellar-core for PRNG seeds."

```
sub_sha256(base_seed, index):
  "SHA256(baseSeed || XDR-encode-uint64(index))"
  NOTE: XDR uint64 is 8 bytes big-endian
  NOTE: stellar-core casts index to uint64 before serialization
  → SHA256(base_seed ++ big_endian_u64(index))
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 741    | 185        |
| Functions     | 16     | 16         |
