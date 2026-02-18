## Pseudocode: crates/tx/src/validation.rs

"Transaction validation logic including structure, fee, time bounds,
ledger bounds, sequence, signature, and Soroban validation."

"Two validation modes:
- validate_basic: Minimal checks for catchup/replay (no account data needed)
- validate_full: Complete validation including signatures and balance (for live submission)"

### LedgerContext

```
struct LedgerContext:
  sequence: u32              // current ledger sequence number
  close_time: u64            // ledger close time (unix timestamp)
  base_fee: u32              // base fee per operation in stroops
  base_reserve: u32          // base reserve per ledger entry in stroops
  protocol_version: u32      // protocol version number
  network_id: NetworkId      // network identifier
  soroban_prng_seed: bytes?  // optional PRNG seed for Soroban
                             // "computed as subSha256(txSetHash, txIndex)"
```

### validate_signatures

"Verifies signatures are cryptographically valid for the tx hash.
Does NOT verify signer weights — that requires account information."

```
function validate_signatures(frame, context):
  tx_hash = frame.hash(context.network_id)
  GUARD tx_hash computation fails  → INVALID_SIGNATURE

  NOTE: individual signature format validation deferred to
        has_sufficient_signer_weight() when account signers available
  → ok
```

### validate_sequence

```
function validate_sequence(frame, source_account):
  if source_account is provided:
    expected = source_account.seq_num + 1
    actual = frame.sequence_number
    GUARD actual != expected  → BAD_SEQUENCE(expected, actual)
  → ok
```

### validate_min_seq_num

```
function validate_min_seq_num(frame, source_account):
  if frame.preconditions is V2:
    if V2.min_seq_num exists:
      GUARD source_account.seq_num < min_seq_num
        → BAD_MIN_ACCOUNT_SEQUENCE
  → ok
```

### validate_extra_signers

```
function validate_extra_signers(frame, context):
  if frame.preconditions is V2:
    if V2.extra_signers is not empty:
      extra_hash = fee_bump_inner_hash(frame, context.network_id)
      signatures = if frame.is_fee_bump:
                     frame.inner_signatures
                   else:
                     frame.signatures
      GUARD not has_required_extra_signers(
              extra_hash, signatures, V2.extra_signers)
        → EXTRA_SIGNERS_NOT_MET
  → ok
```

### validate_fee

```
function validate_fee(frame, context):
  op_count = frame.operation_count
  required_fee = op_count * context.base_fee
  provided_fee = frame.fee
  GUARD provided_fee < required_fee
    → INSUFFICIENT_FEE(required_fee, provided_fee)
  → ok
```

### validate_time_bounds

```
function validate_time_bounds(frame, context):
  time_bounds = extract from frame.preconditions
    (None → ok, Time(tb) → tb, V2 → V2.time_bounds)

  if time_bounds exists:
    // Check min time
    if min_time > 0 and context.close_time < min_time:
      → TOO_EARLY(min_time, context.close_time)

    // Check max time (0 means no limit)
    if max_time > 0 and context.close_time > max_time:
      → TOO_LATE(max_time, context.close_time)

  → ok
```

### validate_ledger_bounds

```
function validate_ledger_bounds(frame, context):
  // Only V2 preconditions have ledger bounds
  ledger_bounds = extract from V2 preconditions
  if no V2 preconditions: → ok

  if ledger_bounds exists:
    current = context.sequence

    if min_ledger > 0 and current < min_ledger:
      → BAD_LEDGER_BOUNDS(min_ledger, max_ledger, current)

    // 0 means no limit
    if max_ledger > 0 and current > max_ledger:
      → BAD_LEDGER_BOUNDS(min_ledger, max_ledger, current)

  → ok
```

### validate_structure

```
function validate_structure(frame):
  GUARD not frame.is_valid_structure
    → INVALID_STRUCTURE("basic structure validation failed")
  → ok
```

### validate_soroban_resources

```
function validate_soroban_resources(frame, context):
  if not frame.is_soroban: → ok

  GUARD frame.soroban_data is none
    → INVALID_STRUCTURE("missing soroban transaction data")

  data = frame.soroban_data
  footprint = data.resources.footprint

  if data.ext is V1(resource_ext):
    prev = none
    for each index in resource_ext.archived_soroban_entries:
      // Indices must be sorted and unique
      if prev exists:
        GUARD index <= prev
          → INVALID_STRUCTURE("archived soroban entry indices
                               must be sorted and unique")
      prev = index

      // Index must be within read_write footprint
      key = footprint.read_write[index]
      GUARD key not found
        → INVALID_STRUCTURE("archived soroban entry index
                             out of bounds")

      // Key must be archivable (persistent contract data or code)
      GUARD not is_archivable_soroban_key(key)
        → INVALID_STRUCTURE("archived soroban entry must be
                             a persistent contract entry")

  → ok
```

### Helper: is_archivable_soroban_key

```
function is_archivable_soroban_key(key):
  if key is ContractData:
    → key.durability == Persistent
  if key is ContractCode:
    → true
  → false
```

### validate_fee_bump_rules

"Fee bump-specific validation: outer fee >= inner fee (with base fee
multiplier), inner transaction structure, inner signature format."

```
function validate_fee_bump_rules(frame, context):
  if not frame.is_fee_bump: → ok

  fee_bump_frame = FeeBumpFrame.from_frame(frame, context.network_id)
```

**Calls:** [`validate_fee_bump`](fee_bump.pc.md#validate_fee_bump)

```
  validate_fee_bump(fee_bump_frame, context)
  // Maps FeeBumpErrors to ValidationErrors:
  //   InsufficientOuterFee → FEE_BUMP_INSUFFICIENT_FEE
  //   TooManyOperations    → FEE_BUMP_INVALID_INNER
  //   InvalidInnerTxType   → FEE_BUMP_INVALID_INNER
  //   InvalidInnerSignature→ INVALID_SIGNATURE
```

### validate_basic

"Convenience function that runs all basic checks suitable for catchup.
Does not require account data and trusts historical results."

```
function validate_basic(frame, context):
  errors = []
  run validate_structure(frame)           → collect error
  run validate_fee(frame, context)        → collect error
  run validate_time_bounds(frame, context) → collect error
  run validate_ledger_bounds(frame, context) → collect error
  run validate_soroban_resources(frame, context) → collect error
  run validate_fee_bump_rules(frame, context) → collect error

  NOTE: signature validation skipped in basic mode

  if errors is empty: → ok
  else: → errors
```

### validate_full

"Full validation with account data."

```
function validate_full(frame, context, source_account):
  errors = []
  run validate_structure(frame)                     → collect error
  run validate_fee(frame, context)                  → collect error
  run validate_time_bounds(frame, context)           → collect error
  run validate_ledger_bounds(frame, context)          → collect error
  run validate_min_seq_num(frame, source_account)    → collect error
  run validate_sequence(frame, source_account)       → collect error
  run validate_signatures(frame, context)            → collect error
  run validate_extra_signers(frame, context)         → collect error
  run validate_soroban_resources(frame, context)     → collect error
  run validate_fee_bump_rules(frame, context)        → collect error

  // Check account balance can cover fee
  available_balance = source_account.balance
  fee = frame.total_fee
  if available_balance < fee:
    errors.append(INSUFFICIENT_BALANCE)

  if errors is empty: → ok
  else: → errors
```

### Helper: fee_bump_inner_hash

```
function fee_bump_inner_hash(frame, network_id):
  if frame.envelope is FeeBump:
    inner_env = fee_bump.inner_tx
    inner_frame = TransactionFrame(inner_env, network_id)
    → inner_frame.hash(network_id)
  else:
    → frame.hash(network_id)
```

### Helper: has_required_extra_signers

```
function has_required_extra_signers(tx_hash, signatures, extra_signers):
  for each signer in extra_signers:
    if signer is Ed25519(key):
      pk = PublicKey.from_bytes(key)
      GUARD not has_ed25519_signature(tx_hash, signatures, pk)
        → false
    if signer is PreAuthTx(key):
      GUARD key != tx_hash  → false
    if signer is HashX(key):
      GUARD not has_hashx_signature(signatures, key)
        → false
    if signer is Ed25519SignedPayload(payload):
      GUARD not has_signed_payload_signature(
              tx_hash, signatures, payload)
        → false
  → true
```

### Helper: has_ed25519_signature

```
function has_ed25519_signature(tx_hash, signatures, pk):
  → any signature in signatures where
      verify_signature_with_key(tx_hash, sig, pk)
```

### Helper: has_hashx_signature

```
function has_hashx_signature(signatures, key):
  → any signature in signatures where:
      sig.signature length == 32
      and sig.hint == key[28..32]
      and SHA256(sig.signature) == key
```

### Helper: has_signed_payload_signature

"CAP-0040: signed payload signer requires a valid signature of the
payload from the ed25519 public key."

```
function has_signed_payload_signature(tx_hash, signatures, signed_payload):
  pk = PublicKey.from_bytes(signed_payload.ed25519)

  "The hint for signed payloads is XOR of pubkey hint and payload hint.
   See SignatureUtils::getSignedPayloadHint in stellar-core."
  pubkey_hint = signed_payload.ed25519[28..32]
  if signed_payload.payload.length >= 4:
    payload_hint = signed_payload.payload[last 4 bytes]
  else:
    payload_hint = signed_payload.payload padded to 4 bytes
  expected_hint = pubkey_hint XOR payload_hint

  → any signature in signatures where:
      sig.hint == expected_hint
      and verify(pk, signed_payload.payload, sig.signature)
```

### verify_signature_with_key

```
function verify_signature_with_key(tx_hash, sig, public_key):
  key_bytes = public_key.as_bytes
  expected_hint = key_bytes[28..32]

  GUARD sig.hint != expected_hint  → false

  → verify_hash(public_key, tx_hash, sig.signature)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 837    | 207        |
| Functions     | 17     | 17         |
