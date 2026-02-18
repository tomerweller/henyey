## Pseudocode: crates/tx/src/fee_bump.rs

"Fee bump transaction handling (CAP-0015)."
"Fee bump transactions wrap an existing inner transaction and provide"
"a new fee paid by a potentially different account."

---

### Enum: FeeBumpError

```
enum FeeBumpError:
  NotFeeBump
  InsufficientOuterFee { outer_fee, required_min }
  TooManyOperations(count)
  InvalidInnerTxType
  InvalidInnerSignature
  HashError(message)
```

---

### FeeBumpFrame

```
struct FeeBumpFrame:
  frame: TransactionFrame       // outer fee bump frame
  inner_frame: TransactionFrame // the wrapped inner V1 tx
  network_id: NetworkId
  inner_hash: optional Hash256  // cached
```

### FeeBumpFrame.from_envelope

```
function from_envelope(envelope, network_id):
  GUARD envelope is NOT TxFeeBump → NotFeeBump

  inner_envelope = envelope.tx.inner_tx
  inner_frame = TransactionFrame.with_network(
    Tx(inner_envelope), network_id)

  → FeeBumpFrame {
      frame: TransactionFrame.with_network(envelope, network_id),
      inner_frame,
      network_id,
      inner_hash: null
    }
```

### FeeBumpFrame.from_frame

```
function from_frame(frame, network_id):
  GUARD NOT frame.is_fee_bump() → NotFeeBump

  inner_envelope = frame.envelope().tx.inner_tx
  inner_frame = TransactionFrame.with_network(
    Tx(inner_envelope), network_id)

  → FeeBumpFrame { frame, inner_frame, network_id, inner_hash: null }
```

### FeeBumpFrame — accessors

```
function fee_source():            → fee_bump_tx().fee_source
function fee_source_account_id(): → muxed_to_account_id(fee_source())
function inner_source():          → inner_envelope().tx.source_account
function inner_source_account_id(): → muxed_to_account_id(inner_source())
function outer_fee():             → fee_bump_tx().fee
function inner_fee():             → inner_envelope().tx.fee
function operation_count():       → inner_envelope().tx.operations.len()
function outer_signatures():      → fee_bump_envelope().signatures
function inner_signatures():      → inner_envelope().signatures
function hash():                  → frame.hash(network_id)
function sequence_number():       → inner_envelope().tx.seq_num
function is_soroban():            → inner_frame.is_soroban()
function declared_soroban_resource_fee(): → inner_frame.declared_soroban_resource_fee()
function refundable_fee():        → inner_frame.refundable_fee()
function fee_source_is_inner_source():
  → fee_source_account_id() == inner_source_account_id()
```

### FeeBumpFrame.inner_transaction_hash

"Compute and cache the inner transaction hash."

```
function inner_transaction_hash():
  if inner_hash is cached:
    → inner_hash
  hash = inner_frame.hash(network_id)
  inner_hash = hash  // cache
  → hash
```

---

### validate_fee_bump

"Validates fee bump specific rules."
"Mirrors stellar-core FeeBumpTransactionFrame::commonValidPreSeqNum."

```
function validate_fee_bump(frame, context):

  --- Phase 1: Inclusion fee validation ---
  op_count = frame.operation_count()
  outer_op_count = max(1, op_count + 1)
  outer_min_inclusion_fee = outer_op_count * context.base_fee
  outer_inclusion_fee = frame.frame().inclusion_fee()

  GUARD outer_inclusion_fee < outer_min_inclusion_fee
    → InsufficientOuterFee

  inner_inclusion_fee = frame.inner_frame().inclusion_fee()

  if inner_inclusion_fee >= 0:
    inner_min_inclusion_fee = max(1, op_count) * context.base_fee
    "Cross-multiplication to avoid division"
    v1 = outer_inclusion_fee * inner_min_inclusion_fee
    v2 = inner_inclusion_fee * outer_min_inclusion_fee
    if v1 < v2:
      required_outer = ceil(v2 / inner_min_inclusion_fee)
      GUARD true → InsufficientOuterFee(
        max(outer_min_inclusion_fee, required_outer))
  else:
    "Negative inner inclusion fee only allowed for Soroban"
    GUARD NOT frame.inner_frame().is_soroban() → InvalidInnerTxType

  --- Phase 2: Operation count validation ---
  GUARD frame.operation_count() == 0 → TooManyOperations(0)
  GUARD frame.operation_count() > 100 → TooManyOperations

  --- Phase 3: Inner hash computation ---
  inner_hash = frame.inner_transaction_hash()

  --- Phase 4: Inner signature well-formedness ---
  for each sig in frame.inner_signatures():
    GUARD sig.signature length != 64 → InvalidInnerSignature

  NOTE: Full inner signature verification (checking against account
  signers) requires account data and is done during application.

  → ok
```

---

### verify_inner_signatures

"Performs cryptographic verification of inner signatures."

```
function verify_inner_signatures(inner_hash, signatures, public_keys):
  for each sig in signatures:
    hint = sig.hint (last 4 bytes)
    matching_key = find key in public_keys where
                   key[28..32] == hint
    if matching_key exists:
      if verify_signature_with_key(inner_hash, sig, matching_key):
        continue
    → false

  → true
```

**Calls:** `verify_signature_with_key` REF: validation::verify_signature_with_key

---

### FeeBumpMutableTransactionResult

"Mutable result for fee bump transactions."
"Tracks both outer fee bump result and inner transaction result."

```
struct FeeBumpMutableTransactionResult:
  outer_fee_charged: int64
  inner_tx_hash: Hash256
  inner_fee_charged: int64
  inner_success: bool
  inner_op_results: list of OperationResult
  inner_result_code: optional InnerTransactionResultResult
  refundable_fee_tracker: optional RefundableFeeTracker
```

### FeeBumpMutableTransactionResult.new

```
function new(outer_fee_charged, inner_tx_hash, inner_fee_charged, op_count):
  → FeeBumpMutableTransactionResult {
      outer_fee_charged,
      inner_tx_hash,
      inner_fee_charged,
      inner_success: true,
      inner_op_results: [Success placeholder] * op_count,
      inner_result_code: null,
      refundable_fee_tracker: null
    }
```

### FeeBumpMutableTransactionResult.create_error

```
function create_error(outer_fee, inner_hash, inner_fee, error_code):
  → FeeBumpMutableTransactionResult {
      outer_fee_charged: outer_fee,
      inner_tx_hash: inner_hash,
      inner_fee_charged: inner_fee,
      inner_success: false,
      inner_op_results: [],
      inner_result_code: error_code,
      refundable_fee_tracker: null
    }
```

### FeeBumpMutableTransactionResult.set_inner_error

```
function set_inner_error(code):
  inner_success = false
  inner_result_code = code
  "Reset refundable fees on error"
  if refundable_fee_tracker exists:
    refundable_fee_tracker.reset_consumed_fee()
```

### FeeBumpMutableTransactionResult.finalize_fee_refund

"For protocol < 25: Refund is applied to inner fee"
"For protocol >= 25: Inner fee is 0, refund applied to outer"

```
function finalize_fee_refund(protocol_version):
  if refundable_fee_tracker exists:
    refund = refundable_fee_tracker.get_fee_refund()

    @version(≥25):
      "All fees come from outer, so refund from outer"
      MUTATE outer_fee_charged -= refund
    @version(<25):
      "Inner fee was charged, refund applies there"
      MUTATE inner_fee_charged -= refund
```

### FeeBumpMutableTransactionResult.result_code

```
function result_code():
  if inner_success:
    → TxFeeBumpInnerSuccess
  else:
    → TxFeeBumpInnerFailed
```

### FeeBumpMutableTransactionResult.to_xdr

```
function to_xdr():
  if inner_success:
    inner_result = TxSuccess(inner_op_results)
  else:
    inner_result = inner_result_code
                   or default TxFailed(inner_op_results)

  inner_result_pair = InnerTransactionResultPair {
    transaction_hash: inner_tx_hash,
    result: InnerTransactionResult {
      fee_charged: inner_fee_charged,
      result: inner_result
    }
  }

  if inner_success:
    result = TxFeeBumpInnerSuccess(inner_result_pair)
  else:
    result = TxFeeBumpInnerFailed(inner_result_pair)

  → TransactionResult {
      fee_charged: outer_fee_charged,
      result
    }
```

---

### calculate_inner_fee_charged

"This matches stellar-core FeeBumpTransactionFrame::getInnerFullFee."

```
function calculate_inner_fee_charged(inner_declared_fee, protocol_version):
  @version(≥25):
    "Inner fee is always 0"
    → 0
  @version(<25):
    → inner_declared_fee
```

---

### wrap_inner_result_in_fee_bump

"Wrap an already-executed inner transaction result in a fee bump result."

```
function wrap_inner_result_in_fee_bump(inner_hash, inner_result, outer_fee_charged):
  inner_success = inner_result.result is TxSuccess

  inner_result_result = convert inner_result.result to
    InnerTransactionResultResult
    NOTE: For nested fee bump results, unwrap the inner pair

  inner_result_pair = InnerTransactionResultPair {
    transaction_hash: inner_hash,
    result: InnerTransactionResult {
      fee_charged: inner_result.fee_charged,
      result: inner_result_result
    }
  }

  if inner_success:
    result = TxFeeBumpInnerSuccess(inner_result_pair)
  else:
    result = TxFeeBumpInnerFailed(inner_result_pair)

  → TransactionResult {
      fee_charged: outer_fee_charged,
      result
    }
```

---

### extract_inner_hash_from_result

```
function extract_inner_hash_from_result(result):
  if result.result is TxFeeBumpInnerSuccess(pair)
     or TxFeeBumpInnerFailed(pair):
    → pair.transaction_hash
  else:
    → null
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~680   | ~220       |
| Functions     | 28     | 28         |
