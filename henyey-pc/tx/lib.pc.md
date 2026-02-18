## Pseudocode: crates/tx/src/lib.rs

"Transaction processing for rs-stellar-core."
"This crate provides the core transaction validation and execution logic for"
"the Stellar network, supporting both classic Stellar operations and Soroban"
"smart contract execution."

NOTE: This file is primarily a module declaration and re-export hub. The
production logic consists of enum definitions, a From conversion, and two
high-level facade types (TransactionValidator, TransactionExecutor).

---

### Enum: ValidationResult

"Summary result of transaction validation."

```
enum ValidationResult:
  Valid
  InvalidSignature
  InsufficientFee
  BadSequence
  NoAccount
  InsufficientBalance
  TooLate
  TooEarly
  BadMinSeqAgeOrGap
  BadAuthExtra
  Invalid
```

---

### ValidationResult from ValidationError

```
function validation_result_from(err):
  if err is InvalidStructure:       → Invalid
  if err is InvalidSignature:       → InvalidSignature
  if err is MissingSignatures:      → InvalidSignature
  if err is BadSequence:            → BadSequence
  if err is InsufficientFee:        → InsufficientFee
  if err is SourceAccountNotFound:  → NoAccount
  if err is InsufficientBalance:    → InsufficientBalance
  if err is TooLate:                → TooLate
  if err is TooEarly:               → TooEarly
  if err is BadLedgerBounds(min, max, current):
    if max > 0 AND current > max:   → TooLate
    if min > 0 AND current < min:   → TooEarly
    else:                            → Invalid
  if err is BadMinAccountSequence:          → BadSequence
  if err is BadMinAccountSequenceAge:       → BadMinSeqAgeOrGap
  if err is BadMinAccountSequenceLedgerGap: → BadMinSeqAgeOrGap
  if err is ExtraSignersNotMet:             → BadAuthExtra
  if err is FeeBumpInsufficientFee:         → InsufficientFee
  if err is FeeBumpInvalidInner:            → Invalid
```

---

### TransactionValidator

"High-level transaction validator."

```
struct TransactionValidator:
  context: LedgerContext
```

### TransactionValidator.new

```
function TransactionValidator.new(context):
  → TransactionValidator { context }
```

### TransactionValidator.testnet

```
function TransactionValidator.testnet(sequence, close_time):
  → TransactionValidator { context: LedgerContext.testnet(sequence, close_time) }
```

### TransactionValidator.mainnet

```
function TransactionValidator.mainnet(sequence, close_time):
  → TransactionValidator { context: LedgerContext.mainnet(sequence, close_time) }
```

### TransactionValidator.validate

"Validate a transaction envelope (basic checks only)."

```
function validate(tx_envelope):
  frame = TransactionFrame.new(tx_envelope)
  errors = validate_basic(frame, self.context)
  if no errors:
    → Valid
  else:
    "Return the first error"
    → validation_result_from(errors[0])
```

**Calls:** `validate_basic` REF: validation::validate_basic

### TransactionValidator.validate_with_account

"Full validation with account data."

```
function validate_with_account(tx_envelope, source_account):
  frame = TransactionFrame.new(tx_envelope)
  errors = validate_full(frame, self.context, source_account)
  if no errors:
    → Valid
  else:
    → validation_result_from(errors[0])
```

**Calls:** `validate_full` REF: validation::validate_full

### TransactionValidator.check_signatures

```
function check_signatures(tx_envelope):
  frame = TransactionFrame.new(tx_envelope)
  → validate_signatures(frame, self.context) succeeds
```

**Calls:** `validate_signatures` REF: validation::validate_signatures

---

### TransactionExecutor

"Transaction executor for applying transactions."

```
struct TransactionExecutor:
  _context: ApplyContext
```

### TransactionExecutor.new

```
function TransactionExecutor.new(context):
  → TransactionExecutor { _context: context }
```

### TransactionExecutor.execute

"Note: For full live execution, use execute_with_state."

```
function execute(tx_envelope, delta):
  → error("use execute_with_state or apply_from_history")
```

### TransactionExecutor.apply_historical

"Apply a transaction from history (for catchup)."

```
function apply_historical(tx_envelope, result, meta, delta):
  frame = TransactionFrame.new(tx_envelope)
  → apply_from_history(frame, result, meta, delta)
```

**Calls:** `apply_from_history` REF: apply::apply_from_history

---

### Struct: TransactionResult (simplified)

"Simplified transaction execution result."

```
struct TransactionResult:
  fee_charged: int64
  operation_results: list of OperationResult
  success: bool
```

### TransactionResult from TxApplyResult

```
function transaction_result_from(result):
  op_results = []
  for each op in result.operation_results():
    if op.is_success():
      op_results.append(Success)
    else:
      op_results.append(Failed(OpFailed))

  → TransactionResult {
      fee_charged: result.fee_charged,
      operation_results: op_results,
      success: result.success
    }
```

---

### Enum: OperationResult

```
enum OperationResult:
  Success
  Failed(OperationError)
```

### Enum: OperationError

```
enum OperationError:
  OpFailed
  NoAccount
  Underfunded
  LineFull
  NotAuthorized
  Other(string)
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~280   | ~120       |
| Functions     | 10     | 10         |
