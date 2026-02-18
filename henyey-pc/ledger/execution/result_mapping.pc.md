## Pseudocode: crates/ledger/src/execution/result_mapping.rs

### map_failure_to_result

```
map_failure_to_result(failure):
  "Direct mapping from ExecutionFailure enum to TransactionResultResult"
  return lookup:
    Malformed           → TxMalformed
    MissingOperation    → TxMissingOperation
    InvalidSignature    → TxBadAuth
    BadAuthExtra        → TxBadAuthExtra
    BadMinSeqAgeOrGap   → TxBadMinSeqAgeOrGap
    TooEarly            → TxTooEarly
    TooLate             → TxTooLate
    BadSequence         → TxBadSeq
    InsufficientFee     → TxInsufficientFee
    InsufficientBalance → TxInsufficientBalance
    NoAccount           → TxNoAccount
    NotSupported        → TxNotSupported
    InternalError       → TxInternalError
    BadSponsorship      → TxBadSponsorship
    OperationFailed     → TxFailed(empty op results)
```

### insufficient_refundable_fee_result

```
insufficient_refundable_fee_result(op):
  if op is InvokeHostFunction:
    → InvokeHostFunction::InsufficientRefundableFee
  if op is ExtendFootprintTtl:
    → ExtendFootprintTtl::InsufficientRefundableFee
  if op is RestoreFootprint:
    → RestoreFootprint::InsufficientRefundableFee
  otherwise:
    → OpNotSupported
```

### map_failure_to_inner_result

```
map_failure_to_inner_result(failure, op_results):
  "Same mapping as map_failure_to_result but for InnerTransactionResultResult"
  "Used for fee-bump inner transaction results"
  return lookup:
    Malformed           → TxMalformed
    MissingOperation    → TxMissingOperation
    InvalidSignature    → TxBadAuth
    BadAuthExtra        → TxBadAuthExtra
    BadMinSeqAgeOrGap   → TxBadMinSeqAgeOrGap
    TooEarly            → TxTooEarly
    TooLate             → TxTooLate
    BadSequence         → TxBadSeq
    InsufficientFee     → TxInsufficientFee
    InsufficientBalance → TxInsufficientBalance
    NoAccount           → TxNoAccount
    NotSupported        → TxNotSupported
    InternalError       → TxInternalError
    BadSponsorship      → TxBadSponsorship
    OperationFailed     → TxFailed(op_results)
```

### build_tx_result_pair

```
build_tx_result_pair(frame, network_id, exec, base_fee, protocol_version):
  tx_hash = frame.hash(network_id)
  op_results = exec.operation_results

  if frame.is_fee_bump():
    inner_hash = fee_bump_inner_hash(frame, network_id)
```

**Calls**: [fee_bump_inner_hash](signatures.pc.md#fee_bump_inner_hash) | [map_failure_to_inner_result](#map_failure_to_inner_result) | [map_failure_to_result](#map_failure_to_result)

```
    if exec.success:
      inner_result = TxSuccess(op_results)
    else if exec.failure exists:
      inner_result = map_failure_to_inner_result(failure, op_results)
    else:
      inner_result = TxFailed(op_results)

    --- Inner fee calculation ---
    "Protocol >= 25: 0 (outer pays everything)"
    "Protocol < 25 and protocol >= 11:"
    "  - For Soroban: resourceFee + min(inclusionFee, baseFee * numOps) - refund"
    "    (stellar-core had a bug where refund was applied to inner fee;"
    "     this was fixed in p25)"
    "  - For classic: min(inner_fee, baseFee * numOps)"

    @version(≥25):
      inner_fee_charged = 0
    @version(<25):
      num_inner_ops = frame.operation_count()
      adjusted_fee = base_fee * max(1, num_inner_ops)
      if frame.is_soroban():
        resource_fee = frame.declared_soroban_resource_fee()
        inner_fee = frame.inner_fee()
        inclusion_fee = inner_fee - resource_fee
        computed_fee = resource_fee + min(inclusion_fee, adjusted_fee)
        "Prior to protocol 25, stellar-core incorrectly applied the refund"
        "to the inner feeCharged field for fee bump transactions."
        inner_fee_charged = computed_fee - exec.fee_refund
      else:
        inner_fee_charged = min(frame.inner_fee(), adjusted_fee)

    inner_pair = { inner_hash, inner_fee_charged, inner_result }

    if exec.success:
      result = TxFeeBumpInnerSuccess(inner_pair)
    else:
      result = TxFeeBumpInnerFailed(inner_pair)

    → { fee_charged: exec.fee_charged, result }

  else if exec.success:
    → { fee_charged: exec.fee_charged, TxSuccess(op_results) }

  else if exec.failure exists:
    if failure is OperationFailed:
      result = TxFailed(op_results)
    else:
      result = map_failure_to_result(failure)
    → { fee_charged: exec.fee_charged, result }

  else:
    → { fee_charged: exec.fee_charged, TxFailed(op_results) }

  → TransactionResultPair { tx_hash, result }
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 177    | 90         |
| Functions     | 4      | 4          |
