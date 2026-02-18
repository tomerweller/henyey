## Pseudocode: crates/tx/src/result.rs

"Transaction and operation result types."
"Wrapper types around XDR result structures for easier handling and inspection."

### TxApplyResult (struct)

```
TxApplyResult:
  success       // bool
  fee_charged   // stroops
  result        // TxResultWrapper
```

### TxResultWrapper (struct)

```
TxResultWrapper:
  inner         // XDR TransactionResult
```

### TxResultWrapper::is_success

```
function is_success() → bool:
  → inner.result is TxSuccess or TxFeeBumpInnerSuccess
```

### TxResultWrapper::result_code

```
function result_code() → TxResultCode:
  → map inner.result variant to TxResultCode enum
    // 1:1 mapping of all 19 XDR variants
```

### TxResultWrapper::operation_results

```
function operation_results() → list or null:
  if inner.result is TxSuccess or TxFailed:
    → wrap each OperationResult as OpResultWrapper

  if inner.result is TxFeeBumpInnerSuccess or TxFeeBumpInnerFailed:
    inner_result = inner.result.inner_pair.result
    if inner_result is TxSuccess or TxFailed:
      → wrap each OperationResult as OpResultWrapper
    → null

  → null
```

### TxResultWrapper::successful_operation_count

```
function successful_operation_count() → int:
  results = operation_results()
  if results is null:
    → 0
  → count of results where is_success() is true
```

### TxResultWrapper::failed_operation_count

```
function failed_operation_count() → int:
  results = operation_results()
  if results is null:
    → 0
  → count of results where is_success() is false
```

### TxResultCode (enum)

```
TxResultCode:
  TxFeeBumpInnerSuccess, TxFeeBumpInnerFailed,
  TxSuccess, TxFailed,
  TxTooEarly, TxTooLate, TxMissingOperation,
  TxBadSeq, TxBadAuth, TxInsufficientBalance,
  TxNoAccount, TxInsufficientFee, TxBadAuthExtra,
  TxInternalError, TxNotSupported, TxBadSponsorship,
  TxBadMinSeqAgeOrGap, TxMalformed, TxSorobanInvalid
```

### OpResultWrapper (struct)

```
OpResultWrapper:
  inner         // XDR OperationResult
```

### OpResultWrapper::is_success

```
function is_success() → bool:
  GUARD inner is not OpInner → false
  → check inner operation-specific result is Success variant
    // checks all 26 operation types: CreateAccount, Payment,
    // PathPaymentStrictReceive, ManageSellOffer,
    // CreatePassiveSellOffer, SetOptions, ChangeTrust,
    // AllowTrust, AccountMerge, Inflation, ManageData,
    // BumpSequence, ManageBuyOffer, PathPaymentStrictSend,
    // CreateClaimableBalance, ClaimClaimableBalance,
    // BeginSponsoringFutureReserves,
    // EndSponsoringFutureReserves, RevokeSponsorship,
    // Clawback, ClawbackClaimableBalance,
    // SetTrustLineFlags, LiquidityPoolDeposit,
    // LiquidityPoolWithdraw, InvokeHostFunction,
    // ExtendFootprintTtl, RestoreFootprint
```

### OpResultCode (enum)

```
OpResultCode:
  OpInner, OpBadAuth, OpNoAccount,
  OpNotSupported, OpTooManySubentries,
  OpExceededWorkLimit, OpTooManySponsoring
```

---

### RefundableFeeTracker (struct)

"Tracks refundable resources and fees for Soroban transactions."
"During Soroban execution, various resources are consumed that may be"
"partially refundable if not fully used."

```
RefundableFeeTracker:
  max_refundable_fee           // from transaction
  consumed_events_size_bytes   // contract events size
  consumed_rent_fee            // accumulated rent fee
  consumed_refundable_fee      // total consumed refundable
```

### RefundableFeeTracker::consume_rent_fee

```
function consume_rent_fee(rent_fee):
  MUTATE consumed_rent_fee += rent_fee

  GUARD max_refundable_fee < consumed_rent_fee
    → error(RentFeeExceeded)

  "Update total consumed"
  MUTATE consumed_refundable_fee = consumed_rent_fee
```

### RefundableFeeTracker::consume_events_size

```
function consume_events_size(size_bytes):
  MUTATE consumed_events_size_bytes += size_bytes
```

### RefundableFeeTracker::update_consumed_refundable_fee

"Called after computing the actual resource fee based on consumption."

```
function update_consumed_refundable_fee(refundable_fee):
  MUTATE consumed_refundable_fee = consumed_rent_fee + refundable_fee

  GUARD max_refundable_fee < consumed_refundable_fee
    → error(RefundableFeeExceeded)
```

### RefundableFeeTracker::get_fee_refund

```
function get_fee_refund() → int:
  → max_refundable_fee - consumed_refundable_fee
```

### RefundableFeeTracker::reset_consumed_fee

"When a transaction fails, all consumed fees are reset so that the"
"maximum refund is returned to the fee source."

```
function reset_consumed_fee():
  MUTATE consumed_events_size_bytes = 0
  MUTATE consumed_rent_fee = 0
  MUTATE consumed_refundable_fee = 0
```

---

### MutableTransactionResult (struct)

"Mutable transaction result for use during transaction execution."

```
MutableTransactionResult:
  inner                    // XDR TransactionResult being built
  refundable_fee_tracker   // optional RefundableFeeTracker for Soroban
```

### MutableTransactionResult::new

```
function new(fee_charged):
  inner = TransactionResult {
    fee_charged: fee_charged,
    result: TxSuccess(empty ops),
  }
  refundable_fee_tracker = null
```

### MutableTransactionResult::create_error

```
function create_error(code, fee_charged):
  result = map code to corresponding XDR result variant
    // handles all 19 result codes
    // fee bump codes get empty inner result pairs
  → MutableTransactionResult { inner: { fee_charged, result } }
```

### MutableTransactionResult::create_success

```
function create_success(fee_charged, op_count):
  results = array of op_count placeholder success results
  → MutableTransactionResult {
      inner: { fee_charged, result: TxSuccess(results) }
    }
```

### MutableTransactionResult::set_error

"Also resets any consumed refundable fees so maximum refund is returned."

```
function set_error(code):
  MUTATE inner.result = map code to XDR result variant
    // fee bump codes handled separately → TxInternalError

  "Reset refundable fees on error"
  if refundable_fee_tracker exists:
    refundable_fee_tracker.reset_consumed_fee()
```

**Calls**: [reset_consumed_fee](#refundablesfeetrackerrreset_consumed_fee)

### MutableTransactionResult::finalize_fee_refund

"Called after transaction execution completes. Applies the refund to reduce fee_charged."

```
function finalize_fee_refund(protocol_version):
  if refundable_fee_tracker exists:
    MUTATE inner.fee_charged -= refundable_fee_tracker.get_fee_refund()
```

**Calls**: [get_fee_refund](#refundablefeetrackerget_fee_refund)

### MutableTransactionResult::is_success

```
function is_success() → bool:
  → inner.result is TxSuccess or TxFeeBumpInnerSuccess
```

---

### TxSetResultSummary (struct)

"Aggregates statistics across multiple transactions."

```
TxSetResultSummary:
  total                  // total transactions
  successful             // successful transactions
  failed                 // failed transactions
  total_fee              // total fee charged
  total_operations       // total operations
  successful_operations  // successful operations
```

### TxSetResultSummary::add

```
function add(result, op_count):
  MUTATE total += 1
  MUTATE total_fee += result.fee_charged
  MUTATE total_operations += op_count

  if result.success:
    MUTATE successful += 1
    MUTATE successful_operations +=
      result.result.successful_operation_count()
  else:
    MUTATE failed += 1
```

**Calls**: [successful_operation_count](#txresultwrappersuccessful_operation_count)

### TxSetResultSummary::success_rate

```
function success_rate() → float:
  if total == 0:
    → 0.0
  → (successful / total) * 100.0
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 913    | ~190       |
| Functions     | 28     | 21         |

NOTE: 7 trivial accessor/constructor functions omitted (from_xdr, into_xdr,
as_xdr, fee_charged getters, set_fee_charged, into_wrapper,
initialize_refundable_fee_tracker).
