## Pseudocode: crates/tx/src/operations/execute/payment.rs

### execute_payment

"Transfers assets from source account to destination.
For native assets, the transfer is direct. For credit assets,
both accounts must have trustlines for the asset."

```
function execute_payment(op, source, state, context):
  dest = muxed_to_account_id(op.destination)

  "Amount must be positive"
  GUARD op.amount <= 0                         → MALFORMED

  "Asset must be valid (stellar-core doCheckValid)"
  GUARD not is_asset_valid(op.asset)           → MALFORMED

  "stellar-core optimization: if sending native XLM to self,
   mark as instant success without accessing any ledger entries.
   This matches behavior from protocol v3+.
   (Before v3, this applied to all asset types, but we only support v23+)"
  if source == dest and op.asset is Native:
    → SUCCESS

  "stellar-core delegates ALL payments to PathPaymentStrictReceive
   (PaymentOpFrame.cpp:56-126). Build the equivalent operation
   and translate results."
  pp_op = PathPaymentStrictReceiveOp {
    send_asset:   op.asset,
    send_max:     op.amount,
    destination:  op.destination,
    dest_asset:   op.asset,
    dest_amount:  op.amount,
    path:         []
  }
```

**Calls:** [`execute_path_payment_strict_receive`](path_payment.pc.md#execute_path_payment_strict_receive)

```
  pp_result = execute_path_payment_strict_receive(
                pp_op, source, state, context)

  "Translate PathPaymentStrictReceive result codes
   to Payment result codes"
  payment_code = translate_result_code(pp_result)
  → payment_code
```

### Helper: translate_result_code

```
function translate_result_code(pp_result):
  mapping:
    PP_SUCCESS           → PAY_SUCCESS
    PP_MALFORMED         → PAY_MALFORMED
    PP_UNDERFUNDED       → PAY_UNDERFUNDED
    PP_SRC_NOT_AUTHORIZED → PAY_SRC_NOT_AUTHORIZED
    PP_SRC_NO_TRUST      → PAY_SRC_NO_TRUST
    PP_NO_DESTINATION    → PAY_NO_DESTINATION
    PP_NO_TRUST          → PAY_NO_TRUST
    PP_NOT_AUTHORIZED    → PAY_NOT_AUTHORIZED
    PP_LINE_FULL         → PAY_LINE_FULL
    PP_NO_ISSUER         → PAY_NO_ISSUER
    otherwise            → PAY_MALFORMED
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 113    | 48         |
| Functions     | 2      | 2          |
