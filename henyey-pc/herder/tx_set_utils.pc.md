## Pseudocode: crates/herder/src/tx_set_utils.rs

"Transaction set utility functions for filtering invalid transactions from
candidate transaction sets. Used during nomination (to build valid tx sets)
and post-ledger-close (to ban transactions that became invalid)."

"Mirrors TxSetUtils::getInvalidTxList() and TxSetUtils::trimInvalid()
from stellar-core src/herder/TxSetUtils.cpp."

### Data: CloseTimeBounds

"In upstream stellar-core, lowerBoundCloseTimeOffset and upperBoundCloseTimeOffset
create a range of possible close times during nomination (since the exact close
time is not yet known). For post-ledger-close validation, both offsets are 0."

```
CloseTimeBounds:
  lower_bound_offset    // offset for min_time validation
  upper_bound_offset    // offset for max_time validation
```

### Data: TxSetValidationContext

"Provides ledger state information needed to validate transactions against
the next ledger (LCL + 1)."

```
TxSetValidationContext:
  next_ledger_seq       // LCL + 1
  close_time
  base_fee
  base_reserve
  protocol_version
  network_id
```

---

### CloseTimeBounds::exact

```
function exact() → CloseTimeBounds:
  → CloseTimeBounds { lower_bound_offset: 0, upper_bound_offset: 0 }
```

### CloseTimeBounds::with_offsets

```
function with_offsets(lower, upper) → CloseTimeBounds:
  → CloseTimeBounds { lower_bound_offset: lower, upper_bound_offset: upper }
```

### TxSetValidationContext::new

```
function new(last_closed_ledger_seq, close_time, base_fee,
             base_reserve, protocol_version, network_id):
  → TxSetValidationContext {
      next_ledger_seq: saturating_add(last_closed_ledger_seq, 1),
      close_time, base_fee, base_reserve, protocol_version, network_id }
```

### Helper: to_ledger_context

```
function to_ledger_context(close_time) → LedgerContext:
  → LedgerContext(next_ledger_seq, close_time, base_fee,
                  base_reserve, protocol_version, network_id)
```

---

### get_invalid_tx_list

"Mirrors TxSetUtils::getInvalidTxList() in stellar-core.
Validates each transaction using validate_basic against a ledger context
for the next ledger (LCL + 1)."

```
function get_invalid_tx_list(txs, ctx, close_time_bounds)
    → list<TransactionEnvelope>:

  invalid_txs = []

  "For time bounds validation during nomination, upstream uses the upper
  bound close time for max_time checks and lower bound for min_time checks."
  upper_close_time = ctx.close_time + close_time_bounds.upper_bound_offset
  lower_close_time = ctx.close_time + close_time_bounds.lower_bound_offset

  upper_ledger_ctx = ctx.to_ledger_context(upper_close_time)
  need_lower_check = (lower_close_time != upper_close_time)

  for each tx in txs:
    frame = TransactionFrame(tx, ctx.network_id)

    "Validate with upper bound close time (catches max_time violations)"
    if validate_basic(frame, upper_ledger_ctx) fails:
      invalid_txs.append(tx)
      continue

    "If offsets differ, also validate with lower bound (catches min_time violations)"
    if need_lower_check:
      lower_ledger_ctx = ctx.to_ledger_context(lower_close_time)
      if validate_basic(frame, lower_ledger_ctx) fails:
        invalid_txs.append(tx)

  → invalid_txs
```

**Calls:** [`validate_basic`](../tx/validate.pc.md)

### trim_invalid

"Mirrors TxSetUtils::trimInvalid() in stellar-core. Finds invalid
transactions, then removes them from the input set using hash comparison."

```
function trim_invalid(txs, ctx, close_time_bounds)
    → (valid_txs, invalid_txs):

  invalid_txs = get_invalid_tx_list(txs, ctx, close_time_bounds)

  if invalid_txs is empty:
    → (txs, [])

  valid_txs = remove_txs(txs, invalid_txs)
  → (valid_txs, invalid_txs)
```

### Helper: remove_txs

"Equivalent to removeTxs() in TxSetUtils.cpp."

```
function remove_txs(txs, txs_to_remove) → list<TransactionEnvelope>:
  remove_set = set of hash(tx) for each tx in txs_to_remove
  → [tx for tx in txs where hash(tx) not in remove_set]
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~125   | ~55        |
| Functions     | 7      | 7          |
