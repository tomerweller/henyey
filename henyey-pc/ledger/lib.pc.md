## Pseudocode: crates/ledger/src/lib.rs

"Ledger management for rs-stellar-core."
"This crate provides the core ledger state management and ledger close pipeline
for the Stellar network. It coordinates transaction execution, state updates,
bucket list modifications, and ledger metadata generation."

### Data Structures

```
struct LedgerInfo:
  sequence            : u32
  previous_ledger_hash: Hash256
  bucket_list_hash    : Hash256
  close_time          : u64
  base_fee            : u32
  base_reserve        : u32
  protocol_version    : u32

enum LedgerChange:
  Create(LedgerEntry)
  Update(LedgerEntry)
  Delete(LedgerKey)
```

### Helper: LedgerInfo.from_header

```
function from_header(header):
  → LedgerInfo {
    sequence            = header.ledger_seq,
    previous_ledger_hash= header.previous_ledger_hash,
    bucket_list_hash    = header.bucket_list_hash,
    close_time          = header.scp_value.close_time,
    base_fee            = header.base_fee,
    base_reserve        = header.base_reserve,
    protocol_version    = header.ledger_version
  }
```

---

### fees::calculate_fee

"Computes the minimum required fee based on operation count and base fee.
The actual charged fee is capped by the transaction's declared maximum."

```
function calculate_fee(tx, base_fee):
  num_ops = length(tx.operations)
  min_fee = num_ops * base_fee
  "The transaction's fee field is the maximum
   the user is willing to pay"
  → min(tx.fee, min_fee)
```

### fees::calculate_envelope_fee

"Handles all transaction envelope types (V0, V1, and fee bump).
For fee bump transactions, uses the outer transaction's fee."

```
function calculate_envelope_fee(env, base_fee):
  if env is TxV0:
    num_ops = length(env.tx.operations)
    → num_ops * base_fee
  if env is Tx:
    → calculate_fee(env.tx, base_fee)
  if env is TxFeeBump:
    "For fee bump, use the outer fee"
    → env.tx.fee
```

### fees::can_afford_fee

```
function can_afford_fee(account, fee):
  available = available_balance(account)
  → available >= fee
```

### fees::available_balance

"Returns the account balance minus selling liabilities."

```
function available_balance(account):
  selling_liabilities = 0
  if account.ext is V1:
    selling_liabilities = account.ext.v1.liabilities.selling
  "Available = balance - selling_liabilities
   (reserves are checked separately)"
  → account.balance - selling_liabilities
```

---

CONST STROOPS_PER_XLM = 10_000_000  // 1 XLM = 10,000,000 stroops

### reserves::minimum_balance

"The amount of XLM that must be held in reserve and cannot be spent."

"Formula: (2 + num_sub_entries + num_sponsoring - num_sponsored) * base_reserve"

```
function minimum_balance(account, base_reserve):
  num_sponsoring = 0
  num_sponsored  = 0
  if account.ext is V1:
    if account.ext.v1.ext is V2:
      num_sponsoring = account.ext.v1.ext.v2.num_sponsoring
      num_sponsored  = account.ext.v1.ext.v2.num_sponsored
  "Base account entries (2) + sub entries
   + sponsoring - sponsored"
  num_entries = 2 + account.num_sub_entries
              + num_sponsoring - num_sponsored
  → num_entries * base_reserve
```

### reserves::selling_liabilities

```
function selling_liabilities(account):
  if account.ext is V0:
    → 0
  if account.ext is V1:
    → account.ext.v1.liabilities.selling
```

### reserves::buying_liabilities

```
function buying_liabilities(account):
  if account.ext is V0:
    → 0
  if account.ext is V1:
    → account.ext.v1.liabilities.buying
```

### reserves::available_to_send

"Maximum amount of XLM that can be transferred out while
maintaining the minimum balance and honoring open offers."

"Formula: balance - minimum_balance - selling_liabilities"

```
function available_to_send(account, base_reserve):
  min_bal   = minimum_balance(account, base_reserve)
  sell_liab = selling_liabilities(account)
  → saturating_sub(
      saturating_sub(account.balance, min_bal),
      sell_liab)
```

### reserves::available_to_receive

"Maximum amount of XLM that can be received before hitting
the maximum balance limit (INT64_MAX stroops)."

"Formula: INT64_MAX - balance - buying_liabilities"

```
function available_to_receive(account):
  buy_liab = buying_liabilities(account)
  → saturating_sub(
      saturating_sub(INT64_MAX, account.balance),
      buy_liab)
```

### reserves::can_add_sub_entry

"Adding a sub-entry increases the minimum balance requirement
by one base reserve."

```
function can_add_sub_entry(account, base_reserve):
  current_min = minimum_balance(account, base_reserve)
  new_min     = current_min + base_reserve
  sell_liab   = selling_liabilities(account)
  → account.balance >= new_min + sell_liab
```

---

### trustlines::selling_liabilities

```
function selling_liabilities(trustline):
  if trustline.ext is V0:
    → 0
  if trustline.ext is V1:
    → trustline.ext.v1.liabilities.selling
```

### trustlines::buying_liabilities

```
function buying_liabilities(trustline):
  if trustline.ext is V0:
    → 0
  if trustline.ext is V1:
    → trustline.ext.v1.liabilities.buying
```

### trustlines::available_to_send

"Maximum amount of the asset that can be transferred out
while honoring open sell offers."

"Formula: balance - selling_liabilities"

```
function available_to_send(trustline):
  → saturating_sub(trustline.balance,
                    selling_liabilities(trustline))
```

### trustlines::available_to_receive

"Maximum amount of the asset that can be received before
hitting the trustline limit, accounting for buying liabilities."

"Formula: limit - balance - buying_liabilities"

```
function available_to_receive(trustline):
  → saturating_sub(
      saturating_sub(trustline.limit, trustline.balance),
      buying_liabilities(trustline))
```

### trustlines::can_add_selling_liabilities

"Check if adding delta to selling liabilities would be valid."
"Requirements: current_selling + delta >= 0 and <= balance"

```
function can_add_selling_liabilities(trustline, delta):
  current  = selling_liabilities(trustline)
  new_liab = checked_add(current, delta)
  GUARD overflow                → false
  GUARD new_liab < 0           → false
  GUARD new_liab > trustline.balance → false
  → true
```

### trustlines::can_add_buying_liabilities

"Check if adding delta to buying liabilities would be valid."
"Requirements: current_buying + delta >= 0 and <= limit - balance"

```
function can_add_buying_liabilities(trustline, delta):
  current  = buying_liabilities(trustline)
  new_liab = checked_add(current, delta)
  GUARD overflow                          → false
  GUARD new_liab < 0                      → false
  GUARD new_liab > trustline.limit - trustline.balance → false
  → true
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 541    | 176        |
| Functions     | 15     | 15         |
