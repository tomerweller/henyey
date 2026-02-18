## Pseudocode: crates/tx/src/operations/mod.rs

"Operation types, validation, and threshold classification."

### OperationType (enum)

```
OperationType:
  // Classic operations (24)
  CreateAccount, Payment, PathPaymentStrictReceive,
  ManageSellOffer, CreatePassiveSellOffer, SetOptions,
  ChangeTrust, AllowTrust, AccountMerge, Inflation,
  ManageData, BumpSequence, ManageBuyOffer,
  PathPaymentStrictSend, CreateClaimableBalance,
  ClaimClaimableBalance, BeginSponsoringFutureReserves,
  EndSponsoringFutureReserves, RevokeSponsorship,
  Clawback, ClawbackClaimableBalance, SetTrustLineFlags,
  LiquidityPoolDeposit, LiquidityPoolWithdraw,

  // Soroban operations (3)
  InvokeHostFunction, ExtendFootprintTtl, RestoreFootprint
```

### OperationType::is_soroban

```
function is_soroban() → bool:
  → type is InvokeHostFunction
    or ExtendFootprintTtl
    or RestoreFootprint
```

### OperationType::from_body

```
function from_body(body) → OperationType:
  → 1:1 mapping from OperationBody variant to OperationType
    // all 27 operation types
```

---

### validate_operation

```
function validate_operation(op) → success or error:
  dispatch on op.body type:
    CreateAccount          → validate_create_account
    Payment                → validate_payment
    PathPaymentStrictReceive → validate_path_payment_strict_receive
    PathPaymentStrictSend  → validate_path_payment_strict_send
    ManageSellOffer        → validate_manage_sell_offer
    ManageBuyOffer         → validate_manage_buy_offer
    CreatePassiveSellOffer → validate_create_passive_sell_offer
    SetOptions             → validate_set_options
    ChangeTrust            → validate_change_trust
    AllowTrust             → ok (validated by XDR)
    AccountMerge           → ok
    Inflation              → ok
    ManageData             → validate_manage_data
    BumpSequence           → validate_bump_sequence
    CreateClaimableBalance → validate_create_claimable_balance
    ClaimClaimableBalance  → ok (validated by XDR)
    BeginSponsoringFutureReserves → ok (validated by XDR)
    EndSponsoringFutureReserves   → ok
    RevokeSponsorship      → ok
    Clawback               → validate_clawback
    ClawbackClaimableBalance → ok (validated by XDR)
    SetTrustLineFlags      → ok (validated by XDR)
    LiquidityPoolDeposit   → validate_liquidity_pool_deposit
    LiquidityPoolWithdraw  → validate_liquidity_pool_withdraw
    InvokeHostFunction     → ok (Soroban validation is complex)
    ExtendFootprintTtl     → validate_extend_footprint_ttl
    RestoreFootprint       → ok (validated by XDR)
```

**Calls**: [validate_create_account](#helper-validate_create_account) | [validate_payment](#helper-validate_payment) | [validate_manage_sell_offer](#helper-validate_manage_sell_offer) | [validate_set_options](#helper-validate_set_options) | [validate_create_claimable_balance](#helper-validate_create_claimable_balance) | [validate_liquidity_pool_deposit](#helper-validate_liquidity_pool_deposit) | [validate_liquidity_pool_withdraw](#helper-validate_liquidity_pool_withdraw)

### Helper: validate_create_account

```
function validate_create_account(op):
  GUARD starting_balance <= 0 → InvalidAmount
```

### Helper: validate_payment

```
function validate_payment(op):
  GUARD amount <= 0 → InvalidAmount
```

### Helper: validate_path_payment_strict_receive

```
function validate_path_payment_strict_receive(op):
  GUARD dest_amount <= 0 → InvalidAmount
  GUARD send_max <= 0    → InvalidAmount
```

### Helper: validate_path_payment_strict_send

```
function validate_path_payment_strict_send(op):
  GUARD send_amount <= 0 → InvalidAmount
  GUARD dest_min <= 0    → InvalidAmount
```

### Helper: validate_manage_sell_offer

```
function validate_manage_sell_offer(op):
  "Amount of 0 is valid (deletes offer)"
  GUARD amount < 0          → InvalidAmount
  "Price must be positive"
  GUARD price.n <= 0 or price.d <= 0 → InvalidPrice
```

### Helper: validate_manage_buy_offer

```
function validate_manage_buy_offer(op):
  GUARD buy_amount < 0      → InvalidAmount
  GUARD price.n <= 0 or price.d <= 0 → InvalidPrice
```

### Helper: validate_create_passive_sell_offer

```
function validate_create_passive_sell_offer(op):
  GUARD amount <= 0         → InvalidAmount
  GUARD price.n <= 0 or price.d <= 0 → InvalidPrice
```

### Helper: validate_set_options

```
function validate_set_options(op):
  CONST MAX_WEIGHT = 255
  if master_weight is set:
    GUARD master_weight > MAX_WEIGHT → InvalidWeight
  if low_threshold is set:
    GUARD low_threshold > 255  → InvalidThreshold
  if med_threshold is set:
    GUARD med_threshold > 255  → InvalidThreshold
  if high_threshold is set:
    GUARD high_threshold > 255 → InvalidThreshold
```

### Helper: validate_change_trust

```
function validate_change_trust(op):
  "Limit of 0 is valid (removes trustline)"
  GUARD limit < 0 → InvalidAmount
```

### Helper: validate_manage_data

```
function validate_manage_data(op):
  GUARD data_name is empty → InvalidDataValue
  "Data value (if present) must be <= 64 bytes"
  if data_value is set:
    GUARD len(data_value) > 64 → InvalidDataValue
```

### Helper: validate_bump_sequence

```
function validate_bump_sequence(op):
  GUARD bump_to < 0 → InvalidAmount
```

### Helper: validate_create_claimable_balance

```
function validate_create_claimable_balance(op):
  GUARD amount <= 0           → InvalidAmount
  GUARD claimants is empty    → InvalidClaimant

  destinations = empty set
  for each claimant in claimants:
    "No duplicate destinations"
    GUARD destination already in destinations → InvalidClaimant
    add destination to destinations
    GUARD not validate_claim_predicate(predicate, depth=1)
      → InvalidClaimant
```

**Calls**: [validate_claim_predicate](#helper-validate_claim_predicate)

### Helper: validate_claim_predicate

```
function validate_claim_predicate(predicate, depth) → bool:
  GUARD depth > 4 → false

  if Unconditional:        → true
  if And(predicates):
    → len == 2
      AND validate_claim_predicate(predicates[0], depth+1)
      AND validate_claim_predicate(predicates[1], depth+1)
  if Or(predicates):
    → len == 2
      AND validate_claim_predicate(predicates[0], depth+1)
      AND validate_claim_predicate(predicates[1], depth+1)
  if Not(inner):
    → inner is not null
      AND validate_claim_predicate(inner, depth+1)
  if BeforeAbsoluteTime(t): → t >= 0
  if BeforeRelativeTime(t): → t >= 0
```

### Helper: validate_clawback

```
function validate_clawback(op):
  GUARD amount <= 0 → InvalidAmount
```

### Helper: validate_liquidity_pool_deposit

```
function validate_liquidity_pool_deposit(op):
  GUARD max_amount_a <= 0  → InvalidAmount
  GUARD max_amount_b <= 0  → InvalidAmount
  GUARD min_price.n <= 0 or min_price.d <= 0
    or max_price.n <= 0 or max_price.d <= 0 → InvalidPrice
  "min_price must not exceed max_price"
  GUARD min_price.n * max_price.d
      > min_price.d * max_price.n → InvalidPrice
```

### Helper: validate_liquidity_pool_withdraw

```
function validate_liquidity_pool_withdraw(op):
  GUARD amount <= 0      → InvalidAmount
  GUARD min_amount_a < 0 → InvalidAmount
  GUARD min_amount_b < 0 → InvalidAmount
```

### Helper: validate_extend_footprint_ttl

```
function validate_extend_footprint_ttl(op):
  GUARD extend_to == 0 → InvalidSorobanData
```

---

### get_operation_source

"If the operation has an explicit source, use that."
"Otherwise, the transaction source is used."

```
function get_operation_source(op, tx_source) → account:
  if op.source_account is set:
    → op.source_account
  → tx_source
```

### ThresholdLevel (enum)

"Stellar accounts have three configurable threshold levels."
"thresholds[0]: Master key weight"
"thresholds[1]: Low threshold"
"thresholds[2]: Medium threshold"
"thresholds[3]: High threshold"

```
ThresholdLevel:
  Low     // index 1
  Medium  // index 2
  High    // index 3
```

### get_threshold_level

```
function get_threshold_level(op) → ThresholdLevel:
  "LOW threshold operations"
  AllowTrust, SetTrustLineFlags, BumpSequence,
  ClaimClaimableBalance, Inflation,
  ExtendFootprintTtl, RestoreFootprint → Low

  "HIGH threshold operations"
  AccountMerge → High

  SetOptions:
    "Requires HIGH when modifying thresholds or signers"
    if master_weight is set
        or low_threshold is set
        or med_threshold is set
        or high_threshold is set
        or signer is set:
      → High
    else:
      → Medium

  "All other operations use MEDIUM threshold"
  everything else → Medium
```

### get_needed_threshold

```
function get_needed_threshold(account, level) → int:
  → account.thresholds[level.index]
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 666    | ~210       |
| Functions     | 24     | 24         |
