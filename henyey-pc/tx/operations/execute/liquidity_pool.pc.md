## Pseudocode: crates/tx/src/operations/execute/liquidity_pool.rs

"Liquidity Pool operation execution."
"Implements LiquidityPoolDeposit and LiquidityPoolWithdraw."

CONST AUTH_REQUIRED_FLAG = 0x1

### execute_liquidity_pool_deposit

```
function execute_liquidity_pool_deposit(op, source, state, context):

  "--- Validate amounts and prices ---"

  GUARD op.max_amount_a <= 0 OR op.max_amount_b <= 0   → Malformed
  GUARD min_price.n <= 0 OR min_price.d <= 0
    OR max_price.n <= 0 OR max_price.d <= 0             → Malformed
  GUARD min_price > max_price (cross-multiply check)    → Malformed

  "--- Load pool ---"

  pool = state.get_liquidity_pool(op.pool_id)
  GUARD pool not found                                  → NoTrust

  extract: asset_a, asset_b, reserve_a, reserve_b,
           total_shares, fee from pool

  "--- Check trustlines ---"

  pool_share_trustline = state.get_trustline(source, pool_share_asset)
  GUARD pool_share_trustline not found                  → NoTrust

  "For each asset (a, b): skip if native or issuer"
  trustline_a = state.get_trustline(source, asset_a)
  GUARD trustline_a not found (and needed)              → NoTrust

  trustline_b = state.get_trustline(source, asset_b)
  GUARD trustline_b not found (and needed)              → NoTrust

  "--- Check authorization ---"

  GUARD asset_a requires auth AND trustline_a not authorized
                                                        → NotAuthorized
  GUARD asset_b requires auth AND trustline_b not authorized
                                                        → NotAuthorized

  "--- Compute available balances ---"

  available_a = native → available_native_balance
               | issuer → MAX_INT64
               | else → trustline.balance - selling_liabilities
  available_b = (same logic for asset_b)
  available_pool_share_limit = pool_share.limit - pool_share.balance

  "--- Compute deposit amounts ---"

  if total_shares == 0:
    result = deposit_into_empty_pool(...)
  else:
    result = deposit_into_non_empty_pool(...)

  handle outcomes:
    Underfunded → Underfunded
    BadPrice    → BadPrice
    LineFull    → LineFull
    Success     → extract deposit_a, deposit_b, shares_received

  "--- Overflow check ---"

  GUARD MAX_INT64 - reserve_a < deposit_a
    OR MAX_INT64 - reserve_b < deposit_b
    OR MAX_INT64 - total_shares < shares_received
                                                        → PoolFull

  "--- Deduct assets from source ---"

  "NOTE: issuers create assets from nothing, no balance to deduct"

  if asset_a is native:
    GUARD account.balance < deposit_a → Underfunded
    MUTATE account.balance -= deposit_a
  else if source is issuer of asset_a:
    (no-op)
  else:
    GUARD trustline_a.balance < deposit_a → Underfunded
    MUTATE trustline_a.balance -= deposit_a

  (same logic for asset_b)

  "--- Credit pool shares ---"

  MUTATE pool_share_trustline.balance += shares_received

  "--- Update pool ---"

  MUTATE pool.reserve_a += deposit_a
  MUTATE pool.reserve_b += deposit_b
  MUTATE pool.total_pool_shares += shares_received

  → Success
```

**Calls**: [deposit_into_empty_pool](#helper-deposit_into_empty_pool) | [deposit_into_non_empty_pool](#helper-deposit_into_non_empty_pool) | [available_native_balance](#helper-available_native_balance) | [account_liabilities](../mod.pc.md#account_liabilities) | [trustline_liabilities](../mod.pc.md#trustline_liabilities)

### execute_liquidity_pool_withdraw

```
function execute_liquidity_pool_withdraw(op, source, state, context):

  "--- Validate ---"

  GUARD op.amount <= 0                   → Malformed
  GUARD op.min_amount_a < 0
    OR op.min_amount_b < 0               → Malformed

  "--- Load pool ---"

  pool = state.get_liquidity_pool(op.pool_id)
  GUARD pool not found                   → NoTrust

  extract: asset_a, asset_b, reserve_a, reserve_b,
           total_shares from pool

  "--- Check pool share balance ---"

  shares_balance = pool_share_trustline.balance
  GUARD pool_share_trustline not found   → NoTrust
  GUARD shares_balance < op.amount       → Underfunded

  "--- Compute withdrawals ---"

  withdraw_a = (op.amount * reserve_a) / total_shares  // round down
  withdraw_b = (op.amount * reserve_b) / total_shares  // round down

  GUARD withdraw_a < op.min_amount_a
    OR withdraw_b < op.min_amount_b      → UnderMinimum

  "--- Check can credit ---"

  for each asset (a, b):
    check = can_credit_asset(state, source, asset, amount)
    GUARD check == NoTrust               → NoTrust
    GUARD check == LineFull              → LineFull

  "--- Apply ---"

  credit_asset(state, source, asset_a, withdraw_a)
  credit_asset(state, source, asset_b, withdraw_b)

  MUTATE pool_share_trustline.balance -= op.amount
  MUTATE pool.reserve_a -= withdraw_a
  MUTATE pool.reserve_b -= withdraw_b
  MUTATE pool.total_pool_shares -= op.amount

  → Success
```

**Calls**: [get_pool_withdrawal_amount](#helper-get_pool_withdrawal_amount) | [can_credit_asset](#helper-can_credit_asset) | [credit_asset](#helper-credit_asset)

### Helper: is_auth_required

```
function is_auth_required(asset, state):
  if asset is native: → false
  issuer_account = state.get_account(asset.issuer)
  → issuer_account.flags has AUTH_REQUIRED_FLAG
```

### Helper: available_native_balance

```
function available_native_balance(source, state, context):
  account = state.get_account(source)
  if not found: → 0
  min_balance = minimum_balance(account, protocol, 0)
  → account.balance - min_balance - selling_liabilities
```

### Helper: is_bad_price

```
function is_bad_price(amount_a, amount_b, min_price, max_price):
  if amount_a == 0 OR amount_b == 0: → true
  → amount_a * min_price.d < amount_b * min_price.n
    OR amount_a * max_price.d > amount_b * max_price.n
```

### Helper: deposit_into_empty_pool

```
function deposit_into_empty_pool(max_a, max_b, avail_a, avail_b,
                                  avail_share_limit, min_price, max_price):
  GUARD avail_a < max_a OR avail_b < max_b  → Underfunded
  GUARD is_bad_price(max_a, max_b, ...)     → BadPrice

  shares = integer_sqrt(max_a * max_b)

  GUARD avail_share_limit < shares          → LineFull

  → Success(max_a, max_b, shares)
```

**Calls**: [is_bad_price](#helper-is_bad_price) | [big_square_root](#helper-big_square_root)

### Helper: deposit_into_non_empty_pool

```
function deposit_into_non_empty_pool(max_a, max_b, avail_a, avail_b,
    avail_share_limit, reserve_a, reserve_b, total_shares,
    min_price, max_price):

  shares_a = (total_shares * max_a) / reserve_a  // round down
  shares_b = (total_shares * max_b) / reserve_b  // round down
  pool_shares = min(shares_a, shares_b)

  amount_a = (pool_shares * reserve_a) / total_shares  // round up
  amount_b = (pool_shares * reserve_b) / total_shares  // round up

  GUARD avail_a < amount_a OR avail_b < amount_b → Underfunded
  GUARD is_bad_price(amount_a, amount_b, ...)    → BadPrice
  GUARD avail_share_limit < pool_shares          → LineFull

  → Success(amount_a, amount_b, pool_shares)
```

### Helper: get_pool_withdrawal_amount

```
function get_pool_withdrawal_amount(amount, total_shares, reserve):
  → (amount * reserve) / total_shares  // round down, 0 on error
```

### Helper: can_credit_asset

```
function can_credit_asset(state, source, asset, amount):
  if asset is native:
    GUARD account not found                         → NoTrust
    GUARD MAX_INT64 - account.balance < amount      → LineFull
    GUARD new_balance > MAX_INT64 - buying_liab     → LineFull
    → Ok

  "Issuers don't need trustlines for their own assets"
  if source is issuer: → Ok

  GUARD trustline not found                          → NoTrust
  GUARD not authorized_to_maintain_liabilities       → LineFull
  GUARD limit - balance < amount                     → LineFull
  GUARD new_balance > limit - buying_liab            → LineFull
  → Ok
```

### Helper: credit_asset

```
function credit_asset(state, source, asset, amount):
  if asset is native:
    MUTATE account.balance += amount
    return

  "Issuers: credits are essentially destroyed"
  if source is issuer: return

  MUTATE trustline.balance += amount
```

### Helper: is_issuer

```
function is_issuer(account, asset):
  if asset is native: → false
  → asset.issuer == account
```

### Helper: big_square_root

```
function big_square_root(a, b):
  product = a * b  // 128-bit
  "Binary search for integer square root"
  low = 0, high = min(product, MAX_INT64)
  while low <= high:
    mid = (low + high) / 2
    if mid * mid == product: → mid
    if mid * mid < product: low = mid + 1
    else: high = mid - 1
  → max(high, 0)
```

### Helper: big_divide

```
function big_divide(a, b, c, round):
  if c == 0: → 0
  numerator = a * b  // 128-bit
  if round == Down:
    result = numerator / c
  if round == Up:
    if numerator == 0: result = 0
    else: result = (numerator + c - 1) / c
  if result > MAX_INT64: → 0
  → result
```

## Summary
| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 697    | 180        |
| Functions    | 16     | 14         |
