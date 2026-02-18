## Pseudocode: crates/tx/src/operations/execute/path_payment.rs

CONST MAX_OFFERS_TO_CROSS = 1000  // protocol 11+ limit per path payment
CONST MAX_BPS = 10_000            // basis-point denominator for pool fees

---

### execute_path_payment_strict_receive

"Sends at most send_max of send_asset to receive exactly dest_amount
of dest_asset at the destination."

```
function execute_path_payment_strict_receive(op, source, state, context):
  dest = muxed_to_account_id(op.destination)

  // --- Phase 1: Validation ---
  GUARD op.send_max <= 0 OR op.dest_amount <= 0   → MALFORMED

  bypass_issuer = should_bypass_issuer_check(
      op.path, op.send_asset, op.dest_asset, dest)
  GUARD NOT bypass_issuer AND dest account missing → NO_DESTINATION

  // --- Phase 2: Credit destination FIRST ---
  err = update_dest_balance(
      dest, op.dest_asset, op.dest_amount,
      bypass_issuer, state, context)
  GUARD err                                        → err.code

  // --- Phase 3: Walk path in REVERSE ---
  full_path = reverse(op.path) + [op.send_asset]
  recv_asset  = op.dest_asset
  max_recv    = op.dest_amount
  offers_claimed = []

  for each send_asset in full_path:
    if recv_asset == send_asset:
      continue

    if NOT bypass_issuer:
      err = check_issuer(send_asset, state, context)
      GUARD err                                    → err.code

    remaining_crosses = MAX_OFFERS_TO_CROSS - len(offers_claimed)
    result, amount_send, amount_recv = convert_with_offers_and_pools(
        source, send_asset, recv_asset,
        max_send=MAX_INT, max_receive=max_recv,
        round=STRICT_RECEIVE,
        state, context, remaining_crosses)

    GUARD result == FILTER_STOP_CROSS_SELF         → OFFER_CROSS_SELF
    GUARD result == CROSSED_TOO_MANY               → OP_EXCEEDED_WORK_LIMIT
    GUARD result != OK OR amount_recv != max_recv  → TOO_FEW_OFFERS

    max_recv   = amount_send
    recv_asset = send_asset
    prepend offer_trail to offers_claimed

  // --- Phase 4: Enforce send cap ---
  GUARD max_recv > op.send_max                     → OVER_SENDMAX

  // --- Phase 5: Debit source LAST ---
  err = update_source_balance(
      source, op.send_asset, max_recv,
      bypass_issuer, state, context)
  GUARD err                                        → err.code

  → SUCCESS(offers_claimed, dest, op.dest_asset, op.dest_amount)
```

**Calls:** [update_dest_balance](#helper-update_dest_balance), [update_source_balance](#helper-update_source_balance), [should_bypass_issuer_check](#helper-should_bypass_issuer_check), [convert_with_offers_and_pools](#convert_with_offers_and_pools)

---

### execute_path_payment_strict_send

"Sends exactly send_amount of send_asset to receive at least dest_min
of dest_asset at the destination."

```
function execute_path_payment_strict_send(op, source, state, context):
  dest = muxed_to_account_id(op.destination)

  // --- Phase 1: Validation ---
  GUARD op.send_amount <= 0 OR op.dest_min <= 0    → MALFORMED

  bypass_issuer = should_bypass_issuer_check(
      op.path, op.send_asset, op.dest_asset, dest)
  GUARD NOT bypass_issuer AND dest account missing  → NO_DESTINATION

  // --- Phase 2: Debit source FIRST ---
  err = update_source_balance(
      source, op.send_asset, op.send_amount,
      bypass_issuer, state, context)
  GUARD err                                         → err.code

  // --- Phase 3: Walk path FORWARD ---
  full_path = op.path + [op.dest_asset]
  send_asset  = op.send_asset
  max_send    = op.send_amount
  offers_claimed = []

  for each recv_asset in full_path:
    if recv_asset == send_asset:
      continue

    if NOT bypass_issuer:
      err = check_issuer(recv_asset, state, context)
      GUARD err                                     → err.code

    remaining_crosses = MAX_OFFERS_TO_CROSS - len(offers_claimed)
    result, amount_send, amount_recv = convert_with_offers_and_pools(
        source, send_asset, recv_asset,
        max_send=max_send, max_receive=MAX_INT,
        round=STRICT_SEND,
        state, context, remaining_crosses)

    GUARD result == FILTER_STOP_CROSS_SELF          → OFFER_CROSS_SELF
    GUARD result == CROSSED_TOO_MANY                → OP_EXCEEDED_WORK_LIMIT
    GUARD result != OK OR amount_send != max_send   → TOO_FEW_OFFERS

    max_send   = amount_recv
    send_asset = recv_asset
    append offer_trail to offers_claimed

  // --- Phase 4: Enforce minimum destination ---
  GUARD max_send < op.dest_min                      → UNDER_DESTMIN

  // --- Phase 5: Credit destination LAST ---
  err = update_dest_balance(
      dest, op.dest_asset, max_send,
      bypass_issuer, state, context)
  GUARD err                                         → err.code

  → SUCCESS(offers_claimed, dest, op.dest_asset, max_send)
```

**Calls:** [update_source_balance](#helper-update_source_balance), [update_dest_balance](#helper-update_dest_balance), [should_bypass_issuer_check](#helper-should_bypass_issuer_check), [convert_with_offers_and_pools](#convert_with_offers_and_pools)

---

### Helper: should_bypass_issuer_check

```
function should_bypass_issuer_check(path, send_asset, dest_asset, dest):
  → dest_asset is NOT native
    AND path is empty
    AND send_asset == dest_asset
    AND issuer_of(dest_asset) == dest
```

REF: operations/execute::issuer_for_asset

---

### Helper: check_issuer

"In protocol 13+ (CAP-0017), issuer checks were removed."

```
function check_issuer(asset, state, context):
  → OK   // no-op for protocol 13+
```

---

### Helper: update_source_balance

```
function update_source_balance(source, asset, amount,
                               bypass_issuer, state, context):

  // --- Native asset ---
  if asset is NATIVE:
    GUARD source account missing                   → UNDERFUNDED
    min_bal = minimum_balance(source_account, protocol_version)
    available = source.balance - min_bal - account_liabilities(source).selling
    GUARD available < amount                       → UNDERFUNDED
    MUTATE source.balance -= amount
    → OK

  // --- Credit asset ---
  if NOT bypass_issuer:
    check_issuer(asset, state, context)

  if issuer_of(asset) == source:
    → OK    // issuer has unlimited supply

  trustline = get_trustline(source, asset)
  GUARD trustline missing                          → SRC_NO_TRUST

  "The AUTH_REQUIRED flag on issuer only affects whether NEW trustlines
   start authorized, but once a trustline exists, its AUTHORIZED flag
   controls whether it can send."
  GUARD trustline NOT authorized                   → SRC_NOT_AUTHORIZED

  available = trustline.balance - trustline_liabilities(trustline).selling
  GUARD available < amount                         → UNDERFUNDED

  MUTATE trustline.balance -= amount
  → OK
```

REF: operations/execute::account_liabilities, operations/execute::trustline_liabilities, operations/execute::is_trustline_authorized

---

### Helper: update_dest_balance

```
function update_dest_balance(dest, asset, amount,
                             bypass_issuer, state, context):

  // --- Native asset ---
  if asset is NATIVE:
    GUARD dest account missing                     → NO_DESTINATION
    GUARD NOT add_account_balance(dest, amount)    → LINE_FULL
    → OK

  // --- Credit asset ---
  if NOT bypass_issuer:
    check_issuer(asset, state, context)

  if issuer_of(asset) == dest:
    → OK    // issuer absorbs unlimited

  trustline = get_trustline(dest, asset)
  GUARD trustline missing                          → NO_TRUST

  "Check destination is authorized — unconditional"
  GUARD trustline NOT authorized                   → NOT_AUTHORIZED

  GUARD NOT add_trustline_balance(trustline, amount) → LINE_FULL
  → OK
```

REF: operations/execute::add_account_balance, operations/execute::add_trustline_balance, operations/execute::is_trustline_authorized

---

### convert_with_offers_and_pools

"Converts between two assets using both order book and liquidity pool,
choosing the better rate."

```
function convert_with_offers_and_pools(params, amount_send, amount_recv,
                                       max_offers_to_cross):

  // Normal rounding (manage offer) skips pools entirely
  if params.round == NORMAL:
    → delegate convert_with_offers(params, amount_send,
                                   amount_recv, max_offers_to_cross)

  // --- Phase 1: Compute hypothetical pool exchange ---
  pool_exchange = compute_pool_exchange(
      params.selling, params.max_send,
      params.buying, params.max_receive,
      params.round, state)

  if pool_exchange is NONE:
    → delegate convert_with_offers(...)

  GUARD max_offers_to_cross == 0  → CROSSED_TOO_MANY

  // --- Phase 2: Speculatively run orderbook path ---
  "Use savepoint instead of cloning entire state
   (avoids O(n) clone of 911K+ offers)."
  savepoint = state.create_savepoint()

  book_result, book_send, book_recv = convert_with_offers(
      params_copy, max_offers_to_cross)

  // --- Phase 3: Compare rates ---
  use_book = (book_result == OK) AND
    (pool_exchange.send * book_recv > pool_exchange.recv * book_send)
    NOTE: cross-multiply comparison avoids division

  if use_book:
    // Book wins — keep speculative changes
    amount_send = book_send
    amount_recv = book_recv
    → book_result

  // Pool wins — rollback speculative book changes
  state.rollback_to_savepoint(savepoint)

  // --- Phase 4: Apply pool exchange ---
  if apply_pool_exchange(selling, buying,
                         pool_exchange.send, pool_exchange.recv, state):
    amount_send = pool_exchange.send
    amount_recv = pool_exchange.recv
    append ClaimLiquidityAtom to offer_trail
    → OK

  // Pool application failed — fall back to orderbook
  → delegate convert_with_offers(...)
```

**Calls:** [convert_with_offers](#convert_with_offers), [compute_pool_exchange](#helper-compute_pool_exchange), [apply_pool_exchange](#helper-apply_pool_exchange)

---

### convert_with_offers

"Walks the orderbook, crossing offers until the conversion is satisfied."

```
function convert_with_offers(params, amount_send, amount_recv,
                             max_offers_to_cross):
  amount_send = 0
  amount_recv = 0
  max_send = params.max_send
  max_recv = params.max_receive
  need_more = (max_send > 0 AND max_recv > 0)

  GUARD need_more AND max_offers_to_cross == 0 → CROSSED_TOO_MANY

  while need_more:
    offer = state.best_offer(params.selling, params.buying)
    if offer is NONE:
      break

    GUARD offer.seller == params.source        → FILTER_STOP_CROSS_SELF
    GUARD trail_len >= max_offers_to_cross     → CROSSED_TOO_MANY

    recv, send, wheat_stays = cross_offer_v10(
        offer, max_recv, max_send, params.round,
        offer_trail, state, context)

    amount_send += send
    amount_recv += recv
    max_send    -= send
    max_recv    -= recv

    "needMore = !wheatStays && (maxWheatReceive > 0 && maxSheepSend > 0)"
    need_more = NOT wheat_stays AND max_send > 0 AND max_recv > 0

  → PARTIAL if need_more, else OK
```

**Calls:** [cross_offer_v10](#cross_offer_v10)

---

### cross_offer_v10

"Cross a single offer from the orderbook. Uses the v10 exchange algorithm."

```
function cross_offer_v10(offer, max_recv, max_send, round,
                         offer_trail, state, context):
  sheep  = offer.buying     // what seller wants
  wheat  = offer.selling    // what seller offers
  seller = offer.seller_id

  state.ensure_offer_entries_loaded(seller, wheat, sheep)

  // --- Step 1: Release liabilities FIRST ---
  "Critical — available balance depends on liabilities being released first"
  selling_liab, buying_liab = offer_liabilities_sell(offer.amount, offer.price)
  MUTATE seller liabilities for selling_asset -= selling_liab
  MUTATE seller liabilities for buying_asset  -= buying_liab

  // --- Step 2: Available amounts AFTER release ---
  max_wheat_send   = min(offer.amount,
                         can_sell_at_most(seller, wheat, state, context))
  max_sheep_receive = can_buy_at_most(seller, sheep, state)

  // --- Step 3: Adjust offer amount ---
  "stellar-core calls adjustOffer here as preventative measure"
  adjusted = adjust_offer_amount(offer.price, max_wheat_send, max_sheep_receive)

  // --- Step 4: Exchange calculation ---
  exchange = exchange_v10(offer.price, adjusted,
                          max_recv, max_send,
                          max_sheep_receive, round)
  wheat_received = exchange.num_wheat_received
  sheep_send     = exchange.num_sheep_send
  wheat_stays    = exchange.wheat_stays

  // --- Step 5: Apply balance changes ---
  if sheep_send != 0:
    MUTATE seller balance for sheep += sheep_send
  if wheat_received != 0:
    MUTATE seller balance for wheat -= wheat_received

  // --- Step 6: New offer amount ---
  if wheat_stays:
    tentative = adjusted - wheat_received
    if tentative > 0:
      post_wheat = min(tentative,
                       can_sell_at_most(seller, wheat, state, context))
      post_sheep = can_buy_at_most(seller, sheep, state)
      new_amount = adjust_offer_amount(offer.price, post_wheat, post_sheep)
    else:
      new_amount = 0
  else:
    new_amount = 0

  // --- Step 7: Delete or update offer ---
  if new_amount == 0:
    sponsor = state.entry_sponsor(offer_key)
    state.delete_offer(seller, offer.offer_id)
    if sponsor exists:
      MUTATE sponsor.num_sponsoring -= 1
      MUTATE seller.num_sponsored   -= 1
    MUTATE seller.num_sub_entries -= 1
  else:
    state.update_offer(offer with amount=new_amount)
    new_sell_liab, new_buy_liab = offer_liabilities_sell(new_amount, offer.price)
    MUTATE seller liabilities for selling_asset += new_sell_liab
    MUTATE seller liabilities for buying_asset  += new_buy_liab

  // --- Step 8: Record claim ---
  "stellar-core always adds one, even for 0-0 exchanges"
  append ClaimOfferAtom(seller, offer_id, wheat, wheat_received,
                        sheep, sheep_send) to offer_trail

  → (wheat_received, sheep_send, wheat_stays)
```

**Calls:** [can_sell_at_most](#helper-can_sell_at_most), [can_buy_at_most](#helper-can_buy_at_most), [offer_liabilities_sell](#helper-offer_liabilities_sell), [apply_liabilities_delta](#helper-apply_liabilities_delta)
REF: offer_exchange::exchange_v10, offer_exchange::adjust_offer_amount

---

### Helper: can_sell_at_most

```
function can_sell_at_most(source, asset, state, context):
  if asset is NATIVE:
    if source account missing: → 0
    min_bal   = minimum_balance(account, protocol_version)
    available = account.balance - min_bal
                - account_liabilities(account).selling
    → max(available, 0)

  if issuer_of(asset) == source:
    → MAX_INT    // issuer has unlimited supply

  if trustline missing: → 0
  if NOT authorized_to_maintain_liabilities(trustline.flags): → 0
  available = trustline.balance - trustline_liabilities(trustline).selling
  → max(available, 0)
```

REF: operations/execute::account_liabilities, operations/execute::trustline_liabilities, operations/execute::is_authorized_to_maintain_liabilities

---

### Helper: can_buy_at_most

```
function can_buy_at_most(source, asset, state):
  if asset is NATIVE:
    if source account missing: → 0
    available = MAX_INT - account.balance
                - account_liabilities(account).buying
    → max(available, 0)

  if issuer_of(asset) == source:
    → MAX_INT    // issuer absorbs unlimited

  if trustline missing: → 0
  if NOT authorized_to_maintain_liabilities(trustline.flags): → 0
  available = trustline.limit - trustline.balance
              - trustline_liabilities(trustline).buying
  → max(available, 0)
```

---

### Helper: offer_liabilities_sell

```
function offer_liabilities_sell(amount, price):
  exchange = exchange_v10_without_price_error_thresholds(
      price, amount,
      max_send=MAX_INT, max_recv=MAX_INT,
      max_sheep=MAX_INT, round=NORMAL)
  → (exchange.num_wheat_received, exchange.num_sheep_send)
```

REF: offer_exchange::exchange_v10_without_price_error_thresholds

---

### Helper: apply_liabilities_delta

```
function apply_liabilities_delta(account_id, selling, buying,
                                 selling_delta, buying_delta, state):
  // --- Selling side ---
  if selling is NATIVE:
    liab = account.liabilities
    update_liabilities(liab, buying_delta=0, selling_delta)
  else if issuer_of(selling) != account_id:
    liab = trustline(account_id, selling).liabilities
    update_liabilities(liab, buying_delta=0, selling_delta)

  // --- Buying side ---
  if buying is NATIVE:
    liab = account.liabilities
    update_liabilities(liab, buying_delta, selling_delta=0)
  else if issuer_of(buying) != account_id:
    liab = trustline(account_id, buying).liabilities
    update_liabilities(liab, buying_delta, selling_delta=0)
```

---

### Helper: update_liabilities

```
function update_liabilities(liab, buying_delta, selling_delta):
  new_buying  = liab.buying  + buying_delta
  new_selling = liab.selling + selling_delta
  ASSERT: no overflow in addition
  ASSERT: new_buying >= 0 AND new_selling >= 0
  MUTATE liab.buying  = new_buying
  MUTATE liab.selling = new_selling
```

---

### Helper: compute_pool_exchange

```
function compute_pool_exchange(send_asset, max_send,
                               recv_asset, max_recv,
                               round, state):
  pool_id = pool_id_for_assets(send_asset, recv_asset)
  pool = state.get_liquidity_pool(pool_id)
  if pool is NONE: → NONE

  if pool.reserve_a <= 0 OR pool.reserve_b <= 0: → NONE

  fee_bps = LIQUIDITY_POOL_FEE_V18

  // Map assets to reserves (A or B direction)
  if send == asset_a AND recv == asset_b:
    reserves_to = reserve_a, reserves_from = reserve_b
  else if send == asset_b AND recv == asset_a:
    reserves_to = reserve_b, reserves_from = reserve_a
  else: → NONE

  ok, to_pool, from_pool = exchange_with_pool(
      reserves_to, max_send,
      reserves_from, max_recv,
      fee_bps, round)
  if NOT ok: → NONE

  → PoolExchange(pool_id, send=to_pool, recv=from_pool)
```

**Calls:** [pool_id_for_assets](#helper-pool_id_for_assets), [exchange_with_pool](#helper-exchange_with_pool)

---

### Helper: apply_pool_exchange

```
function apply_pool_exchange(send_asset, recv_asset,
                             to_pool, from_pool, state):
  pool_id = pool_id_for_assets(send_asset, recv_asset)
  pool = state.get_liquidity_pool_mut(pool_id)
  if pool is NONE: → false

  if send == asset_a AND recv == asset_b:
    MUTATE pool.reserve_a += to_pool
    MUTATE pool.reserve_b -= from_pool
  else if send == asset_b AND recv == asset_a:
    MUTATE pool.reserve_b += to_pool
    MUTATE pool.reserve_a -= from_pool
  else: → false

  ASSERT: no overflow/underflow in reserve arithmetic
  → true
```

---

### Helper: pool_id_for_assets

```
function pool_id_for_assets(send_asset, recv_asset):
  params = ConstantProductPool(
      asset_a = min(send_asset, recv_asset),
      asset_b = max(send_asset, recv_asset),
      fee = LIQUIDITY_POOL_FEE_V18)
  → SHA256(xdr_serialize(params))
```

---

### Helper: exchange_with_pool

"Constant-product AMM exchange with fee, matching stellar-core hugeDivide
algorithm exactly."

```
function exchange_with_pool(reserves_to, max_send,
                            reserves_from, max_recv,
                            fee_bps, round):
  ASSERT: 0 <= fee_bps < MAX_BPS
  ASSERT: reserves_to > 0 AND reserves_from > 0

  if round == STRICT_SEND:
    ASSERT: max_recv == MAX_INT
    max_recv_local = reserves_from

    if max_send > MAX_INT - reserves_to: → false
    to_pool = max_send

    denominator = MAX_BPS * reserves_to
                + (MAX_BPS - fee_bps) * to_pool

    if denominator == 0: → false

    "hugeDivide: floor(A * B / C) using A*Q + floor(A*R / C)"
    A = MAX_BPS - fee_bps
    B = reserves_from * to_pool          // u128
    C = denominator                       // u128
    Q = B / C;  R = B % C
    from_pool = A * Q + floor(A * R / C)

    if from_pool > MAX_INT: → false
    if from_pool > max_recv_local OR from_pool == 0: → false
    → true

  if round == STRICT_RECEIVE:
    ASSERT: max_send == MAX_INT
    max_send_local = MAX_INT - reserves_to
    if max_recv >= reserves_from: → false
    from_pool = max_recv

    "hugeDivide: ceil(A * B / C) using A*Q + ceil(A*R / C)"
    A = MAX_BPS
    B = reserves_to * from_pool           // u128
    C = (reserves_from - from_pool) * (MAX_BPS - fee_bps)  // u128

    if C == 0: → false
    Q = B / C;  R = B % C
    to_pool = A * Q + ceil(A * R / C)

    if to_pool > MAX_INT: → false
    → to_pool <= max_send_local

  if round == NORMAL: → false
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1293  | ~310       |
| Functions     | 18     | 18         |
