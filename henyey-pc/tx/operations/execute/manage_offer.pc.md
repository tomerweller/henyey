## Pseudocode: crates/tx/src/operations/execute/manage_offer.rs

---

### execute_manage_sell_offer

"Creates, updates, or deletes an offer to sell one asset for another."

```
function execute_manage_sell_offer(op, source, state, context):
  → delegate execute_manage_offer(
      source, op.selling, op.buying, op.offer_id,
      op.price, Sell(op.amount), passive=false,
      state, context)
```

**Calls:** [execute_manage_offer](#execute_manage_offer)

---

### execute_manage_buy_offer

"Creates, updates, or deletes an offer to buy one asset with another."

```
function execute_manage_buy_offer(op, source, state, context):
  effective_price = invert_price(op.price)   // swap n and d

  result = execute_manage_offer(
      source, op.selling, op.buying, op.offer_id,
      effective_price, Buy(op.buy_amount), passive=false,
      state, context)

  // Re-wrap ManageSellOffer result as ManageBuyOffer result
  → convert_sell_to_buy_result(result)
```

**Calls:** [execute_manage_offer](#execute_manage_offer)

---

### execute_create_passive_sell_offer

"Creates a passive sell offer that doesn't cross existing offers at same price."

```
function execute_create_passive_sell_offer(op, source, state, context):
  → delegate execute_manage_offer(
      source, op.selling, op.buying, offer_id=0,
      op.price, Sell(op.amount), passive=true,
      state, context)
```

**Calls:** [execute_manage_offer](#execute_manage_offer)

---

### OfferKind

```
OfferKind:
  Sell { amount }        // ManageSellOffer / CreatePassiveSellOffer
  Buy  { buy_amount }    // ManageBuyOffer

  amount():
    Sell → amount
    Buy  → buy_amount

  offer_liabilities(price):
    Sell → offer_liabilities_sell(amount, price)
    Buy  → offer_liabilities_buy(buy_amount, price)

  apply_limits(max_sheep_send, sheep_sent,
               max_wheat_recv, wheat_received):
    Sell → max_sheep_send = min(max_sheep_send,
                                amount - sheep_sent)
    Buy  → max_wheat_recv = min(max_wheat_recv,
                                buy_amount - wheat_received)
```

---

### execute_manage_offer

"Core logic shared by ManageSellOffer, ManageBuyOffer, and
CreatePassiveSellOffer."

```
function execute_manage_offer(source, selling, buying, offer_id,
                              price, offer_kind, passive,
                              state, context):
  offer_amount = offer_kind.amount()

  // --- Phase 1: Basic validation ---
  GUARD selling == buying              → MALFORMED
  GUARD offer_amount < 0              → MALFORMED
  GUARD price.n <= 0 OR price.d <= 0  → MALFORMED

  // --- Phase 2: Delete path ---
  if offer_amount == 0:
    GUARD offer_id == 0               → MALFORMED
    → delegate delete_offer(source, offer_id, state)

  // --- Phase 3: Source account check ---
  GUARD source account missing        → UNDERFUNDED

  // --- Phase 4: Trustline checks ---
  "stellar-core checks trustlines BEFORE checking offer existence.
   This is done in checkOfferValid() which is called before loadOffer().
   We need to match this order to produce identical error codes."

  // Selling trustline
  if selling is NOT native AND issuer_of(selling) != source:
    trustline = get_trustline(source, selling)
    GUARD trustline missing           → SELL_NO_TRUST
    GUARD trustline.balance == 0      → UNDERFUNDED
    GUARD trustline NOT authorized    → SELL_NOT_AUTHORIZED

  // Buying trustline
  if buying is NOT native AND issuer_of(buying) != source:
    trustline = get_trustline(source, buying)
    GUARD trustline missing           → BUY_NO_TRUST
    GUARD trustline NOT authorized    → BUY_NOT_AUTHORIZED

  // --- Phase 5: Offer existence check (AFTER trustline checks) ---
  old_offer = get_offer(source, offer_id) if offer_id != 0
  GUARD offer_id != 0 AND old_offer missing → NOT_FOUND

  // --- Phase 6: Subentry limit for new offers ---
  if old_offer is NONE:
    GUARD source.num_sub_entries >= ACCOUNT_SUBENTRY_LIMIT
        → OP_TOO_MANY_SUBENTRIES

  // --- Phase 7: Sponsorship resolution ---
  sponsor = active_sponsor_for(source) if new offer, else NONE
  reserve_subentry = (new offer) AND (no sponsor)

  // --- Phase 8: Native balance check for existing offers ---
  "For new offers, skip this check: stellar-core checks LowReserve
   BEFORE Underfunded. The later has_selling_capacity check handles
   the Underfunded case for new offers after the LowReserve check."
  if old_offer exists AND selling is NATIVE:
    min_bal = minimum_balance(source_account, protocol_version)
    GUARD source.balance < min_bal    → UNDERFUNDED

  // --- Phase 9: Reserve check for new offers ---
  if old_offer is NONE:
    if sponsor exists:
      min_bal = minimum_balance(sponsor_account, protocol_version,
                                extra_sponsoring=+1)
      available = sponsor.balance - sponsor_liabilities.selling
      GUARD available < min_bal       → LOW_RESERVE
    else:
      min_bal = minimum_balance(source_account, protocol_version,
                                extra_subentries=+1)
      available = source.balance - source_liabilities.selling
      GUARD available < min_bal       → LOW_RESERVE

  // --- Phase 10: Flags ---
  if old_offer exists:
    offer_flags = old_offer.flags
    passive = was_passive(old_offer)  // preserve original passive flag
  else:
    offer_flags = 0
  if passive:
    offer_flags |= PASSIVE_FLAG

  // --- Phase 11: Release old offer liabilities ---
  if old_offer exists:
    ensure old offer trustlines are loaded
    old_sell_liab, old_buy_liab = offer_liabilities_sell(
        old_offer.amount, old_offer.price)
    MUTATE source liabilities for old_offer.selling -= old_sell_liab
    MUTATE source liabilities for old_offer.buying  -= old_buy_liab

  // --- Phase 12: Capacity checks ---
  selling_liab, buying_liab = offer_kind.offer_liabilities(price)

  "Check LineFull before Underfunded to match stellar-core ordering
   (ManageOfferOpFrameBase.cpp:173 checks availableLimit before
    line 198 checks availableBalance)."
  GUARD NOT has_buying_capacity(
      source, buying, buying_liab)     → LINE_FULL
  GUARD NOT has_selling_capacity(
      source, selling, selling_liab,
      reserve_subentry)                → UNDERFUNDED

  // --- Phase 13: Compute exchange limits ---
  max_sheep_send   = can_sell_at_most(source, selling,
                                       state, context, reserve_subentry)
  max_wheat_receive = can_buy_at_most(source, buying, state)
  offer_kind.apply_limits(max_sheep_send, 0,
                          max_wheat_receive, 0)
  GUARD max_wheat_receive == 0         → LINE_FULL

  // --- Phase 14: Cross existing offers ---
  max_wheat_price = Price(n=price.d, d=price.n)  // inverted
  result, sheep_sent, wheat_received = convert_with_offers(
      source, selling, buying,
      max_sheep_send, max_wheat_receive,
      round=NORMAL,
      offer_trail,
      offer_id, passive, max_wheat_price)

  sheep_stays = (result is PARTIAL or FILTER_STOP_BAD_PRICE)
  GUARD result == FILTER_STOP_CROSS_SELF → CROSS_SELF

  // --- Phase 15: Apply exchange results to source ---
  if wheat_received > 0:
    MUTATE source balance for buying  += wheat_received
    MUTATE source balance for selling -= sheep_sent

  // --- Phase 16: Compute remaining offer amount ---
  if sheep_stays:
    sheep_limit = can_sell_at_most(source, selling,
                                    state, context, reserve_subentry)
    wheat_limit = can_buy_at_most(source, buying, state)
    offer_kind.apply_limits(sheep_limit, sheep_sent,
                            wheat_limit, wheat_received)
    amount = adjust_offer_amount(price, sheep_limit, wheat_limit)
  else:
    amount = 0

  // --- Phase 17: Create, update, or delete the offer ---
  if amount > 0:
    if new offer:
      offer_id = generate_offer_id(state)
      if sponsor exists:
        apply_entry_sponsorship(offer_key, sponsor, source)
      state.create_offer(source, offer_id, selling, buying,
                         amount, price, offer_flags)
      MUTATE source.num_sub_entries += 1
      result_offer = CREATED(offer_entry)
    else:
      state.update_offer(source, offer_id, selling, buying,
                         amount, price, offer_flags)
      result_offer = UPDATED(offer_entry)
  else:
    if old_offer exists:
      if offer is sponsored:
        remove_entry_sponsorship(offer_key, source)
      state.delete_offer(source, offer_id)
      MUTATE source.num_sub_entries -= 1
    else:
      "New offer fully consumed during matching.
       In stellar-core (V14+), net effect on fields is zero,
       but account is recorded in LedgerTxn and gets
       lastModified updated on commit."
      state.record_account_access(source)
      if sponsor exists:
        state.record_account_access(sponsor)
    result_offer = DELETED

  // --- Phase 18: Acquire new offer liabilities ---
  if amount > 0:
    new_sell_liab, new_buy_liab = offer_liabilities_sell(amount, price)
    MUTATE source liabilities for selling += new_sell_liab
    MUTATE source liabilities for buying  += new_buy_liab

  → SUCCESS(offers_claimed, result_offer)
```

**Calls:** [validate_offer](#helper-validate_offer), [delete_offer](#delete_offer), [has_selling_capacity](#helper-has_selling_capacity), [has_buying_capacity](#helper-has_buying_capacity), [can_sell_at_most](#helper-can_sell_at_most), [can_buy_at_most](#helper-can_buy_at_most), [convert_with_offers](#convert_with_offers), [apply_liabilities_delta](#helper-apply_liabilities_delta), [offer_liabilities_sell](#helper-offer_liabilities_sell)
REF: offer_exchange::adjust_offer_amount, operations/execute::apply_balance_delta

---

### Helper: validate_offer

```
function validate_offer(selling, buying, amount, price):
  GUARD selling == buying    → MALFORMED
  GUARD amount < 0           → MALFORMED
  GUARD price.n <= 0         → MALFORMED
  GUARD price.d <= 0         → MALFORMED
```

---

### delete_offer

```
function delete_offer(source, offer_id, state):
  offer = get_offer(source, offer_id)
  GUARD offer missing                  → NOT_FOUND

  // Ensure trustlines for old offer assets are loaded
  ensure_trustline_loaded(source, offer.selling)
  ensure_trustline_loaded(source, offer.buying)

  // Release liabilities
  sell_liab, buy_liab = offer_liabilities_sell(offer.amount, offer.price)
  MUTATE source liabilities for offer.selling -= sell_liab
  MUTATE source liabilities for offer.buying  -= buy_liab

  // Remove sponsorship
  sponsor = state.entry_sponsor(offer_key)
  state.delete_offer(source, offer_id)
  if sponsor exists:
    MUTATE sponsor.num_sponsoring -= 1
    MUTATE source.num_sponsored   -= 1

  MUTATE source.num_sub_entries -= 1

  → SUCCESS(offers_claimed=[], DELETED)
```

**Calls:** [offer_liabilities_sell](#helper-offer_liabilities_sell), [apply_liabilities_delta](#helper-apply_liabilities_delta)

---

### convert_with_offers

"Walks the orderbook, crossing offers until the conversion is satisfied.
Differs from path_payment version: filters by price and handles self-crossing
via offer_filter rather than simple source equality check."

```
function convert_with_offers(params, sheep_sent, wheat_received,
                             updating_offer_id, passive,
                             max_wheat_price):
  sheep_sent = 0
  wheat_received = 0
  max_sheep_send   = params.max_send
  max_wheat_receive = params.max_receive
  need_more = (max_sheep_send > 0 AND max_wheat_receive > 0)

  while need_more:
    // Skip the offer being updated (if any)
    offer = state.best_offer_filtered(selling, buying,
        filter: seller != source OR offer_id != updating_offer_id)

    if offer is NONE:
      break

    filter = offer_filter(source, offer, passive, max_wheat_price)
    if filter == STOP_BAD_PRICE:  → FILTER_STOP_BAD_PRICE
    if filter == STOP_CROSS_SELF: → FILTER_STOP_CROSS_SELF

    wheat_recv, sheep_send, wheat_stays = cross_offer_v10(
        offer, max_wheat_receive, max_sheep_send,
        NORMAL, offer_trail, state, context)

    sheep_sent      += sheep_send
    wheat_received  += wheat_recv
    max_sheep_send  -= sheep_send
    max_wheat_receive -= wheat_recv

    need_more = NOT wheat_stays
                AND max_wheat_receive > 0
                AND max_sheep_send > 0
    if NOT need_more: → OK
    if wheat_stays:   → PARTIAL

  → PARTIAL if need_more, else OK
```

**Calls:** [offer_filter](#helper-offer_filter), [cross_offer_v10](#cross_offer_v10)

---

### Helper: offer_filter

"Check price first (offers are sorted by price, so all subsequent will be worse),
then check for self-crossing."

```
function offer_filter(source, offer, passive, max_wheat_price):
  price_cmp = compare_price(offer.price, max_wheat_price)

  // Passive offers don't cross at equal price
  if passive AND price_cmp >= EQUAL:
    → STOP_BAD_PRICE
  if NOT passive AND price_cmp > EQUAL:
    → STOP_BAD_PRICE

  // Only after confirming prices would cross, check self
  if offer.seller == source:
    → STOP_CROSS_SELF

  → KEEP
```

---

### cross_offer_v10

"Cross a single offer from the orderbook. Identical logic to path_payment's
cross_offer_v10 (same 8 steps)."

```
function cross_offer_v10(offer, max_wheat_receive, max_sheep_send,
                         round, offer_trail, state, context):
  sheep  = offer.buying
  wheat  = offer.selling
  seller = offer.seller_id

  state.ensure_offer_entries_loaded(seller, wheat, sheep)

  // Step 1: Release liabilities FIRST
  sell_liab, buy_liab = offer_liabilities_sell(offer.amount, offer.price)
  MUTATE seller liabilities for selling -= sell_liab
  MUTATE seller liabilities for buying  -= buy_liab

  // Step 2: Available amounts AFTER release
  max_wheat_send   = min(offer.amount,
                         can_sell_at_most(seller, wheat, state, context,
                                          reserve_subentry=false))
  max_sheep_recv   = can_buy_at_most(seller, sheep, state)

  // Step 3: Adjust offer amount
  adjusted = adjust_offer_amount(offer.price, max_wheat_send, max_sheep_recv)

  // Step 4: Exchange calculation
  exchange = exchange_v10(offer.price, adjusted,
                          max_wheat_receive, max_sheep_send,
                          max_sheep_recv, round)
  wheat_received = exchange.num_wheat_received
  sheep_send     = exchange.num_sheep_send
  wheat_stays    = exchange.wheat_stays

  // Step 5: Apply balance changes
  if sheep_send != 0:
    MUTATE seller balance for sheep += sheep_send
  if wheat_received != 0:
    MUTATE seller balance for wheat -= wheat_received

  // Step 6: New offer amount
  new_amount = adjusted
  if wheat_stays:
    new_amount -= wheat_received
    if new_amount > 0:
      post_wheat = min(new_amount,
                       can_sell_at_most(seller, wheat, state, context, false))
      post_sheep = can_buy_at_most(seller, sheep, state)
      new_amount = adjust_offer_amount(offer.price, post_wheat, post_sheep)
  else:
    new_amount = 0

  // Step 7: Delete or update offer
  if new_amount == 0:
    sponsor = state.entry_sponsor(offer_key)
    state.delete_offer(seller, offer.offer_id)
    if sponsor exists:
      MUTATE sponsor.num_sponsoring -= 1
      MUTATE seller.num_sponsored   -= 1
    MUTATE seller.num_sub_entries -= 1
  else:
    state.update_offer(offer with amount=new_amount)
    new_sell, new_buy = offer_liabilities_sell(new_amount, offer.price)
    MUTATE seller liabilities for selling += new_sell
    MUTATE seller liabilities for buying  += new_buy

  // Step 8: Record claim
  append ClaimOfferAtom(seller, offer_id, wheat, wheat_received,
                        sheep, sheep_send) to offer_trail

  → (wheat_received, sheep_send, wheat_stays)
```

**Calls:** [can_sell_at_most](#helper-can_sell_at_most), [can_buy_at_most](#helper-can_buy_at_most), [offer_liabilities_sell](#helper-offer_liabilities_sell), [apply_liabilities_delta](#helper-apply_liabilities_delta)
REF: offer_exchange::exchange_v10, offer_exchange::adjust_offer_amount

---

### Helper: compare_price

```
function compare_price(lhs, rhs):
  "Cross-multiply to compare without division"
  lhs_value = lhs.n * rhs.d    // i128
  rhs_value = rhs.n * lhs.d    // i128
  → compare(lhs_value, rhs_value)
```

---

### Helper: has_selling_capacity

```
function has_selling_capacity(source, selling, selling_liab,
                              old_selling_liab, reserve_subentry,
                              state, context):
  if selling is NATIVE:
    if source account missing: → false
    extra = 1 if reserve_subentry else 0
    min_bal = minimum_balance(account, protocol_version, extra)
    effective_liab = account_liabilities(account).selling - old_selling_liab
    available = account.balance - min_bal - effective_liab
    → available >= selling_liab

  if issuer_of(selling) == source: → true

  if trustline missing: → false
  effective_liab = trustline_liabilities(trustline).selling - old_selling_liab
  available = trustline.balance - effective_liab
  → available >= selling_liab
```

---

### Helper: has_buying_capacity

```
function has_buying_capacity(source, buying, buying_liab,
                             old_buying_liab, state):
  if buying is NATIVE:
    if source account missing: → false
    effective_liab = account_liabilities(account).buying - old_buying_liab
    available = MAX_INT - account.balance - effective_liab
    → available >= buying_liab

  if issuer_of(buying) == source: → true

  if trustline missing: → false
  effective_liab = trustline_liabilities(trustline).buying - old_buying_liab
  available = trustline.limit - trustline.balance - effective_liab
  → available >= buying_liab
```

---

### Helper: can_sell_at_most

```
function can_sell_at_most(source, asset, state, context,
                          reserve_subentry):
  if asset is NATIVE:
    if source account missing: → 0
    extra = 1 if reserve_subentry else 0
    min_bal = minimum_balance(account, protocol_version, extra)
    available = account.balance - min_bal
                - account_liabilities(account).selling
    → max(available, 0)

  if issuer_of(asset) == source: → MAX_INT

  if trustline missing: → 0
  if NOT authorized_to_maintain_liabilities(trustline.flags): → 0
  available = trustline.balance - trustline_liabilities(trustline).selling
  → max(available, 0)
```

---

### Helper: can_buy_at_most

```
function can_buy_at_most(source, asset, state):
  if asset is NATIVE:
    if source account missing: → 0
    available = MAX_INT - account.balance
                - account_liabilities(account).buying
    → max(available, 0)

  if issuer_of(asset) == source: → MAX_INT

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

### Helper: offer_liabilities_buy

```
function offer_liabilities_buy(buy_amount, price):
  exchange = exchange_v10_without_price_error_thresholds(
      price, amount=MAX_INT,
      max_send=MAX_INT, max_recv=MAX_INT,
      max_sheep=buy_amount, round=NORMAL)
  → (exchange.num_wheat_received, exchange.num_sheep_send)
```

REF: offer_exchange::exchange_v10_without_price_error_thresholds

---

### Helper: apply_liabilities_delta

```
function apply_liabilities_delta(source, selling, buying,
                                 selling_delta, buying_delta, state):
  // Selling side
  if selling is NATIVE:
    liab = account(source).liabilities
    update_liabilities(liab, buying_delta=0, selling_delta)
  else if issuer_of(selling) != source:
    liab = trustline(source, selling).liabilities
    update_liabilities(liab, buying_delta=0, selling_delta)

  // Buying side
  if buying is NATIVE:
    liab = account(source).liabilities
    update_liabilities(liab, buying_delta, selling_delta=0)
  else if issuer_of(buying) != source:
    liab = trustline(source, buying).liabilities
    update_liabilities(liab, buying_delta, selling_delta=0)
```

---

### Helper: update_liabilities

```
function update_liabilities(liab, buying_delta, selling_delta):
  new_buying  = liab.buying  + buying_delta
  new_selling = liab.selling + selling_delta
  ASSERT: new_buying >= 0 AND new_selling >= 0
  MUTATE liab.buying  = new_buying
  MUTATE liab.selling = new_selling
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1163  | ~350       |
| Functions     | 22     | 22         |
